import os
import time
import re
import feedparser
import psycopg2
import logging
import json
from psycopg2.extras import Json, execute_values
from datetime import datetime, timezone

# --- Logging Konfiguration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Konfiguration aus Umgebungsvariablen laden ---
DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'db')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', 3600))

# RSS-Feeds
RSS_FEEDS = os.getenv('RSS_FEEDS', '').split(',')
if not RSS_FEEDS or RSS_FEEDS == ['']:
    RSS_FEEDS = [
        "https://www.debian.org/security/dsa-long",
        "https://access.redhat.com/security/data/metrics/rhsa.rss",
        "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
        "https://www.heise.de/security/rss/news-atom.xml"
    ]
    logging.warning("Keine RSS_FEEDS in .env gefunden. Verwende Standard-Feeds.")


def connect_to_db():
    """Stellt eine Verbindung zur PostgreSQL-Datenbank her."""
    conn = None
    retries = 10
    while retries > 0 and conn is None:
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST
            )
            logging.info("Erfolgreich mit der Datenbank verbunden.")
            return conn
        except psycopg2.OperationalError as e:
            logging.warning(f"Datenbankverbindung fehlgeschlagen. Versuche es in 5 Sekunden erneut... ({retries} Versuche übrig)")
            retries -= 1
            time.sleep(5)
    logging.error("Konnte keine Verbindung zur Datenbank herstellen. Beende.")
    return None

def create_tables_if_not_exist(conn):
    """Erstellt alle notwendigen Tabellen, falls sie noch nicht existieren."""
    with conn.cursor() as cur:
        # FIX: Jeder CREATE-Befehl wird separat ausgeführt, um die korrekte Erstellung sicherzustellen.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS feeds (
                id SERIAL PRIMARY KEY,
                url TEXT UNIQUE NOT NULL,
                publisher VARCHAR(255),
                category VARCHAR(255),
                last_polled_ts TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                entry_id TEXT UNIQUE NOT NULL,
                feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
                title TEXT,
                link TEXT,
                summary TEXT,
                published_ts TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                raw_data JSONB
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_cves (
                vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                cve_id INTEGER NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
                PRIMARY KEY (vulnerability_id, cve_id)
            );
        """)
        conn.commit()
        logging.info("Alle Tabellen sind bereit.")

def get_or_create_feed(cur, feed_url):
    """Holt oder erstellt einen Feed-Eintrag und gibt dessen ID zurück."""
    now_utc = datetime.now(timezone.utc)
    cur.execute("""
        INSERT INTO feeds (url, last_polled_ts) VALUES (%s, %s)
        ON CONFLICT (url) DO UPDATE SET last_polled_ts = EXCLUDED.last_polled_ts
        RETURNING id;
    """, (feed_url, now_utc))
    return cur.fetchone()[0]

def extract_cves(text):
    """Extrahiert eindeutige CVE-Identifier aus einem Textblock."""
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return sorted(list(set(re.findall(cve_pattern, text, re.IGNORECASE))))

def process_feeds(conn):
    """Ruft RSS-Feeds ab und verarbeitet neue Einträge effizient mit Batch-Operationen."""
    for feed_url in RSS_FEEDS:
        if not feed_url:
            continue
            
        logging.info(f"Verarbeite Feed: {feed_url}")
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                logging.warning(f"Feed {feed_url} ist möglicherweise fehlerhaft: {feed.bozo_exception}")

            logging.info(f"Feed '{feed.feed.get('title', 'Unbekannter Titel')}' hat {len(feed.entries)} Einträge gefunden.")
            
            with conn.cursor() as cur:
                feed_id = get_or_create_feed(cur, feed_url)

                # --- Phase 1: Batch-Insert für neue Schwachstellen ---
                new_vulnerabilities_data = []
                entry_map = {} # Zur späteren Zuordnung von entry_id zu entry-Objekt
                for entry in feed.entries:
                    entry_id = entry.get('link') or entry.get('id')
                    if not entry_id:
                        continue
                    
                    entry_map[entry_id] = entry
                    published_ts = psycopg2.TimestampFromTicks(time.mktime(entry.published_parsed)) if entry.get('published_parsed') else None
                    
                    new_vulnerabilities_data.append((
                        entry_id, feed_id, entry.get('title'), entry.get('link'),
                        entry.get('summary'), published_ts, Json(entry)
                    ))

                if not new_vulnerabilities_data:
                    logging.info(f"Keine neuen Einträge im Feed {feed_url} gefunden.")
                    continue

                # Führe den Batch-Insert durch und hole die IDs der tatsächlich neuen Einträge
                insert_query = """
                    INSERT INTO vulnerabilities (entry_id, feed_id, title, link, summary, published_ts, raw_data)
                    VALUES %s
                    ON CONFLICT (entry_id) DO NOTHING
                    RETURNING id, entry_id;
                """
                inserted_rows = execute_values(cur, insert_query, new_vulnerabilities_data, fetch=True)
                logging.info(f"{len(inserted_rows)} neue Schwachstellen in die Datenbank eingefügt.")

                if not inserted_rows:
                    continue

                # --- Phase 2: CVEs extrahieren und Batch-Inserts vorbereiten ---
                all_found_cves = set()
                vulnerability_cve_relations = []
                
                for vuln_db_id, entry_id in inserted_rows:
                    entry = entry_map[entry_id]
                    search_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
                    found_cves = extract_cves(search_text)
                    if found_cves:
                        all_found_cves.update(found_cves)
                        for cve_string in found_cves:
                            vulnerability_cve_relations.append({'vuln_id': vuln_db_id, 'cve_str': cve_string})

                # --- Phase 3: Batch-Insert für neue CVEs ---
                if all_found_cves:
                    cve_insert_query = "INSERT INTO cves (cve_id) VALUES %s ON CONFLICT (cve_id) DO NOTHING;"
                    execute_values(cur, cve_insert_query, [(cve,) for cve in all_found_cves])
                    
                    # Hole die DB-IDs für alle relevanten CVEs in einer einzigen Abfrage
                    cur.execute("SELECT id, cve_id FROM cves WHERE cve_id = ANY(%s)", (list(all_found_cves),))
                    cve_id_map = {cve_string: db_id for db_id, cve_string in cur.fetchall()}
                    
                    # --- Phase 4: Batch-Insert für die Verknüpfungen ---
                    relation_data = [
                        (rel['vuln_id'], cve_id_map.get(rel['cve_str']))
                        for rel in vulnerability_cve_relations if cve_id_map.get(rel['cve_str'])
                    ]
                    if relation_data:
                        relation_insert_query = "INSERT INTO vulnerability_cves (vulnerability_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;"
                        execute_values(cur, relation_insert_query, relation_data)
                        logging.info(f"{len(relation_data)} CVE-Verknüpfungen erstellt.")

                conn.commit()
            logging.info(f"Feed {feed_url} erfolgreich verarbeitet.")

        except Exception as e:
            logging.error(f"Ein schwerwiegender Fehler ist bei der Verarbeitung von Feed {feed_url} aufgetreten: {e}", exc_info=True)
            conn.rollback()

if __name__ == "__main__":
    conn = connect_to_db()
    if conn:
        create_tables_if_not_exist(conn)
        
        while True:
            process_feeds(conn)
            logging.info(f"Alle Feeds verarbeitet. Nächster Durchlauf in {POLL_INTERVAL} Sekunden.")
            time.sleep(POLL_INTERVAL)

