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
    """Erstellt alle notwendigen Tabellen für die erweiterte Datenextraktion."""
    with conn.cursor() as cur:
        # Phase 1
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
        # Phase 2
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
        # Phase 4: Tabellen für Produkte und Schweregrade
        cur.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                product_name VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS severities (
                id SERIAL PRIMARY KEY,
                severity_level VARCHAR(50) UNIQUE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_products (
                vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                PRIMARY KEY (vulnerability_id, product_id)
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_severities (
                vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                severity_id INTEGER NOT NULL REFERENCES severities(id) ON DELETE CASCADE,
                PRIMARY KEY (vulnerability_id, severity_id)
            );
        """)
        conn.commit()
        logging.info("Alle Tabellen (inkl. products, severities) sind bereit.")

def get_or_create_feed(cur, feed_url):
    """Holt oder erstellt einen Feed-Eintrag und gibt dessen ID zurück."""
    now_utc = datetime.now(timezone.utc)
    cur.execute("""
        INSERT INTO feeds (url, last_polled_ts) VALUES (%s, %s)
        ON CONFLICT (url) DO UPDATE SET last_polled_ts = EXCLUDED.last_polled_ts
        RETURNING id;
    """, (feed_url, now_utc))
    return cur.fetchone()[0]

# --- Extraktions-Parser ---

def extract_cves(text):
    """Extrahiert eindeutige CVE-Identifier."""
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return sorted(list(set(re.findall(cve_pattern, text, re.IGNORECASE))))

def extract_severity(text):
    """Extrahiert einen Schweregrad. Gibt den höchsten gefundenen Wert zurück."""
    # Die Reihenfolge ist wichtig: von kritisch nach niedrig
    severity_map = {
        'critical': ['critical', 'kritisch'],
        'high': ['high', 'hoch'],
        'moderate': ['moderate', 'mittel', 'medium'],
        'low': ['low', 'niedrig']
    }
    text_lower = text.lower()
    for level, keywords in severity_map.items():
        if any(keyword in text_lower for keyword in keywords):
            return level # Gibt den normalisierten Wert zurück
    return None

def extract_products(text):
    """Extrahiert bekannte Produkte. Dies ist eine einfache Implementierung."""
    # Diese Liste müsste kontinuierlich erweitert werden.
    known_products = [
        'Debian', 'Red Hat Enterprise Linux', 'SUSE Linux Enterprise',
        'Ubuntu', 'Windows Server', 'Windows 11', 'Windows 10',
        'Google Chrome', 'Mozilla Firefox', 'Microsoft Edge'
    ]
    found_products = set()
    for product in known_products:
        if re.search(r'\b' + re.escape(product) + r'\b', text, re.IGNORECASE):
            found_products.add(product)
    return list(found_products)

def process_feeds(conn):
    """Ruft RSS-Feeds ab und verarbeitet neue Einträge inkl. erweiterter Datenextraktion."""
    for feed_url in RSS_FEEDS:
        if not feed_url: continue
        
        logging.info(f"Verarbeite Feed: {feed_url}")
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                logging.warning(f"Feed {feed_url} ist möglicherweise fehlerhaft: {feed.bozo_exception}")
            
            logging.info(f"Feed '{feed.feed.get('title', 'Unbekannter Titel')}' hat {len(feed.entries)} Einträge gefunden.")
            
            with conn.cursor() as cur:
                feed_id = get_or_create_feed(cur, feed_url)
                
                new_vulnerabilities_data = []
                entry_map = {}
                for entry in feed.entries:
                    entry_id = entry.get('link') or entry.get('id')
                    if not entry_id: continue
                    entry_map[entry_id] = entry
                    published_ts = psycopg2.TimestampFromTicks(time.mktime(entry.published_parsed)) if entry.get('published_parsed') else None
                    new_vulnerabilities_data.append((
                        entry_id, feed_id, entry.get('title'), entry.get('link'),
                        entry.get('summary'), published_ts, Json(entry)
                    ))
                
                if not new_vulnerabilities_data:
                    logging.info(f"Keine neuen Einträge im Feed {feed_url}.")
                    continue
                    
                insert_query = """
                    INSERT INTO vulnerabilities (entry_id, feed_id, title, link, summary, published_ts, raw_data)
                    VALUES %s ON CONFLICT (entry_id) DO NOTHING RETURNING id, entry_id;
                """
                inserted_rows = execute_values(cur, insert_query, new_vulnerabilities_data, fetch=True)
                logging.info(f"{len(inserted_rows)} neue Schwachstellen eingefügt.")
                
                if not inserted_rows: continue
                    
                # --- Anreicherung für die neu eingefügten Einträge ---
                all_cves, all_products, all_severities = set(), set(), set()
                vuln_relations = [] # Sammelt alle Relationen

                for vuln_db_id, entry_id in inserted_rows:
                    entry = entry_map[entry_id]
                    search_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
                    
                    found_cves = extract_cves(search_text)
                    found_products = extract_products(search_text)
                    found_severity = extract_severity(search_text)
                    
                    all_cves.update(found_cves)
                    all_products.update(found_products)
                    if found_severity: all_severities.add(found_severity)
                        
                    vuln_relations.append({
                        'id': vuln_db_id,
                        'cves': found_cves,
                        'products': found_products,
                        'severity': found_severity
                    })

                # --- Batch-Insert für alle gefundenen Entitäten ---
                if all_cves:
                    execute_values(cur, "INSERT INTO cves (cve_id) VALUES %s ON CONFLICT (cve_id) DO NOTHING;", [(c,) for c in all_cves])
                if all_products:
                    execute_values(cur, "INSERT INTO products (product_name) VALUES %s ON CONFLICT (product_name) DO NOTHING;", [(p,) for p in all_products])
                if all_severities:
                    execute_values(cur, "INSERT INTO severities (severity_level) VALUES %s ON CONFLICT (severity_level) DO NOTHING;", [(s,) for s in all_severities])

                # --- Verknüpfungen erstellen ---
                if not vuln_relations:
                    conn.commit()
                    continue

                # Hole IDs für alle Entitäten in wenigen Abfragen
                cur.execute("SELECT id, cve_id FROM cves WHERE cve_id = ANY(%s)", (list(all_cves),))
                cve_map = {cve_str: db_id for db_id, cve_str in cur.fetchall()}
                
                cur.execute("SELECT id, product_name FROM products WHERE product_name = ANY(%s)", (list(all_products),))
                product_map = {p_name: db_id for db_id, p_name in cur.fetchall()}

                cur.execute("SELECT id, severity_level FROM severities WHERE severity_level = ANY(%s)", (list(all_severities),))
                severity_map = {s_level: db_id for db_id, s_level in cur.fetchall()}
                
                # Daten für Batch-Inserts der Verknüpfungen vorbereiten
                cve_rel_data, prod_rel_data, sev_rel_data = [], [], []
                for rel in vuln_relations:
                    for cve in rel['cves']:
                        if cve_map.get(cve): cve_rel_data.append((rel['id'], cve_map[cve]))
                    for prod in rel['products']:
                        if product_map.get(prod): prod_rel_data.append((rel['id'], product_map[prod]))
                    if rel['severity'] and severity_map.get(rel['severity']):
                        sev_rel_data.append((rel['id'], severity_map[rel['severity']]))
                
                if cve_rel_data:
                    execute_values(cur, "INSERT INTO vulnerability_cves (vulnerability_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", cve_rel_data)
                    logging.info(f"{len(cve_rel_data)} CVE-Verknüpfungen erstellt.")
                if prod_rel_data:
                    execute_values(cur, "INSERT INTO vulnerability_products (vulnerability_id, product_id) VALUES %s ON CONFLICT DO NOTHING;", prod_rel_data)
                    logging.info(f"{len(prod_rel_data)} Produkt-Verknüpfungen erstellt.")
                if sev_rel_data:
                    execute_values(cur, "INSERT INTO vulnerability_severities (vulnerability_id, severity_id) VALUES %s ON CONFLICT DO NOTHING;", sev_rel_data)
                    logging.info(f"{len(sev_rel_data)} Schweregrad-Verknüpfungen erstellt.")
                    
                conn.commit()
            logging.info(f"Feed {feed_url} erfolgreich verarbeitet.")

        except Exception as e:
            logging.error(f"Ein schwerwiegender Fehler bei der Verarbeitung von {feed_url} ist aufgetreten: {e}", exc_info=True)
            conn.rollback()

if __name__ == "__main__":
    conn = connect_to_db()
    if conn:
        create_tables_if_not_exist(conn)
        
        while True:
            process_feeds(conn)
            logging.info(f"Alle Feeds verarbeitet. Nächster Durchlauf in {POLL_INTERVAL} Sekunden.")
            time.sleep(POLL_INTERVAL)

