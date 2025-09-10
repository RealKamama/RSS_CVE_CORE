import os
import time
import re
import feedparser
import psycopg2
import logging
import json
import socket
from psycopg2.extras import Json, execute_values
from datetime import datetime, timezone
from urllib.error import URLError
from dataclasses import dataclass
from typing import Dict, Optional, List, Set, Tuple

# --- Logging Konfiguration ---
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
if not log.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    log.addHandler(handler)

# --- Metriken-Klasse ---
@dataclass
class ProcessingMetrics:
    """Sammelt Verarbeitungsmetriken."""
    feeds_processed: int = 0
    entries_processed: int = 0
    cves_extracted: int = 0
    products_extracted: int = 0
    errors_encountered: int = 0
    processing_time: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'feeds_processed': self.feeds_processed,
            'entries_processed': self.entries_processed,
            'cves_extracted': self.cves_extracted,
            'products_extracted': self.products_extracted,
            'errors_encountered': self.errors_encountered,
            'avg_processing_time': self.processing_time / max(self.feeds_processed, 1)
        }
    
    def log_summary(self):
        """Gibt Zusammenfassung aus."""
        avg_time = self.processing_time / max(self.feeds_processed, 1)
        log.info("=== Verarbeitungs-Zusammenfassung ===")
        log.info(f"  Feeds verarbeitet: {self.feeds_processed}")
        log.info(f"  Einträge verarbeitet: {self.entries_processed}")
        log.info(f"  CVEs extrahiert: {self.cves_extracted}")
        log.info(f"  Produkte extrahiert: {self.products_extracted}")
        log.info(f"  Fehler: {self.errors_encountered}")
        log.info(f"  Durchschn. Zeit/Feed: {avg_time:.2f}s")

# --- Entity Cache ---
class EntityCache:
    """Cache für häufig verwendete Entitäten."""
    
    def __init__(self, conn):
        self.conn = conn
        self.cve_cache = {}
        self.product_cache = {}
        self.severity_cache = {}
        self._load_initial_cache()
    
    def _load_initial_cache(self):
        """Lädt existierende Entitäten beim Start."""
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT id, severity_level FROM severities")
                self.severity_cache = {level: id for id, level in cur.fetchall()}
                
                # Lade nur häufige Produkte initial
                cur.execute("""
                    SELECT p.id, p.product_name 
                    FROM products p 
                    JOIN vulnerability_products vp ON p.id = vp.product_id 
                    GROUP BY p.id 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 100
                """)
                self.product_cache = {name: id for id, name in cur.fetchall()}
        except psycopg2.Error as e:
            log.warning(f"Cache-Initialisierung teilweise fehlgeschlagen: {e}")

# --- Validierungs- und Konfigurationsfunktionen ---
def get_validated_poll_interval():
    """Validiert und gibt das Poll-Intervall zurück."""
    try:
        interval = int(os.getenv('POLL_INTERVAL', 3600))
        if interval < 60:  # Mindestens 1 Minute
            log.warning(f"POLL_INTERVAL {interval} zu klein, setze auf 60 Sekunden")
            return 60
        if interval > 86400:  # Maximal 24 Stunden
            log.warning(f"POLL_INTERVAL {interval} zu groß, setze auf 24 Stunden")
            return 86400
        return interval
    except ValueError:
        log.error("POLL_INTERVAL ist keine gültige Zahl, verwende Standard 3600")
        return 3600

def validate_db_config():
    """Validiert Datenbank-Konfiguration."""
    required_vars = ['POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        log.error(f"Fehlende Umgebungsvariablen: {', '.join(missing)}")
        return False
    return True

# --- Konfiguration aus Umgebungsvariablen laden ---
if not validate_db_config():
    log.critical("Datenbank-Konfiguration unvollständig. Beende.")
    exit(1)

DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'db')
POLL_INTERVAL = get_validated_poll_interval()

# RSS-Feeds
RSS_FEEDS = os.getenv('RSS_FEEDS', '').split(',')
if not RSS_FEEDS or RSS_FEEDS == ['']:
    RSS_FEEDS = [
        "https://www.debian.org/security/dsa-long",
        "https://cvefeed.io/rssfeed/severity/high.atom",
        "https://access.redhat.com/security/data/metrics/rhsa.rss",
        "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
        "https://www.heise.de/security/rss/news-atom.xml"
    ]
    log.warning("Keine RSS_FEEDS in .env gefunden. Verwende Standard-Feeds.")

# --- Datenbankfunktionen ---
def connect_to_db() -> Optional[psycopg2.extensions.connection]:
    """Stellt eine Verbindung zur PostgreSQL-Datenbank her."""
    log.info("Versuche, eine Verbindung zur Datenbank aufzubauen...")
    conn = None
    retries = 10
    retry_delay = 5
    
    while retries > 0 and conn is None:
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                connect_timeout=10
            )
            log.info(">>> Erfolgreich mit der Datenbank verbunden.")
            return conn
        except psycopg2.OperationalError as e:
            log.warning(f"Datenbankverbindung fehlgeschlagen: {e}")
            log.warning(f"Versuche es in {retry_delay} Sekunden erneut... ({retries} Versuche übrig)")
            retries -= 1
            time.sleep(retry_delay)
    
    log.error("!!! Konnte keine Verbindung zur Datenbank herstellen. Beende.")
    return None

def reconnect_to_db(old_conn) -> Optional[psycopg2.extensions.connection]:
    """Versucht Reconnect zur Datenbank."""
    try:
        if old_conn:
            old_conn.close()
    except:
        pass
    return connect_to_db()

def create_tables_if_not_exist(conn):
    """Erstellt alle notwendigen Tabellen für die erweiterte Datenextraktion."""
    log.info("Prüfe und erstelle Datenbanktabellen, falls nicht vorhanden...")
    try:
        with conn.cursor() as cur:
            # Phase 1: Basis-Tabellen
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
            
            # Phase 2: CVE-Tabellen
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
            
            # Phase 3: Produkte und Schweregrade
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
            
            # Erstelle Indizes für bessere Performance
            cur.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_feed_id ON vulnerabilities(feed_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published_ts);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);")
            
            conn.commit()
            log.info(">>> Datenbankschema ist bereit.")
    except psycopg2.Error as e:
        log.error(f"Fehler beim Erstellen der Tabellen: {e}")
        conn.rollback()
        raise

def get_or_create_feed(cur, feed_url):
    """Holt oder erstellt einen Feed-Eintrag und gibt dessen ID zurück."""
    now_utc = datetime.now(timezone.utc)
    cur.execute("""
        INSERT INTO feeds (url, last_polled_ts) VALUES (%s, %s)
        ON CONFLICT (url) DO UPDATE SET last_polled_ts = EXCLUDED.last_polled_ts
        RETURNING id;
    """, (feed_url, now_utc))
    return cur.fetchone()[0]

# --- Feed-Parsing Funktionen ---
def parse_feed_with_timeout(feed_url: str, timeout: int = 30) -> Optional[feedparser.FeedParserDict]:
    """Parse Feed mit Timeout und Fehlerbehandlung."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        feed = feedparser.parse(feed_url)
        return feed
    except (URLError, socket.timeout) as e:
        log.error(f"Timeout oder Netzwerkfehler beim Abrufen von {feed_url}: {e}")
        return None
    except Exception as e:
        log.error(f"Unerwarteter Fehler beim Feed-Parsing von {feed_url}: {e}")
        return None
    finally:
        socket.setdefaulttimeout(original_timeout)

# --- Extraktions-Parser ---
def validate_cve_id(cve_id: str) -> bool:
    """Validiert CVE-ID Format strikt."""
    if re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
        year = int(cve_id.split('-')[1])
        current_year = datetime.now().year
        if 1999 <= year <= current_year + 1:
            return True
    return False

def extract_cves(text: str) -> List[str]:
    """Extrahiert und validiert CVE-Identifier."""
    patterns = [
        r'CVE-\d{4}-\d{4,}',  # Standard Format
        r'CAN-\d{4}-\d{4,}',  # Alte Kandidaten-Notation
    ]
    
    found_cves = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Normalisiere zu CVE (CAN wurde zu CVE)
            normalized = match.upper().replace('CAN-', 'CVE-')
            if validate_cve_id(normalized):
                found_cves.add(normalized)
    
    return sorted(list(found_cves))

def extract_severity(text: str) -> Optional[str]:
    """Erweiterte Schweregrad-Erkennung inkl. CVSS."""
    text_lower = text.lower()
    
    # CVSS Score Mapping
    cvss_patterns = [
        r'CVSS[:\s]+(\d+\.?\d*)',
        r'CVSS[:\s]+Score[:\s]+(\d+\.?\d*)',
        r'Base Score[:\s]+(\d+\.?\d*)'
    ]
    
    for pattern in cvss_patterns:
        cvss_match = re.search(pattern, text, re.IGNORECASE)
        if cvss_match:
            try:
                score = float(cvss_match.group(1))
                if score >= 9.0: return 'critical'
                elif score >= 7.0: return 'high'
                elif score >= 4.0: return 'moderate'
                elif score > 0: return 'low'
            except ValueError:
                pass
    
    # Keyword-basierte Erkennung (Fallback)
    severity_keywords = {
        'critical': ['critical', 'kritisch', 'severity: critical', 'cvss: 9', 'cvss: 10'],
        'high': ['high', 'hoch', 'severe', 'schwerwiegend', 'important', 'wichtig'],
        'moderate': ['moderate', 'mittel', 'medium', 'moderat'],
        'low': ['low', 'niedrig', 'minor', 'gering']
    }
    
    for level, keywords in severity_keywords.items():
        if any(keyword in text_lower for keyword in keywords):
            return level
    
    return None

def extract_products(text: str) -> List[str]:
    """Erweiterte Produkt-Erkennung mit Patterns."""
    found_products = set()
    
    # Basis-Produktliste
    known_products = {
        'debian': 'Debian',
        'ubuntu': 'Ubuntu',
        'red hat enterprise linux': 'Red Hat Enterprise Linux',
        'rhel': 'Red Hat Enterprise Linux',
        'suse linux enterprise': 'SUSE Linux Enterprise',
        'centos': 'CentOS',
        'fedora': 'Fedora',
        'opensuse': 'openSUSE',
        'oracle linux': 'Oracle Linux',
        'alpine linux': 'Alpine Linux',
        'amazon linux': 'Amazon Linux'
    }
    
    # Erweiterte Pattern für Versionserkennung
    version_patterns = [
        (r'(Debian|Ubuntu|Fedora|CentOS)\s+\d+\.?\d*', lambda m: m.group(0)),
        (r'RHEL\s+\d+\.?\d*', lambda m: f"Red Hat Enterprise Linux {m.group(0).replace('RHEL', '').strip()}"),
        (r'(Apache|nginx|MySQL|MariaDB|PostgreSQL|MongoDB|Redis)\s+\d+\.?\d*\.?\d*', lambda m: m.group(0)),
        (r'(PHP|Python|Ruby|Java|Node\.js|Go)\s+\d+\.?\d*\.?\d*', lambda m: m.group(0)),
        (r'Microsoft\s+(Windows|Office|Exchange|SQL Server)\s+[\w\s]*\d{4}', lambda m: m.group(0)),
        (r'(Chrome|Firefox|Safari|Edge)\s+\d+\.?\d*', lambda m: m.group(0)),
        (r'(OpenSSL|OpenSSH|GnuTLS)\s+\d+\.?\d*\.?\d*', lambda m: m.group(0)),
        (r'(Docker|Kubernetes|containerd)\s+\d+\.?\d*\.?\d*', lambda m: m.group(0)),
    ]
    
    text_lower = text.lower()
    
    # Suche nach bekannten Produkten
    for product_key, product_name in known_products.items():
        if product_key in text_lower:
            found_products.add(product_name)
    
    # Suche nach Versionsnummern
    for pattern, formatter in version_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            product = formatter(match)
            # Normalisiere Produktnamen
            if product:
                found_products.add(product.strip())
    
    return list(found_products)

# --- Batch-Verarbeitung ---
def process_batch(cur, batch_entries: List, feed_id: int, cache: EntityCache, metrics: ProcessingMetrics) -> int:
    """Verarbeitet einen Batch von Feed-Einträgen."""
    new_vulnerabilities_data = []
    entry_map = {}
    
    for entry in batch_entries:
        entry_id = entry.get('link') or entry.get('id')
        if not entry_id: 
            continue
            
        entry_map[entry_id] = entry
        published_ts = None
        if entry.get('published_parsed'):
            try:
                published_ts = psycopg2.TimestampFromTicks(time.mktime(entry.published_parsed))
            except (ValueError, OverflowError) as e:
                log.warning(f"Ungültiger Zeitstempel für Entry {entry_id}: {e}")
        
        new_vulnerabilities_data.append((
            entry_id, feed_id, entry.get('title', ''), entry.get('link', ''),
            entry.get('summary', ''), published_ts, Json(entry)
        ))
    
    if not new_vulnerabilities_data:
        return 0
    
    # Batch-Insert für Vulnerabilities
    insert_query = """
        INSERT INTO vulnerabilities (entry_id, feed_id, title, link, summary, published_ts, raw_data)
        VALUES %s ON CONFLICT (entry_id) DO NOTHING RETURNING id, entry_id;
    """
    inserted_rows = execute_values(cur, insert_query, new_vulnerabilities_data, fetch=True)
    
    if not inserted_rows:
        return 0
    
    # Anreicherung für neue Einträge
    all_cves, all_products, all_severities = set(), set(), set()
    vuln_relations = []
    
    for vuln_db_id, entry_id in inserted_rows:
        entry = entry_map[entry_id]
        search_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        
        found_cves = extract_cves(search_text)
        found_products = extract_products(search_text)
        found_severity = extract_severity(search_text)
        
        all_cves.update(found_cves)
        all_products.update(found_products)
        if found_severity: 
            all_severities.add(found_severity)
        
        vuln_relations.append({
            'id': vuln_db_id,
            'cves': found_cves,
            'products': found_products,
            'severity': found_severity
        })
    
    # Update Metriken
    metrics.cves_extracted += len(all_cves)
    metrics.products_extracted += len(all_products)
    
    # Batch-Insert für alle gefundenen Entitäten
    if all_cves:
        execute_values(cur, 
            "INSERT INTO cves (cve_id) VALUES %s ON CONFLICT (cve_id) DO NOTHING;", 
            [(c,) for c in all_cves])
    
    if all_products:
        execute_values(cur, 
            "INSERT INTO products (product_name) VALUES %s ON CONFLICT (product_name) DO NOTHING;", 
            [(p,) for p in all_products])
    
    if all_severities:
        execute_values(cur, 
            "INSERT INTO severities (severity_level) VALUES %s ON CONFLICT (severity_level) DO NOTHING;", 
            [(s,) for s in all_severities])
    
    # Hole IDs für alle Entitäten
    cve_map = {}
    if all_cves:
        cur.execute("SELECT id, cve_id FROM cves WHERE cve_id = ANY(%s)", (list(all_cves),))
        cve_map = {cve_str: db_id for db_id, cve_str in cur.fetchall()}
    
    product_map = {}
    if all_products:
        cur.execute("SELECT id, product_name FROM products WHERE product_name = ANY(%s)", (list(all_products),))
        product_map = {p_name: db_id for db_id, p_name in cur.fetchall()}
    
    severity_map = {}
    if all_severities:
        cur.execute("SELECT id, severity_level FROM severities WHERE severity_level = ANY(%s)", (list(all_severities),))
        severity_map = {s_level: db_id for db_id, s_level in cur.fetchall()}
    
    # Erstelle Verknüpfungen
    cve_rel_data, prod_rel_data, sev_rel_data = [], [], []
    
    for rel in vuln_relations:
        for cve in rel['cves']:
            if cve in cve_map:
                cve_rel_data.append((rel['id'], cve_map[cve]))
        
        for prod in rel['products']:
            if prod in product_map:
                prod_rel_data.append((rel['id'], product_map[prod]))
        
        if rel['severity'] and rel['severity'] in severity_map:
            sev_rel_data.append((rel['id'], severity_map[rel['severity']]))
    
    # Batch-Insert für Verknüpfungen
    if cve_rel_data:
        execute_values(cur, 
            "INSERT INTO vulnerability_cves (vulnerability_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", 
            cve_rel_data)
    
    if prod_rel_data:
        execute_values(cur, 
            "INSERT INTO vulnerability_products (vulnerability_id, product_id) VALUES %s ON CONFLICT DO NOTHING;", 
            prod_rel_data)
    
    if sev_rel_data:
        execute_values(cur, 
            "INSERT INTO vulnerability_severities (vulnerability_id, severity_id) VALUES %s ON CONFLICT DO NOTHING;", 
            sev_rel_data)
    
    return len(inserted_rows)

def process_feed_in_batches(conn, feed_entries: List, feed_id: int, cache: EntityCache, 
                           metrics: ProcessingMetrics, batch_size: int = 100):
    """Verarbeitet Feed-Einträge in Batches für bessere Stabilität."""
    total_entries = len(feed_entries)
    total_processed = 0
    
    for i in range(0, total_entries, batch_size):
        batch = feed_entries[i:i+batch_size]
        batch_num = i // batch_size + 1
        log.info(f"  [Batch {batch_num}] Verarbeite Einträge {i+1} bis {min(i+batch_size, total_entries)}")
        
        try:
            with conn.cursor() as cur:
                processed = process_batch(cur, batch, feed_id, cache, metrics)
                conn.commit()
                total_processed += processed
                log.info(f"  [Batch {batch_num}] {processed} neue Einträge eingefügt")
                
        except psycopg2.IntegrityError as e:
            log.error(f"  [Batch {batch_num}] Integritätsfehler: {e}")
            conn.rollback()
            metrics.errors_encountered += 1
            
        except psycopg2.OperationalError as e:
            log.error(f"  [Batch {batch_num}] Datenbankfehler: {e}")
            conn.rollback()
            metrics.errors_encountered += 1
            # Bei Datenbankfehler Batch abbrechen
            break
            
        except Exception as e:
            log.error(f"  [Batch {batch_num}] Unerwarteter Fehler: {e}")
            conn.rollback()
            metrics.errors_encountered += 1
            # Fahre mit nächstem Batch fort
            continue
    
    return total_processed

def process_feeds(conn, metrics: ProcessingMetrics):
    """Ruft RSS-Feeds ab und verarbeitet neue Einträge."""
    cache = EntityCache(conn)
    
    for feed_url in RSS_FEEDS:
        if not feed_url.strip(): 
            continue
        
        log.info(f"--- Verarbeitung von Feed gestartet: {feed_url} ---")
        start_time = time.time()
        
        try:
            # Feed abrufen mit Timeout
            feed = parse_feed_with_timeout(feed_url, timeout=30)
            if not feed:
                log.error(f"Feed {feed_url} konnte nicht abgerufen werden")
                metrics.errors_encountered += 1
                continue
            
            # Prüfe auf Feed-Fehler
            if feed.bozo:
                if isinstance(feed.bozo_exception, feedparser.CharacterEncodingOverride):
                    log.warning(f"Encoding-Problem in Feed {feed_url}, versuche trotzdem zu parsen")
                else:
                    log.error(f"Feed {feed_url} ist fehlerhaft: {feed.bozo_exception}")
                    metrics.errors_encountered += 1
                    continue
            
            feed_title = feed.feed.get('title', 'Unbekannter Titel')
            num_entries = len(feed.entries)
            log.info(f"  [Parse] Feed '{feed_title}' enthält {num_entries} Einträge")
            
            if num_entries == 0:
                log.info(f"  [Info] Feed enthält keine Einträge")
                metrics.feeds_processed += 1
                continue
            
            # Feed in Datenbank registrieren
            with conn.cursor() as cur:
                feed_id = get_or_create_feed(cur, feed_url)
                conn.commit()
            
            # Verarbeite Einträge in Batches
            processed = process_feed_in_batches(conn, feed.entries, feed_id, cache, metrics)
            
            # Update Metriken
            metrics.feeds_processed += 1
            metrics.entries_processed += processed
            elapsed = time.time() - start_time
            metrics.processing_time += elapsed
            
            log.info(f"  [Fertig] {processed} neue Einträge in {elapsed:.2f}s verarbeitet")
            log.info(f"--- Verarbeitung von Feed beendet: {feed_url} ---\n")
            
        except psycopg2.IntegrityError as e:
            log.error(f"Datenbank-Integritätsfehler bei {feed_url}: {e}")
            conn.rollback()
            metrics.errors_encountered += 1
            
        except psycopg2.OperationalError as e:
            log.error(f"Datenbankverbindung verloren bei {feed_url}: {e}")
            metrics.errors_encountered += 1
            # Versuche Reconnect
            conn = reconnect_to_db(conn)
            if not conn:
                log.critical("Kann Datenbankverbindung nicht wiederherstellen. Beende.")
                raise
            
        except MemoryError:
            log.critical(f"Speicherfehler bei Verarbeitung von {feed_url}. Feed zu groß?")
            conn.rollback()
            metrics.errors_encountered += 1
            
        except KeyboardInterrupt:
            log.info("Unterbrechung durch Benutzer erkannt")
            raise
            
        except Exception as e:
            log.error(f"Unerwarteter Fehler bei {feed_url}: {type(e).__name__}: {e}", exc_info=True)
            conn.rollback()
            metrics.errors_encountered += 1

def main():
    """Hauptfunktion."""
    log.info("==================================================")
    log.info("=== RSS Vulnerability Collector gestartet      ===")
    log.info("==================================================")
    log.info(f"Poll-Intervall: {POLL_INTERVAL} Sekunden")
    log.info(f"Anzahl Feeds: {len(RSS_FEEDS)}")
    
    conn = connect_to_db()
    if not conn:
        log.critical("Keine Datenbankverbindung möglich. Beende.")
        return 1
    
    try:
        create_tables_if_not_exist(conn)
        
        while True:
            # Metriken für jeden Zyklus zurücksetzen
            metrics = ProcessingMetrics()
            cycle_start = time.time()
            log.info(">>> Starte neuen Verarbeitungszyklus für alle Feeds...")
            
            try:
                process_feeds(conn, metrics)
                
                # --- AB HIER WURDE DER CODE VERVOLLSTÄNDIGT ---

                # Zeige Zusammenfassung der Metriken am Ende des Zyklus
                metrics.log_summary()
                
            except Exception as e:
                log.error(f"Ein unerwarteter Fehler ist im Hauptzyklus aufgetreten: {e}", exc_info=True)
                metrics.errors_encountered += 1

            cycle_elapsed = time.time() - cycle_start
            log.info(f"<<< Verarbeitungszyklus in {cycle_elapsed:.2f}s abgeschlossen.")
            
            # Berechne die Schlafzeit bis zum nächsten Poll-Intervall
            sleep_duration = POLL_INTERVAL - cycle_elapsed
            if sleep_duration < 0:
                log.warning(f"Verarbeitungszeit ({cycle_elapsed:.2f}s) war länger als das Poll-Intervall ({POLL_INTERVAL}s). Starte sofort neu.")
                sleep_duration = 0 # Sofort neu starten
            
            log.info(f"Warte {sleep_duration:.2f} Sekunden bis zum nächsten Durchlauf...")
            time.sleep(sleep_duration)

    except KeyboardInterrupt:
        log.info("Beendigung durch Benutzer angefordert. Fahre herunter...")
        return 0 # Erfolgreiches Beenden
    
    finally:
        if conn:
            log.info("Schließe Datenbankverbindung.")
            conn.close()

# --- NOTWENDIGER EINSTIEGSPUNKT ZUM STARTEN DES SKRIPTS ---
if __name__ == "__main__":
    import sys
    # Beendet das Skript mit dem Rückgabewert von main()
    sys.exit(main())