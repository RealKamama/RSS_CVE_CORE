import os
import time
import re
import psycopg2
import logging
from psycopg2.extras import execute_values
from datetime import datetime, timezone

# --- Logging Konfiguration ---
# Erstellt einen Logger mit einem benutzerdefinierten Format für bessere Lesbarkeit.
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
if not log.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    log.addHandler(handler)

# --- Konfiguration aus Umgebungsvariablen laden (identisch zu collector.py) ---
DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'db')

# --- Extraktions-Parser (identisch zu collector.py) ---

def extract_cves(text):
    """Extrahiert eindeutige CVE-Identifier."""
    if not text: return []
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return sorted(list(set(re.findall(cve_pattern, text, re.IGNORECASE))))

def extract_severity(text):
    """Extrahiert einen Schweregrad. Gibt den höchsten gefundenen Wert zurück."""
    if not text: return None
    severity_map = {
        'critical': ['critical', 'kritisch'],
        'high': ['high', 'hoch'],
        'moderate': ['moderate', 'mittel', 'medium'],
        'low': ['low', 'niedrig']
    }
    text_lower = text.lower()
    for level, keywords in severity_map.items():
        if any(keyword in text_lower for keyword in keywords):
            return level
    return None

def extract_products(text):
    """Extrahiert bekannte Produkte. Dies ist eine einfache Implementierung."""
    if not text: return []
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

def connect_to_db():
    """Stellt eine Verbindung zur PostgreSQL-Datenbank her."""
    log.info("Versuche, eine Verbindung zur Datenbank aufzubauen...")
    conn = None
    retries = 5
    while retries > 0 and conn is None:
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST
            )
            log.info(">>> Erfolgreich mit der Datenbank verbunden.")
            return conn
        except psycopg2.OperationalError as e:
            log.warning(f"Datenbankverbindung fehlgeschlagen. Versuche es in 5 Sekunden erneut... ({retries} Versuche übrig)")
            retries -= 1
            time.sleep(5)
    log.error("!!! Konnte keine Verbindung zur Datenbank herstellen. Beende.")
    return None

def enrich_all_vulnerabilities(conn):
    """
    Durchläuft alle vorhandenen Schwachstellen, extrahiert Entitäten 
    und erstellt fehlende Verknüpfungen.
    """
    log.info("Starte die Anreicherung für ALLE bestehenden Schwachstellen in der Datenbank.")
    BATCH_SIZE = 500  # Verarbeitet 500 Einträge auf einmal, um den Speicher zu schonen
    
    # Verwende einen benannten, serverseitigen Cursor für stabiles Abrufen.
    # Dies verhindert, dass alle Ergebnisse auf einmal in den Client-Speicher geladen werden
    # und isoliert den Lese- vom Schreibvorgang.
    with conn.cursor(name='vulnerability_reader') as read_cur:
        read_cur.execute("SELECT id, title, summary FROM vulnerabilities;")
        
        while True:
            log.info(f"Lade nächsten Batch von {BATCH_SIZE} Einträgen...")
            vulnerabilities_batch = read_cur.fetchmany(BATCH_SIZE)
            if not vulnerabilities_batch:
                log.info("Keine weiteren Einträge gefunden. Alle Batches verarbeitet.")
                break

            log.info(f"Verarbeite {len(vulnerabilities_batch)} Einträge...")
            all_cves, all_products, all_severities = set(), set(), set()
            vuln_relations = []

            for vuln_db_id, title, summary in vulnerabilities_batch:
                search_text = f"{title or ''} {summary or ''}"
                
                found_cves = extract_cves(search_text)
                found_products = extract_products(search_text)
                found_severity = extract_severity(search_text)
                
                if not found_cves and not found_products and not found_severity:
                    continue

                all_cves.update(found_cves)
                all_products.update(found_products)
                if found_severity: all_severities.add(found_severity)
                    
                vuln_relations.append({
                    'id': vuln_db_id,
                    'cves': found_cves,
                    'products': found_products,
                    'severity': found_severity
                })
            
            # Verwende einen ZWEITEN, Standard-Cursor nur für die Schreibvorgänge in diesem Batch.
            with conn.cursor() as write_cur:
                log.info(f"  [Enrich] Extraktion für Batch abgeschlossen. Gefunden: {len(all_cves)} CVEs, {len(all_products)} Produkte, {len(all_severities)} Schweregrade.")

                # --- Batch-Insert für alle gefundenen Entitäten ---
                if all_cves:
                    execute_values(write_cur, "INSERT INTO cves (cve_id) VALUES %s ON CONFLICT (cve_id) DO NOTHING;", [(c,) for c in all_cves])
                if all_products:
                    execute_values(write_cur, "INSERT INTO products (product_name) VALUES %s ON CONFLICT (product_name) DO NOTHING;", [(p,) for p in all_products])
                if all_severities:
                    execute_values(write_cur, "INSERT INTO severities (severity_level) VALUES %s ON CONFLICT (severity_level) DO NOTHING;", [(s,) for s in all_severities])

                # --- Verknüpfungen erstellen ---
                if not vuln_relations:
                    log.info("  [Link] Keine neuen Verknüpfungen für diesen Batch zu erstellen.")
                    continue

                # Hole IDs für alle Entitäten
                write_cur.execute("SELECT id, cve_id FROM cves WHERE cve_id = ANY(%s)", (list(all_cves),))
                cve_map = {cve_str: db_id for db_id, cve_str in write_cur.fetchall()}
                
                write_cur.execute("SELECT id, product_name FROM products WHERE product_name = ANY(%s)", (list(all_products),))
                product_map = {p_name: db_id for db_id, p_name in write_cur.fetchall()}

                write_cur.execute("SELECT id, severity_level FROM severities WHERE severity_level = ANY(%s)", (list(all_severities),))
                severity_map = {s_level: db_id for db_id, s_level in write_cur.fetchall()}
                
                # Daten für Batch-Inserts der Verknüpfungen vorbereiten
                cve_rel_data, prod_rel_data, sev_rel_data = [], [], []
                for rel in vuln_relations:
                    for cve in rel['cves']:
                        if cve_map.get(cve): cve_rel_data.append((rel['id'], cve_map[cve]))
                    for prod in rel['products']:
                        if product_map.get(prod): prod_rel_data.append((rel['id'], product_map[prod]))
                    if rel['severity'] and severity_map.get(rel['severity']):
                        sev_rel_data.append((rel['id'], severity_map[rel['severity']]))
                
                log.info("  [Link] Erstelle Verknüpfungen für diesen Batch...")
                if cve_rel_data:
                    execute_values(write_cur, "INSERT INTO vulnerability_cves (vulnerability_id, cve_id) VALUES %s ON CONFLICT DO NOTHING;", cve_rel_data)
                    log.info(f"    -> [DB] {len(cve_rel_data)} CVE-Verknüpfungen erstellt/übersprungen.")
                if prod_rel_data:
                    execute_values(write_cur, "INSERT INTO vulnerability_products (vulnerability_id, product_id) VALUES %s ON CONFLICT DO NOTHING;", prod_rel_data)
                    log.info(f"    -> [DB] {len(prod_rel_data)} Produkt-Verknüpfungen erstellt/übersprungen.")
                if sev_rel_data:
                    execute_values(write_cur, "INSERT INTO vulnerability_severities (vulnerability_id, severity_id) VALUES %s ON CONFLICT DO NOTHING;", sev_rel_data)
                    log.info(f"    -> [DB] {len(sev_rel_data)} Schweregrad-Verknüpfungen erstellt/übersprungen.")
    
    # Der Commit wird erst nach der Schleife für die gesamte Transaktion ausgeführt.
    log.info("Alle Batches verarbeitet. Führe finalen Commit für alle Änderungen aus...")
    conn.commit()
    log.info("Änderungen erfolgreich committet.")


if __name__ == "__main__":
    log.info("======================================================")
    log.info("=== Skript zur Anreicherung bestehender Daten gestartet ===")
    log.info("======================================================")
    conn = connect_to_db()
    if conn:
        try:
            enrich_all_vulnerabilities(conn)
        except Exception as e:
            log.error(f"Ein unerwarteter Fehler ist aufgetreten: {e}", exc_info=True)
            log.info("Führe Rollback für die Transaktion durch...")
            conn.rollback()
        finally:
            conn.close()
            log.info("Datenbankverbindung geschlossen.")
    log.info("======================================================")
    log.info("=== Skript beendet                                   ===")
    log.info("======================================================")

