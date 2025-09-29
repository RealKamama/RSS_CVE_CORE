# collector.py
import os
import time
import psycopg2
import logging
import json
import socket
from psycopg2.extras import Json
from datetime import datetime, timezone
from typing import Dict, Optional, List, Set, Tuple

# --- Import refactored modules ---
import feed_parser
import db_repository
import entity_extractor
from metrics_service import MetricsService

# --- Logging Configuration ---
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
if not log.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    log.addHandler(handler)

# --- Configuration & Validation Functions ---
def get_validated_poll_interval():
    """Validates and returns the poll interval."""
    try:
        interval = int(os.getenv('POLL_INTERVAL', 3600))
        if interval < 60:
            log.warning(f"POLL_INTERVAL {interval} is too short, setting to 60 seconds.")
            return 60
        if interval > 86400:
            log.warning(f"POLL_INTERVAL {interval} is too long, setting to 24 hours.")
            return 86400
        return interval
    except ValueError:
        log.error("POLL_INTERVAL is not a valid number, using default of 3600.")
        return 3600

def validate_db_config():
    """Validates that essential database environment variables are set."""
    required_vars = ['POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD']
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        log.error(f"Missing required environment variables: {', '.join(missing)}")
        return False
    return True

# --- Load Configuration ---
if not validate_db_config():
    log.critical("Database configuration is incomplete. Exiting.")
    exit(1)

DB_NAME = os.getenv('POSTGRES_DB')
DB_USER = os.getenv('POSTGRES_USER')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD')
DB_HOST = os.getenv('DB_HOST', 'db')
POLL_INTERVAL = get_validated_poll_interval()

RSS_FEEDS = os.getenv('RSS_FEEDS', '').split(',')
if not RSS_FEEDS or RSS_FEEDS == ['']:
    RSS_FEEDS = [
        "https://www.debian.org/security/dsa-long",
        "https://cvefeed.io/rssfeed/severity/high.atom",
        "https://access.redhat.com/security/data/metrics/rhsa.rss",
        "https://wid.cert-bund.de/content/public/securityAdvisory/rss",
        "https://www.heise.de/security/rss/news-atom.xml"
    ]
    log.warning("RSS_FEEDS not found in environment. Using default feeds.")

# --- Database Connection Functions ---
def connect_to_db() -> Optional[psycopg2.extensions.connection]:
    """Establishes a connection to the PostgreSQL database with retries."""
    log.info("Attempting to connect to the database...")
    conn = None
    retries = 10
    retry_delay = 5
    
    while retries > 0 and conn is None:
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, connect_timeout=10
            )
            log.info(">>> Successfully connected to the database.")
            return conn
        except psycopg2.OperationalError as e:
            log.warning(f"Database connection failed: {e}")
            log.warning(f"Retrying in {retry_delay} seconds... ({retries} attempts left)")
            retries -= 1
            time.sleep(retry_delay)
    
    log.error("!!! Could not establish a database connection. Exiting.")
    return None

def reconnect_to_db(old_conn) -> Optional[psycopg2.extensions.connection]:
    """Closes an old connection and attempts to create a new one."""
    try:
        if old_conn:
            old_conn.close()
    except:
        pass
    return connect_to_db()

# --- Batch Processing ---
def process_batch(cur, batch_entries: List, feed_id: int, metrics: MetricsService) -> int:
    """Processes a batch of feed entries, extracts entities, and stores them."""
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
                log.warning(f"Invalid timestamp for Entry {entry_id}: {e}")
        
        new_vulnerabilities_data.append((
            entry_id, feed_id, entry.get('title', ''), entry.get('link', ''),
            entry.get('summary', ''), published_ts, Json(entry)
        ))
    
    if not new_vulnerabilities_data:
        return 0
    
    inserted_rows = db_repository.insert_vulnerabilities(cur, new_vulnerabilities_data)
    if not inserted_rows:
        return 0
    
    all_cves, all_products, all_severities = set(), set(), set()
    vuln_relations = []
    
    for vuln_db_id, entry_id in inserted_rows:
        entry = entry_map[entry_id]
        search_text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        
        found_cves = entity_extractor.extract_cves(search_text)
        found_products = entity_extractor.extract_products(search_text)
        found_severity = entity_extractor.extract_severity(search_text)
        
        all_cves.update(found_cves)
        all_products.update(found_products)
        if found_severity:
            all_severities.add(found_severity)
        
        vuln_relations.append({
            'id': vuln_db_id, 'cves': found_cves, 'products': found_products, 'severity': found_severity
        })
    
    metrics.add_cves_extracted(len(all_cves))
    metrics.add_products_extracted(len(all_products))
    
    db_repository.bulk_insert_entities(cur, 'cves', 'cve_id', all_cves)
    db_repository.bulk_insert_entities(cur, 'products', 'product_name', all_products)
    db_repository.bulk_insert_entities(cur, 'severities', 'severity_level', all_severities)
    
    cve_map = db_repository.fetch_entity_ids(cur, 'cves', 'cve_id', all_cves)
    product_map = db_repository.fetch_entity_ids(cur, 'products', 'product_name', all_products)
    severity_map = db_repository.fetch_entity_ids(cur, 'severities', 'severity_level', all_severities)
    
    cve_rel_data, prod_rel_data, sev_rel_data = [], [], []
    for rel in vuln_relations:
        for cve in rel['cves']:
            if cve in cve_map: cve_rel_data.append((rel['id'], cve_map[cve]))
        for prod in rel['products']:
            if prod in product_map: prod_rel_data.append((rel['id'], product_map[prod]))
        if rel['severity'] and rel['severity'] in severity_map:
            sev_rel_data.append((rel['id'], severity_map[rel['severity']]))
    
    db_repository.bulk_insert_relations(cur, 'vulnerability_cves', 'vulnerability_id', 'cve_id', cve_rel_data)
    db_repository.bulk_insert_relations(cur, 'vulnerability_products', 'vulnerability_id', 'product_id', prod_rel_data)
    db_repository.bulk_insert_relations(cur, 'vulnerability_severities', 'vulnerability_id', 'severity_id', sev_rel_data)
    
    return len(inserted_rows)

def process_feed_in_batches(conn, feed_entries: List, feed_id: int, 
                        metrics: MetricsService, batch_size: int = 100):
    """Processes feed entries in batches for better stability."""
    total_entries = len(feed_entries)
    total_processed = 0
    
    for i in range(0, total_entries, batch_size):
        batch = feed_entries[i:i+batch_size]
        batch_num = i // batch_size + 1
        log.info(f"  [Batch {batch_num}] Processing entries {i+1} to {min(i+batch_size, total_entries)}")
        
        try:
            with conn.cursor() as cur:
                processed_in_batch = process_batch(cur, batch, feed_id, metrics)
                conn.commit()
                total_processed += processed_in_batch
                log.info(f"  [Batch {batch_num}] {processed_in_batch} new entries inserted.")
        except psycopg2.Error as e:
            log.error(f"  [Batch {batch_num}] A database error occurred: {e}")
            conn.rollback()
            metrics.increment_errors()
            break 
        except Exception as e:
            log.error(f"  [Batch {batch_num}] An unexpected error occurred: {e}")
            conn.rollback()
            metrics.increment_errors()
            continue
    
    return total_processed

def process_feeds(conn, metrics: MetricsService):
    """Fetches RSS feeds and processes new entries."""
    for feed_url in RSS_FEEDS:
        if not feed_url.strip():
            continue
        
        log.info(f"--- Processing feed: {feed_url} ---")
        start_time = time.time()
        
        try:
            try:
                feed = feed_parser.fetch_and_parse(feed_url, timeout=30)
            except feed_parser.FeedError as e:
                log.error(f"Could not process feed {feed_url}: {e}")
                metrics.increment_errors()
                continue

            is_valid, reason = feed_parser.validate_feed(feed, feed_url)
            if not is_valid:
                log.error(reason)
                metrics.increment_errors()
                continue
            
            feed_title = feed.feed.get('title', 'Unknown Title')
            num_entries = len(feed.entries)
            log.info(f"  [Parse] Feed '{feed_title}' contains {num_entries} entries.")
            
            if num_entries == 0:
                log.info("  [Info] Feed contains no entries to process.")
                metrics.increment_feeds_processed()
                continue
            
            with conn.cursor() as cur:
                now_utc = datetime.now(timezone.utc)
                feed_id = db_repository.get_or_create_feed(cur, feed_url, now_utc)
                conn.commit()
            
            processed_count = process_feed_in_batches(conn, feed.entries, feed_id, metrics)
            metrics.add_entries_processed(processed_count)
            metrics.increment_feeds_processed()

            elapsed = time.time() - start_time
            metrics.add_processing_time(elapsed)
            
            log.info(f"  [Done] {processed_count} new entries processed in {elapsed:.2f}s.")
            log.info(f"--- Finished processing feed: {feed_url} ---\n")
            
        except psycopg2.OperationalError as e:
            log.error(f"Database connection lost while processing {feed_url}: {e}")
            metrics.increment_errors()
            conn = reconnect_to_db(conn)
            if not conn:
                log.critical("Cannot re-establish database connection. Exiting.")
                raise
        except Exception as e:
            log.error(f"An unexpected error occurred with {feed_url}: {type(e).__name__}: {e}", exc_info=True)
            conn.rollback()
            metrics.increment_errors()

def main():
    """Main application entry point."""
    log.info("==================================================")
    log.info("=== RSS Vulnerability Collector Started      ===")
    log.info("==================================================")
    log.info(f"Poll interval: {POLL_INTERVAL} seconds")
    log.info(f"Number of feeds: {len(RSS_FEEDS)}")
    
    conn = connect_to_db()
    if not conn:
        return 1
    
    try:
        db_repository.create_tables(conn)
        
        while True:
            metrics_service = MetricsService()
            cycle_start = time.time()
            log.info(">>> Starting new processing cycle...")
            
            try:
                process_feeds(conn, metrics_service)
                metrics_service.log_summary()
            except Exception as e:
                log.error(f"A critical error occurred in the main loop: {e}", exc_info=True)
                metrics_service.increment_errors()

            cycle_elapsed = time.time() - cycle_start
            log.info(f"<<< Processing cycle completed in {cycle_elapsed:.2f}s.")
            
            sleep_duration = POLL_INTERVAL - cycle_elapsed
            if sleep_duration < 0:
                log.warning(f"Processing time ({cycle_elapsed:.2f}s) exceeded poll interval ({POLL_INTERVAL}s). Starting next cycle immediately.")
                sleep_duration = 0
            
            log.info(f"Waiting {sleep_duration:.2f} seconds until the next run...")
            time.sleep(sleep_duration)

    except KeyboardInterrupt:
        log.info("Shutdown requested by user. Exiting gracefully...")
        return 0
    
    finally:
        if conn:
            log.info("Closing database connection.")
            conn.close()

if __name__ == "__main__":
    import sys
    sys.exit(main())