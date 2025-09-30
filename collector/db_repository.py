# db_repository.py
import logging
from typing import List, Tuple, Dict, Set
from psycopg2.extras import execute_values

log = logging.getLogger(__name__)

def create_tables(conn):
    """Creates all necessary tables for the application."""
    log.info("Checking and creating database tables if they do not exist...")
    try:
        with conn.cursor() as cur:
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
            cur.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_feed_id ON vulnerabilities(feed_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published_ts);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);")
            
            conn.commit()
            log.info(">>> Database schema is ready.")
    except Exception as e:
        log.error(f"Error while creating tables: {e}")
        conn.rollback()
        raise

def get_or_create_feed(cur, feed_url: str, now_utc) -> int:
    """Gets or creates a feed entry and returns its ID."""
    cur.execute("""
        INSERT INTO feeds (url, last_polled_ts) VALUES (%s, %s)
        ON CONFLICT (url) DO UPDATE SET last_polled_ts = EXCLUDED.last_polled_ts
        RETURNING id;
    """, (feed_url, now_utc))
    return cur.fetchone()[0]

def insert_vulnerabilities(cur, vulnerability_data: List[Tuple]) -> List[Tuple[int, str]]:
    """Inserts a batch of vulnerabilities into the database and returns new entries."""
    if not vulnerability_data:
        return []
    insert_query = """
        INSERT INTO vulnerabilities (entry_id, feed_id, title, link, summary, published_ts, raw_data)
        VALUES %s ON CONFLICT (entry_id) DO NOTHING RETURNING id, entry_id;
    """
    return execute_values(cur, insert_query, vulnerability_data, fetch=True)

def bulk_insert_entities(cur, table_name: str, column_name: str, values: Set[str]):
    """Generically inserts a batch of entities (CVEs, Products, etc.)."""
    if not values:
        return
    query = f"INSERT INTO {table_name} ({column_name}) VALUES %s ON CONFLICT ({column_name}) DO NOTHING;"
    execute_values(cur, query, [(v,) for v in values])

def fetch_entity_ids(cur, table_name: str, column_name: str, values: Set[str]) -> Dict[str, int]:
    """Fetches the database IDs for a set of entity string values."""
    if not values:
        return {}
    query = f"SELECT id, {column_name} FROM {table_name} WHERE {column_name} = ANY(%s)"
    cur.execute(query, (list(values),))
    return {value: db_id for db_id, value in cur.fetchall()}

def bulk_insert_relations(cur, table_name: str, col1_name: str, col2_name: str, relations: List[Tuple[int, int]]):
    """Generically inserts many-to-many relationships."""
    if not relations:
        return
    query = f"INSERT INTO {table_name} ({col1_name}, {col2_name}) VALUES %s ON CONFLICT DO NOTHING;"
    execute_values(cur, query, relations)