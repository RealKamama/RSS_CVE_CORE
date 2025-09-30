import psycopg2
import json
from psycopg2.extras import RealDictCursor
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from typing import List, Dict, Any, Optional

from config import DATABASE_CONFIG, get_logger

# --- Logging Configuration ---
log = get_logger(__name__)

# --- App Initialization ---
app = Flask(__name__)
CORS(app)

# Whitelist für sichere Sortierung
SORT_WHITELIST = {
    "date": "v.published_ts",
    "publisher": "f.publisher",
    "severity": "s.severity_level"
}

def get_db_connection() -> Optional[psycopg2.extensions.connection]:
    """Stellt eine Verbindung zur Datenbank her."""
    try:
        conn = psycopg2.connect(**DATABASE_CONFIG, cursor_factory=RealDictCursor)
        log.info("Database connection established successfully.")
        return conn
    except psycopg2.OperationalError as e:
        log.error(f"!!! Could not connect to the database: {e}")
        return None

def _execute_query(conn: psycopg2.extensions.connection, search_term: Optional[str] = None, severity_level: Optional[str] = None, page: int = 1, limit: int = 20, sort_by: str = "date", sort_order: str = "desc") -> Dict[str, Any]:
    """Führt eine paginierte, gefilterte und sortierte Abfrage für Schwachstellen aus."""
    with conn.cursor() as cur:
        from_clause = """
            FROM vulnerabilities v
            LEFT JOIN feeds f ON v.feed_id = f.id
            LEFT JOIN vulnerability_severities vs ON v.id = vs.vulnerability_id
            LEFT JOIN severities s ON vs.severity_id = s.id
        """
        
        conditions = []
        params = []
        if search_term:
            search_pattern = f"%{search_term}%"
            conditions.append("(v.title ILIKE %s OR v.summary ILIKE %s OR f.publisher ILIKE %s)")
            params.extend([search_pattern, search_pattern, search_pattern])
        if severity_level:
            conditions.append("s.severity_level = %s")
            params.append(severity_level)
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        count_query = f"SELECT COUNT(*) {from_clause} {where_clause};"
        cur.execute(count_query, tuple(params))
        total_items = cur.fetchone()['count']

        sort_column = SORT_WHITELIST.get(sort_by, "v.published_ts")
        sort_direction = "ASC" if sort_order.lower() == "asc" else "DESC"
        order_by_clause = f"ORDER BY {sort_column} {sort_direction}"

        offset = (page - 1) * limit
        paginated_query = f"""
            SELECT
                v.id, v.title, v.link, v.summary, v.published_ts,
                f.url AS feed_url, f.publisher AS feed_publisher,
                s.severity_level,
                COALESCE((SELECT json_agg(c.cve_id) FROM vulnerability_cves vc JOIN cves c ON vc.cve_id = c.id WHERE vc.vulnerability_id = v.id), '[]'::json) AS cves,
                COALESCE((SELECT json_agg(p.product_name) FROM vulnerability_products vp JOIN products p ON vp.product_id = p.id WHERE vp.vulnerability_id = v.id), '[]'::json) AS products
            {from_clause}
            {where_clause}
            {order_by_clause}
            LIMIT %s OFFSET %s;
        """
        
        paginated_params = tuple(params + [limit, offset])
        cur.execute(paginated_query, paginated_params)
        vulnerabilities = cur.fetchall()
        
        log.info(f"Loaded {len(vulnerabilities)} of {total_items} total entries.")
        return {'items': vulnerabilities, 'total': total_items}

def _execute_single_query(conn: psycopg2.extensions.connection, vulnerability_id: int) -> Optional[Dict[str, Any]]:
    """Führt eine Abfrage für eine einzelne Schwachstelle anhand ihrer ID aus."""
    with conn.cursor() as cur:
        query = """
            SELECT
                v.id, v.title, v.link, v.summary, v.published_ts,
                f.url AS feed_url, f.publisher AS feed_publisher,
                s.severity_level,
                COALESCE((SELECT json_agg(c.cve_id) FROM vulnerability_cves vc JOIN cves c ON vc.cve_id = c.id WHERE vc.vulnerability_id = v.id), '[]'::json) AS cves,
                COALESCE((SELECT json_agg(p.product_name) FROM vulnerability_products vp JOIN products p ON vp.product_id = p.id WHERE vp.vulnerability_id = v.id), '[]'::json) AS products
            FROM vulnerabilities v
            LEFT JOIN feeds f ON v.feed_id = f.id
            LEFT JOIN vulnerability_severities vs ON v.id = vs.vulnerability_id
            LEFT JOIN severities s ON vs.severity_id = s.id
            WHERE v.id = %s;
        """
        cur.execute(query, (vulnerability_id,))
        result = cur.fetchone()
        return result

def _process_results(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Formatiert Zeitstempel in Abfrageergebnissen."""
    for item in rows:
        if item.get('published_ts'):
            item['published_ts'] = item['published_ts'].isoformat()
    return rows

@app.route('/')
def index():
    """Rendert die Hauptseite der Anwendung."""
    return render_template('index.html')

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """API-Endpunkt für die Liste der Schwachstellen mit Filterung, Paginierung und Sortierung."""
    search = request.args.get('search')
    severity = request.args.get('severity')
    sort_by = request.args.get('sortBy', 'date')
    sort_order = request.args.get('order', 'desc')

    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
    except ValueError:
        page = 1
        limit = 20
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        query_result = _execute_query(conn, search_term=search, severity_level=severity, page=page, limit=limit, sort_by=sort_by, sort_order=sort_order)
        processed_items = _process_results(query_result['items'])
        
        response_data = {
            "total_items": query_result['total'],
            "page": page,
            "limit": limit,
            "items": processed_items
        }
        return jsonify(response_data)
        
    except Exception as e:
        log.error(f"Error during database query: {e}", exc_info=True)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/vulnerabilities/<int:vulnerability_id>')
def get_vulnerability_by_id(vulnerability_id: int):
    """API-Endpunkt, der eine einzelne Schwachstelle anhand ihrer ID abruft."""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed"}), 500

    try:
        vulnerability = _execute_single_query(conn, vulnerability_id)
        if not vulnerability:
            return jsonify({"error": "Vulnerability not found"}), 404
        
        processed_vulnerability = _process_results([vulnerability])[0]
        return jsonify(processed_vulnerability)
    except Exception as e:
        log.error(f"Error fetching single vulnerability: {e}", exc_info=True)
        return jsonify({"error": "Failed to fetch data"}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)