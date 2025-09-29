# entity_extractor.py
import re
from datetime import datetime
from typing import Optional, List

def validate_cve_id(cve_id: str) -> bool:
    """Validates CVE-ID format strictly."""
    if re.match(r'^CVE-\d{4}-\d{4,}$', cve_id, re.IGNORECASE):
        year = int(cve_id.split('-')[1])
        current_year = datetime.now().year
        if 1999 <= year <= current_year + 1:
            return True
    return False

def extract_cves(text: str) -> List[str]:
    """Extracts and validates CVE-identifiers."""
    patterns = [
        r'CVE-\d{4}-\d{4,}',  # Standard Format
        r'CAN-\d{4}-\d{4,}',  # Old candidate notation
    ]
    
    found_cves = set()
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Normalize to CVE (CAN became CVE)
            normalized = match.upper().replace('CAN-', 'CVE-')
            if validate_cve_id(normalized):
                found_cves.add(normalized)
    
    return sorted(list(found_cves))

def extract_severity(text: str) -> Optional[str]:
    """Extended severity detection including CVSS."""
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
    
    # Keyword-based detection (Fallback)
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
    """Extended product detection with patterns."""
    found_products = set()
    
    # Base product list
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
    
    # Extended patterns for version detection
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
    
    # Search for known products
    for product_key, product_name in known_products.items():
        if product_key in text_lower:
            found_products.add(product_name)
    
    # Search for version numbers
    for pattern, formatter in version_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            product = formatter(match)
            # Normalize product names
            if product:
                found_products.add(product.strip())
    
    return list(found_products)