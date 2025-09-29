# metrics_service.py
import time
import logging
from typing import Dict

log = logging.getLogger(__name__)

class MetricsService:
    """A centralized service for collecting and reporting processing metrics."""

    def __init__(self):
        self._feeds_processed: int = 0
        self._entries_processed: int = 0
        self._cves_extracted: int = 0
        self._products_extracted: int = 0
        self._errors_encountered: int = 0
        self._total_processing_time: float = 0.0

    def increment_feeds_processed(self):
        self._feeds_processed += 1

    def add_entries_processed(self, count: int):
        self._entries_processed += count

    def add_cves_extracted(self, count: int):
        self._cves_extracted += count

    def add_products_extracted(self, count: int):
        self._products_extracted += count

    def increment_errors(self):
        self._errors_encountered += 1
        
    def add_processing_time(self, seconds: float):
        self._total_processing_time += seconds

    def to_dict(self) -> Dict:
        """Returns the current metrics as a dictionary."""
        return {
            'feeds_processed': self._feeds_processed,
            'entries_processed': self._entries_processed,
            'cves_extracted': self._cves_extracted,
            'products_extracted': self._products_extracted,
            'errors_encountered': self._errors_encountered,
            'avg_processing_time': self._total_processing_time / max(self._feeds_processed, 1)
        }

    def log_summary(self):
        """Logs a formatted summary of the processing cycle."""
        avg_time = self._total_processing_time / max(self._feeds_processed, 1)
        log.info("=== Processing Summary ===")
        log.info(f"  Feeds Processed: {self._feeds_processed}")
        log.info(f"  Entries Processed: {self._entries_processed}")
        log.info(f"  CVEs Extracted: {self._cves_extracted}")
        log.info(f"  Products Extracted: {self._products_extracted}")
        log.info(f"  Errors Encountered: {self._errors_encountered}")
        log.info(f"  Avg. Time per Feed: {avg_time:.2f}s")