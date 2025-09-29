# feed_parser.py
import socket
import logging
from typing import Optional, Tuple
from urllib.error import URLError

import feedparser

log = logging.getLogger(__name__)

# --- Custom Exceptions for better error handling ---
class FeedError(Exception):
    """Base exception for feed processing errors."""
    pass

class FeedTimeoutError(FeedError):
    """Raised when a feed fetch times out."""
    pass

class FeedParsingError(FeedError):
    """Raised for general feed parsing issues."""
    pass

def fetch_and_parse(url: str, timeout: int = 30) -> feedparser.FeedParserDict:
    """
    Fetches and parses a feed with a specified timeout.

    Args:
        url: The URL of the RSS/Atom feed.
        timeout: Connection and read timeout in seconds.

    Returns:
        A parsed feed object from feedparser.

    Raises:
        FeedTimeoutError: If the request times out or a network error occurs.
        FeedParsingError: For any other unexpected errors during parsing.
    """
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        feed = feedparser.parse(url)
        return feed
    except (URLError, socket.timeout) as e:
        raise FeedTimeoutError(f"Timeout or network error for {url}: {e}") from e
    except Exception as e:
        raise FeedParsingError(f"Unexpected error parsing feed {url}: {e}") from e
    finally:
        socket.setdefaulttimeout(original_timeout)

def validate_feed(feed: feedparser.FeedParserDict, url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a parsed feed for common errors (e.g., bozo bit).

    Args:
        feed: The parsed feed object.
        url: The feed's URL, for context in logging.

    Returns:
        A tuple containing a boolean (is_valid) and an optional reason string if invalid.
    """
    if feed.bozo:
        # CharacterEncodingOverride is a warning, not a fatal error. We can proceed.
        if isinstance(feed.bozo_exception, feedparser.CharacterEncodingOverride):
            log.warning(f"Encoding issue in feed {url}, but parsing will proceed: {feed.bozo_exception}")
            return True, "CharacterEncodingOverride"
        else:
            reason = f"Feed {url} is malformed or invalid: {feed.bozo_exception}"
            return False, reason
    return True, None