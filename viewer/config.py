# config.py
"""
Handles application configuration and logger setup.

This module centralizes the loading of environment variables for database
configuration and provides a factory function for creating standardized
logger instances throughout the application.
"""
import os
import logging

# Centralized database configuration.
# Keys are named to match the parameters of psycopg2.connect() for easy unpacking.
DATABASE_CONFIG = {
    'dbname': os.getenv('POSTGRES_DB'),
    'user': os.getenv('POSTGRES_USER'),
    'password': os.getenv('POSTGRES_PASSWORD'),
    'host': os.getenv('DB_HOST', 'db')
}

def get_logger(name: str) -> logging.Logger:
    """
    Creates and configures a logger instance.

    This factory function ensures that logger configuration is consistent
    and prevents duplicate handlers from being added.

    Args:
        name: The name of the logger, typically __name__.

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger