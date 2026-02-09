"""Centralised logging configuration for ARPSurgeon."""
from __future__ import annotations

import logging
import sys

LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: int = logging.INFO) -> None:
    """Configure the root ``arpsurgeon`` logger.

    Call once during application startup (CLI or web).  Subsequent calls
    are idempotent — the handler is only added if absent.
    """
    logger = logging.getLogger("arpsurgeon")
    if logger.handlers:
        return
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the ``arpsurgeon`` namespace."""
    return logging.getLogger(f"arpsurgeon.{name}")
