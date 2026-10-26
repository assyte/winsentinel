"""Thread-safe logging that feeds both a rotating file and the UI console."""

from __future__ import annotations

import logging
import os
import queue
from logging.handlers import QueueHandler, RotatingFileHandler
from pathlib import Path

from core.constants import APP_DATA_DIRNAME, APP_NAME

LOG_QUEUE: "queue.Queue[logging.LogRecord]" = queue.Queue(maxsize=4000)
_configured = False
_log_path: Path | None = None


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / APP_DATA_DIRNAME
    return Path.home() / f".{APP_DATA_DIRNAME.lower()}"


def get_log_path() -> Path | None:
    return _log_path


def setup_logging() -> logging.Logger:
    """Configure the ``winsentinel`` logger once per process."""

    global _configured, _log_path
    logger = logging.getLogger("winsentinel")
    if _configured:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers.clear()

    queue_handler = QueueHandler(LOG_QUEUE)
    queue_handler.setLevel(logging.DEBUG)
    queue_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(queue_handler)

    try:
        log_dir = app_data_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        _log_path = log_dir / "winsentinel.log"
        file_handler = RotatingFileHandler(
            _log_path,
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(file_handler)
    except OSError:
        # A read-only profile should never stop the application from starting.
        _log_path = None

    _configured = True
    logger.debug("%s logging initialised", APP_NAME)
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    setup_logging()
    if not name:
        return logging.getLogger("winsentinel")
    return logging.getLogger(f"winsentinel.{name}")
