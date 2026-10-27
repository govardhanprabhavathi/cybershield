import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format logs as structured JSON objects for automated ingestion and auditability."""

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        # Include custom security and request attributes if provided
        for attr in ("session_id", "user_id", "request_id", "risk_score", "confidence_score", "action", "event_type"):
            if hasattr(record, attr):
                log_payload[attr] = getattr(record, attr)

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


def setup_logging(environment: str = "development", debug: bool = True) -> logging.Logger:
    """Configure system-wide root and CyberShield loggers."""
    logger = logging.getLogger("cybershield")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Avoid duplicate handlers if setup is invoked repeatedly
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if environment == "production":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
        logger.addHandler(handler)

    return logger


logger = setup_logging()
