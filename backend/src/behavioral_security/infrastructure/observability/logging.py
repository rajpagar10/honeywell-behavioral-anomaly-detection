"""Central structured logging configuration."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from behavioral_security.infrastructure.config.settings import LoggingSettings

_CONTEXT_FIELDS = (
    "correlation_id",
    "event_id",
    "entity_id",
    "alert_id",
    "model_version",
    "simulation_run_id",
)


class JsonFormatter(logging.Formatter):
    """Render stable single-line JSON records for log aggregation."""

    def __init__(self, service_name: str) -> None:
        """Initialize the formatter with its emitting service name."""

        super().__init__()
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a log record and approved context attributes."""

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "service": self._service_name,
            "message": record.getMessage(),
        }
        for field in _CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def configure_logging(settings: LoggingSettings) -> None:
    """Replace root handlers with the configured console or JSON handler."""

    handler = logging.StreamHandler(sys.stdout)
    if settings.format == "json":
        handler.setFormatter(JsonFormatter(settings.service_name))
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.level)
    logging.captureWarnings(True)
