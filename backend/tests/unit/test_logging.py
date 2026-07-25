"""Structured logging tests."""

import json
import logging

from behavioral_security.infrastructure.observability.logging import JsonFormatter


def test_json_formatter_emits_context() -> None:
    formatter = JsonFormatter("unit-test")
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="processed %s",
        args=("event",),
        exc_info=None,
    )
    record.__dict__["correlation_id"] = "correlation-1"

    payload = json.loads(formatter.format(record))

    assert payload["service"] == "unit-test"
    assert payload["message"] == "processed event"
    assert payload["correlation_id"] == "correlation-1"
