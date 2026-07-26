"""Focused tests for evidence-grounded investigation behavior."""

from collections.abc import Mapping, Sequence
from typing import Any

from behavioral_security.application.investigation import InvestigationService
from behavioral_security.core.enums import AnalystQuestion, InvestigationFeedback
from behavioral_security.core.models.feedback import AnalystFeedback

ALERT_ID = "b0aafa27-647c-5bf0-9209-2aa94b9fdbf3"


class FakeRepository:
    """In-memory investigation repository used by focused unit tests."""

    def __init__(self, context: dict[str, Any]) -> None:
        """Store one context and captured feedback."""

        self.context = context
        self.feedback: list[AnalystFeedback] = []

    def investigation_context(self, alert_id: str) -> dict[str, Any] | None:
        """Return the fixture only for its alert identifier."""

        return self.context if alert_id == ALERT_ID else None

    def persist_feedback(self, feedback: AnalystFeedback) -> None:
        """Capture persisted feedback."""

        self.feedback.append(feedback)


class FailingSelector:
    """Provider double that proves deterministic fallback is non-fatal."""

    def __init__(self) -> None:
        """Initialize the call counter."""

        self.calls = 0

    def select(
        self,
        question: AnalystQuestion,
        facts: Mapping[str, str],
        recommendations: Mapping[str, str],
    ) -> tuple[Sequence[str], Sequence[str]]:
        """Simulate an unavailable local Ollama service."""

        self.calls += 1
        raise ConnectionError("Ollama is unavailable")


def test_investigation_falls_back_and_records_feedback() -> None:
    """Provider failure returns grounded templates and feedback remains writable."""

    repository = FakeRepository(_context())
    selector = FailingSelector()
    service = InvestigationService(
        repository,
        selector,
        configured_provider="ollama",
        retry_cooldown_seconds=30,
    )

    result = service.investigate(ALERT_ID, AnalystQuestion.WHY_GENERATED)
    assert result is not None
    assert result.provider == "template_fallback"
    assert result.evidence.entity == "user-0042"
    assert result.evidence.source_ip == "203.0.113.40"
    assert result.evidence.previous_location is not None
    assert "critical enterprise resource" in result.answer
    assert selector.calls == 1

    repeated = service.investigate(ALERT_ID, AnalystQuestion.CONCEPT_DRIFT)
    assert repeated is not None
    assert repeated.provider == "template_fallback"
    assert selector.calls == 1

    receipt = service.record_feedback(
        ALERT_ID,
        InvestigationFeedback.CONFIRMED_THREAT,
    )
    assert receipt is not None
    assert receipt.feedback == InvestigationFeedback.CONFIRMED_THREAT
    assert len(repository.feedback) == 1
    assert repository.feedback[0].disposition.value == "true_positive"


def test_missing_alert_returns_none() -> None:
    """Unknown alert identifiers do not create investigations or feedback."""

    service = InvestigationService(
        FakeRepository(_context()),
        None,
        configured_provider="template",
        retry_cooldown_seconds=30,
    )

    assert service.investigate("missing") is None
    assert service.record_feedback("missing", InvestigationFeedback.NEEDS_INVESTIGATION) is None


def _context() -> dict[str, Any]:
    """Return one complete allowlisted investigation context."""

    return {
        "alert": {
            "alert_id": ALERT_ID,
            "entity_id": "user-0042",
            "entity_type": "user",
            "attack_type": "impossible_travel",
            "severity": "high",
            "risk_score": 92.0,
            "classifier_confidence": 0.96,
            "event_timestamp": "2026-01-07T22:50:46+00:00",
            "updated_at": "2026-07-26T10:29:31+00:00",
            "cold_start": False,
            "drift_status": "adapting",
            "recommended_actions": [
                "Verify user identity.",
                "Revoke suspicious sessions.",
            ],
            "explanation": {
                "components": [
                    {
                        "factor": "ml_confidence",
                        "raw_value": 0.99,
                    }
                ],
                "reasons": [
                    {
                        "feature_name": "resource_sensitivity",
                        "summary": "a critical enterprise resource was accessed",
                        "observed_value": "critical",
                        "expected_value": "low or medium",
                        "contribution": 10.0,
                    },
                    {
                        "feature_name": "new_device_indicator",
                        "summary": "the device fingerprint is unseen",
                        "observed_value": "device-new",
                        "expected_value": "known device",
                        "contribution": 8.0,
                    },
                ],
            },
        },
        "event": {
            "source_ip": "203.0.113.40",
            "geo_location": {
                "country_code": "DE",
                "city": "Frankfurt",
                "latitude": 50.1109,
                "longitude": 8.6821,
            },
            "resource_accessed": "finance-db",
            "device_fingerprint": "device-new",
            "resource_sensitivity": "critical",
        },
        "previous_event": {
            "timestamp": "2026-01-07T22:40:46+00:00",
            "geo_location": {
                "country_code": "IN",
                "city": "Pune",
                "latitude": 18.5204,
                "longitude": 73.8567,
            },
            "auth_outcome": "success",
            "alerted": False,
        },
        "failed_logins": 2,
    }
