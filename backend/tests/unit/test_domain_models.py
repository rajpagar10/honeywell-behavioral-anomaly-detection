"""Domain contract validation tests."""

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from behavioral_security.core.enums import (
    AnalystDisposition,
    AttackType,
    AuthenticationMethod,
    EntityType,
    Severity,
)
from behavioral_security.core.models.access_event import AccessEvent, GroundTruthRecord
from behavioral_security.core.models.common import GeoLocation
from behavioral_security.core.models.feedback import AnalystFeedback
from behavioral_security.core.models.profile import (
    BaselineWeights,
    EntityProfile,
    SessionStatistics,
)


def _access_event() -> AccessEvent:
    return AccessEvent(
        event_id=uuid4(),
        entity_id="user-001",
        entity_type=EntityType.USER,
        timestamp=datetime(2026, 7, 25, 9, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        source_ip="192.0.2.10",
        geo_location=GeoLocation(
            country_code="IN",
            city="Bengaluru",
            latitude=12.9716,
            longitude=77.5946,
        ),
        resource_accessed="engineering/telemetry",
        auth_method=AuthenticationMethod.MFA,
        session_duration=420.0,
        command_sequence=("login", "read_dashboard"),
        device_fingerprint="device-fingerprint-001",
    )


def test_access_event_normalizes_time_and_excludes_label() -> None:
    event = _access_event()

    assert event.timestamp.utcoffset() == timedelta(0)
    assert "label" not in AccessEvent.model_fields
    assert event.model_dump()["entity_type"] is EntityType.USER


def test_ground_truth_is_a_separate_contract() -> None:
    event = _access_event()
    record = GroundTruthRecord(
        event_id=event.event_id,
        label=AttackType.IMPOSSIBLE_TRAVEL,
        generated_at=datetime.now(UTC),
    )

    assert record.event_id == event.event_id
    assert record.label is AttackType.IMPOSSIBLE_TRAVEL


def test_profile_rejects_invalid_baseline_weights() -> None:
    with pytest.raises(ValidationError, match="sum to 1.0"):
        BaselineWeights(entity=0.5, department=0.5, entity_type=0.5, organization=0.0)


def test_profile_rejects_reversed_timestamps() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="last_observed_at"):
        EntityProfile(
            profile_id=uuid4(),
            entity_id="user-001",
            entity_type=EntityType.USER,
            profile_version=1,
            effective_sample_size=4,
            maturity=0.2,
            baseline_weights=BaselineWeights(
                entity=0.2,
                department=0.4,
                entity_type=0.3,
                organization=0.1,
            ),
            session_statistics=SessionStatistics(
                count=4,
                mean_seconds=100,
                standard_deviation_seconds=10,
                median_seconds=95,
            ),
            failed_login_rate=0.0,
            first_observed_at=now,
            last_observed_at=now - timedelta(hours=1),
            updated_at=now,
        )


def test_analyst_feedback_normalizes_time() -> None:
    feedback = AnalystFeedback(
        feedback_id=uuid4(),
        alert_id=uuid4(),
        analyst_id="analyst-01",
        disposition=AnalystDisposition.TRUE_POSITIVE,
        corrected_attack_type=AttackType.LATERAL_MOVEMENT,
        notes="Verified against the entity timeline.",
        created_at=datetime.now(UTC),
    )

    assert feedback.created_at.tzinfo is UTC
    assert Severity.CRITICAL.value == "critical"
