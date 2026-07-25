"""Detection, risk, and alert consistency tests."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from behavioral_security.core.enums import (
    AttackType,
    EntityType,
    EvidenceDirection,
    RiskFactorName,
    Severity,
)
from behavioral_security.core.models.alert import ClassifiedAlert
from behavioral_security.core.models.detection import DetectionResult
from behavioral_security.core.models.risk import (
    ExplanationReason,
    RiskContribution,
    RiskScoreExplanation,
)


def _explanation(event_id: UUID, score: float = 82.0) -> RiskScoreExplanation:
    return RiskScoreExplanation(
        event_id=event_id,
        score=score,
        severity=Severity.HIGH,
        confidence=0.9,
        policy_version="risk-v1",
        profile_maturity=0.8,
        baseline_level="individual",
        components=(
            RiskContribution(
                factor=RiskFactorName.BEHAVIORAL_DEVIATION,
                raw_value=2.1,
                normalized_value=0.82,
                weight=0.5,
                contribution=41.0,
            ),
        ),
        reasons=(
            ExplanationReason(
                summary="Login occurred outside the established activity window.",
                feature_name="login_hour_probability",
                observed_value="0.01",
                expected_value=">= 0.20",
                contribution=20.0,
                direction=EvidenceDirection.INCREASES_RISK,
                evidence_source="profile-v3",
            ),
        ),
    )


def test_detection_score_is_bounded() -> None:
    with pytest.raises(ValidationError):
        DetectionResult(
            detection_id=uuid4(),
            event_id=uuid4(),
            detected_at=datetime.now(UTC),
            anomaly_score=1.1,
            is_anomaly=True,
        )


def test_alert_requires_matching_explanation_score() -> None:
    event_id = uuid4()
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="risk scores must match"):
        ClassifiedAlert(
            alert_id=uuid4(),
            event_id=event_id,
            entity_id="user-001",
            entity_type=EntityType.USER,
            attack_type=AttackType.IMPOSSIBLE_TRAVEL,
            severity=Severity.HIGH,
            risk_score=80.0,
            classifier_confidence=0.9,
            classifier_version="rf-v1",
            explanation=_explanation(event_id, score=82.0),
            created_at=now,
            updated_at=now + timedelta(seconds=1),
        )
