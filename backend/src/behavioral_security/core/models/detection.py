"""Model prediction, rule finding, and fused detection contracts."""

from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from behavioral_security.core.constants import FEATURE_SCHEMA_VERSION
from behavioral_security.core.enums import (
    AttackType,
    EvidenceDirection,
    ModelFamily,
    Severity,
)
from behavioral_security.core.models.common import Probability, StrictModel


class EvidenceItem(StrictModel):
    """Traceable feature evidence supporting or mitigating a finding."""

    feature_name: Annotated[str, Field(min_length=1, max_length=128)]
    observed_value: Any
    expected_value: Any
    contribution: Annotated[float, Field(ge=0.0)]
    direction: EvidenceDirection
    source: Annotated[str, Field(min_length=1, max_length=128)]


class ModelPrediction(StrictModel):
    """Versioned, calibrated output from a single detection model."""

    model_name: Annotated[str, Field(min_length=1, max_length=128)]
    model_version: Annotated[str, Field(min_length=1, max_length=64)]
    model_family: ModelFamily
    score: Probability
    confidence: Probability
    predicted_attack: AttackType | None = None
    evidence: tuple[EvidenceItem, ...] = ()


class RuleFinding(StrictModel):
    """Auditable result from a deterministic security rule."""

    rule_id: Annotated[str, Field(min_length=1, max_length=128)]
    rule_version: Annotated[str, Field(min_length=1, max_length=64)]
    title: Annotated[str, Field(min_length=1, max_length=256)]
    attack_type: AttackType
    severity: Severity
    confidence: Probability
    evidence: tuple[EvidenceItem, ...]


class DetectionResult(StrictModel):
    """Fused anomaly result produced before final risk policy evaluation."""

    detection_id: UUID
    event_id: UUID
    detected_at: AwareDatetime
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    anomaly_score: Probability
    is_anomaly: bool
    predictions: tuple[ModelPrediction, ...] = ()
    rule_findings: tuple[RuleFinding, ...] = ()

    @field_validator("detected_at")
    @classmethod
    def normalize_detected_at(cls, value: datetime) -> datetime:
        """Normalize the detection timestamp to UTC."""

        return value.astimezone(UTC)
