"""Classified SOC alert contract."""

from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from behavioral_security.core.enums import AlertStatus, AttackType, EntityType, Severity
from behavioral_security.core.models.common import Identifier, Probability, RiskScore, StrictModel
from behavioral_security.core.models.risk import RiskScoreExplanation


class ClassifiedAlert(StrictModel):
    """Versioned alert ready for analyst triage."""

    alert_id: UUID
    event_id: UUID
    entity_id: Identifier
    entity_type: EntityType
    attack_type: AttackType
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    risk_score: RiskScore
    classifier_confidence: Probability
    classifier_version: Annotated[str, Field(min_length=1, max_length=64)]
    correlation_key: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    event_timestamp: AwareDatetime | None = None
    top_contributing_factors: tuple[str, ...] = ()
    human_explanation: str = ""
    recommended_actions: tuple[str, ...] = ()
    cold_start: bool = False
    drift_status: str = "stable"
    explanation: RiskScoreExplanation
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("created_at", "updated_at", "event_timestamp")
    @classmethod
    def normalize_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize alert timestamps to UTC."""

        return value.astimezone(UTC) if value is not None else None

    @model_validator(mode="after")
    def updated_after_creation(self) -> Self:
        """Ensure alert lifecycle timestamps are ordered."""

        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.explanation.event_id != self.event_id:
            raise ValueError("alert and explanation must reference the same event")
        if abs(self.explanation.score - self.risk_score) > 1e-6:
            raise ValueError("alert and explanation risk scores must match")
        return self
