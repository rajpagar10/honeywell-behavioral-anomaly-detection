"""Grounded AI-assisted investigation contracts."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field

from behavioral_security.core.enums import (
    AnalystQuestion,
    AttackType,
    EntityType,
    InvestigationFeedback,
    ResourceSensitivity,
    Severity,
)
from behavioral_security.core.models.common import (
    GeoLocation,
    Identifier,
    Probability,
    RiskScore,
    StrictModel,
)


class InvestigationReason(StrictModel):
    """One traceable behavioral or risk reason supplied to the copilot."""

    feature: str
    summary: str
    observed: str
    expected: str
    contribution: Annotated[float, Field(ge=0.0, le=100.0)]


class InvestigationEvidence(StrictModel):
    """Allowlisted evidence object that isolates the copilot from storage."""

    alert_id: str
    entity: Identifier
    entity_type: EntityType
    attack_type: AttackType
    severity: Severity
    anomaly_score: Probability | None = None
    risk_score: RiskScore
    confidence: Probability
    timestamp: AwareDatetime
    source_ip: str | None = None
    geo_location: GeoLocation | None = None
    previous_location: GeoLocation | None = None
    device_fingerprint: str | None = None
    known_device: bool | None = None
    login_hour: Annotated[int, Field(ge=0, le=23)]
    resource_accessed: str | None = None
    failed_logins: Annotated[int, Field(ge=0)] | None = None
    resource_sensitivity: ResourceSensitivity | None = None
    cold_start: bool
    concept_drift: bool
    drift_status: str
    reasons: tuple[InvestigationReason, ...]


class InvestigationTimelineEvent(StrictModel):
    """One grounded step in the alert investigation timeline."""

    title: str
    timestamp: AwareDatetime
    detail: str


class InvestigationResponse(StrictModel):
    """Complete evidence-grounded investigation response."""

    badge: Literal["AI Assisted Investigation"] = "AI Assisted Investigation"
    disclaimer: Literal["Analyst verification required."] = "Analyst verification required."
    provider: Literal["ollama", "template", "template_fallback"]
    question: AnalystQuestion
    summary: str
    answer: str
    why_generated: tuple[str, ...]
    behavioral_deviations: tuple[str, ...]
    evidence: InvestigationEvidence
    recommendations: tuple[str, ...]
    timeline: tuple[InvestigationTimelineEvent, ...]


class InvestigationFeedbackRequest(StrictModel):
    """Feedback command accepted by the investigation resource."""

    feedback: InvestigationFeedback


class InvestigationFeedbackReceipt(StrictModel):
    """Persisted analyst feedback acknowledgement."""

    alert_id: str
    feedback: InvestigationFeedback
    timestamp: AwareDatetime


def as_aware_datetime(value: str | datetime) -> datetime:
    """Parse an ISO timestamp into an aware datetime."""

    parsed = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("investigation timestamps must include a timezone")
    return parsed
