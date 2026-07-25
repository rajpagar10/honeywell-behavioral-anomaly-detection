"""Risk-score component and explanation contracts."""

from typing import Annotated
from uuid import UUID

from pydantic import Field

from behavioral_security.core.enums import EvidenceDirection, RiskFactorName, Severity
from behavioral_security.core.models.common import Probability, RiskScore, StrictModel


class RiskContribution(StrictModel):
    """One normalized input and its weighted risk contribution."""

    factor: RiskFactorName
    raw_value: float
    normalized_value: Probability
    weight: Annotated[float, Field(ge=0.0)]
    contribution: Annotated[float, Field(ge=0.0, le=100.0)]


class ExplanationReason(StrictModel):
    """Human-readable reason backed by observed and expected evidence."""

    summary: Annotated[str, Field(min_length=1, max_length=512)]
    feature_name: Annotated[str, Field(min_length=1, max_length=128)]
    observed_value: str
    expected_value: str
    contribution: Annotated[float, Field(ge=0.0, le=100.0)]
    direction: EvidenceDirection
    evidence_source: Annotated[str, Field(min_length=1, max_length=128)]


class RiskScoreExplanation(StrictModel):
    """Complete, auditable explanation for a normalized risk score."""

    event_id: UUID
    score: RiskScore
    severity: Severity
    confidence: Probability
    policy_version: Annotated[str, Field(min_length=1, max_length=64)]
    profile_maturity: Probability
    baseline_level: Annotated[str, Field(min_length=1, max_length=64)]
    components: tuple[RiskContribution, ...]
    reasons: tuple[ExplanationReason, ...]
