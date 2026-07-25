"""Behavioral profile contracts for identities and devices."""

from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from behavioral_security.core.constants import PROFILE_SCHEMA_VERSION
from behavioral_security.core.enums import AuthenticationMethod, EntityType
from behavioral_security.core.models.common import Identifier, Probability, StrictModel


class BaselineWeights(StrictModel):
    """Weights used to blend entity and peer-group baselines."""

    entity: Probability
    department: Probability
    entity_type: Probability
    organization: Probability

    @model_validator(mode="after")
    def weights_sum_to_one(self) -> Self:
        """Require baseline weights to form a convex combination."""

        total = self.entity + self.department + self.entity_type + self.organization
        if abs(total - 1.0) > 1e-6:
            raise ValueError("baseline weights must sum to 1.0")
        return self


class SessionStatistics(StrictModel):
    """Numerically stable summary of observed session durations."""

    count: Annotated[int, Field(ge=0)]
    mean_seconds: Annotated[float, Field(ge=0.0)]
    standard_deviation_seconds: Annotated[float, Field(ge=0.0)]
    median_seconds: Annotated[float, Field(ge=0.0)]


class EntityProfile(StrictModel):
    """Versioned behavioral baseline for one user, account, or device."""

    profile_id: UUID
    entity_id: Identifier
    entity_type: EntityType
    department: str | None = None
    profile_version: Annotated[int, Field(ge=1)]
    schema_version: str = PROFILE_SCHEMA_VERSION
    effective_sample_size: Annotated[float, Field(ge=0.0)]
    maturity: Probability
    baseline_weights: BaselineWeights
    login_hour_probabilities: dict[Annotated[int, Field(ge=0, le=23)], Probability] = Field(
        default_factory=dict
    )
    resource_probabilities: dict[str, Probability] = Field(default_factory=dict)
    authentication_probabilities: dict[AuthenticationMethod, Probability] = Field(
        default_factory=dict
    )
    geolocation_probabilities: dict[str, Probability] = Field(default_factory=dict)
    known_device_fingerprints: frozenset[str] = Field(default_factory=frozenset)
    session_statistics: SessionStatistics
    failed_login_rate: Probability
    resource_transition_probabilities: dict[str, dict[str, Probability]] = Field(
        default_factory=dict
    )
    frequently_accessed_systems: tuple[str, ...] = ()
    first_observed_at: AwareDatetime
    last_observed_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("first_observed_at", "last_observed_at", "updated_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime) -> datetime:
        """Normalize profile timestamps to UTC."""

        return value.astimezone(UTC)

    @model_validator(mode="after")
    def timestamps_are_ordered(self) -> Self:
        """Ensure a profile cannot be updated before it was observed."""

        if self.last_observed_at < self.first_observed_at:
            raise ValueError("last_observed_at must not precede first_observed_at")
        if self.updated_at < self.last_observed_at:
            raise ValueError("updated_at must not precede last_observed_at")
        return self
