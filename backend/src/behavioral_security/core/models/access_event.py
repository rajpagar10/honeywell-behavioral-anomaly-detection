"""Operational access-event and isolated ground-truth contracts."""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from behavioral_security.core.constants import EVENT_SCHEMA_VERSION
from behavioral_security.core.enums import (
    AttackType,
    AuthenticationMethod,
    AuthenticationOutcome,
    EntityType,
    ResourceSensitivity,
)
from behavioral_security.core.models.common import GeoLocation, Identifier, JsonObject, StrictModel


class AccessEvent(StrictModel):
    """Validated operational event; intentionally excludes any ground-truth label."""

    event_id: UUID
    entity_id: Identifier
    entity_type: EntityType
    timestamp: AwareDatetime
    source_ip: IPv4Address | IPv6Address
    geo_location: GeoLocation
    resource_accessed: Annotated[str, Field(min_length=1, max_length=256)]
    auth_method: AuthenticationMethod
    session_duration: Annotated[float, Field(ge=0.0)]
    command_sequence: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...]
    device_fingerprint: Annotated[str, Field(min_length=8, max_length=256)]
    auth_outcome: AuthenticationOutcome = AuthenticationOutcome.SUCCESS
    department: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    resource_sensitivity: ResourceSensitivity = ResourceSensitivity.MEDIUM
    bytes_transferred: Annotated[int, Field(ge=0)] = 0
    destination_ip: IPv4Address | IPv6Address | None = None
    schema_version: str = EVENT_SCHEMA_VERSION
    extensions: JsonObject = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Normalize an aware event timestamp to UTC."""

        return value.astimezone(UTC)


class GroundTruthRecord(StrictModel):
    """Evaluation-only label stored outside the operational event database."""

    event_id: UUID
    label: AttackType
    attack_campaign_id: UUID | None = None
    generated_at: AwareDatetime
    scenario_metadata: JsonObject = Field(default_factory=dict)

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        """Normalize the generation timestamp to UTC."""

        return value.astimezone(UTC)
