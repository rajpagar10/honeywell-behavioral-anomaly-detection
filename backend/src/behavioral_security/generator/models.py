"""Synthetic organization and generated dataset models."""

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from behavioral_security.core.enums import AuthenticationMethod, EntityType
from behavioral_security.core.models.access_event import AccessEvent, GroundTruthRecord
from behavioral_security.core.models.common import GeoLocation, Identifier, StrictModel


class BehaviorProfile(StrictModel):
    """Stable normal behavior and planned legitimate changes for one entity."""

    profile_id: UUID
    entity_id: Identifier
    entity_type: EntityType
    department: Annotated[str, Field(min_length=1, max_length=128)]
    home_location: GeoLocation
    allowed_locations: tuple[GeoLocation, ...]
    common_resources: tuple[Annotated[str, Field(min_length=1, max_length=256)], ...]
    authentication_methods: tuple[AuthenticationMethod, ...]
    normal_login_hours: tuple[Annotated[int, Field(ge=0, le=23)], ...]
    known_devices: tuple[Annotated[str, Field(min_length=8, max_length=256)], ...]
    source_ips: tuple[IPv4Address | IPv6Address, ...]
    mean_session_seconds: Annotated[float, Field(gt=0.0)]
    session_stddev_seconds: Annotated[float, Field(gt=0.0)]
    command_templates: dict[str, tuple[str, ...]]
    activity_weight: Annotated[float, Field(gt=0.0)]
    active_after: AwareDatetime
    cold_start: bool = False
    drift_start: AwareDatetime | None = None
    drift_login_hour_offset: Annotated[int, Field(ge=-8, le=8)] = 0
    drift_resources: tuple[str, ...] = ()
    drift_device: str | None = None

    @field_validator("active_after", "drift_start")
    @classmethod
    def normalize_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize profile lifecycle timestamps to UTC."""

        return value.astimezone(UTC) if value is not None else None


@dataclass(frozen=True, slots=True)
class GeneratedDataset:
    """In-memory event, label, and profile collections."""

    events: tuple[AccessEvent, ...]
    labels: tuple[GroundTruthRecord, ...]
    profiles: tuple[BehaviorProfile, ...]


class GenerationSummary(StrictModel):
    """Validated dataset statistics written to the export manifest."""

    dataset_name: str
    seed: int
    event_count: int
    entity_count: int
    normal_count: int
    anomaly_count: int
    anomaly_percentage: float
    class_distribution: dict[str, int]
    entity_distribution: dict[str, int]
    cold_start_entities: int
    drift_entities: int
    first_timestamp: AwareDatetime
    last_timestamp: AwareDatetime


@dataclass(frozen=True, slots=True)
class ExportedDataset:
    """Filesystem locations for a completed dataset export."""

    events_path: Path
    labels_path: Path
    profiles_path: Path
    manifest_path: Path
