"""Reusable validated domain value objects."""

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
RiskScore = Annotated[float, Field(ge=0.0, le=100.0)]
JsonObject = dict[str, Any]


class StrictModel(BaseModel):
    """Base model that rejects unknown data and supports immutable evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class GeoLocation(StrictModel):
    """Normalized geographic coordinates and human-readable location."""

    country_code: Annotated[str, Field(min_length=2, max_length=2, pattern=r"^[A-Z]{2}$")]
    city: Annotated[str, Field(min_length=1, max_length=128)]
    latitude: Annotated[float, Field(ge=-90.0, le=90.0)]
    longitude: Annotated[float, Field(ge=-180.0, le=180.0)]


class TimestampedModel(StrictModel):
    """Base model for records with normalized UTC creation timestamps."""

    created_at: AwareDatetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        """Normalize an aware creation timestamp to UTC."""

        return value.astimezone(UTC)
