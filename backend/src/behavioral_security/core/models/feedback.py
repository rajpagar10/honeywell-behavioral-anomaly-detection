"""Analyst feedback contract for auditable investigation outcomes."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from behavioral_security.core.enums import AnalystDisposition, AttackType
from behavioral_security.core.models.common import Identifier, StrictModel


class AnalystFeedback(StrictModel):
    """Append-only analyst disposition associated with one alert."""

    feedback_id: UUID
    alert_id: UUID
    analyst_id: Identifier
    disposition: AnalystDisposition
    notes: Annotated[str, Field(min_length=1, max_length=4000)] | None = None
    corrected_attack_type: AttackType | None = None
    created_at: AwareDatetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        """Normalize the feedback timestamp to UTC."""

        return value.astimezone(UTC)
