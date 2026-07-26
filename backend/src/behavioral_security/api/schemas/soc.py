"""Request contracts for SOC queries and event replay."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ReplayRequest(BaseModel):
    """Optional controls for a bounded demonstration replay."""

    model_config = ConfigDict(extra="forbid")

    interval_ms: Annotated[int, Field(ge=0, le=60_000)] | None = None
    max_events: Annotated[int, Field(ge=1, le=100_000)] | None = None
