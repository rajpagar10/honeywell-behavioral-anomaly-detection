"""Health and readiness response schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Service liveness response."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["healthy"]
    service: str
    version: str
    environment: str


class ReadinessResponse(BaseModel):
    """Dependency readiness response."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ready"]
    components: dict[str, bool]
