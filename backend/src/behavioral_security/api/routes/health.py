"""Liveness and dependency-readiness endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from behavioral_security.api.dependencies import get_database_manager
from behavioral_security.api.schemas.health import HealthResponse, ReadinessResponse
from behavioral_security.core.constants import APP_NAME, APP_VERSION
from behavioral_security.infrastructure.database.manager import DatabaseManager

router = APIRouter(tags=["System"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Check process liveness",
    description="Returns success when the API process can serve requests.",
)
def health(request: Request) -> HealthResponse:
    """Return API process liveness without testing external dependencies."""

    return HealthResponse(
        status="healthy",
        service=APP_NAME,
        version=APP_VERSION,
        environment=request.app.state.settings.runtime.environment,
    )


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Check service readiness",
    description="Verifies that required operational and evaluation schemas are available.",
)
def readiness(
    manager: Annotated[DatabaseManager, Depends(get_database_manager)],
) -> ReadinessResponse:
    """Return readiness only when all required persistence components are healthy."""

    components = manager.readiness()
    if not all(components.values()):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "not_ready", "components": components},
        )
    return ReadinessResponse(status="ready", components=components)
