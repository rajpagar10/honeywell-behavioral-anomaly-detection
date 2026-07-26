"""SOC dashboard, alert, entity, evaluation, and replay endpoints."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from behavioral_security.api.dependencies import get_investigation_service, get_soc_service
from behavioral_security.api.schemas.soc import InvestigationFeedbackRequest, ReplayRequest
from behavioral_security.application.investigation import InvestigationService
from behavioral_security.application.realtime import RealtimeSOCService
from behavioral_security.core.enums import AnalystQuestion
from behavioral_security.core.models.investigation import (
    InvestigationFeedbackReceipt,
    InvestigationResponse,
)

router = APIRouter(tags=["SOC"])


@router.get("/dashboard/summary", summary="Get SOC dashboard summary")
def dashboard_summary(
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
) -> dict[str, Any]:
    """Return event, alert, entity, severity, and model metric summaries."""

    return service.dashboard_summary()


@router.get("/events/recent", summary="Get recent operational events")
def recent_events(
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[dict[str, Any]]:
    """Return recent replayed events without ground-truth labels."""

    return service.recent_events(limit)


@router.get("/alerts", summary="Get risk-ranked alerts")
def ranked_alerts(
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[dict[str, Any]]:
    """Return alerts ordered by risk score and recency."""

    return service.ranked_alerts(limit)


@router.get("/alerts/{alert_id}", summary="Get alert explanation")
def alert_details(
    alert_id: str,
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
) -> dict[str, Any]:
    """Return complete risk contributions, explanation, and actions."""

    alert = service.alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return alert


@router.get(
    "/alerts/{alert_id}/investigation",
    response_model=InvestigationResponse,
    summary="Get an AI-assisted grounded investigation",
)
def alert_investigation(
    alert_id: str,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
    question: AnalystQuestion = AnalystQuestion.EXECUTIVE_SUMMARY,
) -> InvestigationResponse:
    """Return a grounded investigation using only curated alert evidence."""

    investigation = service.investigate(alert_id, question)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return investigation


@router.post(
    "/alerts/{alert_id}/investigation",
    response_model=InvestigationFeedbackReceipt,
    status_code=status.HTTP_201_CREATED,
    summary="Store investigation feedback",
)
def store_investigation_feedback(
    alert_id: str,
    request: InvestigationFeedbackRequest,
    service: Annotated[InvestigationService, Depends(get_investigation_service)],
) -> InvestigationFeedbackReceipt:
    """Persist one append-only analyst feedback disposition."""

    receipt = service.record_feedback(alert_id, request.feedback)
    if receipt is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return receipt


@router.get("/entities/{entity_id}", summary="Get entity profile and history")
def entity_history(
    entity_id: str,
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> dict[str, Any]:
    """Return entity history with cold-start and adaptive drift state."""

    history = service.entity_history(entity_id, limit)
    if history is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entity not found")
    return history


@router.get("/evaluation/metrics", summary="Get model evaluation metrics")
def evaluation_metrics(
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
) -> dict[str, Any]:
    """Return the latest persisted model evaluation metrics."""

    return service.evaluation_metrics()


@router.post("/replay/start", status_code=status.HTTP_202_ACCEPTED, summary="Start event replay")
async def start_replay(
    request: ReplayRequest,
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
) -> dict[str, Any]:
    """Start sequential background event processing."""

    try:
        return await service.start_replay(
            interval_ms=request.interval_ms,
            max_events=request.max_events,
        )
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error


@router.get("/replay/status", summary="Get event replay status")
def replay_status(
    service: Annotated[RealtimeSOCService, Depends(get_soc_service)],
    run_id: str | None = None,
) -> dict[str, Any]:
    """Return latest or requested replay progress."""

    replay = service.replay_status(run_id)
    if replay is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="replay not found")
    return replay
