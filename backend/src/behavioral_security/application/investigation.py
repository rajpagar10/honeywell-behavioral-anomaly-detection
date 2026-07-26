"""Evidence-grounded SOC investigation orchestration."""

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

from behavioral_security.application.investigation_rendering import (
    INSUFFICIENT_EVIDENCE,
    behavioral_deviations,
    default_selection,
    executive_summary,
    fact_catalog,
    recommendation_catalog,
    render_answer,
    timeline,
    validated_ids,
)
from behavioral_security.core.enums import (
    AnalystDisposition,
    AnalystQuestion,
    InvestigationFeedback,
)
from behavioral_security.core.models.feedback import AnalystFeedback
from behavioral_security.core.models.investigation import (
    InvestigationEvidence,
    InvestigationFeedbackReceipt,
    InvestigationReason,
    InvestigationResponse,
    as_aware_datetime,
)

_LOGGER = logging.getLogger(__name__)


class InvestigationRepository(Protocol):
    """Persistence operations required by the investigation service."""

    def investigation_context(self, alert_id: str) -> dict[str, Any] | None:
        """Return an allowlisted alert and event context."""

    def persist_feedback(self, feedback: AnalystFeedback) -> None:
        """Persist append-only analyst feedback."""


class EvidenceSelector(Protocol):
    """Optional provider that selects only from supplied fact identifiers."""

    def select(
        self,
        question: AnalystQuestion,
        facts: Mapping[str, str],
        recommendations: Mapping[str, str],
    ) -> tuple[Sequence[str], Sequence[str]]:
        """Select grounded fact and recommendation identifiers."""


class InvestigationService:
    """Build grounded investigations with optional LLM-assisted selection."""

    def __init__(
        self,
        repository: InvestigationRepository,
        selector: EvidenceSelector | None,
        *,
        configured_provider: str,
        retry_cooldown_seconds: int,
    ) -> None:
        """Store the repository and optional bounded evidence selector."""

        self._repository = repository
        self._selector = selector
        self._configured_provider = configured_provider
        self._retry_cooldown_seconds = retry_cooldown_seconds
        self._provider_retry_at = 0.0

    def investigate(
        self,
        alert_id: str,
        question: AnalystQuestion = AnalystQuestion.EXECUTIVE_SUMMARY,
    ) -> InvestigationResponse | None:
        """Return an investigation grounded exclusively in allowlisted evidence."""

        context = self._repository.investigation_context(alert_id)
        if context is None:
            return None
        evidence = _build_evidence(context)
        facts = fact_catalog(evidence)
        recommendations = recommendation_catalog(context)
        fact_ids, action_ids = default_selection(question, facts, recommendations)
        provider = "template_fallback" if self._configured_provider == "ollama" else "template"
        if self._selector is not None and monotonic() >= self._provider_retry_at:
            try:
                selected_facts, selected_actions = self._selector.select(
                    question,
                    facts,
                    recommendations,
                )
                validated_facts = validated_ids(selected_facts, facts)
                validated_actions = validated_ids(selected_actions, recommendations)
                if validated_facts or validated_actions:
                    fact_ids = validated_facts or fact_ids
                    action_ids = validated_actions or action_ids
                    provider = "ollama"
                else:
                    provider = "template_fallback"
            except Exception as error:
                _LOGGER.warning("investigation_provider_fallback", extra={"error": str(error)})
                self._provider_retry_at = monotonic() + self._retry_cooldown_seconds
                provider = "template_fallback"
        answer = render_answer(fact_ids, action_ids, facts, recommendations)
        return InvestigationResponse(
            provider=provider,
            question=question,
            summary=executive_summary(evidence),
            answer=answer,
            why_generated=tuple(reason.summary for reason in evidence.reasons)
            or (INSUFFICIENT_EVIDENCE,),
            behavioral_deviations=behavioral_deviations(evidence),
            evidence=evidence,
            recommendations=tuple(recommendations.values()) or (INSUFFICIENT_EVIDENCE,),
            timeline=timeline(context, evidence),
        )

    def record_feedback(
        self,
        alert_id: str,
        feedback: InvestigationFeedback,
    ) -> InvestigationFeedbackReceipt | None:
        """Validate the alert and persist an append-only analyst disposition."""

        if self._repository.investigation_context(alert_id) is None:
            return None
        timestamp = datetime.now(UTC)
        model = AnalystFeedback(
            feedback_id=uuid4(),
            alert_id=alert_id,
            analyst_id="dashboard-analyst",
            disposition=_disposition(feedback),
            created_at=timestamp,
        )
        self._repository.persist_feedback(model)
        return InvestigationFeedbackReceipt(
            alert_id=alert_id,
            feedback=feedback,
            timestamp=timestamp,
        )


def _build_evidence(context: Mapping[str, Any]) -> InvestigationEvidence:
    """Transform repository context into the strict copilot evidence contract."""

    alert = context["alert"]
    event = context["event"]
    explanation = alert.get("explanation", {})
    timestamp = as_aware_datetime(str(alert["event_timestamp"]))
    reasons = tuple(
        InvestigationReason(
            feature=str(reason.get("feature_name", "unknown")),
            summary=str(reason.get("summary") or INSUFFICIENT_EVIDENCE),
            observed=str(reason.get("observed_value") or INSUFFICIENT_EVIDENCE),
            expected=str(reason.get("expected_value") or INSUFFICIENT_EVIDENCE),
            contribution=float(reason.get("contribution", 0.0)),
        )
        for reason in explanation.get("reasons", [])
    )
    anomaly_component = next(
        (
            component
            for component in explanation.get("components", [])
            if component.get("factor") == "ml_confidence"
        ),
        None,
    )
    known_device: bool | None = not any(
        reason.feature == "new_device_indicator" for reason in reasons
    )
    if alert.get("cold_start") and not any(
        reason.feature == "new_device_indicator" for reason in reasons
    ):
        known_device = None
    return InvestigationEvidence(
        alert_id=str(alert["alert_id"]),
        entity=str(alert["entity_id"]),
        entity_type=str(alert["entity_type"]),
        attack_type=str(alert["attack_type"]),
        severity=str(alert["severity"]),
        anomaly_score=(
            float(anomaly_component["raw_value"]) if anomaly_component is not None else None
        ),
        risk_score=float(alert["risk_score"]),
        confidence=float(alert["classifier_confidence"]),
        timestamp=timestamp,
        source_ip=_optional_text(event.get("source_ip")),
        geo_location=event.get("geo_location"),
        previous_location=(context.get("previous_event") or {}).get("geo_location"),
        device_fingerprint=_optional_text(event.get("device_fingerprint")),
        known_device=known_device,
        login_hour=timestamp.hour,
        resource_accessed=_optional_text(event.get("resource_accessed")),
        failed_logins=int(context["failed_logins"]),
        resource_sensitivity=event.get("resource_sensitivity"),
        cold_start=bool(alert.get("cold_start")),
        concept_drift=str(alert.get("drift_status", "stable")) != "stable",
        drift_status=str(alert.get("drift_status", "stable")),
        reasons=reasons,
    )


def _disposition(feedback: InvestigationFeedback) -> AnalystDisposition:
    """Map dashboard feedback labels to the existing domain taxonomy."""

    return {
        InvestigationFeedback.CONFIRMED_THREAT: AnalystDisposition.TRUE_POSITIVE,
        InvestigationFeedback.FALSE_POSITIVE: AnalystDisposition.FALSE_POSITIVE,
        InvestigationFeedback.BENIGN: AnalystDisposition.BENIGN_CHANGE,
        InvestigationFeedback.NEEDS_INVESTIGATION: AnalystDisposition.NEEDS_MORE_INFORMATION,
    }[feedback]


def _optional_text(value: object) -> str | None:
    """Return non-empty text or ``None``."""

    text = "" if value is None else str(value).strip()
    return text or None
