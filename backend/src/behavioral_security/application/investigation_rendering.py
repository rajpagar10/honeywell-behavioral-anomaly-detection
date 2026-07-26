"""Deterministic rendering for evidence-grounded investigations."""

from collections.abc import Mapping, Sequence
from typing import Any

from behavioral_security.core.enums import AnalystQuestion
from behavioral_security.core.models.investigation import (
    InvestigationEvidence,
    InvestigationTimelineEvent,
    as_aware_datetime,
)

INSUFFICIENT_EVIDENCE = "Insufficient evidence available."


def fact_catalog(evidence: InvestigationEvidence) -> dict[str, str]:
    """Create natural-language facts containing only supplied evidence."""

    facts = {
        "alert": (
            f"{evidence.entity} generated a {evidence.severity.value} risk "
            f"{evidence.attack_type.value.replace('_', ' ')} alert with a risk score of "
            f"{evidence.risk_score:.1f}/100 and classification confidence of "
            f"{evidence.confidence:.0%}."
        ),
        "time": (
            f"The activity occurred at {evidence.timestamp.isoformat()} during login hour "
            f"{evidence.login_hour:02d}:00 UTC."
        ),
        "adaptive_state": (
            f"Cold start is {str(evidence.cold_start).lower()} and concept drift status is "
            f"{evidence.drift_status}."
        ),
    }
    if evidence.anomaly_score is not None:
        facts["anomaly"] = f"The anomaly-model score is {evidence.anomaly_score:.2f}."
    if evidence.source_ip:
        facts["source"] = f"The observed source IP is {evidence.source_ip}."
    if evidence.geo_location:
        facts["location"] = (
            f"The observed location is {evidence.geo_location.city}, "
            f"{evidence.geo_location.country_code}."
        )
    if evidence.previous_location:
        facts["previous_location"] = (
            f"The previous observed location is {evidence.previous_location.city}, "
            f"{evidence.previous_location.country_code}."
        )
    if evidence.resource_accessed:
        facts["resource"] = f"The accessed resource is {evidence.resource_accessed}" + (
            f" with {evidence.resource_sensitivity.value} sensitivity."
            if evidence.resource_sensitivity
            else "."
        )
    if evidence.device_fingerprint:
        device_state = (
            "known"
            if evidence.known_device is True
            else "unseen"
            if evidence.known_device is False
            else "not established because the entity is in cold start"
        )
        facts["device"] = (
            f"Device {evidence.device_fingerprint} is {device_state} for this baseline."
        )
    if evidence.failed_logins is not None:
        facts["failures"] = (
            f"There were {evidence.failed_logins} failed logins in the preceding seven days."
        )
    for index, reason in enumerate(evidence.reasons):
        facts[f"reason_{index}"] = (
            f"{reason.summary.capitalize()}; observed {reason.observed}, expected "
            f"{reason.expected}."
        )
    return facts


def recommendation_catalog(context: Mapping[str, Any]) -> dict[str, str]:
    """Return alert recommendations as an immutable identifier catalog."""

    return {
        f"action_{index}": str(action)
        for index, action in enumerate(context["alert"].get("recommended_actions", []))
        if str(action).strip()
    }


def default_selection(
    question: AnalystQuestion,
    facts: Mapping[str, str],
    recommendations: Mapping[str, str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Select deterministic evidence for every supported analyst question."""

    reason_ids = tuple(key for key in facts if key.startswith("reason_"))
    selections = {
        AnalystQuestion.EXECUTIVE_SUMMARY: (
            tuple(
                key for key in ("alert", "location", "resource", "adaptive_state") if key in facts
            ),
            (),
        ),
        AnalystQuestion.WHY_GENERATED: (reason_ids, ()),
        AnalystQuestion.ABNORMAL_BEHAVIORS: (reason_ids, ()),
        AnalystQuestion.HIGH_RISK_SCORE: (
            tuple(key for key in ("alert", "anomaly", *reason_ids[:3]) if key in facts),
            (),
        ),
        AnalystQuestion.CONCEPT_DRIFT: (
            tuple(key for key in ("adaptive_state", "time") if key in facts),
            (),
        ),
        AnalystQuestion.INVESTIGATE_FIRST: (
            tuple(key for key in ("alert", "source", "location", "resource") if key in facts),
            tuple(recommendations),
        ),
    }
    return selections[question]


def validated_ids(values: Sequence[str], catalog: Mapping[str, str]) -> tuple[str, ...]:
    """Discard provider output that is not an exact supplied identifier."""

    return tuple(dict.fromkeys(value for value in values if value in catalog))


def render_answer(
    fact_ids: Sequence[str],
    action_ids: Sequence[str],
    facts: Mapping[str, str],
    recommendations: Mapping[str, str],
) -> str:
    """Render selected evidence without accepting provider-authored prose."""

    sentences = [facts[key] for key in fact_ids if key in facts]
    actions = [recommendations[key] for key in action_ids if key in recommendations]
    if actions:
        sentences.append("Recommended actions: " + "; ".join(actions))
    return " ".join(sentences) if sentences else INSUFFICIENT_EVIDENCE


def executive_summary(evidence: InvestigationEvidence) -> str:
    """Return a concise deterministic summary of the alert."""

    return (
        f"{evidence.severity.value.upper()} RISK ALERT: {evidence.entity} was flagged for "
        f"{evidence.attack_type.value.replace('_', ' ')} with risk "
        f"{evidence.risk_score:.1f}/100 and confidence {evidence.confidence:.0%}."
    )


def behavioral_deviations(evidence: InvestigationEvidence) -> tuple[str, ...]:
    """Return observable deviations without adding inferred facts."""

    values = tuple(
        reason.summary
        for reason in evidence.reasons
        if reason.feature not in {"rule_score", "resource_sensitivity"}
    )
    return values or (INSUFFICIENT_EVIDENCE,)


def timeline(
    context: Mapping[str, Any],
    evidence: InvestigationEvidence,
) -> tuple[InvestigationTimelineEvent, ...]:
    """Build a short evidence-backed investigation timeline."""

    events: list[InvestigationTimelineEvent] = []
    previous = context.get("previous_event")
    if previous:
        previous_time = as_aware_datetime(str(previous["timestamp"]))
        previous_title = (
            "Normal Login"
            if previous.get("auth_outcome") == "success" and not previous.get("alerted")
            else "Previous Login"
        )
        events.append(
            InvestigationTimelineEvent(
                title=previous_title,
                timestamp=previous_time,
                detail=f"Previous activity for {evidence.entity}.",
            )
        )
    events.append(
        InvestigationTimelineEvent(
            title="Suspicious Login",
            timestamp=evidence.timestamp,
            detail=f"{evidence.attack_type.value.replace('_', ' ').title()} evidence observed.",
        )
    )
    if evidence.known_device is False and evidence.device_fingerprint:
        events.append(
            InvestigationTimelineEvent(
                title="Device Change",
                timestamp=evidence.timestamp,
                detail=f"Unseen device {evidence.device_fingerprint} was observed.",
            )
        )
    events.append(
        InvestigationTimelineEvent(
            title="Alert Generated",
            timestamp=as_aware_datetime(str(context["alert"]["updated_at"])),
            detail=f"Risk score {evidence.risk_score:.1f}/100 assigned.",
        )
    )
    return tuple(events)
