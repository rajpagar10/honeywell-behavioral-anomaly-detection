"""Deterministic explainable risk scoring and alert generation."""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final
from uuid import NAMESPACE_URL, UUID, uuid5

from behavioral_security.core.enums import (
    AttackType,
    EntityType,
    EvidenceDirection,
    RiskFactorName,
    Severity,
)
from behavioral_security.core.models.alert import ClassifiedAlert
from behavioral_security.core.models.risk import (
    ExplanationReason,
    RiskContribution,
    RiskScoreExplanation,
)
from behavioral_security.core.taxonomy import attack_definition

_WEIGHTS: Final[dict[RiskFactorName, float]] = {
    RiskFactorName.ML_CONFIDENCE: 0.24,
    RiskFactorName.ATTACK_SEVERITY: 0.12,
    RiskFactorName.RULE_CONFIDENCE: 0.15,
    RiskFactorName.BEHAVIORAL_DEVIATION: 0.15,
    RiskFactorName.RESOURCE_SENSITIVITY: 0.10,
    RiskFactorName.DEVICE_TRUST: 0.08,
    RiskFactorName.GEO_TRUST: 0.08,
    RiskFactorName.HISTORICAL_TRUST: 0.08,
}
_SENSITIVITY: Final = {"low": 0.1, "medium": 0.35, "high": 0.7, "critical": 1.0}
_ATTACK_RISK: Final = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}


class RiskPolicy:
    """Convert model, rule, and behavioral evidence into SOC alerts."""

    version = "risk-v1"

    def assess(
        self,
        row: Mapping[str, Any],
        *,
        anomaly_score: float,
        predicted_attack: str,
        classifier_confidence: float,
        rule_score: float,
        drift_status: str,
    ) -> ClassifiedAlert:
        """Create an auditable alert candidate for one event."""

        attack_type = AttackType(predicted_attack)
        maturity = _bounded(float(row["profile_maturity"]))
        cold_start = maturity < 0.35
        normalized = self._factors(
            row,
            anomaly_score,
            attack_type,
            classifier_confidence,
            rule_score,
        )
        components = tuple(
            RiskContribution(
                factor=factor,
                raw_value=value,
                normalized_value=value,
                weight=_WEIGHTS[factor],
                contribution=value * _WEIGHTS[factor] * 100.0,
            )
            for factor, value in normalized.items()
        )
        score = sum(item.contribution for item in components)
        if cold_start:
            score *= 0.82 + 0.18 * maturity
        score = min(100.0, score)
        confidence = _bounded(
            (anomaly_score * 0.45 + classifier_confidence * 0.35 + rule_score * 0.20)
            * (0.6 + 0.4 * maturity)
        )
        reasons = _reasons(row, components)
        event_id = UUID(str(row["event_id"]))
        timestamp = _as_datetime(row["timestamp"])
        severity = _severity(score)
        explanation = RiskScoreExplanation(
            event_id=event_id,
            score=round(score, 4),
            severity=severity,
            confidence=confidence,
            policy_version=self.version,
            profile_maturity=maturity,
            baseline_level="peer" if cold_start else "individual",
            components=components,
            reasons=reasons,
        )
        return ClassifiedAlert(
            alert_id=uuid5(NAMESPACE_URL, f"badp:alert:{event_id}"),
            event_id=event_id,
            entity_id=str(row["entity_id"]),
            entity_type=EntityType(str(row["entity_type"])),
            attack_type=attack_type,
            severity=severity,
            risk_score=round(score, 4),
            classifier_confidence=confidence,
            classifier_version="random-forest-v1",
            correlation_key=f"{row['entity_id']}:{attack_type.value}",
            event_timestamp=timestamp,
            top_contributing_factors=tuple(reason.summary for reason in reasons[:5]),
            human_explanation=_explanation_text(reasons, cold_start, drift_status),
            recommended_actions=_actions(attack_type),
            cold_start=cold_start,
            drift_status=drift_status,
            explanation=explanation,
            created_at=timestamp,
            updated_at=datetime.now(UTC),
        )

    def _factors(
        self,
        row: Mapping[str, Any],
        anomaly_score: float,
        attack_type: AttackType,
        classifier_confidence: float,
        rule_score: float,
    ) -> dict[RiskFactorName, float]:
        """Normalize the required policy inputs."""

        behavioral = _mean(
            float(row["login_hour_deviation"]),
            float(row["unusual_resource_score"]),
            min(1.0, float(row["session_duration_deviation"]) / 5.0),
            float(row["resource_transition_rarity"]),
        )
        geo = max(
            min(1.0, float(row["travel_velocity_kph"]) / 900.0),
            float(row["location_rarity"]),
        )
        history = max(
            float(row["historical_failed_rate"]),
            min(1.0, float(row["failed_attempt_frequency"]) / 5.0),
        )
        default_severity = attack_definition(attack_type).default_severity
        return {
            RiskFactorName.ML_CONFIDENCE: _bounded(anomaly_score),
            RiskFactorName.ATTACK_SEVERITY: _bounded(
                classifier_confidence * _ATTACK_RISK[default_severity]
            ),
            RiskFactorName.RULE_CONFIDENCE: _bounded(rule_score),
            RiskFactorName.BEHAVIORAL_DEVIATION: _bounded(behavioral),
            RiskFactorName.RESOURCE_SENSITIVITY: _SENSITIVITY[str(row["resource_sensitivity"])],
            RiskFactorName.DEVICE_TRUST: _bounded(float(row["new_device_indicator"])),
            RiskFactorName.GEO_TRUST: _bounded(geo),
            RiskFactorName.HISTORICAL_TRUST: _bounded(history),
        }


def _reasons(
    row: Mapping[str, Any],
    components: tuple[RiskContribution, ...],
) -> tuple[ExplanationReason, ...]:
    """Build concise deterministic reasons from observed evidence."""

    values = {item.factor: item.contribution for item in components}
    candidates: list[ExplanationReason] = []
    _append(
        candidates,
        float(row["new_device_indicator"]) >= 0.9,
        "the device fingerprint is unseen",
        "new_device_indicator",
        str(row["device_fingerprint"]),
        "known device",
        values[RiskFactorName.DEVICE_TRUST],
    )
    _append(
        candidates,
        float(row["travel_velocity_kph"]) > 900.0,
        "the calculated travel velocity is physically impossible",
        "travel_velocity_kph",
        f"{float(row['travel_velocity_kph']):.0f} km/h",
        "≤ 900 km/h",
        values[RiskFactorName.GEO_TRUST],
    )
    _append(
        candidates,
        float(row["login_hour_deviation"]) >= 0.25,
        "the login occurred outside normal hours",
        "login_hour_deviation",
        f"{float(row['login_hour_deviation']):.2f}",
        "< 0.25",
        values[RiskFactorName.BEHAVIORAL_DEVIATION],
    )
    _append(
        candidates,
        float(row["unusual_resource_score"]) >= 0.75,
        "the resource is rare for this profile",
        "unusual_resource_score",
        str(row["resource_accessed"]),
        "common resource",
        values[RiskFactorName.BEHAVIORAL_DEVIATION],
    )
    _append(
        candidates,
        float(row["failed_attempt_frequency"]) >= 2.0,
        "recent authentication failures exceed the normal pattern",
        "failed_attempt_frequency",
        str(int(float(row["failed_attempt_frequency"]))),
        "< 2",
        values[RiskFactorName.HISTORICAL_TRUST],
    )
    _append(
        candidates,
        float(row["rule_score"]) >= 0.5,
        f"sequence evidence matched {row['rule_attack_type']}",
        "rule_score",
        f"{float(row['rule_score']):.2f}",
        "0.00",
        values[RiskFactorName.RULE_CONFIDENCE],
    )
    _append(
        candidates,
        str(row["resource_sensitivity"]) == "critical",
        "a critical enterprise resource was accessed",
        "resource_sensitivity",
        "critical",
        "low or medium",
        values[RiskFactorName.RESOURCE_SENSITIVITY],
    )
    if not candidates:
        candidates.append(
            _reason(
                "the combined anomaly score exceeded the behavioral threshold",
                "anomaly_score",
                f"{float(row['anomaly_score']):.2f}",
                "below model threshold",
                values[RiskFactorName.ML_CONFIDENCE],
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.contribution, reverse=True))


def _append(
    reasons: list[ExplanationReason],
    condition: bool,
    summary: str,
    feature: str,
    observed: str,
    expected: str,
    contribution: float,
) -> None:
    """Append a reason when its deterministic condition holds."""

    if condition:
        reasons.append(_reason(summary, feature, observed, expected, contribution))


def _reason(
    summary: str,
    feature: str,
    observed: str,
    expected: str,
    contribution: float,
) -> ExplanationReason:
    """Create one structured explanation reason."""

    return ExplanationReason(
        summary=summary,
        feature_name=feature,
        observed_value=observed,
        expected_value=expected,
        contribution=min(100.0, contribution),
        direction=EvidenceDirection.INCREASES_RISK,
        evidence_source="risk-policy-v1",
    )


def _explanation_text(
    reasons: tuple[ExplanationReason, ...],
    cold_start: bool,
    drift_status: str,
) -> str:
    """Compose a short analyst-facing explanation."""

    explanation = "Flagged because " + ", ".join(reason.summary for reason in reasons[:3]) + "."
    if cold_start:
        explanation += " Confidence is reduced because a peer baseline is in use."
    if drift_status != "stable":
        explanation += f" Behavioral drift status is {drift_status}."
    return explanation


def _actions(attack_type: AttackType) -> tuple[str, ...]:
    """Return deterministic analyst actions for an attack."""

    specialized = {
        AttackType.BRUTE_FORCE: "Rate-limit authentication attempts.",
        AttackType.CREDENTIAL_STUFFING: "Block the source and require credential reset.",
        AttackType.IMPOSSIBLE_TRAVEL: "Revoke sessions and verify both locations.",
        AttackType.LATERAL_MOVEMENT: "Isolate the source host and inspect remote access.",
        AttackType.DEVICE_SPOOFING: "Challenge the device and rotate device credentials.",
        AttackType.LOW_AND_SLOW_EXFILTRATION: "Restrict egress and preserve transfer logs.",
        AttackType.INSIDER_DRIFT: "Review access justification with the data owner.",
        AttackType.NORMAL: "Monitor for correlated activity.",
    }[attack_type]
    return (
        specialized,
        "Validate the activity with the entity owner.",
        "Review adjacent events.",
    )


def _severity(score: float) -> Severity:
    """Map a score to a SOC severity band."""

    if score >= 85.0:
        return Severity.CRITICAL
    if score >= 70.0:
        return Severity.HIGH
    if score >= 55.0:
        return Severity.MEDIUM
    if score >= 40.0:
        return Severity.LOW
    return Severity.INFO


def _bounded(value: float) -> float:
    """Clamp a value to the probability interval."""

    return min(1.0, max(0.0, value))


def _mean(*values: float) -> float:
    """Return the arithmetic mean."""

    return sum(values) / len(values)


def _as_datetime(value: object) -> datetime:
    """Normalize a pandas or native timestamp to UTC."""

    converted = getattr(value, "to_pydatetime", lambda: value)()
    if not isinstance(converted, datetime):
        raise ValueError("event timestamp must be datetime-like")
    return converted.astimezone(UTC)
