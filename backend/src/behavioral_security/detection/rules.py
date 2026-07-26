"""Deterministic attack rules over sequential engineered behavior."""

from typing import Any

import pandas as pd

from behavioral_security.core.enums import AttackType


def apply_sequence_rules(features: pd.DataFrame) -> pd.DataFrame:
    """Return highest-confidence rule evidence for each ordered event."""

    results = [_evaluate(row) for row in features.to_dict(orient="records")]
    return pd.DataFrame(results, index=features.index)


def _evaluate(row: dict[str, Any]) -> dict[str, object]:
    """Evaluate all deterministic scenario rules for one event."""

    candidates: list[tuple[AttackType, float]] = []
    commands = {str(value) for value in row["command_sequence"]}
    failed = str(row["auth_outcome"]) == "failure"
    if failed and float(row["source_failure_entity_count"]) >= 3:
        candidates.append((AttackType.CREDENTIAL_STUFFING, 0.99))
    if (
        str(row["auth_method"]) == "password"
        and float(row["new_device_indicator"]) >= 1.0
        and float(row["new_source_ip_indicator"]) >= 1.0
        and float(row["failed_attempt_frequency"]) >= 2
    ):
        candidates.append((AttackType.BRUTE_FORCE, 0.98))
    if (
        float(row["travel_velocity_kph"]) > 900.0
        and float(row["geo_distance_km"]) > 500.0
        and float(row["new_source_ip_indicator"]) >= 1.0
    ):
        candidates.append((AttackType.IMPOSSIBLE_TRAVEL, 0.99))
    if {"enumerate_network", "remote_service"}.issubset(commands) and float(
        row["destination_indicator"]
    ) == 1.0:
        candidates.append((AttackType.LATERAL_MOVEMENT, 0.99))
    if (
        "compress_chunk" in commands
        and int(row["bytes_transferred"]) >= 300_000
        and float(row["destination_indicator"]) == 1.0
    ):
        candidates.append((AttackType.LOW_AND_SLOW_EXFILTRATION, 0.98))
    if {"bulk_read", "export"}.issubset(commands):
        candidates.append((AttackType.INSIDER_DRIFT, 0.98))
    if (
        float(row["new_device_indicator"]) >= 0.25
        and float(row["new_source_ip_indicator"]) >= 0.25
        and float(row["external_source_indicator"]) == 1.0
        and float(row["profile_maturity"]) >= 0.15
        and not failed
    ):
        candidates.append((AttackType.DEVICE_SPOOFING, 0.98))
    if not candidates:
        return {"rule_attack_type": AttackType.NORMAL.value, "rule_score": 0.0}
    attack_type, score = max(candidates, key=lambda item: item[1])
    return {"rule_attack_type": attack_type.value, "rule_score": score}
