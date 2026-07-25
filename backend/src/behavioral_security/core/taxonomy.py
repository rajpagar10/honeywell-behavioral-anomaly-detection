"""Canonical attack metadata used across generation, detection, and presentation."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from behavioral_security.core.enums import AttackType, Severity


@dataclass(frozen=True, slots=True)
class AttackDefinition:
    """Human-facing metadata for one attack category."""

    display_name: str
    description: str
    default_severity: Severity


ATTACK_TAXONOMY: Final[Mapping[AttackType, AttackDefinition]] = MappingProxyType(
    {
        AttackType.NORMAL: AttackDefinition(
            display_name="Normal",
            description="Activity consistent with the applicable behavioral baseline.",
            default_severity=Severity.INFO,
        ),
        AttackType.BRUTE_FORCE: AttackDefinition(
            display_name="Brute Force",
            description="Concentrated authentication failures targeting an identity.",
            default_severity=Severity.HIGH,
        ),
        AttackType.IMPOSSIBLE_TRAVEL: AttackDefinition(
            display_name="Impossible Travel",
            description="Geographically distant activity occurring faster than feasible travel.",
            default_severity=Severity.HIGH,
        ),
        AttackType.CREDENTIAL_STUFFING: AttackDefinition(
            display_name="Credential Stuffing",
            description="Coordinated reused-credential attempts across multiple identities.",
            default_severity=Severity.HIGH,
        ),
        AttackType.LATERAL_MOVEMENT: AttackDefinition(
            display_name="Lateral Movement",
            description="Rare traversal across internal resources after initial access.",
            default_severity=Severity.CRITICAL,
        ),
        AttackType.DEVICE_SPOOFING: AttackDefinition(
            display_name="Device Spoofing",
            description="Conflicting device identity evidence associated with an entity.",
            default_severity=Severity.HIGH,
        ),
        AttackType.LOW_AND_SLOW_EXFILTRATION: AttackDefinition(
            display_name="Low-and-Slow Exfiltration",
            description="Sustained, low-volume access consistent with covert data removal.",
            default_severity=Severity.CRITICAL,
        ),
        AttackType.INSIDER_DRIFT: AttackDefinition(
            display_name="Insider Drift",
            description="Gradual deviation toward risky resource and command behavior.",
            default_severity=Severity.HIGH,
        ),
    }
)


def attack_definition(attack_type: AttackType) -> AttackDefinition:
    """Return immutable metadata for an attack type."""

    return ATTACK_TAXONOMY[attack_type]
