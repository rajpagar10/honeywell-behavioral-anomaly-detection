"""Resource-access and data-movement attack strategies."""

import random

from behavioral_security.core.enums import ResourceSensitivity
from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.attacks.base import mutate_event
from behavioral_security.generator.catalogs import RARE_SENSITIVE_RESOURCES
from behavioral_security.generator.models import BehaviorProfile
from behavioral_security.generator.planner import AttackDirective


class LateralMovementAttack:
    """Traverse rare privileged systems using remote execution behavior."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Mutate resource and commands into a progressive lateral path."""

        del profile, last_event, rng
        resource = RARE_SENSITIVE_RESOURCES[directive.step % len(RARE_SENSITIVE_RESOURCES)]
        commands = (
            "authenticate",
            "enumerate_network",
            "remote_service",
            f"access_{directive.step + 1}",
        )
        return mutate_event(
            event,
            {
                "resource_accessed": resource,
                "resource_sensitivity": ResourceSensitivity.CRITICAL,
                "command_sequence": commands,
                "destination_ip": f"10.99.0.{directive.step % 200 + 10}",
                "session_duration": event.session_duration * 1.6,
            },
        )


class LowAndSlowExfiltrationAttack:
    """Accumulate moderate transfers from sensitive resources over many events."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Mutate an event into one bounded exfiltration chunk."""

        del profile, last_event, rng
        resource = RARE_SENSITIVE_RESOURCES[(directive.step + 2) % len(RARE_SENSITIVE_RESOURCES)]
        return mutate_event(
            event,
            {
                "resource_accessed": resource,
                "resource_sensitivity": ResourceSensitivity.CRITICAL,
                "command_sequence": ("authenticate", "query", "read_chunk", "compress_chunk"),
                "bytes_transferred": 350_000 + directive.step * 25_000,
                "destination_ip": "192.0.2.220",
            },
        )


class InsiderDriftAttack:
    """Create gradually increasing misuse by an otherwise legitimate user."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Increase resource rarity, transfer volume, and session length by step."""

        del profile, last_event, rng
        progress = (directive.step + 1) / directive.total_steps
        resource = RARE_SENSITIVE_RESOURCES[(directive.step + 1) % len(RARE_SENSITIVE_RESOURCES)]
        return mutate_event(
            event,
            {
                "resource_accessed": resource,
                "resource_sensitivity": ResourceSensitivity.CRITICAL,
                "command_sequence": ("authenticate", "search", "bulk_read", "export"),
                "session_duration": event.session_duration * (1.0 + progress * 2.0),
                "bytes_transferred": round(150_000 + progress * 650_000),
            },
        )
