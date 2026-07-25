"""Authentication-focused attack strategies."""

import random

from behavioral_security.core.enums import AuthenticationMethod, AuthenticationOutcome
from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.attacks.base import mutate_event
from behavioral_security.generator.models import BehaviorProfile
from behavioral_security.generator.planner import AttackDirective


class BruteForceAttack:
    """Create repeated password failures with a final compromise attempt."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Mutate an event into one step of a reproducible brute-force campaign."""

        del profile, last_event, rng
        outcome = (
            AuthenticationOutcome.SUCCESS
            if directive.step == directive.total_steps - 1
            else AuthenticationOutcome.FAILURE
        )
        return mutate_event(
            event,
            {
                "source_ip": "198.51.100.24",
                "auth_method": AuthenticationMethod.PASSWORD,
                "auth_outcome": outcome,
                "session_duration": 12.0 if outcome is AuthenticationOutcome.SUCCESS else 1.0,
                "command_sequence": (
                    ("authenticate", "establish_session")
                    if outcome is AuthenticationOutcome.SUCCESS
                    else ("authenticate",)
                ),
                "device_fingerprint": f"unknown-bruteforce-{directive.campaign_id.hex[:12]}",
                "bytes_transferred": 0,
            },
        )


class CredentialStuffingAttack:
    """Reuse one external source and device across many user identities."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Mutate an event into a credential-stuffing authentication attempt."""

        del profile, last_event, rng
        return mutate_event(
            event,
            {
                "source_ip": "203.0.113.44",
                "auth_method": AuthenticationMethod.PASSWORD,
                "auth_outcome": AuthenticationOutcome.FAILURE,
                "session_duration": 1.0,
                "command_sequence": ("authenticate",),
                "device_fingerprint": f"stuffing-client-{directive.campaign_id.hex[:12]}",
                "bytes_transferred": 0,
            },
        )
