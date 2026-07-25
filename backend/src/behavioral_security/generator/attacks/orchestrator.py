"""Campaign target selection and attack strategy orchestration."""

import random
from collections.abc import Mapping

from behavioral_security.core.enums import AttackType, EntityType
from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.attacks.access import (
    InsiderDriftAttack,
    LateralMovementAttack,
    LowAndSlowExfiltrationAttack,
)
from behavioral_security.generator.attacks.authentication import (
    BruteForceAttack,
    CredentialStuffingAttack,
)
from behavioral_security.generator.attacks.base import AttackStrategy
from behavioral_security.generator.attacks.mobility import (
    DeviceSpoofingAttack,
    ImpossibleTravelAttack,
)
from behavioral_security.generator.models import BehaviorProfile
from behavioral_security.generator.planner import AttackDirective


class AttackOrchestrator:
    """Own attack campaign targets and dispatch event mutations."""

    def __init__(
        self,
        profiles: tuple[BehaviorProfile, ...],
        rng: random.Random,
    ) -> None:
        """Select reproducible campaign targets and initialize all strategies."""

        self._rng = rng
        self._profiles = {profile.entity_id: profile for profile in profiles}
        self._users = tuple(
            profile
            for profile in profiles
            if profile.entity_type is EntityType.USER and not profile.cold_start
        )
        if not self._users:
            raise ValueError("at least one established user is required for attack campaigns")
        lateral_candidates = tuple(
            profile
            for profile in profiles
            if profile.entity_type in {EntityType.USER, EntityType.SERVICE_ACCOUNT}
            and not profile.cold_start
        )
        self._fixed_targets = {
            AttackType.BRUTE_FORCE: rng.choice(self._users),
            AttackType.LATERAL_MOVEMENT: rng.choice(lateral_candidates),
            AttackType.LOW_AND_SLOW_EXFILTRATION: rng.choice(self._users),
            AttackType.INSIDER_DRIFT: rng.choice(self._users),
        }
        self._strategies: Mapping[AttackType, AttackStrategy] = {
            AttackType.BRUTE_FORCE: BruteForceAttack(),
            AttackType.IMPOSSIBLE_TRAVEL: ImpossibleTravelAttack(),
            AttackType.CREDENTIAL_STUFFING: CredentialStuffingAttack(),
            AttackType.LATERAL_MOVEMENT: LateralMovementAttack(),
            AttackType.DEVICE_SPOOFING: DeviceSpoofingAttack(),
            AttackType.LOW_AND_SLOW_EXFILTRATION: LowAndSlowExfiltrationAttack(),
            AttackType.INSIDER_DRIFT: InsiderDriftAttack(),
        }

    def profile_for(
        self,
        directive: AttackDirective,
        fallback: BehaviorProfile,
        last_events: Mapping[str, AccessEvent],
    ) -> BehaviorProfile:
        """Return the campaign-consistent entity profile for an attack step."""

        if directive.attack_type is AttackType.CREDENTIAL_STUFFING:
            return self._users[directive.step % len(self._users)]
        if directive.attack_type is AttackType.IMPOSSIBLE_TRAVEL:
            recent_users = [
                event
                for entity_id, event in last_events.items()
                if self._profiles[entity_id].entity_type is EntityType.USER
            ]
            if recent_users:
                latest = max(recent_users, key=lambda event: event.timestamp)
                return self._profiles[latest.entity_id]
            return self._users[0]
        fixed = self._fixed_targets.get(directive.attack_type)
        return fixed or fallback

    def apply(
        self,
        directive: AttackDirective,
        event: AccessEvent,
        profile: BehaviorProfile,
        last_event: AccessEvent | None,
    ) -> AccessEvent:
        """Apply the strategy registered for a planned attack directive."""

        strategy = self._strategies[directive.attack_type]
        return strategy.apply(event, profile, directive, last_event, self._rng)
