"""Shared attack strategy contracts and helpers."""

import random
from typing import Protocol

from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.models import BehaviorProfile
from behavioral_security.generator.planner import AttackDirective


class AttackStrategy(Protocol):
    """Mutation contract implemented by every synthetic attack."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Return an anomalous event preserving event identity and time."""

        ...


def mutate_event(event: AccessEvent, updates: dict[str, object]) -> AccessEvent:
    """Apply attack mutations and revalidate the complete event contract."""

    payload = event.model_dump()
    payload.update(updates)
    return AccessEvent.model_validate(payload)
