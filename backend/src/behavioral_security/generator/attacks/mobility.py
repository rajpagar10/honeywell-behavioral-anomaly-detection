"""Geography and device identity attack strategies."""

import random

from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.attacks.base import mutate_event
from behavioral_security.generator.catalogs import LOCATIONS
from behavioral_security.generator.models import BehaviorProfile
from behavioral_security.generator.planner import AttackDirective


class ImpossibleTravelAttack:
    """Move activity to a geographically distant location within the event stream."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Select a location far from the entity's immediately preceding event."""

        del profile, directive, rng
        origin = last_event.geo_location if last_event is not None else event.geo_location
        destination = max(
            LOCATIONS,
            key=lambda location: (
                (location.latitude - origin.latitude) ** 2
                + (location.longitude - origin.longitude) ** 2
            ),
        )
        return mutate_event(
            event,
            {
                "geo_location": destination,
                "source_ip": "203.0.113.88",
            },
        )


class DeviceSpoofingAttack:
    """Replace a known device identity with campaign-consistent spoofed evidence."""

    def apply(
        self,
        event: AccessEvent,
        profile: BehaviorProfile,
        directive: AttackDirective,
        last_event: AccessEvent | None,
        rng: random.Random,
    ) -> AccessEvent:
        """Mutate a device fingerprint while preserving other context."""

        del profile, last_event, rng
        return mutate_event(
            event,
            {
                "device_fingerprint": f"spoofed-device-{directive.campaign_id.hex[:16]}",
                "source_ip": "198.51.100.91",
            },
        )
