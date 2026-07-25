"""Normal event generation from stable entity behavior profiles."""

import random
from datetime import datetime, timedelta
from uuid import UUID

from behavioral_security.core.enums import (
    AuthenticationOutcome,
    EntityType,
    ResourceSensitivity,
)
from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.models import BehaviorProfile


class NormalEventFactory:
    """Generate behavior consistent with an entity profile and lifecycle phase."""

    def __init__(self, config: GeneratorConfig, rng: random.Random) -> None:
        """Store deterministic generation dependencies."""

        self._config = config
        self._rng = rng

    def create(
        self,
        profile: BehaviorProfile,
        timestamp: datetime,
        event_id: UUID,
    ) -> AccessEvent:
        """Create one valid operational event without a ground-truth label."""

        drift_progress = _drift_progress(profile, timestamp, self._config)
        drifting = drift_progress > 0.0
        use_drift_resource = drifting and self._rng.random() < drift_progress
        resources = (
            profile.drift_resources
            if use_drift_resource and profile.drift_resources
            else profile.common_resources
        )
        resource = self._rng.choice(resources)
        use_drift_device = (
            drifting
            and profile.drift_device is not None
            and self._rng.random() < drift_progress * 0.65
        )
        device = (
            profile.drift_device if use_drift_device else self._rng.choice(profile.known_devices)
        )
        duration = max(
            1.0,
            self._rng.gauss(
                profile.mean_session_seconds,
                profile.session_stddev_seconds,
            ),
        )
        auth_outcome = (
            AuthenticationOutcome.FAILURE
            if self._rng.random() < self._config.normal_failure_rate
            else AuthenticationOutcome.SUCCESS
        )
        base_commands = profile.command_templates["default"]
        command_sequence = (
            base_commands if auth_outcome is AuthenticationOutcome.SUCCESS else (base_commands[0],)
        )
        return AccessEvent(
            event_id=event_id,
            entity_id=profile.entity_id,
            entity_type=profile.entity_type,
            timestamp=timestamp,
            source_ip=self._rng.choice(profile.source_ips),
            geo_location=self._rng.choice(profile.allowed_locations),
            resource_accessed=resource,
            auth_method=self._rng.choice(profile.authentication_methods),
            auth_outcome=auth_outcome,
            session_duration=round(duration, 3),
            command_sequence=command_sequence,
            device_fingerprint=device,
            department=profile.department,
            resource_sensitivity=_resource_sensitivity(resource),
            bytes_transferred=_normal_transfer_bytes(profile.entity_type, self._rng),
            destination_ip=None,
            extensions={
                "profile_id": str(profile.profile_id),
                "cold_start_entity": profile.cold_start,
                "behavior_phase": "concept_drift" if drifting else "stable",
                "drift_progress": round(drift_progress, 4),
            },
        )


def profile_is_active(profile: BehaviorProfile, timestamp: datetime) -> bool:
    """Return whether an entity exists and is behaviorally active at a timestamp."""

    if timestamp < profile.active_after:
        return False
    hour = timestamp.hour
    if profile.entity_type is not EntityType.USER:
        return True
    if profile.drift_start is not None and timestamp >= profile.drift_start:
        shifted = {
            (value + profile.drift_login_hour_offset) % 24 for value in profile.normal_login_hours
        }
        return hour in shifted
    return hour in profile.normal_login_hours


def _drift_progress(
    profile: BehaviorProfile,
    timestamp: datetime,
    config: GeneratorConfig,
) -> float:
    """Return gradual legitimate drift progress between zero and one."""

    if profile.drift_start is None or timestamp < profile.drift_start:
        return 0.0
    simulation_end = config.start_at + _duration(config)
    remaining_seconds = (simulation_end - profile.drift_start).total_seconds()
    if remaining_seconds <= 0:
        return 1.0
    return min(1.0, (timestamp - profile.drift_start).total_seconds() / remaining_seconds)


def _duration(config: GeneratorConfig) -> timedelta:
    """Return the configured simulation duration as a timedelta."""

    return timedelta(hours=config.duration_hours)


def _resource_sensitivity(resource: str) -> ResourceSensitivity:
    """Classify resource sensitivity from the fictional enterprise catalog."""

    if any(
        token in resource for token in ("vault", "domain-controller", "payroll", "design-archive")
    ):
        return ResourceSensitivity.CRITICAL
    if any(token in resource for token in ("erp", "secrets", "identity", "site-controller")):
        return ResourceSensitivity.HIGH
    if resource.startswith("shared/"):
        return ResourceSensitivity.LOW
    return ResourceSensitivity.MEDIUM


def _normal_transfer_bytes(entity_type: EntityType, rng: random.Random) -> int:
    """Generate bounded normal transfer volume by entity category."""

    ranges = {
        EntityType.USER: (2_000, 120_000),
        EntityType.SERVICE_ACCOUNT: (1_000, 80_000),
        EntityType.IOT_DEVICE: (250, 8_000),
        EntityType.EDGE_DEVICE: (2_000, 40_000),
    }
    lower, upper = ranges[entity_type]
    return rng.randint(lower, upper)
