"""Dataset quality and attack-scenario invariant validation."""

from collections import Counter, defaultdict
from math import asin, cos, radians, sin, sqrt

from behavioral_security.core.enums import (
    AttackType,
    AuthenticationOutcome,
    EntityType,
)
from behavioral_security.core.models.access_event import AccessEvent
from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.models import (
    GeneratedDataset,
    GenerationSummary,
)

_REQUIRED_ATTACKS = frozenset(attack for attack in AttackType if attack is not AttackType.NORMAL)


class DatasetValidationError(ValueError):
    """Raised when generated output violates one or more quality invariants."""

    def __init__(self, issues: list[str]) -> None:
        """Store all detected issues in one actionable exception."""

        self.issues = tuple(issues)
        super().__init__("; ".join(issues))


def validate_dataset(
    dataset: GeneratedDataset,
    config: GeneratorConfig,
) -> GenerationSummary:
    """Validate schema, separation, prevalence, lifecycle, and attack invariants."""

    issues: list[str] = []
    if len(dataset.events) != config.event_count:
        issues.append("event count does not match configuration")
    if len(dataset.labels) != len(dataset.events):
        issues.append("every event must have exactly one separate label")
    event_ids = [event.event_id for event in dataset.events]
    label_ids = [label.event_id for label in dataset.labels]
    if len(set(event_ids)) != len(event_ids):
        issues.append("event identifiers must be unique")
    if set(event_ids) != set(label_ids):
        issues.append("event and ground-truth identifiers must match")
    if any(
        current.timestamp >= following.timestamp
        for current, following in zip(dataset.events, dataset.events[1:], strict=False)
    ):
        issues.append("events must be strictly ordered by timestamp")
    entity_types = {event.entity_type for event in dataset.events}
    if entity_types != set(EntityType):
        issues.append("all required entity types must appear in events")

    distribution = Counter(label.label for label in dataset.labels)
    if distribution[AttackType.NORMAL] + config.anomaly_event_count != config.event_count:
        issues.append("normal and anomaly counts do not reconcile")
    actual_anomalies = config.event_count - distribution[AttackType.NORMAL]
    if actual_anomalies != config.anomaly_event_count:
        issues.append("anomaly count does not match configured rate")
    observed_attacks = set(distribution) - {AttackType.NORMAL}
    if observed_attacks != _REQUIRED_ATTACKS:
        issues.append("every required attack must be represented")
    _validate_profile_lifecycle(dataset, issues)
    _validate_attack_invariants(dataset, issues)
    if issues:
        raise DatasetValidationError(issues)
    return _build_summary(dataset, config, distribution)


def _validate_profile_lifecycle(
    dataset: GeneratedDataset,
    issues: list[str],
) -> None:
    """Validate cold-start activation and legitimate concept-drift coverage."""

    profiles = {profile.entity_id: profile for profile in dataset.profiles}
    for event in dataset.events:
        profile = profiles[event.entity_id]
        if event.timestamp < profile.active_after:
            issues.append(f"cold-start entity emitted before activation: {event.entity_id}")
            break
    if any(profile.drift_start is not None for profile in dataset.profiles):
        drifting_normal = any(
            event.extensions.get("behavior_phase") == "concept_drift"
            and label.label is AttackType.NORMAL
            for event, label in zip(dataset.events, dataset.labels, strict=True)
        )
        if not drifting_normal:
            issues.append("concept-drift entities produced no legitimate drift events")


def _validate_attack_invariants(
    dataset: GeneratedDataset,
    issues: list[str],
) -> None:
    """Validate observable behavior for every attack family."""

    events_by_attack: dict[AttackType, list[AccessEvent]] = defaultdict(list)
    labels_by_id = {label.event_id: label for label in dataset.labels}
    profiles = {profile.entity_id: profile for profile in dataset.profiles}
    for event in dataset.events:
        label = labels_by_id[event.event_id]
        if label.label is not AttackType.NORMAL:
            events_by_attack[label.label].append(event)

    brute_events = events_by_attack[AttackType.BRUTE_FORCE]
    if sum(event.auth_outcome is AuthenticationOutcome.FAILURE for event in brute_events) < max(
        1, len(brute_events) - 1
    ):
        issues.append("brute-force campaign lacks repeated authentication failures")

    stuffing_events = events_by_attack[AttackType.CREDENTIAL_STUFFING]
    if len({str(event.source_ip) for event in stuffing_events}) != 1:
        issues.append("credential-stuffing campaign must share one source")
    if len({event.entity_id for event in stuffing_events}) < min(2, len(stuffing_events)):
        issues.append("credential-stuffing campaign must target multiple identities")

    lateral_events = events_by_attack[AttackType.LATERAL_MOVEMENT]
    if any(
        event.resource_accessed in profiles[event.entity_id].common_resources
        for event in lateral_events
    ):
        issues.append("lateral-movement resources must be outside normal profiles")

    spoof_events = events_by_attack[AttackType.DEVICE_SPOOFING]
    if any(
        event.device_fingerprint in profiles[event.entity_id].known_devices
        for event in spoof_events
    ):
        issues.append("device-spoofing fingerprints must be unknown")

    exfil_events = events_by_attack[AttackType.LOW_AND_SLOW_EXFILTRATION]
    if any(event.bytes_transferred < 300_000 for event in exfil_events):
        issues.append("exfiltration chunks must exceed the configured normal range")

    insider_events = events_by_attack[AttackType.INSIDER_DRIFT]
    if any(
        event.resource_accessed in profiles[event.entity_id].common_resources
        for event in insider_events
    ):
        issues.append("insider-drift resources must depart from the normal profile")

    impossible_ids = {
        label.event_id for label in dataset.labels if label.label is AttackType.IMPOSSIBLE_TRAVEL
    }
    last_by_entity: dict[str, AccessEvent] = {}
    velocities: list[float] = []
    for event in dataset.events:
        previous = last_by_entity.get(event.entity_id)
        if event.event_id in impossible_ids and previous is not None:
            elapsed_hours = (event.timestamp - previous.timestamp).total_seconds() / 3600
            if elapsed_hours > 0:
                velocities.append(_distance_km(previous, event) / elapsed_hours)
        last_by_entity[event.entity_id] = event
    if not velocities or min(velocities) <= 900:
        issues.append("impossible-travel events must exceed 900 km/h")


def _distance_km(first: AccessEvent, second: AccessEvent) -> float:
    """Calculate great-circle distance between two event locations."""

    latitude_1 = radians(first.geo_location.latitude)
    latitude_2 = radians(second.geo_location.latitude)
    latitude_delta = latitude_2 - latitude_1
    longitude_delta = radians(second.geo_location.longitude - first.geo_location.longitude)
    haversine = (
        sin(latitude_delta / 2) ** 2
        + cos(latitude_1) * cos(latitude_2) * sin(longitude_delta / 2) ** 2
    )
    return 2 * 6371.0088 * asin(sqrt(haversine))


def _build_summary(
    dataset: GeneratedDataset,
    config: GeneratorConfig,
    distribution: Counter[AttackType],
) -> GenerationSummary:
    """Create a stable manifest summary from validated output."""

    entity_distribution = Counter(event.entity_type.value for event in dataset.events)
    class_distribution = {attack.value: distribution[attack] for attack in AttackType}
    anomaly_count = config.event_count - distribution[AttackType.NORMAL]
    return GenerationSummary(
        dataset_name=config.dataset_name,
        seed=config.seed,
        event_count=config.event_count,
        entity_count=len(dataset.profiles),
        normal_count=distribution[AttackType.NORMAL],
        anomaly_count=anomaly_count,
        anomaly_percentage=round(anomaly_count / config.event_count * 100, 4),
        class_distribution=class_distribution,
        entity_distribution=dict(sorted(entity_distribution.items())),
        cold_start_entities=sum(profile.cold_start for profile in dataset.profiles),
        drift_entities=sum(profile.drift_start is not None for profile in dataset.profiles),
        first_timestamp=dataset.events[0].timestamp,
        last_timestamp=dataset.events[-1].timestamp,
    )
