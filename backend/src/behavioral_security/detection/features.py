"""Sequential behavioral feature engineering."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_address, ip_network
from math import asin, cos, log1p, radians, sin, sqrt
from typing import Any

import pandas as pd

from behavioral_security.core.enums import AuthenticationMethod
from behavioral_security.core.models.profile import EntityProfile
from behavioral_security.profiling.models import ProfileStore

MODEL_FEATURES = (
    "login_hour_deviation",
    "new_device_indicator",
    "new_source_ip_indicator",
    "geo_distance_km",
    "travel_velocity_kph",
    "unusual_resource_score",
    "failed_attempt_frequency",
    "session_duration_deviation",
    "time_since_previous_event",
    "resource_transition_rarity",
    "cumulative_transfer_behavior",
    "entity_history_statistics",
    "historical_failed_rate",
    "authentication_rarity",
    "location_rarity",
    "source_failure_entity_count",
    "critical_resource_indicator",
    "destination_indicator",
    "risky_command_indicator",
    "profile_maturity",
)


@dataclass(slots=True)
class _EntityState:
    """Mutable prior-event state used only during ordered transformation."""

    timestamp: pd.Timestamp
    resource: str
    latitude: float
    longitude: float
    failures: int
    observations: int


def engineer_features(events: pd.DataFrame, profiles: ProfileStore) -> pd.DataFrame:
    """Add profile-deviation and rolling sequence features to ordered events."""

    frame = events.sort_values("timestamp", kind="stable").reset_index(drop=True).copy()
    states: dict[str, _EntityState] = {}
    transfers: dict[str, deque[tuple[pd.Timestamp, int]]] = defaultdict(deque)
    entity_failures: dict[str, deque[pd.Timestamp]] = defaultdict(deque)
    source_failures: dict[str, deque[tuple[pd.Timestamp, str]]] = defaultdict(deque)
    features: list[dict[str, float]] = []
    history_window = timedelta(days=7)
    transfer_window = timedelta(hours=24)

    for row in frame.to_dict(orient="records"):
        timestamp = pd.Timestamp(row["timestamp"])
        entity_id = str(row["entity_id"])
        source_ip = str(row["source_ip"])
        department = None if pd.isna(row["department"]) else str(row["department"])
        profile = profiles.resolve(entity_id, department, str(row["entity_type"]))
        known_entity = entity_id in profiles.entities
        state = states.get(entity_id)
        location = _location(row["geo_location"])
        distance = (
            _haversine_km(state.latitude, state.longitude, location[0], location[1])
            if state
            else 0.0
        )
        elapsed = max(1.0, (timestamp - state.timestamp).total_seconds()) if state else 0.0
        velocity = min(20_000.0, distance / (elapsed / 3600.0)) if state else 0.0
        _expire_timestamps(entity_failures[entity_id], timestamp, history_window)
        _expire_pairs(source_failures[source_ip], timestamp, history_window)
        _expire_pairs(transfers[entity_id], timestamp, transfer_window)
        failed = str(row["auth_outcome"]) == "failure"
        if failed:
            entity_failures[entity_id].append(timestamp)
            source_failures[source_ip].append((timestamp, entity_id))
        transfers[entity_id].append((timestamp, int(row["bytes_transferred"])))
        prior_resource = state.resource if state else None
        features.append(
            {
                "login_hour_deviation": _hour_deviation(timestamp.hour, profile),
                "new_device_indicator": _new_device(row, profile, known_entity),
                "new_source_ip_indicator": _new_source_ip(
                    source_ip, entity_id, profiles, known_entity
                ),
                "external_source_indicator": float(not _is_enterprise_private(source_ip)),
                "geo_distance_km": min(distance, 20_000.0),
                "travel_velocity_kph": velocity,
                "unusual_resource_score": 1.0
                - profile.resource_probabilities.get(str(row["resource_accessed"]), 0.0),
                "failed_attempt_frequency": float(len(entity_failures[entity_id])),
                "session_duration_deviation": _duration_deviation(row, profile),
                "time_since_previous_event": log1p(elapsed),
                "resource_transition_rarity": _transition_rarity(
                    prior_resource, str(row["resource_accessed"]), profile
                ),
                "cumulative_transfer_behavior": log1p(
                    sum(value for _, value in transfers[entity_id]) / 1000.0
                ),
                "entity_history_statistics": log1p(state.observations if state else 0),
                "historical_failed_rate": (
                    state.failures / state.observations if state and state.observations else 0.0
                ),
                "authentication_rarity": 1.0
                - profile.authentication_probabilities.get(
                    AuthenticationMethod(str(row["auth_method"])), 0.0
                ),
                "location_rarity": 1.0
                - profile.geolocation_probabilities.get(_location_key(row["geo_location"]), 0.0),
                "source_failure_entity_count": float(
                    len({value for _, value in source_failures[source_ip]})
                ),
                "critical_resource_indicator": float(
                    str(row["resource_sensitivity"]) == "critical"
                ),
                "destination_indicator": float(not pd.isna(row["destination_ip"])),
                "risky_command_indicator": _risky_command(row["command_sequence"]),
                "profile_maturity": profile.maturity if known_entity else profile.maturity * 0.25,
            }
        )
        states[entity_id] = _EntityState(
            timestamp=timestamp,
            resource=str(row["resource_accessed"]),
            latitude=location[0],
            longitude=location[1],
            failures=(state.failures if state else 0) + int(failed),
            observations=(state.observations if state else 0) + 1,
        )
    return pd.concat([frame, pd.DataFrame(features)], axis=1)


def _hour_deviation(hour: int, profile: EntityProfile) -> float:
    """Measure circular distance from observed normal login hours."""

    hours = tuple(profile.login_hour_probabilities)
    if not hours:
        return 0.0
    distance = min(min(abs(hour - value), 24 - abs(hour - value)) for value in hours)
    return distance / 12.0


def _new_device(row: dict[str, Any], profile: EntityProfile, known_entity: bool) -> float:
    """Return device novelty with conservative cold-start handling."""

    if not known_entity:
        return 0.25
    return float(str(row["device_fingerprint"]) not in profile.known_device_fingerprints)


def _new_source_ip(
    source_ip: str,
    entity_id: str,
    profiles: ProfileStore,
    known_entity: bool,
) -> float:
    """Return source-address novelty with cold-start dampening."""

    if not known_entity:
        return 0.25
    return float(source_ip not in profiles.known_source_ips.get(entity_id, frozenset()))


def _is_enterprise_private(source_ip: str) -> bool:
    """Return whether an address is inside RFC 1918 enterprise space."""

    address = ip_address(source_ip)
    return any(
        address in network
        for network in (
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
        )
    )


def _duration_deviation(row: dict[str, Any], profile: EntityProfile) -> float:
    """Return a clipped robust duration z-score."""

    statistics = profile.session_statistics
    scale = max(statistics.standard_deviation_seconds, statistics.mean_seconds * 0.1, 1.0)
    return min(10.0, abs(float(row["session_duration"]) - statistics.mean_seconds) / scale)


def _transition_rarity(
    source: str | None,
    destination: str,
    profile: EntityProfile,
) -> float:
    """Return one minus the learned resource-transition probability."""

    if source is None:
        return 0.0
    probability = profile.resource_transition_probabilities.get(source, {}).get(destination, 0.0)
    return 1.0 - probability


def _risky_command(commands: object) -> float:
    """Identify command sequences associated with privilege traversal or export."""

    if not isinstance(commands, list):
        return 0.0
    risky = {"remote_service", "enumerate_network", "compress_chunk", "bulk_read", "export"}
    return min(1.0, len(risky.intersection(map(str, commands))) / 2.0)


def _location(value: object) -> tuple[float, float]:
    """Extract latitude and longitude from a decoded geolocation."""

    if not isinstance(value, dict):
        raise ValueError("geolocation must be a decoded mapping")
    return float(value["latitude"]), float(value["longitude"])


def _location_key(value: object) -> str:
    """Create the key used by behavioral geolocation probabilities."""

    if not isinstance(value, dict):
        raise ValueError("geolocation must be a decoded mapping")
    return f"{value['country_code']}:{value['city']}"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two coordinates."""

    earth_radius_km = 6371.0088
    latitude_delta = radians(lat2 - lat1)
    longitude_delta = radians(lon2 - lon1)
    term = sin(latitude_delta / 2) ** 2 + (
        cos(radians(lat1)) * cos(radians(lat2)) * sin(longitude_delta / 2) ** 2
    )
    return earth_radius_km * 2 * asin(sqrt(term))


def _expire_timestamps(
    values: deque[pd.Timestamp],
    now: pd.Timestamp,
    window: timedelta,
) -> None:
    """Remove timestamp entries outside the rolling window."""

    while values and now - values[0] > window:
        values.popleft()


def _expire_pairs(
    values: deque[tuple[pd.Timestamp, Any]],
    now: pd.Timestamp,
    window: timedelta,
) -> None:
    """Remove timestamped values outside the rolling window."""

    while values and now - values[0][0] > window:
        values.popleft()
