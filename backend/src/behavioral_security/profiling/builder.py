"""Build robust per-entity and peer behavioral profiles."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import cast
from uuid import NAMESPACE_URL, uuid5

import pandas as pd

from behavioral_security.core.enums import AuthenticationMethod, EntityType
from behavioral_security.core.models.profile import (
    BaselineWeights,
    EntityProfile,
    SessionStatistics,
)
from behavioral_security.profiling.models import ProfileStore


def build_profile_store(events: pd.DataFrame, profile_fraction: float) -> ProfileStore:
    """Build entity profiles from the initial clean behavioral window."""

    cutoff = max(1, round(len(events) * profile_fraction))
    baseline = events.iloc[:cutoff].copy()
    if baseline.empty:
        raise ValueError("at least one event is required to build profiles")
    entities = {
        str(entity_id): _build_profile(
            group,
            entity_id=str(entity_id),
            scope="entity",
            department=_first_text(group["department"]),
            entity_type=str(group["entity_type"].iloc[0]),
        )
        for entity_id, group in baseline.groupby("entity_id", sort=True)
    }
    departments = {
        str(department): _build_profile(
            group,
            entity_id=f"baseline/department/{department}",
            scope="department",
            department=str(department),
            entity_type=str(group["entity_type"].mode().iloc[0]),
        )
        for department, group in baseline.dropna(subset=["department"]).groupby(
            "department", sort=True
        )
    }
    entity_types = {
        str(entity_type): _build_profile(
            group,
            entity_id=f"baseline/type/{entity_type}",
            scope="entity_type",
            department=None,
            entity_type=str(entity_type),
        )
        for entity_type, group in baseline.groupby("entity_type", sort=True)
    }
    organization = _build_profile(
        baseline,
        entity_id="baseline/organization",
        scope="organization",
        department=None,
        entity_type=str(baseline["entity_type"].mode().iloc[0]),
    )
    known_source_ips = {
        str(entity_id): frozenset(group["source_ip"].astype(str).unique())
        for entity_id, group in baseline.groupby("entity_id", sort=True)
    }
    return ProfileStore(
        entities,
        departments,
        entity_types,
        organization,
        known_source_ips,
    )


def _build_profile(
    frame: pd.DataFrame,
    *,
    entity_id: str,
    scope: str,
    department: str | None,
    entity_type: str,
) -> EntityProfile:
    """Create one domain profile from an observed event slice."""

    ordered = frame.sort_values("timestamp", kind="stable")
    size = len(ordered)
    durations = ordered["session_duration"].astype(float)
    transitions: dict[str, Counter[str]] = defaultdict(Counter)
    resources = ordered["resource_accessed"].astype(str).tolist()
    for source, destination in zip(resources, resources[1:], strict=False):
        transitions[source][destination] += 1
    first = _as_datetime(ordered["timestamp"].iloc[0])
    last = _as_datetime(ordered["timestamp"].iloc[-1])
    return EntityProfile(
        profile_id=uuid5(NAMESPACE_URL, f"badp:{scope}:{entity_id}"),
        entity_id=entity_id,
        entity_type=EntityType(entity_type),
        department=department,
        profile_version=1,
        effective_sample_size=float(size),
        maturity=min(1.0, size / 50.0),
        baseline_weights=_baseline_weights(scope),
        login_hour_probabilities=_probabilities(value.hour for value in ordered["timestamp"]),
        resource_probabilities=_probabilities(resources),
        authentication_probabilities={
            AuthenticationMethod(str(key)): value
            for key, value in _probabilities(ordered["auth_method"].astype(str)).items()
        },
        geolocation_probabilities=_probabilities(
            _location_key(value) for value in ordered["geo_location"]
        ),
        known_device_fingerprints=frozenset(ordered["device_fingerprint"].astype(str).unique()),
        session_statistics=SessionStatistics(
            count=size,
            mean_seconds=float(durations.mean()),
            standard_deviation_seconds=float(durations.std(ddof=0)),
            median_seconds=float(durations.median()),
        ),
        failed_login_rate=float((ordered["auth_outcome"] == "failure").mean()),
        resource_transition_probabilities={
            source: _counter_probabilities(counts) for source, counts in transitions.items()
        },
        frequently_accessed_systems=tuple(
            ordered["resource_accessed"].value_counts().head(8).index.astype(str)
        ),
        first_observed_at=first,
        last_observed_at=last,
        updated_at=last,
    )


def _probabilities(values: Iterable[object]) -> dict[object, float]:
    """Convert observed values into a categorical probability distribution."""

    counts = Counter(values)
    total = sum(counts.values())
    return {key: count / total for key, count in counts.items()}


def _counter_probabilities(counts: Counter[str]) -> dict[str, float]:
    """Normalize transition counts."""

    total = sum(counts.values())
    return {key: value / total for key, value in counts.items()}


def _baseline_weights(scope: str) -> BaselineWeights:
    """Return auditable weights describing the resolved profile scope."""

    weights = {
        "entity": (0.7, 0.15, 0.1, 0.05),
        "department": (0.0, 0.7, 0.2, 0.1),
        "entity_type": (0.0, 0.0, 0.8, 0.2),
        "organization": (0.0, 0.0, 0.0, 1.0),
    }[scope]
    return BaselineWeights(
        entity=weights[0],
        department=weights[1],
        entity_type=weights[2],
        organization=weights[3],
    )


def _location_key(value: object) -> str:
    """Create a stable key from an exported geolocation."""

    if not isinstance(value, dict):
        raise ValueError("geolocation must be a decoded mapping")
    return f"{value['country_code']}:{value['city']}"


def _first_text(series: pd.Series) -> str | None:
    """Return the first non-null text value."""

    values = series.dropna()
    return str(values.iloc[0]) if not values.empty else None


def _as_datetime(value: object) -> datetime:
    """Convert a pandas timestamp into a UTC datetime."""

    timestamp = pd.Timestamp(value)
    return cast(datetime, timestamp.to_pydatetime()).astimezone(UTC)
