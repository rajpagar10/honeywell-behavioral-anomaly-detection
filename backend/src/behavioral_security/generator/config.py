"""Validated synthetic dataset configuration."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Self

import yaml
from pydantic import AwareDatetime, Field, field_validator, model_validator

from behavioral_security.core.enums import AttackType
from behavioral_security.core.models.common import Probability, StrictModel

_REQUIRED_ATTACKS = frozenset(attack for attack in AttackType if attack is not AttackType.NORMAL)
MINIMUM_ATTACK_EVENTS = {
    AttackType.BRUTE_FORCE: 3,
    AttackType.CREDENTIAL_STUFFING: 3,
    AttackType.IMPOSSIBLE_TRAVEL: 1,
    AttackType.LATERAL_MOVEMENT: 1,
    AttackType.DEVICE_SPOOFING: 1,
    AttackType.LOW_AND_SLOW_EXFILTRATION: 1,
    AttackType.INSIDER_DRIFT: 1,
}


def _default_attack_weights() -> dict[AttackType, float]:
    """Return equal weights for every required attack."""

    return {attack: 1.0 for attack in _REQUIRED_ATTACKS}


class PopulationConfig(StrictModel):
    """Entity counts represented in a synthetic organization."""

    users: Annotated[int, Field(ge=1)] = 60
    service_accounts: Annotated[int, Field(ge=1)] = 12
    iot_devices: Annotated[int, Field(ge=1)] = 24
    edge_devices: Annotated[int, Field(ge=1)] = 12

    @property
    def total(self) -> int:
        """Return the total configured entity count."""

        return self.users + self.service_accounts + self.iot_devices + self.edge_devices


class GeneratorConfig(StrictModel):
    """Complete reproducible event-generation configuration."""

    dataset_name: Annotated[str, Field(min_length=1, max_length=128)]
    seed: Annotated[int, Field(ge=0, le=2_147_483_647)] = 1729
    event_count: Annotated[int, Field(ge=250)]
    anomaly_rate: Annotated[float, Field(ge=0.005, le=0.03)]
    start_at: AwareDatetime
    duration_hours: Annotated[int, Field(ge=24, le=8760)] = 168
    population: PopulationConfig = PopulationConfig()
    cold_start_fraction: Annotated[float, Field(ge=0.0, le=0.5)] = 0.1
    cold_start_activation_fraction: Annotated[float, Field(ge=0.3, le=0.9)] = 0.65
    drift_fraction: Annotated[float, Field(ge=0.0, le=0.5)] = 0.15
    drift_start_fraction: Annotated[float, Field(ge=0.3, le=0.9)] = 0.55
    warmup_fraction: Annotated[float, Field(ge=0.1, le=0.6)] = 0.2
    normal_failure_rate: Probability = 0.012
    attack_weights: dict[AttackType, Annotated[float, Field(gt=0.0)]] = Field(
        default_factory=_default_attack_weights
    )

    @field_validator("start_at")
    @classmethod
    def normalize_start_at(cls, value: datetime) -> datetime:
        """Normalize the simulation start to UTC."""

        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_attack_capacity(self) -> Self:
        """Require enough anomaly events and post-warmup positions for all attacks."""

        attacks = set(self.attack_weights)
        if attacks != _REQUIRED_ATTACKS:
            raise ValueError("attack_weights must contain every required attack exactly once")
        anomaly_count = self.anomaly_event_count
        minimum_anomalies = sum(MINIMUM_ATTACK_EVENTS.values())
        if anomaly_count < minimum_anomalies:
            raise ValueError(
                "event_count and anomaly_rate must produce at least "
                f"{minimum_anomalies} anomalies for complete campaigns"
            )
        warmup_events = round(self.event_count * self.warmup_fraction)
        if anomaly_count > self.event_count - warmup_events:
            raise ValueError("not enough post-warmup positions for configured anomalies")
        return self

    @property
    def anomaly_event_count(self) -> int:
        """Return the exact number of anomalous events to inject."""

        return round(self.event_count * self.anomaly_rate)


def load_generator_config(path: Path) -> GeneratorConfig:
    """Load and validate a generator YAML configuration."""

    if not path.is_file():
        raise FileNotFoundError(f"generator configuration does not exist: {path}")
    with path.open(encoding="utf-8") as stream:
        content = yaml.safe_load(stream)
    if not isinstance(content, dict):
        raise ValueError("generator configuration root must be a mapping")
    return GeneratorConfig.model_validate(content)
