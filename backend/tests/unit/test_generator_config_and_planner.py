"""Generator configuration, organization, and attack planning tests."""

import random
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from behavioral_security.core.enums import AttackType, EntityType
from behavioral_security.generator.config import GeneratorConfig, PopulationConfig
from behavioral_security.generator.organization import build_organization
from behavioral_security.generator.planner import plan_attacks

from ..factories import make_generator_config


@pytest.mark.parametrize("rate", [0.0049, 0.0301])
def test_anomaly_rate_outside_required_range_is_rejected(rate: float) -> None:
    with pytest.raises(ValidationError):
        GeneratorConfig(
            dataset_name="invalid",
            event_count=2000,
            anomaly_rate=rate,
            start_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_configuration_requires_capacity_for_every_attack() -> None:
    with pytest.raises(ValidationError, match="at least 11 anomalies"):
        GeneratorConfig(
            dataset_name="too_small",
            event_count=250,
            anomaly_rate=0.005,
            start_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_attack_plan_is_exact_balanced_and_after_warmup() -> None:
    config = make_generator_config()
    plan = plan_attacks(config, random.Random(config.seed))

    assert len(plan) == config.anomaly_event_count
    assert min(plan) >= round(config.event_count * config.warmup_fraction)
    assert {directive.attack_type for directive in plan.values()} == {
        attack for attack in AttackType if attack is not AttackType.NORMAL
    }
    counts = {
        attack: sum(directive.attack_type is attack for directive in plan.values())
        for attack in AttackType
        if attack is not AttackType.NORMAL
    }
    assert counts[AttackType.BRUTE_FORCE] >= 3
    assert counts[AttackType.CREDENTIAL_STUFFING] >= 3
    assert all(count >= 1 for count in counts.values())


def test_organization_has_all_entity_types_and_lifecycle_cohorts() -> None:
    config = make_generator_config()
    profiles = build_organization(config, random.Random(config.seed))

    assert len(profiles) == config.population.total
    assert {profile.entity_type for profile in profiles} == set(EntityType)
    assert sum(profile.cold_start for profile in profiles) == round(
        len(profiles) * config.cold_start_fraction
    )
    assert sum(profile.drift_start is not None for profile in profiles) == round(
        len(profiles) * config.drift_fraction
    )
    assert len({profile.entity_id for profile in profiles}) == len(profiles)


def test_population_total() -> None:
    population = PopulationConfig(users=2, service_accounts=3, iot_devices=4, edge_devices=5)

    assert population.total == 14
