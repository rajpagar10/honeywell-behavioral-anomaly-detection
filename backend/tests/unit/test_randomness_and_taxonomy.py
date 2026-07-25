"""Randomness and taxonomy tests."""

import random

import pytest

from behavioral_security.core.enums import AttackType, Severity
from behavioral_security.core.randomness import set_global_seed
from behavioral_security.core.taxonomy import ATTACK_TAXONOMY, attack_definition


def test_python_randomness_is_reproducible() -> None:
    first_report = set_global_seed(123, deterministic_torch=False)
    first_value = random.random()
    second_report = set_global_seed(123, deterministic_torch=False)
    second_value = random.random()

    assert first_report.python_seeded
    assert second_report.python_seeded
    assert first_value == second_value


def test_negative_seed_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        set_global_seed(-1)


def test_taxonomy_covers_every_attack_type() -> None:
    assert set(ATTACK_TAXONOMY) == set(AttackType)
    assert attack_definition(AttackType.LATERAL_MOVEMENT).default_severity is Severity.CRITICAL
