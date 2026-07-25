"""Deterministic anomaly-slot and campaign planning."""

import random
from dataclasses import dataclass
from uuid import UUID

from behavioral_security.core.enums import AttackType
from behavioral_security.generator.config import MINIMUM_ATTACK_EVENTS, GeneratorConfig
from behavioral_security.generator.organization import deterministic_uuid


@dataclass(frozen=True, slots=True)
class AttackDirective:
    """One planned anomalous event within a campaign."""

    attack_type: AttackType
    campaign_id: UUID
    step: int
    total_steps: int


def plan_attacks(
    config: GeneratorConfig,
    rng: random.Random,
) -> dict[int, AttackDirective]:
    """Assign exact post-warmup event positions to weighted attack campaigns."""

    counts = _allocate_attack_counts(config)
    labels = [attack_type for attack_type, count in counts.items() for _ in range(count)]
    rng.shuffle(labels)
    warmup_events = round(config.event_count * config.warmup_fraction)
    positions = sorted(
        rng.sample(range(warmup_events, config.event_count), config.anomaly_event_count)
    )
    campaign_ids = {
        attack_type: deterministic_uuid(rng)
        for attack_type in sorted(counts, key=lambda item: item.value)
    }
    next_step = dict.fromkeys(counts, 0)
    plan: dict[int, AttackDirective] = {}
    for position, attack_type in zip(positions, labels, strict=True):
        step = next_step[attack_type]
        plan[position] = AttackDirective(
            attack_type=attack_type,
            campaign_id=campaign_ids[attack_type],
            step=step,
            total_steps=counts[attack_type],
        )
        next_step[attack_type] += 1
    return plan


def _allocate_attack_counts(config: GeneratorConfig) -> dict[AttackType, int]:
    """Allocate anomalies by configured weight while guaranteeing every attack."""

    attacks = sorted(config.attack_weights, key=lambda item: item.value)
    counts = {attack: MINIMUM_ATTACK_EVENTS[attack] for attack in attacks}
    remaining = config.anomaly_event_count - sum(counts.values())
    total_weight = sum(config.attack_weights.values())
    exact_shares = {
        attack: remaining * config.attack_weights[attack] / total_weight for attack in attacks
    }
    for attack in attacks:
        allocated = int(exact_shares[attack])
        counts[attack] += allocated
        remaining -= allocated
    ranked = sorted(
        attacks,
        key=lambda attack: (exact_shares[attack] % 1, attack.value),
        reverse=True,
    )
    for attack in ranked[:remaining]:
        counts[attack] += 1
    return counts
