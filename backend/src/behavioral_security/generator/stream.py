"""Time-ordered synthetic event stream generation."""

import random
from datetime import datetime, timedelta

from behavioral_security.core.enums import AttackType
from behavioral_security.core.models.access_event import AccessEvent, GroundTruthRecord
from behavioral_security.generator.attacks.orchestrator import AttackOrchestrator
from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.models import GeneratedDataset
from behavioral_security.generator.normal import NormalEventFactory, profile_is_active
from behavioral_security.generator.organization import build_organization, deterministic_uuid
from behavioral_security.generator.planner import plan_attacks


def generate_dataset(config: GeneratorConfig) -> GeneratedDataset:
    """Generate a reproducible sequential dataset from a validated configuration."""

    rng = random.Random(config.seed)
    profiles = build_organization(config, rng)
    attack_plan = plan_attacks(config, rng)
    attack_orchestrator = AttackOrchestrator(profiles, rng)
    normal_factory = NormalEventFactory(config, rng)
    timestamps = _event_timestamps(config, rng)
    events: list[AccessEvent] = []
    labels: list[GroundTruthRecord] = []
    last_events: dict[str, AccessEvent] = {}

    for index, timestamp in enumerate(timestamps):
        eligible = [profile for profile in profiles if profile_is_active(profile, timestamp)]
        if not eligible:
            eligible = [profile for profile in profiles if timestamp >= profile.active_after]
        fallback = rng.choices(
            eligible,
            weights=[profile.activity_weight for profile in eligible],
            k=1,
        )[0]
        directive = attack_plan.get(index)
        profile = (
            attack_orchestrator.profile_for(directive, fallback, last_events)
            if directive is not None
            else fallback
        )
        event = normal_factory.create(profile, timestamp, deterministic_uuid(rng))
        if directive is not None:
            event = attack_orchestrator.apply(
                directive,
                event,
                profile,
                last_events.get(profile.entity_id),
            )
        last_events[profile.entity_id] = event
        label = directive.attack_type if directive is not None else AttackType.NORMAL
        labels.append(
            GroundTruthRecord(
                event_id=event.event_id,
                label=label,
                attack_campaign_id=directive.campaign_id if directive is not None else None,
                generated_at=timestamp,
                scenario_metadata=(
                    {
                        "campaign_step": directive.step + 1,
                        "campaign_size": directive.total_steps,
                    }
                    if directive is not None
                    else {"behavior_phase": event.extensions["behavior_phase"]}
                ),
            )
        )
        events.append(event)
    return GeneratedDataset(
        events=tuple(events),
        labels=tuple(labels),
        profiles=profiles,
    )


def _event_timestamps(
    config: GeneratorConfig,
    rng: random.Random,
) -> tuple[datetime, ...]:
    """Create irregular but strictly increasing timestamps across the simulation."""

    gaps = [rng.expovariate(1.0) for _ in range(config.event_count)]
    total = sum(gaps)
    duration_seconds = config.duration_hours * 3600
    elapsed = 0.0
    timestamps = []
    for gap in gaps:
        elapsed += gap
        offset = min(duration_seconds, elapsed / total * duration_seconds)
        timestamps.append(config.start_at + timedelta(seconds=offset))
    return tuple(timestamps)
