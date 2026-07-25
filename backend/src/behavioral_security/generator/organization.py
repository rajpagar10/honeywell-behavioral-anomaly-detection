"""Deterministic synthetic organization and entity-profile construction."""

import random
from datetime import timedelta
from ipaddress import ip_address
from uuid import UUID

from behavioral_security.core.enums import AuthenticationMethod, EntityType
from behavioral_security.generator.catalogs import (
    COMMAND_TEMPLATES,
    DEPARTMENT_RESOURCES,
    DEPARTMENTS,
    EDGE_RESOURCES,
    IOT_RESOURCES,
    LOCATIONS,
    SERVICE_RESOURCES,
)
from behavioral_security.generator.config import GeneratorConfig
from behavioral_security.generator.models import BehaviorProfile


def build_organization(config: GeneratorConfig, rng: random.Random) -> tuple[BehaviorProfile, ...]:
    """Build stable profiles and assign deterministic cold-start and drift cohorts."""

    profiles: list[BehaviorProfile] = []
    profiles.extend(_build_users(config, rng))
    profiles.extend(_build_service_accounts(config, rng))
    profiles.extend(_build_devices(config, rng, EntityType.IOT_DEVICE))
    profiles.extend(_build_devices(config, rng, EntityType.EDGE_DEVICE))
    cold_start_count = round(len(profiles) * config.cold_start_fraction)
    cold_ids = {profile.entity_id for profile in rng.sample(profiles, cold_start_count)}
    drift_candidates = [profile for profile in profiles if profile.entity_id not in cold_ids]
    drift_count = min(round(len(profiles) * config.drift_fraction), len(drift_candidates))
    drift_ids = {profile.entity_id for profile in rng.sample(drift_candidates, drift_count)}
    duration = timedelta(hours=config.duration_hours)
    cold_activation = config.start_at + duration * config.cold_start_activation_fraction
    drift_start = config.start_at + duration * config.drift_start_fraction

    enriched: list[BehaviorProfile] = []
    for profile in profiles:
        updates: dict[str, object] = {}
        if profile.entity_id in cold_ids:
            updates.update({"cold_start": True, "active_after": cold_activation})
        if profile.entity_id in drift_ids:
            updates.update(
                {
                    "drift_start": drift_start,
                    "drift_login_hour_offset": rng.choice((-3, -2, 2, 3)),
                    "drift_resources": (
                        f"{profile.department}/collaboration",
                        "shared/analytics",
                    ),
                    "drift_device": f"drift-{profile.entity_id}-device",
                }
            )
        enriched.append(profile.model_copy(update=updates))
    return tuple(enriched)


def deterministic_uuid(rng: random.Random) -> UUID:
    """Create a reproducible RFC 4122 version-4 UUID from a seeded RNG."""

    return UUID(int=rng.getrandbits(128), version=4)


def _build_users(config: GeneratorConfig, rng: random.Random) -> list[BehaviorProfile]:
    """Create human identity profiles with department-specific behavior."""

    profiles: list[BehaviorProfile] = []
    for index in range(config.population.users):
        department = DEPARTMENTS[index % len(DEPARTMENTS)]
        location = LOCATIONS[index % 4]
        start_hour = rng.choice((7, 8, 9, 10))
        profiles.append(
            BehaviorProfile(
                profile_id=deterministic_uuid(rng),
                entity_id=f"user-{index + 1:04d}",
                entity_type=EntityType.USER,
                department=department,
                home_location=location,
                allowed_locations=(location, LOCATIONS[(index + 1) % 4]),
                common_resources=DEPARTMENT_RESOURCES[department],
                authentication_methods=(AuthenticationMethod.SSO, AuthenticationMethod.MFA),
                normal_login_hours=tuple(range(start_hour, min(start_hour + 10, 24))),
                known_devices=(
                    f"user-{index + 1:04d}-laptop",
                    f"user-{index + 1:04d}-mobile",
                ),
                source_ips=(ip_address(f"10.10.{index // 250}.{index % 250 + 1}"),),
                mean_session_seconds=rng.uniform(900, 3600),
                session_stddev_seconds=rng.uniform(180, 600),
                command_templates={"default": COMMAND_TEMPLATES["user"]},
                activity_weight=1.0,
                active_after=config.start_at,
            )
        )
    return profiles


def _build_service_accounts(
    config: GeneratorConfig,
    rng: random.Random,
) -> list[BehaviorProfile]:
    """Create non-interactive service-account profiles."""

    profiles: list[BehaviorProfile] = []
    for index in range(config.population.service_accounts):
        profiles.append(
            BehaviorProfile(
                profile_id=deterministic_uuid(rng),
                entity_id=f"svc-{index + 1:04d}",
                entity_type=EntityType.SERVICE_ACCOUNT,
                department="platform",
                home_location=LOCATIONS[index % 4],
                allowed_locations=(LOCATIONS[index % 4],),
                common_resources=SERVICE_RESOURCES,
                authentication_methods=(
                    AuthenticationMethod.SERVICE_TOKEN,
                    AuthenticationMethod.CERTIFICATE,
                ),
                normal_login_hours=tuple(range(24)),
                known_devices=(f"svc-{index + 1:04d}-runtime",),
                source_ips=(ip_address(f"10.20.{index // 250}.{index % 250 + 1}"),),
                mean_session_seconds=rng.uniform(30, 300),
                session_stddev_seconds=rng.uniform(10, 60),
                command_templates={"default": COMMAND_TEMPLATES["service_account"]},
                activity_weight=1.8,
                active_after=config.start_at,
            )
        )
    return profiles


def _build_devices(
    config: GeneratorConfig,
    rng: random.Random,
    entity_type: EntityType,
) -> list[BehaviorProfile]:
    """Create IoT or edge-device profiles with constrained destinations."""

    count = (
        config.population.iot_devices
        if entity_type is EntityType.IOT_DEVICE
        else config.population.edge_devices
    )
    prefix = "iot" if entity_type is EntityType.IOT_DEVICE else "edge"
    resources = IOT_RESOURCES if entity_type is EntityType.IOT_DEVICE else EDGE_RESOURCES
    network = 30 if entity_type is EntityType.IOT_DEVICE else 40
    weight = 2.4 if entity_type is EntityType.IOT_DEVICE else 2.0
    profiles: list[BehaviorProfile] = []
    for index in range(count):
        profiles.append(
            BehaviorProfile(
                profile_id=deterministic_uuid(rng),
                entity_id=f"{prefix}-{index + 1:04d}",
                entity_type=entity_type,
                department="manufacturing",
                home_location=LOCATIONS[index % 4],
                allowed_locations=(LOCATIONS[index % 4],),
                common_resources=resources,
                authentication_methods=(AuthenticationMethod.CERTIFICATE,),
                normal_login_hours=tuple(range(24)),
                known_devices=(f"{prefix}-{index + 1:04d}-fingerprint",),
                source_ips=(ip_address(f"10.{network}.{index // 250}.{index % 250 + 1}"),),
                mean_session_seconds=rng.uniform(5, 90),
                session_stddev_seconds=rng.uniform(2, 20),
                command_templates={"default": COMMAND_TEMPLATES[prefix + "_device"]},
                activity_weight=weight,
                active_after=config.start_at,
            )
        )
    return profiles
