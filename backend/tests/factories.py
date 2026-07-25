"""Typed test factories for reusable domain configurations."""

from datetime import UTC, datetime

from behavioral_security.generator.config import GeneratorConfig, PopulationConfig


def make_generator_config(
    *,
    seed: int = 1234,
    event_count: int = 400,
    anomaly_rate: float = 0.03,
) -> GeneratorConfig:
    """Create a compact generator configuration that includes every attack."""

    return GeneratorConfig(
        dataset_name="unit_test_dataset",
        seed=seed,
        event_count=event_count,
        anomaly_rate=anomaly_rate,
        start_at=datetime(2026, 1, 5, tzinfo=UTC),
        duration_hours=48,
        population=PopulationConfig(
            users=8,
            service_accounts=2,
            iot_devices=3,
            edge_devices=2,
        ),
        cold_start_fraction=0.2,
        cold_start_activation_fraction=0.6,
        drift_fraction=0.2,
        drift_start_fraction=0.5,
        warmup_fraction=0.2,
    )
