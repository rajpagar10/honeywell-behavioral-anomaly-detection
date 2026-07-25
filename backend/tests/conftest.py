"""Shared test fixtures."""

from pathlib import Path

import pytest

from behavioral_security.infrastructure.config.settings import (
    ApiSettings,
    DatabaseSettings,
    LoggingSettings,
    RandomnessSettings,
    RuntimeSettings,
    Settings,
)


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    """Return isolated settings with separate temporary databases."""

    return Settings(
        runtime=RuntimeSettings(environment="test"),
        api=ApiSettings(docs_enabled=False, cors_origins=()),
        database=DatabaseSettings(
            operational_path=tmp_path / "operational.db",
            evaluation_path=tmp_path / "evaluation.db",
            wal_enabled=False,
            busy_timeout_ms=1000,
        ),
        logging=LoggingSettings(level="WARNING", format="console", service_name="test"),
        randomness=RandomnessSettings(seed=42, deterministic_torch=False),
    )
