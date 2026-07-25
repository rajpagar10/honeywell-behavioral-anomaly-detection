"""Configuration loading tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from behavioral_security.infrastructure.config.loader import load_settings
from behavioral_security.infrastructure.config.settings import DatabaseSettings


def test_environment_overrides_yaml(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text(
        """
runtime:
  environment: test
api:
  port: 8000
database:
  operational_path: operational.db
  evaluation_path: evaluation.db
logging:
  level: WARNING
randomness:
  seed: 10
""",
        encoding="utf-8",
    )

    settings = load_settings(
        config,
        env_file=tmp_path / "missing.env",
        environ={
            "BADP_API__PORT": "9100",
            "BADP_RANDOMNESS__SEED": "99",
            "BADP_API__CORS_ORIGINS": '["https://soc.example"]',
        },
    )

    assert settings.api.port == 9100
    assert settings.randomness.seed == 99
    assert settings.api.cors_origins == ("https://soc.example",)


def test_invalid_environment_shape_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text("runtime:\n  environment: test\n", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid nested configuration variable"):
        load_settings(
            config,
            env_file=tmp_path / "missing.env",
            environ={"BADP_INVALID": "value"},
        )


def test_operational_and_evaluation_paths_must_differ() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        DatabaseSettings(operational_path=Path("same.db"), evaluation_path=Path("same.db"))
