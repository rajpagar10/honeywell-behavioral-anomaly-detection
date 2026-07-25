"""Operational CLI tests."""

import json
from pathlib import Path

import pytest
import yaml

from behavioral_security.cli import main

from ..factories import make_generator_config


def _write_config(path: Path, operational: Path, evaluation: Path) -> None:
    path.write_text(
        f"""
runtime:
  environment: test
api:
  docs_enabled: false
database:
  operational_path: {operational.as_posix()}
  evaluation_path: {evaluation.as_posix()}
  wal_enabled: false
logging:
  level: WARNING
  format: console
randomness:
  seed: 42
  deterministic_torch: false
""",
        encoding="utf-8",
    )


def test_check_config_and_init_db(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "config.yaml"
    operational = tmp_path / "operational.db"
    evaluation = tmp_path / "evaluation.db"
    _write_config(config, operational, evaluation)

    assert main(["--config", str(config), "check-config"]) == 0
    check_output = json.loads(capsys.readouterr().out)
    assert check_output["runtime"]["environment"] == "test"

    assert main(["--config", str(config), "init-db"]) == 0
    init_output = json.loads(capsys.readouterr().out)
    assert init_output["status"] == "initialized"
    assert operational.is_file()
    assert evaluation.is_file()


def test_generate_data_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app_config = tmp_path / "app.yaml"
    _write_config(
        app_config,
        tmp_path / "operational.db",
        tmp_path / "evaluation.db",
    )
    generator_config = tmp_path / "generator.yaml"
    generator_config.write_text(
        yaml.safe_dump(make_generator_config().model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    output = tmp_path / "generated"

    result = main(
        [
            "--config",
            str(app_config),
            "generate-data",
            "--generator-config",
            str(generator_config),
            "--output",
            str(output),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["summary"]["event_count"] == 400
    assert Path(payload["files"]["events"]).is_file()
