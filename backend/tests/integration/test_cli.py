"""Operational CLI tests."""

import json
from pathlib import Path

import pytest

from behavioral_security.cli import main


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
