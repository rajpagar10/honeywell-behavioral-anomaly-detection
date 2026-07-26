"""SQLite schema initialization tests."""

import sqlite3
from pathlib import Path

from behavioral_security.infrastructure.config.loader import find_project_root
from behavioral_security.infrastructure.config.settings import Settings
from behavioral_security.infrastructure.database.manager import DatabaseManager


def _table_names(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {str(row[0]) for row in rows}


def test_database_initialization_is_idempotent(test_settings: Settings) -> None:
    manager = DatabaseManager.from_settings(
        test_settings.database,
        project_root=find_project_root(),
    )

    first = manager.initialize()
    second = manager.initialize()

    assert first == {"operational": (1, 2), "evaluation": (1,)}
    assert second == {"operational": (), "evaluation": ()}
    assert all(manager.readiness().values())


def test_ground_truth_isolated_from_operational_database(test_settings: Settings) -> None:
    manager = DatabaseManager.from_settings(
        test_settings.database,
        project_root=find_project_root(),
    )
    manager.initialize()

    operational_tables = _table_names(manager.operational.path)
    evaluation_tables = _table_names(manager.evaluation.path)

    assert "security_events" in operational_tables
    assert "ground_truth" not in operational_tables
    assert "ground_truth" in evaluation_tables
    assert "security_events" not in evaluation_tables
