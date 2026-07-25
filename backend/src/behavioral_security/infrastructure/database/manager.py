"""Operational and evaluation database lifecycle management."""

from pathlib import Path

from behavioral_security.infrastructure.config.settings import DatabaseSettings
from behavioral_security.infrastructure.database.connection import SQLiteConnectionFactory
from behavioral_security.infrastructure.database.migrations import (
    EVALUATION_MIGRATIONS,
    OPERATIONAL_MIGRATIONS,
)
from behavioral_security.infrastructure.database.runner import apply_migrations


class DatabaseManager:
    """Own separate operational and evaluation SQLite databases."""

    def __init__(
        self,
        operational: SQLiteConnectionFactory,
        evaluation: SQLiteConnectionFactory,
    ) -> None:
        """Initialize the manager with explicit connection factories."""

        self.operational = operational
        self.evaluation = evaluation

    @classmethod
    def from_settings(cls, settings: DatabaseSettings, *, project_root: Path) -> "DatabaseManager":
        """Build database factories with paths resolved from the project root."""

        operational_path = _resolve_path(settings.operational_path, project_root)
        evaluation_path = _resolve_path(settings.evaluation_path, project_root)
        return cls(
            SQLiteConnectionFactory(
                operational_path,
                busy_timeout_ms=settings.busy_timeout_ms,
                wal_enabled=settings.wal_enabled,
            ),
            SQLiteConnectionFactory(
                evaluation_path,
                busy_timeout_ms=settings.busy_timeout_ms,
                wal_enabled=settings.wal_enabled,
            ),
        )

    def initialize(self) -> dict[str, tuple[int, ...]]:
        """Create both databases and apply all outstanding migrations."""

        with self.operational.connect() as connection:
            operational = apply_migrations(connection, OPERATIONAL_MIGRATIONS)
        with self.evaluation.connect() as connection:
            evaluation = apply_migrations(connection, EVALUATION_MIGRATIONS)
        return {"operational": operational, "evaluation": evaluation}

    def readiness(self) -> dict[str, bool]:
        """Check connectivity and migration state for both databases."""

        return {
            "operational_database": self._is_ready(
                self.operational,
                expected_version=max(item.version for item in OPERATIONAL_MIGRATIONS),
            ),
            "evaluation_database": self._is_ready(
                self.evaluation,
                expected_version=max(item.version for item in EVALUATION_MIGRATIONS),
            ),
        }

    @staticmethod
    def _is_ready(factory: SQLiteConnectionFactory, *, expected_version: int) -> bool:
        """Return whether a database is reachable at the expected schema version."""

        try:
            with factory.connect() as connection:
                row = connection.execute(
                    "SELECT MAX(version) AS version FROM schema_migrations"
                ).fetchone()
            return row is not None and row["version"] == expected_version
        except Exception:
            return False


def _resolve_path(path: Path, root: Path) -> Path:
    """Resolve a configured database path against the project root."""

    return path if path.is_absolute() else root / path
