"""Idempotent SQLite migration runner."""

import sqlite3
from collections.abc import Sequence

from behavioral_security.infrastructure.database.migrations import Migration

_MIGRATION_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def apply_migrations(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration],
) -> tuple[int, ...]:
    """Apply unapplied migrations in ascending version order."""

    connection.execute(_MIGRATION_TABLE)
    applied = {
        int(row["version"])
        for row in connection.execute("SELECT version FROM schema_migrations").fetchall()
    }
    newly_applied: list[int] = []
    for migration in sorted(migrations, key=lambda item: item.version):
        if migration.version in applied:
            continue
        with connection:
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations(version, name) VALUES (?, ?)",
                (migration.version, migration.name),
            )
        newly_applied.append(migration.version)
    return tuple(newly_applied)
