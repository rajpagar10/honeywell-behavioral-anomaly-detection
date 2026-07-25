"""Safe SQLite connection factory."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class SQLiteConnectionFactory:
    """Create consistently configured SQLite connections."""

    def __init__(self, path: Path, *, busy_timeout_ms: int, wal_enabled: bool) -> None:
        """Store validated SQLite connection settings."""

        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        self.wal_enabled = wal_enabled

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Open a connection, commit on success, and roll back on failure."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            if self.wal_enabled:
                connection.execute("PRAGMA journal_mode = WAL")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
