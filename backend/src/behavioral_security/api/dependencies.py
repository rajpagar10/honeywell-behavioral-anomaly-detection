"""FastAPI dependency accessors."""

from fastapi import Request

from behavioral_security.infrastructure.database.manager import DatabaseManager


def get_database_manager(request: Request) -> DatabaseManager:
    """Return the database manager initialized during application startup."""

    manager: DatabaseManager = request.app.state.database_manager
    return manager
