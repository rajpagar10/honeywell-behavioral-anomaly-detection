"""FastAPI composition root."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from behavioral_security.api.middleware import CorrelationIdMiddleware
from behavioral_security.api.routes.health import router as health_router
from behavioral_security.core.constants import APP_VERSION
from behavioral_security.core.randomness import set_global_seed
from behavioral_security.infrastructure.config.loader import find_project_root, get_settings
from behavioral_security.infrastructure.config.settings import Settings
from behavioral_security.infrastructure.database.manager import DatabaseManager
from behavioral_security.infrastructure.observability.logging import configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a fully configured FastAPI application."""

    resolved_settings = settings or get_settings()
    configure_logging(resolved_settings.logging)
    set_global_seed(
        resolved_settings.randomness.seed,
        deterministic_torch=resolved_settings.randomness.deterministic_torch,
    )
    database_manager = DatabaseManager.from_settings(
        resolved_settings.database,
        project_root=find_project_root(),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Initialize durable dependencies before serving traffic."""

        database_manager.initialize()
        app.state.database_manager = database_manager
        yield

    docs_url = "/docs" if resolved_settings.api.docs_enabled else None
    redoc_url = "/redoc" if resolved_settings.api.docs_enabled else None
    app = FastAPI(
        title=resolved_settings.api.title,
        version=APP_VERSION,
        debug=resolved_settings.runtime.debug,
        docs_url=docs_url,
        redoc_url=redoc_url,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.database_manager = database_manager
    app.add_middleware(CorrelationIdMiddleware)
    if resolved_settings.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved_settings.api.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
        )
    app.include_router(health_router)
    return app


app = create_app()
