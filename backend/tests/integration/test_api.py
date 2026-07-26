"""FastAPI health contract tests."""

from fastapi.testclient import TestClient

from behavioral_security.api.app import create_app
from behavioral_security.infrastructure.config.settings import Settings


def test_health_and_readiness_endpoints(test_settings: Settings) -> None:
    with TestClient(create_app(test_settings)) as client:
        health = client.get("/health")
        readiness = client.get("/ready")

    assert health.status_code == 200
    assert health.json() == {
        "status": "healthy",
        "service": "SentinelAI",
        "version": "0.2.0",
        "environment": "test",
    }
    assert readiness.status_code == 200
    assert readiness.json()["status"] == "ready"
    assert all(readiness.json()["components"].values())
    assert health.headers["X-Correlation-ID"]


def test_openapi_documents_operational_endpoints(test_settings: Settings) -> None:
    settings = test_settings.model_copy(
        update={"api": test_settings.api.model_copy(update={"docs_enabled": True})}
    )
    with TestClient(create_app(settings)) as client:
        schema = client.get("/openapi.json").json()

    assert "/health" in schema["paths"]
    assert "/ready" in schema["paths"]
