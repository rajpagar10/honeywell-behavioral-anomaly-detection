"""Typed application settings."""

from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from behavioral_security.core.constants import APP_NAME


class SettingsModel(BaseModel):
    """Immutable settings base that rejects unknown configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class RuntimeSettings(SettingsModel):
    """Runtime environment and debug settings."""

    environment: Literal["development", "test", "production"] = "production"
    debug: bool = False


class ApiSettings(SettingsModel):
    """HTTP server and OpenAPI settings."""

    title: str = f"{APP_NAME} API"
    host: str = "0.0.0.0"
    port: Annotated[int, Field(ge=1, le=65535)] = 8000
    prefix: str = "/api/v1"
    docs_enabled: bool = True
    cors_origins: tuple[str, ...] = ()

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        """Require an absolute API prefix without a trailing slash."""

        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("API prefix must start with '/' and must not end with '/'")
        return value


class DatabaseSettings(SettingsModel):
    """SQLite persistence and concurrency settings."""

    operational_path: Path = Path("data/runtime/behavioral_security.db")
    evaluation_path: Path = Path("data/evaluation/ground_truth.db")
    busy_timeout_ms: Annotated[int, Field(ge=100, le=120_000)] = 5000
    wal_enabled: bool = True

    @model_validator(mode="after")
    def databases_are_separate(self) -> Self:
        """Prevent evaluation labels from sharing the operational database."""

        if self.operational_path.resolve() == self.evaluation_path.resolve():
            raise ValueError("operational and evaluation database paths must differ")
        return self


class LoggingSettings(SettingsModel):
    """Structured logging settings."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "console"] = "json"
    service_name: str = "behavioral-security-api"


class RandomnessSettings(SettingsModel):
    """Global reproducibility settings."""

    seed: Annotated[int, Field(ge=0, le=2_147_483_647)] = 1729
    deterministic_torch: bool = True


class IntelligenceSettings(SettingsModel):
    """Paths and thresholds for model-backed replay intelligence."""

    model_path: Path = Path("artifacts/models/fast/model.joblib")
    events_path: Path = Path("data/samples/honeywell_demo/events.csv")
    metrics_path: Path = Path("artifacts/models/fast/metrics.json")
    alert_threshold: Annotated[float, Field(ge=0.0, le=100.0)] = 55.0
    replay_interval_ms: Annotated[int, Field(ge=0, le=60_000)] = 100
    recent_limit: Annotated[int, Field(ge=1, le=1000)] = 100


class Settings(SettingsModel):
    """Central validated configuration graph."""

    runtime: RuntimeSettings = RuntimeSettings()
    api: ApiSettings = ApiSettings()
    database: DatabaseSettings = DatabaseSettings()
    logging: LoggingSettings = LoggingSettings()
    randomness: RandomnessSettings = RandomnessSettings()
    intelligence: IntelligenceSettings = IntelligenceSettings()
