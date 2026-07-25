"""Layered YAML, dotenv, and environment configuration loader."""

import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values

from behavioral_security.core.constants import ENV_PREFIX
from behavioral_security.infrastructure.config.settings import Settings

_CONTROL_VARIABLES = {f"{ENV_PREFIX}CONFIG_FILE", f"{ENV_PREFIX}ENV_FILE"}


def find_project_root(start: Path | None = None) -> Path:
    """Find the nearest parent containing the project manifest."""

    candidates = [start.resolve() if start else Path.cwd().resolve()]
    candidates.extend(Path(__file__).resolve().parents)
    for candidate in candidates:
        for directory in (candidate, *candidate.parents):
            if (directory / "pyproject.toml").is_file():
                return directory
    raise FileNotFoundError("could not locate pyproject.toml")


def load_settings(
    config_path: Path | None = None,
    *,
    env_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Settings:
    """Load settings with precedence environment > dotenv > YAML > defaults."""

    root = find_project_root()
    actual_environment = dict(os.environ if environ is None else environ)
    selected_env_file = env_file or Path(
        actual_environment.get(f"{ENV_PREFIX}ENV_FILE", root / ".env")
    )
    selected_env_file = _resolve_from_root(selected_env_file, root)
    dotenv_environment = {
        key: value for key, value in dotenv_values(selected_env_file).items() if value is not None
    }
    combined_environment = {**dotenv_environment, **actual_environment}

    selected_config = config_path or Path(
        combined_environment.get(f"{ENV_PREFIX}CONFIG_FILE", root / "config" / "base.yaml")
    )
    selected_config = _resolve_from_root(selected_config, root)
    yaml_settings = _read_yaml(selected_config)
    environment_settings = _nested_environment(combined_environment)
    merged = _deep_merge(yaml_settings, environment_settings)
    return Settings.model_validate(merged)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable settings instance."""

    return load_settings()


def clear_settings_cache() -> None:
    """Clear the process settings cache for controlled tests and reloads."""

    get_settings.cache_clear()


def _resolve_from_root(path: Path, root: Path) -> Path:
    """Resolve a possibly relative path against the project root."""

    return path if path.is_absolute() else root / path


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML mapping from disk."""

    if not path.is_file():
        raise FileNotFoundError(f"configuration file does not exist: {path}")
    with path.open(encoding="utf-8") as stream:
        content = yaml.safe_load(stream) or {}
    if not isinstance(content, dict):
        raise ValueError("configuration root must be a mapping")
    return {str(key): value for key, value in content.items()}


def _nested_environment(environment: Mapping[str, str]) -> dict[str, Any]:
    """Convert double-underscore environment keys into nested mappings."""

    result: dict[str, Any] = {}
    for key, raw_value in environment.items():
        if not key.startswith(ENV_PREFIX) or key in _CONTROL_VARIABLES:
            continue
        segments = key.removeprefix(ENV_PREFIX).lower().split("__")
        if len(segments) < 2 or any(not segment for segment in segments):
            raise ValueError(f"invalid nested configuration variable: {key}")
        _set_nested(result, segments, _parse_environment_value(raw_value))
    return result


def _set_nested(target: dict[str, Any], segments: list[str], value: Any) -> None:
    """Set a value in a nested dictionary without losing sibling keys."""

    cursor = target
    for segment in segments[:-1]:
        child = cursor.setdefault(segment, {})
        if not isinstance(child, dict):
            raise ValueError(f"configuration key collision at {segment}")
        cursor = child
    cursor[segments[-1]] = value


def _parse_environment_value(value: str) -> Any:
    """Parse environment values using YAML scalar and collection semantics."""

    return yaml.safe_load(value)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge configuration mappings without mutating inputs."""

    merged = dict(base)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(existing, value)
        else:
            merged[key] = value
    return merged
