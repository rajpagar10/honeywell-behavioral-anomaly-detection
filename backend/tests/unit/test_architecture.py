"""Architecture and repository quality guardrails."""

import ast
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = PROJECT_ROOT / "backend" / "src" / "behavioral_security"


def test_python_files_do_not_exceed_400_lines() -> None:
    oversized = {
        path.relative_to(PROJECT_ROOT): len(path.read_text(encoding="utf-8").splitlines())
        for path in SOURCE_ROOT.rglob("*.py")
        if len(path.read_text(encoding="utf-8").splitlines()) > 400
    }
    assert oversized == {}


def test_core_does_not_import_outer_layers() -> None:
    forbidden_prefixes = (
        "behavioral_security.api",
        "behavioral_security.application",
        "behavioral_security.infrastructure",
        "fastapi",
        "sqlite3",
        "streamlit",
    )
    violations: list[str] = []
    for path in (SOURCE_ROOT / "core").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imports = [node.module or ""]
            else:
                continue
            if any(name.startswith(forbidden_prefixes) for name in imports):
                violations.append(str(path.relative_to(PROJECT_ROOT)))
    assert violations == []


def test_docker_compose_has_real_api_health_check() -> None:
    compose = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    api = compose["services"]["api"]

    assert api["build"]["dockerfile"] == "docker/backend.Dockerfile"
    assert api["ports"] == ["8000:8000"]
    dockerfile = (PROJECT_ROOT / "docker" / "backend.Dockerfile").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in dockerfile
    assert "/ready" in dockerfile
