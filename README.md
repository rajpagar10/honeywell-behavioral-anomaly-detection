# Behavioral Security Platform

Enterprise-grade foundation for an AI-powered behavioral anomaly detection and
SOC investigation platform. The system is being delivered through
approval-gated milestones; Milestone 2 establishes validated domain contracts,
configuration, persistence schemas, CLI tooling, and API health endpoints.

## Current scope

Implemented:

- Clean Architecture package boundaries
- typed YAML, dotenv, and environment configuration
- structured JSON or console logging
- validated access-event, profile, detection, alert, risk, and feedback models
- isolated operational and ground-truth SQLite databases
- idempotent schema migrations
- repository and unit-of-work ports
- deterministic random seeding
- `check-config`, `init-db`, and `serve` CLI commands
- FastAPI liveness and readiness endpoints
- test, lint, typing, CI, and Docker foundations

Intentionally deferred:

- synthetic event generation and attack injection
- behavioral profile algorithms
- anomaly and classification models
- risk calculation and explanation algorithms
- event streaming and Streamlit dashboard

## Prerequisites

- Python 3.11 or 3.12
- Git
- Docker with Compose, if using the container workflow

## Local setup

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
badp --config config/development.yaml check-config
badp --config config/development.yaml init-db
badp --config config/development.yaml serve
```

Linux or macOS:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
cp .env.example .env
badp --config config/development.yaml check-config
badp --config config/development.yaml init-db
badp --config config/development.yaml serve
```

Open:

- API health: <http://127.0.0.1:8000/health>
- dependency readiness: <http://127.0.0.1:8000/ready>
- OpenAPI documentation: <http://127.0.0.1:8000/docs>

## Configuration

Settings load in this order, from highest to lowest priority:

1. process environment variables;
2. values in `.env`;
3. the selected YAML configuration;
4. typed defaults.

Use `BADP_CONFIG_FILE` to select a YAML file. Nested overrides use a double
underscore:

```text
BADP_API__PORT=9000
BADP_LOGGING__LEVEL=DEBUG
BADP_DATABASE__OPERATIONAL_PATH=data/runtime/custom.db
```

Operational and evaluation database paths must differ. Ground-truth labels are
stored only in the evaluation database and do not exist in the online event
schema.

## Quality commands

```bash
ruff format .
ruff check .
mypy
pytest
```

The coverage gate is 85% for the current Python package. Source files are
limited to 400 lines by an architecture test.

## Docker

```bash
docker compose build
docker compose up
```

The container runs as a non-root user, persists SQLite files in a named volume,
and reports readiness through the `/ready` health check. Dashboard and simulator
containers will be added only when those applications are implemented.

## Repository layout

```text
backend/src/behavioral_security/
├── api/                 FastAPI presentation layer
├── application/         use-case orchestration
├── core/                domain models, taxonomy, and ports
├── infrastructure/      configuration, SQLite, and observability
├── generator/           Milestone 3 boundary
├── profiling/           Milestone 4 boundary
├── detection/           Milestone 5 boundary
├── classification/      Milestone 6 boundary
├── explainability/      Milestone 7 boundary
├── risk/                Milestone 7 boundary
└── streaming/           Milestone 9 boundary
```

Architecture records and requirement traceability are under
`docs/milestone-1/`.

## Security notes

- Never commit `.env` or runtime databases.
- Synthetic identities must use fictional data and reserved network ranges.
- Model artifacts will require a trusted path and checksum before loading.
- Production authentication and authorization are planned at the API boundary;
  current endpoints expose health information only.
