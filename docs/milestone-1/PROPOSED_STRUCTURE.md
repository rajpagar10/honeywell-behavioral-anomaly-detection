# Proposed Repository Structure

## Design rules

- Domain and application packages do not import FastAPI, Streamlit, SQLite,
  scikit-learn, PyTorch, or concrete persistence implementations.
- Infrastructure adapters implement ports owned by the core.
- FastAPI and Streamlit communicate through versioned API contracts.
- Training and inference reuse the same feature definitions.
- Operational events and evaluation labels are stored separately.
- Tests mirror the package boundaries.
- Every source file remains at or below 400 lines.

## Proposed tree

```text
.
├── backend/
│   ├── src/behavioral_security/
│   │   ├── core/
│   │   │   ├── entities/
│   │   │   ├── value_objects/
│   │   │   ├── enums/
│   │   │   ├── exceptions/
│   │   │   └── ports/
│   │   ├── application/
│   │   │   ├── commands/
│   │   │   ├── queries/
│   │   │   ├── dto/
│   │   │   └── services/
│   │   ├── generator/
│   │   │   ├── profiles/
│   │   │   ├── attacks/
│   │   │   ├── distributions/
│   │   │   └── exporters/
│   │   ├── profiling/
│   │   │   ├── features/
│   │   │   ├── baselines/
│   │   │   ├── transitions/
│   │   │   └── drift/
│   │   ├── detection/
│   │   │   ├── statistical/
│   │   │   ├── neural/
│   │   │   ├── sequence/
│   │   │   ├── rules/
│   │   │   └── ensemble/
│   │   ├── classification/
│   │   │   ├── models/
│   │   │   ├── calibration/
│   │   │   └── imbalance/
│   │   ├── explainability/
│   │   │   ├── contributors/
│   │   │   ├── narratives/
│   │   │   └── evidence/
│   │   ├── risk/
│   │   │   ├── scoring/
│   │   │   └── policy/
│   │   ├── streaming/
│   │   │   ├── replay/
│   │   │   ├── publishers/
│   │   │   └── consumers/
│   │   ├── infrastructure/
│   │   │   ├── database/
│   │   │   ├── repositories/
│   │   │   ├── model_store/
│   │   │   ├── observability/
│   │   │   └── security/
│   │   └── api/
│   │       ├── routes/
│   │       ├── schemas/
│   │       ├── dependencies/
│   │       ├── middleware/
│   │       └── app.py
│   └── tests/
│       ├── unit/
│       ├── integration/
│       ├── contract/
│       ├── performance/
│       └── fixtures/
├── dashboard/
│   ├── app.py
│   ├── pages/
│   ├── components/
│   ├── charts/
│   ├── clients/
│   ├── state/
│   ├── theme/
│   └── tests/
├── config/
│   ├── base.yaml
│   ├── development.yaml
│   ├── test.yaml
│   └── model_profiles/
├── data/
│   ├── raw/.gitkeep
│   ├── processed/.gitkeep
│   └── samples/
├── artifacts/
│   └── .gitkeep
├── docker/
│   ├── backend.Dockerfile
│   ├── dashboard.Dockerfile
│   └── simulator.Dockerfile
├── docs/
│   ├── milestone-1/
│   ├── api/
│   ├── architecture/
│   ├── operations/
│   └── models/
├── scripts/
│   ├── generate_data.py
│   ├── train_models.py
│   ├── evaluate_models.py
│   ├── run_simulation.py
│   └── seed_demo.py
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Makefile
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## Module ownership

| Module | Responsibility |
|---|---|
| `core` | Framework-independent entities, policies, and ports |
| `application` | Use-case orchestration and transaction boundaries |
| `generator` | Synthetic identities, normal behavior, attacks, and label export |
| `profiling` | Individual and peer baselines, transitions, decay, and drift |
| `detection` | Unknown, rule-based, and sequential anomaly detection |
| `classification` | Supervised attack family prediction and calibration |
| `explainability` | Feature contributions, evidence, and narratives |
| `risk` | Configurable risk policy and severity mapping |
| `streaming` | Replay, event publication, ordering, and backpressure |
| `infrastructure` | SQLite, repositories, artifacts, logs, metrics, and security |
| `api` | Versioned HTTP/WebSocket contracts |
| `dashboard` | SOC user experience consuming only public APIs |

## Dependency policy

```text
dashboard ────────> API contracts
api ──────────────> application ─────────────> core
streaming ────────> application
infrastructure ───> core ports
ML implementations > core model ports
```

Concrete dependency wiring occurs only in the composition root. Circular imports
and cross-module database access are prohibited.
