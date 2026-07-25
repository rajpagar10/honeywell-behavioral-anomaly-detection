# Honeywell Requirement Traceability

## Status legend

- **Designed:** architecture and acceptance approach are defined in Milestone 1.
- **Not started:** no implementation exists in the inspected repository.
- **Later milestone:** intentionally deferred by the approved incremental workflow.

## Functional and quality requirements

| Honeywell requirement | Planned module | Planned implementation approach | Evaluation metric | Current status |
|---|---|---|---|---|
| Synthetic enterprise access logs | `generator/profiles`, `generator/distributions` | Seeded entity-specific probabilistic schedules, resources, devices, locations, authentication, sessions, and commands | 100% schema validity; deterministic replay by seed; distribution tests pass | Designed; implementation not started |
| Users | `generator/profiles/user.py` | Department, shift, role, resource, device, and travel-aware behavior | Configured user count and profile diversity achieved | Designed; implementation not started |
| Service accounts | `generator/profiles/service_account.py` | Stable machine schedules, non-interactive auth, narrow resource graph | No human-only fields emitted; expected periodicity reproduced | Designed; implementation not started |
| IoT devices | `generator/profiles/iot_device.py` | Periodic telemetry and constrained destination/resource behavior | Resource and cadence distributions match configured profile | Designed; implementation not started |
| Edge devices | `generator/profiles/edge_device.py` | Site-aware access, maintenance windows, gateway and command patterns | Site and maintenance behavior validated | Designed; implementation not started |
| Configurable attack percentage | `generator/attacks/orchestrator.py`, `config/base.yaml` | Seeded weighted attack scheduler with entity eligibility rules | Observed attack rate within statistical tolerance of configuration | Designed; implementation not started |
| Normal behavior label | `generator/exporters` | Evaluation label stored by immutable event ID | Every generated event has exactly one ground-truth record | Designed; implementation not started |
| Brute force | `generator/attacks/brute_force.py` | Burst of failures followed optionally by success, with source variation controls | Scenario invariant and detection recall tests | Designed; implementation not started |
| Impossible travel | `generator/attacks/impossible_travel.py` | Geodesic distance and elapsed time create infeasible travel velocity | Injected velocity always exceeds configured feasible bound | Designed; implementation not started |
| Credential stuffing | `generator/attacks/credential_stuffing.py` | Distributed login attempts across identities from coordinated sources/devices | Cross-identity campaign invariants pass | Designed; implementation not started |
| Lateral movement | `generator/attacks/lateral_movement.py` | Compromised identity traverses rare resource and host transitions | Injected path is measurably rare under baseline graph | Designed; implementation not started |
| Device spoofing | `generator/attacks/device_spoofing.py` | Conflicting fingerprint, geo, and identity evidence | Fingerprint inconsistency invariants pass | Designed; implementation not started |
| Low-and-slow exfiltration | `generator/attacks/low_slow_exfiltration.py` | Sustained small transfers and sensitive-resource aggregation over long windows | Windowed cumulative behavior exceeds attack policy | Designed; implementation not started |
| Insider drift | `generator/attacks/insider_drift.py` | Gradual resource, time, command, and volume deviation | Drift curve changes monotonically and remains reproducible | Designed; implementation not started |
| Ground truth kept separately | `generator/exporters`, `infrastructure/database` | Operational event store excludes label; isolated ground-truth table/export keyed by `event_id` | Zero label fields in inference inputs; leakage test passes | Designed; implementation not started |
| Individual profiles | `profiling/baselines` | Per-entity time-decayed statistics and categorical distributions | Profile isolation and update tests pass | Designed; implementation not started |
| Typical login hours | `profiling/features/temporal.py` | Circular hour/day distributions with shift-aware likelihood | Known-hours score above out-of-window score | Designed; implementation not started |
| Common resources and systems | `profiling/features/resources.py` | Decayed counts with smoothing and sensitivity context | Frequency estimates match controlled fixtures | Designed; implementation not started |
| Known devices | `profiling/features/devices.py` | Fingerprint trust, first/last seen, and conflict tracking | New/known/conflicting device cases correctly distinguished | Designed; implementation not started |
| Average session duration | `profiling/features/session.py` | Weighted online mean, variance, robust quantiles | Numerical error within tolerance of batch reference | Designed; implementation not started |
| Average failed logins | `profiling/features/authentication.py` | Decayed failure rate and burst windows | Matches controlled event-window reference | Designed; implementation not started |
| Normal geolocations | `profiling/features/geography.py` | Location frequencies, geodesic travel, and site trust | Known-location and travel scenario tests pass | Designed; implementation not started |
| Authentication methods | `profiling/features/authentication.py` | Smoothed per-entity and peer-group method probabilities | Rare-method likelihood calibrated on fixtures | Designed; implementation not started |
| Resource transition probabilities | `profiling/transitions` | First-order Markov graph with Laplace smoothing and decayed counts | Transition matrix rows normalize to 1; rarity tests pass | Designed; implementation not started |
| Continuously update profiles | `application/services/profile_service.py` | Post-scoring update with suspicious-event quarantine and idempotency | Duplicate event causes no second update; accepted event updates once | Designed; implementation not started |
| Isolation Forest | `detection/statistical/isolation_forest.py` | Segment-aware unsupervised detector with calibrated anomaly score | PR-AUC, recall, FPR, fit/inference latency reported | Designed; implementation not started |
| One-Class SVM | `detection/statistical/one_class_svm.py` | Scaled novelty detector for bounded cohorts and benchmark comparison | PR-AUC and resource usage benchmarked | Designed; implementation not started |
| Autoencoder | `detection/neural/autoencoder.py` | PyTorch reconstruction detector with early stopping and per-feature error | Reconstruction separation, PR-AUC, calibrated FPR | Designed; implementation not started |
| XGBoost | `classification/models/xgboost.py` | Weighted multiclass boosted-tree adapter with probability calibration | Macro-F1, per-attack recall, PR-AUC, calibration error | Designed; implementation not started |
| Random Forest | `classification/models/random_forest.py` | Class-weighted, explainable baseline classifier | Macro-F1, per-attack recall, inference latency | Designed; implementation not started |
| LightGBM | `classification/models/lightgbm.py` | Weighted multiclass gradient boosting optimized for tabular features | Macro-F1, per-attack recall, training time | Designed; implementation not started |
| LSTM | `detection/sequence/lstm.py` | Masked event-sequence encoder predicting anomaly/next behavior | Sequence PR-AUC and per-attack recall | Designed; implementation not started |
| GRU | `detection/sequence/gru.py` | Lower-latency sequence encoder and default deep sequence model | Sequence PR-AUC and p95 latency | Designed; implementation not started |
| Transformer | `detection/sequence/transformer.py` | Masked self-attention over event tokens with positional/time encoding | Long-range attack recall, PR-AUC, latency | Designed; implementation not started |
| Model switching | `core/ports/model.py`, configuration, model registry | Common lifecycle interface and configuration-selected adapters | Contract suite passes for every adapter | Designed; implementation not started |
| Human-readable alert explanation | `explainability` | Evidence-backed reason contributors and deterministic narrative renderer | Every alert has reason, observed value, baseline, and contribution | Designed; implementation not started |
| Weighted risk score from required factors | `risk/scoring` | Versioned configuration combines calibrated components and trust modifiers | Score bounded 0–100; monotonicity/property tests pass | Designed; implementation not started |
| Concept drift | `profiling/drift` | Rolling windows, exponential decay, PSI/JSD and Page-Hinkley signals, gated adaptation | Synthetic benign-shift adaptation time and post-adaptation FPR | Designed; implementation not started |
| Cold start | `profiling/baselines/hierarchy.py` | Maturity-weighted entity, department, entity-type, and organization priors | New-entity FPR and convergence-to-personal profile | Designed; implementation not started |
| Overview dashboard | `dashboard/pages/overview.py` | KPI cards, risk trend, severity, attack mix, and top entities | Page renders; metrics reconcile with API | Designed; implementation not started |
| Live Events | `dashboard/pages/live_events.py` | Incremental event feed, filters, pause/resume, event detail | Update lag and filter interaction tests | Designed; implementation not started |
| Alerts | `dashboard/pages/alerts.py` | Triage queue with severity, state, evidence, and assignment | Sort/filter/detail workflows pass | Designed; implementation not started |
| Risk Timeline | `dashboard/pages/risk_timeline.py` | Entity and organization risk history with drill-down | Chart values reconcile with stored assessments | Designed; implementation not started |
| User Profiles | `dashboard/pages/user_profiles.py` | Maturity, baseline, trust, behavior, and deviation views | Selected entity data matches profile API | Designed; implementation not started |
| Device Profiles | `dashboard/pages/device_profiles.py` | Fingerprint trust, users, locations, resources, and anomalies | Relationship data reconciles with API | Designed; implementation not started |
| Attack Heatmap | `dashboard/pages/attack_heatmap.py` | Time/geography/entity-type matrices with meaningful aggregation | Aggregates match source alert queries | Designed; implementation not started |
| Explainability | `dashboard/pages/explainability.py` | Risk waterfall, feature evidence, expected versus observed | Every displayed reason traceable to persisted evidence | Designed; implementation not started |
| Analyst Investigation | `dashboard/pages/investigation.py` | Alert timeline, related entities/events, notes, and dispositions | End-to-end disposition audit test passes | Designed; implementation not started |
| System Health | `dashboard/pages/system_health.py` | Throughput, latency, queue depth, model versions, drift, and failures | Metrics update and readiness states are correct | Designed; implementation not started |
| Dark theme, charts, filtering, search | `dashboard/theme`, `components`, `charts` | Shared design tokens and reusable accessible controls | Visual QA; all tables/charts support required interactions | Designed; implementation not started |
| Continuous event replay | `streaming/replay` | Time-scaled deterministic replay with ordering, backpressure, and restart cursor | No event loss/duplication in recovery test; target rate sustained | Designed; implementation not started |
| Automatic dashboard updates | `streaming/publishers`, API, dashboard client | WebSocket live feed plus cursor-based recovery polling | p95 event-to-dashboard latency target met | Designed; implementation not started |
| Architecture and system documentation | `docs/architecture` | C4-style diagrams, ADRs, deployment and data-flow documents | Required documents exist and match implementation | Milestone 1 baseline designed |
| API documentation | FastAPI OpenAPI plus `docs/api` | Typed versioned schemas, examples, errors, auth, and pagination | OpenAPI contract validation passes | Designed; implementation not started |
| Installation and README | Root `README.md`, `docs/operations` | Local, Docker, configuration, demo, troubleshooting | Clean-machine installation rehearsal succeeds | Designed; implementation not started |
| Model documentation | `docs/models` | Model cards, feature schema, metrics, limits, and provenance | Model artifact cannot be promoted without model card | Designed; implementation not started |
| Future improvements and limitations | Root README and architecture docs | Explicit trade-offs, production migration path, known limitations | Sections reviewed before release | Designed; implementation not started |
| Unit and integration tests | `backend/tests`, `dashboard/tests` | Unit, integration, contract, scenario, performance, and property tests | CI passes; coverage target at least 85% for core/application | Designed; implementation not started |
| Docker support | `docker`, `docker-compose.yml` | Separate API, dashboard, and simulator services with health checks | Compose stack starts and passes smoke test | Designed; implementation not started |
| Requirements and environment variables | `pyproject.toml`, requirements files, `.env.example` | Pinned compatible dependencies; validated settings with safe defaults | Dependency install and configuration validation pass | Designed; implementation not started |
| Configuration file | `config` | Layered YAML plus environment overrides and secret exclusion | Config precedence and invalid-value tests pass | Designed; implementation not started |
| Clean Architecture and SOLID | Package boundaries and import rules | Ports/adapters, composition root, focused services, dependency inversion | Architecture dependency test passes | Designed; implementation not started |
| Maximum 400 lines per file | Entire repository | CI line-count quality gate with justified data-file exclusions | Zero source files over 400 lines | Designed; implementation not started |
| Typing, docstrings, reusable code | Entire Python repository | Strict static analysis, documented public and private functions, shared abstractions | Type check, lint, and docstring checks pass | Designed; implementation not started |

## Platform-level evaluation gates

Final operating thresholds will be measured on a held-out, time-ordered synthetic
evaluation set and reported both overall and by attack and entity type.

| Quality dimension | Initial acceptance target |
|---|---|
| Mature-profile false-positive rate | At most 3% at the selected operating threshold |
| Known-attack macro recall | At least 85%, with no attack family below 70% |
| Classification macro-F1 | At least 0.80 |
| Alert explanation completeness | 100% |
| Event processing latency | p95 below 250 ms on documented reference hardware |
| Event-to-dashboard visibility | p95 below 2 seconds |
| Sustained MVP replay throughput | At least 100 events/second |
| Core/application test coverage | At least 85% |
| Ground-truth leakage | Zero label access in operational feature/detection paths |

Targets are quality gates, not claims of current performance. Actual measurements
must be published with dataset seed, configuration, split method, and hardware.
