# Delivery Roadmap, Scope, and Risks

## Minimum viable version

The MVP is an end-to-end, evaluable SOC product slice rather than a notebook:

- reproducible organization and all seven attack generators;
- operational event/ground-truth separation;
- SQLite schema, migrations, repositories, and model registry;
- individual, department, entity-type, and organization profiles;
- decay, rolling windows, cold-start blending, and suspicious-event quarantine;
- deterministic rules, Isolation Forest, Random Forest, and GRU enabled by
  default;
- complete selectable One-Class SVM, autoencoder, XGBoost, LightGBM, LSTM, and
  Transformer adapters delivered before final compliance sign-off;
- calibrated fusion, `0–100` risk, and evidence-backed explanations;
- versioned FastAPI endpoints and live/cursor recovery;
- all ten polished Streamlit SOC pages;
- deterministic continuous replay;
- unit, integration, contract, scenario, and smoke tests;
- Docker Compose, environment/configuration, README, and operating documents.

The MVP operating profile favors explainability and CPU reliability. It does not
claim distributed scalability.

## Advanced version

The advanced version extends the compliant MVP with:

- multi-model champion/challenger scoring and automated promotion gates;
- campaign correlation across identities, devices, sources, and resources;
- graph-derived lateral movement features;
- batched GPU inference and larger Transformer context;
- drift-triggered shadow retraining and safe canary evaluation;
- richer analyst feedback governance and alert suppression policies;
- signed artifacts, OIDC/RBAC integration, and retention controls;
- PostgreSQL/TimescaleDB and Kafka-compatible adapters;
- horizontally scalable scoring workers and centralized observability;
- extended OT/ICS protocol features and external SIEM integrations.

## Implementation roadmap

### Milestone 1 — Inspection and architecture

Scope:

- inspect repository;
- map every requirement;
- define architecture, data flow, models, risks, and roadmap.

Acceptance:

- repository state is evidence-based;
- traceability assigns every requirement to a module and metric;
- no application implementation is created;
- user approves architecture and stated assumptions.

Status: complete, awaiting approval.

### Milestone 2 — Repository foundation and contracts

Scope:

- initialize the proposed project structure and Git-safe defaults;
- establish dependency manifests, configuration, logging, typing, and linting;
- define domain entities, enums, ports, API schemas, and database migrations;
- add architecture-boundary and configuration tests;
- add container skeletons that run real health endpoints.

Acceptance:

- clean installation succeeds on Python 3.11;
- configuration precedence and validation tests pass;
- migration creates every approved table and index;
- domain has no framework imports;
- `/health` and `/ready` contracts pass;
- source-file length gate passes.

Approval gate: stop before synthetic behavior implementation.

### Milestone 3 — Synthetic data generator

Scope:

- create organization and unique entity profiles;
- implement normal behavior and all seven attack scenarios;
- implement deterministic seeds, configuration, exports, and isolated labels;
- add schema, distribution, scenario-invariant, and leakage tests.

Acceptance:

- all required entity types and fields are generated;
- every attack passes scenario-specific invariants;
- configured attack prevalence is reproduced within tolerance;
- same seed/config yields the same dataset;
- operational inference data contains no labels;
- generated dataset has a documented data-quality report.

Approval gate: demonstrate sample data and test report.

### Milestone 4 — Behavioral profiling

Scope:

- implement temporal, resource, device, authentication, geography, session, and
  transition profiles;
- implement hierarchy, maturity blending, decay, windows, and quarantine;
- persist and version profiles;
- implement PSI, JSD, and Page-Hinkley drift signals.

Acceptance:

- controlled fixtures match batch statistical references;
- profile updates are idempotent and event-time safe;
- cold-start blend shifts smoothly toward the individual;
- suspicious events cannot immediately poison a profile;
- benign synthetic shift adapts and reduces post-adaptation false positives.

Approval gate: present profiles and cold-start/drift evaluation.

### Milestone 5 — Unknown and sequence anomaly detection

Scope:

- build shared preprocessing and model lifecycle contracts;
- implement Isolation Forest, One-Class SVM, and autoencoder;
- implement rules and transition surprise;
- implement LSTM, GRU, and Transformer sequence detectors;
- add artifact persistence, calibration, evaluation, and model cards.

Acceptance:

- all model adapters pass the same lifecycle contract suite;
- no training/test or sequence-window leakage;
- scores are calibrated and thresholded on held-out data;
- per-model PR-AUC, FPR, recall, latency, and resource use are reported;
- saved artifacts reproduce predictions within tolerance.

Approval gate: approve default detector configuration.

### Milestone 6 — Known attack classification

Scope:

- implement Random Forest, XGBoost, and LightGBM adapters;
- handle imbalance, calibrate probabilities, compare candidates;
- create promotion criteria and confusion/per-attack reports.

Acceptance:

- all attack families appear in evaluation;
- macro-F1 target is at least 0.80;
- macro recall target is at least 85%, with no family below 70%;
- calibration and latency are reported;
- champion selection is reproducible and justified.

Approval gate: approve classifier and operating thresholds.

### Milestone 7 — Risk and explainability

Scope:

- implement versioned risk policy and ensemble fusion;
- implement model-specific feature contributions;
- generate persisted explanations, severity, and correlated alerts;
- implement deduplication, cooldown, and analyst disposition.

Acceptance:

- scores are bounded and monotonic under risk-increasing inputs;
- all required risk factors are represented;
- every alert has traceable observed/expected evidence and versions;
- duplicate events and correlated findings do not create alert storms;
- mature-profile false-positive target is at most 3% on held-out data.

Approval gate: review representative alerts and evidence.

### Milestone 8 — SOC dashboard

Scope:

- build shared dark theme, API client, components, charts, filters, and search;
- implement Overview, Live Events, Alerts, Risk Timeline, User Profiles, Device
  Profiles, Attack Heatmap, Explainability, Investigation, and System Health;
- add responsive layout, empty/error/loading states, and accessibility checks.

Acceptance:

- all ten pages are navigable and backed only by APIs;
- all chart aggregates reconcile with API fixtures;
- alert-to-evidence and entity investigation workflows are complete;
- filters and search behave consistently;
- visual QA confirms legibility at target resolutions.

Approval gate: dashboard walkthrough and screenshots.

### Milestone 9 — Near-real-time simulation

Scope:

- add paced replay, ordering, batching, backpressure, and recovery cursor;
- publish committed updates over WebSocket;
- integrate auto-refresh and reconnect in the dashboard;
- add latency, throughput, loss, duplicate, and recovery tests.

Acceptance:

- sustained replay reaches at least 100 events/second;
- p95 event processing is below 250 ms on recorded reference hardware;
- p95 dashboard visibility is below two seconds;
- reconnect recovers all committed events without duplicate profile updates;
- system health shows live operational metrics.

Approval gate: live end-to-end demonstration.

### Milestone 10 — Release documentation and deployment

Scope:

- complete architecture, data flow, API, model, operations, installation,
  security, limitations, and future-improvement documentation;
- finalize Dockerfiles, Compose, environment examples, health checks, and scripts;
- run complete test, security, quality, and clean-install rehearsals.

Acceptance:

- Compose starts API, dashboard, and simulator from a clean checkout;
- OpenAPI and configuration references match runtime behavior;
- all tests and quality gates pass;
- demo runbook reproduces the evaluated scenario;
- all requirements have evidence and no unresolved “not started” trace entries.

Approval gate: final release candidate review.

## Technical risks and fallbacks

| Risk | Impact | Early control | Fallback plan |
|---|---|---|---|
| Synthetic data is too easy or leaks attack signatures | Inflated metrics and poor credibility | Natural-prevalence test set, invariant review, time split, leakage tests | Harden scenarios, hide generator-only fields, add noise and unseen campaign variants |
| Rare attacks produce unstable evaluation | Misleading aggregate scores | Minimum evaluation support and confidence intervals | Increase evaluation-only samples while preserving a separate natural-prevalence set |
| Profile poisoning | Attack becomes accepted as normal | Score-before-update, quarantine, analyst feedback provenance | Roll back profile version and rebuild excluding compromised interval |
| Cold-start false positives | New identities overwhelm SOC | Hierarchical priors, wider uncertainty, multi-signal threshold | Run peer-only baseline until maturity threshold |
| Legitimate behavior drift appears malicious | Persistent alert noise | Decay, multi-signal drift, cohort comparison | Temporarily widen affected cohort thresholds and recalibrate in shadow mode |
| Adaptive learning hides low-and-slow attack | Reduced recall | Multi-window aggregates and quarantine suspicious observations | Freeze affected feature updates and investigate from last trusted profile |
| One-Class SVM does not scale | Training/inference delay | Cohort size and latency guardrails | Use Isolation Forest or autoencoder as active detector; retain OCSVM benchmark |
| Deep sequence models lack data | Overfit and unstable explanations | Time split, regularization, early stopping, simple transition baseline | Keep GRU/Transformer in shadow; use transition graph plus tabular ensemble |
| Classifier overfits generator artifacts | Poor unknown-variant generalization | Scenario variants and hold out attack parameter ranges | Rely on anomaly/rule ensemble; regenerate with domain randomization |
| Score calibration differs by entity type | Inconsistent severity | Segment calibration and calibration-error monitoring | Use conservative per-segment thresholds or rule-led scoring |
| SQLite write contention | Lost latency target | WAL, single writer, batching, short transactions | Reduce noncritical metric writes; switch repository adapter to PostgreSQL |
| WebSocket disconnect loses UI events | Incomplete live view | Durable commit cursor | Recover incrementally over REST and resume subscription |
| Streamlit rerun/state limitations | Fragile investigation UX | Central state wrapper and isolated components | Use cursor polling for reliability; preserve API for future React client |
| ML dependency conflicts or heavy images | Build failures | Python 3.11, locked compatible versions, CPU wheels | Separate optional training image from lean inference image |
| Unsafe model artifact loading | Code execution risk | Trusted paths, hash manifests, controlled formats | Refuse artifact and retain last verified model |
| Scope pressure reduces quality | Incomplete modules or polish | Approval-gated vertical milestones and measurable acceptance | Deliver default production path first; advanced adapters follow before compliance sign-off |
| Hardware-dependent latency targets | Unfair or irreproducible claim | Record CPU, memory, batch, data size, and model version | Publish measured results and tune operating profile without hiding variance |

## Assumptions requiring approval

1. **Event contract extension:** the stated schema is treated as the required
   minimum. `event_id`, `auth_outcome`, `department`, `resource_sensitivity`,
   transfer-volume, destination, and schema-version fields may be added because
   several requested attacks and profile measures cannot be represented
   faithfully without them.
2. **Label separation:** exported evaluation datasets may offer an explicitly
   requested joined `label` view, but online events and the operational events
   table will never contain the label.
3. **Dashboard technology:** Streamlit is the sole MVP frontend. A separate
   JavaScript frontend is not planned because Streamlit is explicitly required.
4. **Python baseline:** Python 3.11 is used for the broadest ML dependency
   compatibility.
5. **Initial deployment:** SQLite is a supported single-node demonstration
   database, not a claim of distributed enterprise scale. Ports preserve the
   migration path.
6. **Default models:** Isolation Forest, Random Forest, and GRU are the default
   operating set. Every requested alternative will be fully implemented and
   selectable, but running every model on every event is not required.
7. **Performance gates:** latency and throughput targets are measured on and
   reported with the available reference hardware.
8. **Synthetic geography:** fictional identities and reserved IP ranges are used;
   geographic city coordinates may be based on public reference data.

No assumption authorizes implementation until Milestone 1 is approved.
