# SentinelAI Presentation Content

**AI-Powered Behavioral Threat Detection & Investigation Platform**

## Slide 1 — The problem

- Static rules miss novel compromise behavior.
- SOC analysts face high alert volume and weak context.
- Users, service identities, IoT, and edge devices behave differently.
- New entities and legitimate change make fixed thresholds unreliable.

## Slide 2 — Proposed solution

- Learn normal behavior for every identity and device.
- Combine unknown-anomaly ML, known-attack rules, and classification.
- Convert evidence into explainable, risk-ranked SOC alerts.
- Replay events near real time in an investigation-ready dashboard.

## Slide 3 — Architecture

- Synthetic generator → profiles → sequential features
- Isolation Forest + deterministic rules + Random Forest
- Explainable risk policy → SQLite → FastAPI → Streamlit
- Ground truth is isolated and used only during evaluation.

## Slide 4 — Data and attack taxonomy

- 2,000 events, 108 entities, four entity types, 1.5% anomalies
- Stable individual schedules, resources, devices, locations, and transitions
- Brute force, impossible travel, credential stuffing, lateral movement
- Device spoofing, low-and-slow exfiltration, insider drift

## Slide 5 — Detection approach

- Isolation Forest discovers multivariate unknown behavior.
- Rolling failures, previous events, travel velocity, and transitions encode sequence.
- Rules provide precise evidence for recognizable attack sequences.
- Class-weighted Random Forest handles attack-type imbalance.

## Slide 6 — Explainability and risk

- 0–100 score combines model, classifier, rule, behavior, resource, device,
  geography, and entity history.
- Every alert lists top contributing factors.
- Concise deterministic explanation—no LLM.
- Recommended analyst actions accelerate triage.

## Slide 7 — Cold start and concept drift

- Fallback: entity → department → entity type → organization.
- Cold-start confidence is explicitly reduced and labeled.
- Trusted behavior updates an exponential-decay recent baseline.
- Anomalies cannot immediately poison the profile.

## Slide 8 — Dashboard and demo

- Executive metrics, live replay, ranked queue, filters, and detail view
- Risk, attack, entity, and confusion-matrix charts
- Entity history with cold-start and drift state
- API/database/replay system health

## Slide 9 — Results

- Precision 64.29%; recall 100%; F1 78.26%
- PR-AUC 57.71%; false-positive rate 0.85%
- Top-1% alert budget: 50% precision, 33.33% recall
- All seven attacks represented in classification output

## Slide 10 — Limitations and path to production

- Validate calibration on real Honeywell telemetry.
- Add authentication, RBAC, signed artifacts, and audit integration.
- Scale SQLite replay to a durable event bus when volume requires it.
- Use analyst feedback for threshold and profile governance.
