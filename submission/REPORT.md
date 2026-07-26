# SentinelAI Hackathon Report

**AI-Powered Behavioral Threat Detection & Investigation Platform**

## Executive summary

The platform demonstrates how behavioral analytics can reduce reliance on
static signatures in a mixed enterprise and industrial environment. It creates
individual normal-behavior profiles, combines unsupervised ML with explainable
sequence rules, and turns detections into ranked SOC alerts.

## Problem and users

Security analysts must identify compromised accounts and devices across noisy
authentication and access telemetry. New entities have little history,
legitimate behavior changes over time, and opaque anomaly scores slow triage.

## Implemented solution

- 2,000 sequential synthetic events across users, service accounts, IoT, and
  edge devices
- Seven configurable attacks with separately stored ground truth
- Entity and peer behavioral baselines
- Rolling and previous-event feature engineering
- Isolation Forest, deterministic rules, and Random Forest classification
- Weighted 0–100 risk with deterministic explanations and response actions
- Cold-start confidence reduction and peer baselines
- Exponential-decay drift tracking protected from anomalous updates
- SQLite, FastAPI, background replay, and Streamlit SOC dashboard

## Detection design

Isolation Forest identifies unknown multivariate deviations. Rules capture
high-value sequences including repeated failures, cross-identity password
attempts, impossible velocity, rare privileged transitions, device/source
conflicts, and sustained transfer behavior. A class-weighted Random Forest
predicts attack type. Rolling history and transition rarity provide a stable
sequence-aware MVP without deep-learning operational risk.

## Explainability

Every alert includes its anomaly score, classifier confidence, rule evidence,
behavioral deviation, asset sensitivity, device novelty, geographic anomaly,
and historical behavior contributions. Human-readable explanations are
deterministic and traceable to observed features. No LLM is used.

## Results

Held-out evaluation contains 600 events and nine anomalies:

| Metric | Result |
|---|---:|
| Precision | 64.29% |
| Recall | 100.00% |
| F1 | 78.26% |
| PR-AUC | 57.71% |
| False-positive rate | 0.85% |
| Top-1% precision / recall | 50.00% / 33.33% |

The system prioritizes recall for high-consequence activity while keeping the
held-out false-positive rate below one percent. Per-attack metrics and the
confusion matrix are included in `submission/results/`.

## Engineering quality

The code uses typed modular packages, validated schemas, configuration through
environment variables/YAML, reproducible seeds, isolated ground truth,
idempotent SQLite migrations, documented APIs, and CI-enforced formatting,
linting, typing, tests, and coverage.

## Limitations and future work

The dataset is synthetic and small; production calibration requires Honeywell
telemetry and analyst feedback. The SQLite replay is intentionally
single-process. Future work includes RBAC, signed model artifacts, distributed
streaming, feedback-driven calibration, model monitoring, and optional deep
sequence ensembles after an operational baseline is established.
