# SentinelAI Presentation Content

**AI-Powered Behavioral Threat Detection & Investigation Platform**

Developed for the Honeywell Campus Connect Hackathon.

**Source code:** [GitHub repository](https://github.com/rajpagar10/honeywell-behavioral-anomaly-detection)

## Slide 1 - Title Page

- **Idea:** SentinelAI
- **Problem statement:** AI-powered behavioral anomaly detection for cybersecurity
- **Theme:** Cybersecurity
- **Category:** Software
- **Purpose:** Detect, explain, and investigate abnormal user and device behavior

## Slide 2 - Proposed Solution

- Learn normal behavior for users, service accounts, IoT devices, and edge devices.
- Combine unknown-anomaly ML, deterministic attack rules, and attack classification.
- Convert evidence into explainable 0-100 risk scores and ranked SOC alerts.
- Handle new entities through peer baselines and legitimate change through trusted decay.
- Give analysts a grounded AI investigation copilot with deterministic fallback.

**Why it is different:** SentinelAI connects detection, explanation, adaptation,
real-time replay, and analyst investigation in one working SOC platform.

## Slide 3 - Technical Approach

**Data flow**

Synthetic events -> behavioral profiles -> sequential features -> detection and
classification -> explainable risk -> SQLite -> FastAPI -> SOC dashboard

**Detection**

- Isolation Forest discovers multivariate unknown behavior.
- Rolling failures, prior events, travel velocity, and transition rarity encode sequence.
- Deterministic rules identify seven attack families with precise evidence.
- Class-weighted Random Forest classifies attack type under imbalance.

**Technology**

Python, FastAPI, Streamlit, scikit-learn, Pandas, NumPy, SQLite, Plotly, Docker,
Ollama, pytest, Ruff, mypy, and GitHub Actions.

## Slide 4 - Feasibility and Viability

- Working one-command demo generates, trains, serves, and replays 2,000 events.
- Held-out precision 94.62%, recall 97.78%, F1 96.17%, and PR-AUC 97.38%.
- False-positive rate is 0.17%; top-1% analyst-budget precision is 100%.
- Cold-start confidence reduction and peer baselines prevent overconfident alerts.
- Trusted decay adapts profiles while anomalous events cannot poison the baseline.
- SQLite and polling keep the demo reliable; durable streaming and RBAC are clear production upgrades.

## Slide 5 - Artifacts and Working Prototype

- White multi-workspace SOC dashboard with live operations and ranked alerts
- Alert details with evidence, risk contributions, actions, and analyst feedback
- Grounded AI Investigation Copilot with Ollama and automatic template fallback
- FastAPI endpoints, SQLite replay state, Docker support, and startup scripts
- Reproducible datasets, saved model artifacts, evaluation results, and 37 passing tests
- Public source: github.com/rajpagar10/honeywell-behavioral-anomaly-detection

## Slide 6 - Research and References

- Liu, Ting, and Zhou - Isolation Forest
- Breiman - Random Forests
- scikit-learn documentation - IsolationForest and RandomForestClassifier
- FastAPI documentation - typed asynchronous APIs
- Streamlit and Plotly documentation - interactive SOC visualization
- Ollama documentation - local open-source model serving
- Complete implementation and evidence:
  github.com/rajpagar10/honeywell-behavioral-anomaly-detection
