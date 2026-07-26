# Architecture

```mermaid
flowchart TB
  subgraph Offline["Offline preparation"]
    GEN["Synthetic organization + attacks"] --> EVENTS["events.csv"]
    GEN --> LABELS["labels.csv — evaluation only"]
    EVENTS --> PROFILE["Entity and peer profiles"]
    PROFILE --> FEATURES["Sequential features"]
    FEATURES --> IF["Isolation Forest"]
    FEATURES --> RF["Class-weighted Random Forest"]
    LABELS --> EVAL["Evaluation"]
    IF --> EVAL
    RF --> EVAL
  end

  subgraph Online["Near-real-time SOC path"]
    REPLAY["Sequential event replay"] --> FE["Feature + rolling history"]
    FE --> UNKNOWN["Isolation Forest"]
    FE --> RULES["Deterministic attack rules"]
    FE --> CLASSIFY["Attack classifier"]
    UNKNOWN --> RISK["0–100 explainable risk"]
    RULES --> RISK
    CLASSIFY --> RISK
    RISK --> SQLITE["SQLite events, alerts, replay state"]
    SQLITE --> API["FastAPI /api/v1"]
    API --> DASH["Streamlit analyst dashboard"]
  end
```

Cold-start resolution follows entity → department → entity type → organization.
Trusted normal events update recent baselines through exponential decay;
anomalous events are excluded from profile updates.
