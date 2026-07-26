# SentinelAI Demonstration Guide

**AI-Powered Behavioral Threat Detection & Investigation Platform**

**Source code:** [GitHub repository](https://github.com/rajpagar10/honeywell-behavioral-anomaly-detection)

## Start

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1
```

Linux/macOS:

```bash
bash scripts/run_demo.sh
```

Open <http://127.0.0.1:8501>.

## Five-minute walkthrough

1. **Executive Overview:** show event, alert, entity, risk, cold-start, and drift
   indicators.
2. **Live Operations:** show replay progress and sequential events.
3. **Alert Investigation:** filter and inspect brute force, impossible travel,
   lateral movement, device spoofing, and low-and-slow exfiltration.
4. Open an alert to show its risk contributions, explanation, and recommended
   actions.
5. **Entity Behavior:** show normal hours, resources, recent history,
   cold-start status, and adaptive drift state.
6. **Model Evaluation:** show precision, recall, F1, PR-AUC, false-positive
   rate, top-1% budget, confusion matrix, and per-attack results.
7. **System Health:** show API, databases, and replay status.

The generated dataset also contains normal behavior, credential stuffing,
insider drift, 11 cold-start entities, and 16 legitimate drift entities.

## Stop

```powershell
powershell -ExecutionPolicy Bypass -File scripts/stop_demo.ps1
```

or:

```bash
bash scripts/stop_demo.sh
```
