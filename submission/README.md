# SentinelAI Submission Package

**AI-Powered Behavioral Threat Detection & Investigation Platform**

Developed for the Honeywell Campus Connect Hackathon.

## Included

- [`REPORT.md`](REPORT.md): concise hackathon report
- [`PRESENTATION.md`](PRESENTATION.md): presentation-ready 10-slide narrative
- [`ARCHITECTURE.md`](ARCHITECTURE.md): architecture and data-flow diagrams
- [`DEMO.md`](DEMO.md): exact demonstration sequence
- [`results/metrics.json`](results/metrics.json): held-out metrics
- [`results/confusion_matrix.csv`](results/confusion_matrix.csv): sample matrix
- Root [`README.md`](../README.md): setup, operation, and model instructions

## Source instructions

The source remains in the repository root; it is not duplicated here. Install
with `python -m pip install -e ".[dev,ml,dashboard]"`, then use the one-command
demo in `scripts/`.

Excluded intentionally: virtual environments, caches, secrets, runtime
databases, model checkpoints, logs, and unbounded generated datasets.
