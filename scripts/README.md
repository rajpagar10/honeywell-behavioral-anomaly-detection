# SentinelAI Demo Scripts

- Windows: `powershell -ExecutionPolicy Bypass -File scripts/run_demo.ps1`
- Linux/macOS: `bash scripts/run_demo.sh`
- Windows stop: `powershell -ExecutionPolicy Bypass -File scripts/stop_demo.ps1`
- Linux/macOS stop: `bash scripts/stop_demo.sh`

The run script installs the lightweight ML/dashboard dependencies, validates or
generates data, trains the fast model, initializes SQLite, starts the API and
dashboard, and launches a full replay with the demo alert threshold.
