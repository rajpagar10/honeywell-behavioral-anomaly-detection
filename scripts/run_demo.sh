#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
if [[ "${1:-}" != "--skip-install" ]]; then
  .venv/bin/python -m pip install -e ".[ml,dashboard]"
fi

if [[ ! -f data/samples/honeywell_demo/manifest.json ]]; then
  .venv/bin/badp generate-data --generator-config config/generator/demo.yaml \
    --output data/samples/honeywell_demo
fi
.venv/bin/badp train-model --dataset data/samples/honeywell_demo \
  --training-config config/training/fast.yaml --output artifacts/models/fast
.venv/bin/badp init-db

mkdir -p artifacts/demo
export BADP_INTELLIGENCE__ALERT_THRESHOLD=40
export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
.venv/bin/badp serve >artifacts/demo/api.log 2>&1 &
API_PID=$!

for _ in {1..60}; do
  if .venv/bin/python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"; then
    break
  fi
  sleep 0.5
done

.venv/bin/streamlit run dashboard/app.py --server.port 8501 \
  >artifacts/demo/dashboard.log 2>&1 &
DASHBOARD_PID=$!
.venv/bin/python -c \
  "import json,urllib.request; data=json.dumps({'interval_ms':25,'max_events':2000}).encode(); request=urllib.request.Request('http://127.0.0.1:8000/api/v1/replay/start',data=data,headers={'Content-Type':'application/json'},method='POST'); urllib.request.urlopen(request)"

printf '{"api":%s,"dashboard":%s}\n' "$API_PID" "$DASHBOARD_PID" \
  >artifacts/demo/processes.json
echo "Dashboard: http://127.0.0.1:8501"
echo "API docs:  http://127.0.0.1:8000/docs"
echo "Stop with: bash scripts/stop_demo.sh"
