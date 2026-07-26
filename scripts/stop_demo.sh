#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
if [[ -f artifacts/demo/processes.json ]]; then
  .venv/bin/python -c \
    "import json,os,signal,pathlib; p=json.loads(pathlib.Path('artifacts/demo/processes.json').read_text()); [os.kill(int(pid), signal.SIGTERM) for pid in p.values()]"
  echo "Demo processes stopped."
else
  echo "No demo process file found."
fi
