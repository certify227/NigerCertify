#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -d "$ROOT/backend/.venv" ]]; then
  python3 -m venv "$ROOT/backend/.venv"
  "$ROOT/backend/.venv/bin/pip" install -r "$ROOT/backend/requirements.txt"
fi

if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  (cd "$ROOT/frontend" && npm install)
fi

echo "Backend → http://127.0.0.1:8000"
echo "Frontend → http://127.0.0.1:5173"
echo "Docs API → http://127.0.0.1:8000/docs"

(cd "$ROOT/backend" && "$ROOT/backend/.venv/bin/uvicorn" app.main:app --reload --port 8000) &
API_PID=$!
trap 'kill $API_PID' EXIT

(cd "$ROOT/frontend" && npm run dev -- --host 0.0.0.0 --port 5173)