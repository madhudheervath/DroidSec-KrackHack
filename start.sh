#!/usr/bin/env bash

set -euo pipefail

# Railway/container default paths. Fall back to repo root when run locally.
APP_ROOT="/app"
if [[ ! -d "$APP_ROOT/backend" ]] || [[ ! -d "$APP_ROOT/frontend" ]]; then
  APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  echo "Using local app root: $APP_ROOT"
fi

BACKEND_DIR="$APP_ROOT/backend"
FRONTEND_DIR="$APP_ROOT/frontend"
APP_PORT="${PORT:-3000}"
BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"

# Prefer project venv when available (local dev), otherwise system python (container).
if [[ -x "$BACKEND_DIR/venv/bin/python" ]]; then
  BACKEND_PYTHON="$BACKEND_DIR/venv/bin/python"
else
  BACKEND_PYTHON="python3"
fi

cleanup() {
  if [[ -n "${BACKEND_PID:-}" ]]; then
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "Starting backend on ${BACKEND_HOST}:${BACKEND_PORT}..."
cd "$BACKEND_DIR"
PORT="$BACKEND_PORT" "$BACKEND_PYTHON" main.py &
BACKEND_PID=$!

echo "Waiting for backend health endpoint..."
READY=0
for _ in $(seq 1 30); do
  if curl -fsS "http://${BACKEND_HOST}:${BACKEND_PORT}/" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [[ "$READY" -ne 1 ]]; then
  echo "Backend failed to start. Exiting."
  exit 1
fi

echo "Starting frontend on 0.0.0.0:${APP_PORT}..."
cd "$FRONTEND_DIR"
if [[ ! -f ".next/BUILD_ID" ]]; then
  echo "No production frontend build found. Running npm run build..."
  npm run build
fi
npx next start -H 0.0.0.0 -p "$APP_PORT"
