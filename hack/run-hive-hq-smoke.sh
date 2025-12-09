#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# ---- Config (override by exporting env vars before running) ----
: "${AXUM_HOST:=127.0.0.1}"
: "${AXUM_PORT:=8080}"

: "${DATABASE_HOST:=localhost}"
: "${DATABASE_HOST_RO:=localhost}"
: "${DATABASE_PORT:=5432}"
: "${DATABASE_NAME:=hive}"
: "${DATABASE_USER:=hive_user}"
: "${DATABASE_PASSWORD:=hive-password}"

# JWT secret is required by the API. Generate a dev one if not provided.
if [[ -z "${JWT_SECRET:-}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    export JWT_SECRET
    JWT_SECRET="$(openssl rand -base64 32)"
  else
    echo "ERROR: JWT_SECRET is not set and openssl is not available." >&2
    echo "Set JWT_SECRET to any 32+ byte value." >&2
    exit 1
  fi
fi

export AXUM_HOST AXUM_PORT \
  DATABASE_HOST DATABASE_HOST_RO DATABASE_PORT DATABASE_NAME DATABASE_USER DATABASE_PASSWORD

echo "Checking Postgres at ${DATABASE_HOST}:${DATABASE_PORT} (db=${DATABASE_NAME}, user=${DATABASE_USER})"
if command -v pg_isready >/dev/null 2>&1; then
  pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" >/dev/null
elif command -v nc >/dev/null 2>&1; then
  nc -z "$DATABASE_HOST" "$DATABASE_PORT" >/dev/null
fi

# Quick auth check if psql is available.
if command -v psql >/dev/null 2>&1; then
  PGPASSWORD="$DATABASE_PASSWORD" psql \
    -h "$DATABASE_HOST" -p "$DATABASE_PORT" -U "$DATABASE_USER" -d "$DATABASE_NAME" \
    -c 'select 1' >/dev/null
fi

echo "Building UI (only if needed)"
if [[ ! -f hive-hq/ui/dist/index.html ]]; then
  (cd hive-hq/ui && (test -d node_modules || npm install) && npm run build)
fi

echo
echo "Starting Hive HQ API (serves UI too) on http://${AXUM_HOST}:${AXUM_PORT}"
echo "- Login: click 'Get Dev Token' (dev-mode)"
echo "- Add repo: Repositories -> Add Repository -> paste GitHub URL"
echo

echo "Tip: API-only smoke without UI (in another terminal):"
echo "  curl -s http://${AXUM_HOST}:${AXUM_PORT}/api/free-token"
echo

exec cargo run -p api --features dev-mode
