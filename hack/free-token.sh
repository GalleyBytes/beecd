#!/usr/bin/env bash
set -euo pipefail

# Always run from repo root so `cargo run -p api` works no matter where this script is invoked.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Redirect all messages to stderr by default
exec 3>&1 1>&2

# Configurable settings
NAMESPACE="${NAMESPACE:-beecd-helm}"
HIVE_HQ_SECRET="${HIVE_HQ_SECRET:-beecd-hive-hq}"
HIVE_DB_SECRET="${HIVE_DB_SECRET:-beecd-hive-db}"
GITHUB_SECRET="${GITHUB_SECRET:-beecd-github}"

require_namespace() {
  if ! kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
    echo "ERROR: Kubernetes namespace '${NAMESPACE}' not found" >&2
    echo "Hint: set NAMESPACE to the namespace where beecd is installed." >&2
    echo "Example: NAMESPACE=beecd ./hack/free-token.sh" >&2
    exit 1
  fi
}

get_secret_field_b64() {
  local secret="$1"
  local field="$2"
  local b64

  if ! b64="$(kubectl -n "${NAMESPACE}" get secret "${secret}" -o "jsonpath={.data.${field}}" 2>/dev/null)"; then
    echo "ERROR: Failed to read secret '${secret}' in namespace '${NAMESPACE}'" >&2
    exit 1
  fi

  if [ -z "${b64}" ]; then
    echo "ERROR: Secret '${secret}' field '${field}' is missing/empty in namespace '${NAMESPACE}'" >&2
    exit 1
  fi

  echo "${b64}" | base64 -d
}

# Export environment variables from Kubernetes namespace
echo "# Extracting secrets from ${NAMESPACE} namespace..."

require_namespace

# JWT Secret
export JWT_SECRET="$(get_secret_field_b64 "${HIVE_HQ_SECRET}" "JWT_SECRET")"
if [ "${#JWT_SECRET}" -lt 32 ]; then
  echo "ERROR: JWT_SECRET decoded length is ${#JWT_SECRET} bytes; expected at least 32" >&2
  echo "Check that HIVE_HQ_SECRET='${HIVE_HQ_SECRET}' is correct for namespace '${NAMESPACE}'." >&2
  exit 1
fi
echo "✓ JWT_SECRET"

# Database connection from hive-db secret
export DATABASE_NAME="$(get_secret_field_b64 "${HIVE_DB_SECRET}" "DATABASE_NAME")"
export DATABASE_USER="$(get_secret_field_b64 "${HIVE_DB_SECRET}" "DATABASE_USER")"
export DATABASE_PASSWORD="$(get_secret_field_b64 "${HIVE_DB_SECRET}" "DATABASE_PASSWORD")"
echo "✓ DATABASE_NAME: $DATABASE_NAME"
echo "✓ DATABASE_USER: $DATABASE_USER"
echo "✓ DATABASE_PASSWORD"

# Override host/port for local port-forward
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
echo "✓ DATABASE_HOST: localhost (port-forward)"
echo "✓ DATABASE_PORT: 5432"

# GitHub Token (if needed)
export GITHUB_TOKEN="$(get_secret_field_b64 "${GITHUB_SECRET}" "GHPASS")"
export GITHUB_USER="$(get_secret_field_b64 "${GITHUB_SECRET}" "GHUSER")"
echo "✓ GITHUB_TOKEN"
echo "✓ GITHUB_USER"

echo ""

API_HOST="${API_HOST:-localhost}"

get_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

if [ -z "${API_PORT:-}" ]; then
  API_PORT="$(get_free_port)"
else
  API_PORT="${API_PORT}"
fi

API_URL="http://${API_HOST}:${API_PORT}/api/free-token"
echo "✓ API_PORT: ${API_PORT}"
echo "✓ API_URL: ${API_URL}"

# Start API in background with dev-mode
echo "Starting API server..."
export AXUM_HOST="${AXUM_HOST:-127.0.0.1}"
export AXUM_PORT="${API_PORT}"
API_LOG_FILE="${API_LOG_FILE:-$(mktemp -t beecd-free-token-api.XXXXXX.log)}"
echo "✓ API_LOG_FILE: ${API_LOG_FILE}"

# Capture logs so failures are actionable.
cargo run -p api --features dev-mode >"${API_LOG_FILE}" 2>&1 &
API_PID=$!

# Ensure cleanup no matter what
cleanup() {
  if kill -0 "$API_PID" 2>/dev/null; then
    echo "Stopping API server..."
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait for API to be ready
echo "Waiting for API server to be ready..."
for i in {1..1800}; do
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "ERROR: API server exited during startup"
    echo "--- api log (last 200 lines) ---"
    tail -n 200 "${API_LOG_FILE}" || true
    exit 1
  fi
  if curl -sSf "${API_URL}" >/dev/null 2>&1; then
    echo "API server ready"
    break
  fi
  if [ "$i" -eq 1800 ]; then
    echo "ERROR: API server failed to start"
    echo "--- api log (last 200 lines) ---"
    tail -n 200 "${API_LOG_FILE}" || true
    exit 1
  fi
  sleep 0.5
done

# Fetch token and print to stdout (fd 3)
echo "Fetching token..."
TOKEN=$(curl -sS "${API_URL}" 2>&1)

if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "$TOKEN" >&3
    echo "Done - token retrieved"
else
    echo "ERROR: No token received"
    exit 1
fi
