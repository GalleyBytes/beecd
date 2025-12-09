#!/usr/bin/env bash
set -euo pipefail

# generate-jwt-secret.sh
# Generates a secure JWT secret and creates a Kubernetes Secret manifest.
# By default, errors if the secret already exists in the cluster.

NAMESPACE="${NAMESPACE:-default}"
SECRET_NAME="${SECRET_NAME:-hive-jwt}"
KEY_LENGTH="${KEY_LENGTH:-48}"  # 48 bytes = 64 chars base64
OUT_FILE=""
APPLY="false"
FORCE="false"
DRY_RUN="false"

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Generates a JWT secret and optionally applies it to Kubernetes.

Options:
  --namespace NAME      Kubernetes namespace (default: default, env: NAMESPACE)
  --secret-name NAME    Secret name (default: hive-jwt, env: SECRET_NAME)
  --key-length N        Random bytes for secret (default: 48, env: KEY_LENGTH)
  --output FILE         Write manifest to file (default: stdout if not --apply)
  --apply               Apply secret to cluster via kubectl
  --force               Overwrite if secret already exists
  --dry-run             Show what would be created without doing it
  -h, --help            Show this help

Examples:
  # Generate and apply to production namespace
  $0 --namespace beecd --secret-name hive-jwt-prod --apply

  # Generate manifest file only
  $0 --namespace beecd --output deploy/jwt-secret.yaml

  # Force overwrite existing secret
  $0 --namespace beecd --apply --force
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)
      NAMESPACE="$2"; shift 2;;
    --secret-name)
      SECRET_NAME="$2"; shift 2;;
    --key-length)
      KEY_LENGTH="$2"; shift 2;;
    --output)
      OUT_FILE="$2"; shift 2;;
    --apply)
      APPLY="true"; shift;;
    --force)
      FORCE="true"; shift;;
    --dry-run)
      DRY_RUN="true"; shift;;
    -h|--help)
      usage; exit 0;;
    *)
      echo "Unknown argument: $1" >&2; usage; exit 1;;
  esac
done

# Check for required tools
command -v openssl >/dev/null 2>&1 || { echo "Error: openssl not found" >&2; exit 1; }
if [[ "$APPLY" == "true" ]]; then
  command -v kubectl >/dev/null 2>&1 || { echo "Error: kubectl not found" >&2; exit 1; }
fi

# Check if secret already exists (only if applying)
if [[ "$APPLY" == "true" && "$FORCE" != "true" && "$DRY_RUN" != "true" ]]; then
  if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "Error: Secret '$SECRET_NAME' already exists in namespace '$NAMESPACE'" >&2
    echo "Use --force to overwrite" >&2
    exit 1
  fi
fi

# Generate the secret
JWT_SECRET=$(openssl rand -base64 "$KEY_LENGTH")
JWT_SECRET_B64=$(printf "%s" "$JWT_SECRET" | base64)

# Build the manifest
MANIFEST=$(cat <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: $SECRET_NAME
  namespace: $NAMESPACE
type: Opaque
data:
  JWT_SECRET_KEY: $JWT_SECRET_B64
YAML
)

if [[ "$DRY_RUN" == "true" ]]; then
  echo "# DRY RUN - would create:"
  echo "$MANIFEST"
  exit 0
fi

# Output manifest to file if requested
if [[ -n "$OUT_FILE" ]]; then
  echo "$MANIFEST" > "$OUT_FILE"
  echo "Wrote manifest to: $OUT_FILE"
fi

# Apply to cluster if requested
if [[ "$APPLY" == "true" ]]; then
  if [[ "$FORCE" == "true" ]]; then
    echo "$MANIFEST" | kubectl apply -f -
  else
    echo "$MANIFEST" | kubectl create -f -
  fi
  echo "Secret '$SECRET_NAME' created in namespace '$NAMESPACE'"
elif [[ -z "$OUT_FILE" ]]; then
  # No --apply and no --output: print to stdout
  echo "$MANIFEST"
fi
