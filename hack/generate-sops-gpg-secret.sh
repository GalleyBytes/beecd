#!/usr/bin/env bash
set -euo pipefail

# generate-sops-gpg-secret.sh
# Generates a new OpenPGP key using GnuPG, extracts the fingerprint and private key,
# base64-encodes both, and creates a Kubernetes Secret manifest for SOPS.
# By default, errors if the secret already exists in the cluster.

# Requirements: gpg, awk, sed, base64
# Optional: kubectl (for --apply)

NAMESPACE="${NAMESPACE:-default}"
SECRET_NAME="${SECRET_NAME:-sops-gpg}"
KEY_NAME="${KEY_NAME:-hive-sops}"           # UID name
KEY_EMAIL="${KEY_EMAIL:-hive@example.com}"   # UID email
KEY_COMMENT="${KEY_COMMENT:-sops}"           # UID comment
KEY_TYPE="${KEY_TYPE:-RSA}"
KEY_LENGTH="${KEY_LENGTH:-4096}"
EXPIRE="${EXPIRE:-0}"                        # 0 = never
OUT_FILE=""
APPLY="false"
FORCE="false"
DRY_RUN="false"

usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Generates a GPG key for SOPS encryption and optionally applies it to Kubernetes.

Options:
  --namespace NAME      Kubernetes namespace (default: default, env: NAMESPACE)
  --secret-name NAME    Secret name (default: sops-gpg, env: SECRET_NAME)
  --uid-name NAME       GPG key name (default: hive-sops, env: KEY_NAME)
  --uid-email EMAIL     GPG key email (default: hive@example.com, env: KEY_EMAIL)
  --uid-comment TEXT    GPG key comment (default: sops, env: KEY_COMMENT)
  --output FILE         Write manifest to file (default: stdout if not --apply)
  --apply               Apply secret to cluster via kubectl
  --force               Overwrite if secret already exists
  --dry-run             Show what would be created without doing it
  -h, --help            Show this help

Environment variables:
  NAMESPACE, SECRET_NAME, KEY_NAME, KEY_EMAIL, KEY_COMMENT, KEY_TYPE, KEY_LENGTH, EXPIRE

Examples:
  # Generate and apply to production namespace
  $0 --namespace beecd --apply

  # Generate manifest file only
  $0 --namespace beecd --output deploy/sops-secret.yaml

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
    --uid-name)
      KEY_NAME="$2"; shift 2;;
    --uid-email)
      KEY_EMAIL="$2"; shift 2;;
    --uid-comment)
      KEY_COMMENT="$2"; shift 2;;
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
command -v gpg >/dev/null 2>&1 || { echo "Error: gpg not found" >&2; exit 1; }
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

# Create a temporary GNUPG home to avoid contaminating user keyring
GNUPGHOME_TMP="$(mktemp -d)"
export GNUPGHOME="$GNUPGHOME_TMP"
trap 'rm -rf "$GNUPGHOME_TMP"' EXIT

cat >"$GNUPGHOME_TMP/genkey.batch" <<EOF
Key-Type: $KEY_TYPE
Key-Length: $KEY_LENGTH
Subkey-Type: $KEY_TYPE
Subkey-Length: $KEY_LENGTH
Name-Real: $KEY_NAME
Name-Comment: $KEY_COMMENT
Name-Email: $KEY_EMAIL
Expire-Date: $EXPIRE
%no-protection
%commit
EOF

echo "Generating PGP key..." >&2
gpg --batch --generate-key "$GNUPGHOME_TMP/genkey.batch" 2>/dev/null

# Get fingerprint (first fingerprint from this GNUPG home)
FINGER_PRINT=$(gpg --batch --list-keys --with-colons 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
if [[ -z "$FINGER_PRINT" ]]; then
  echo "Error: failed to get fingerprint" >&2; exit 1
fi

# Export private key (ASCII armored)
GPG_KEY_ARMOR=$(gpg --batch --export-secret-keys --armor 2>/dev/null | sed 's/\r$//')
if [[ -z "$GPG_KEY_ARMOR" ]]; then
  echo "Error: failed to export private key" >&2; exit 1
fi

FPR_B64=$(printf "%s" "$FINGER_PRINT" | base64)
KEY_B64=$(printf "%s" "$GPG_KEY_ARMOR" | base64)

# Build the manifest
MANIFEST=$(cat <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: $SECRET_NAME
  namespace: $NAMESPACE
type: Opaque
data:
  FINGER_PRINT: $FPR_B64
  GPG_KEY: $KEY_B64
YAML
)

echo "Fingerprint: $FINGER_PRINT" >&2

if [[ "$DRY_RUN" == "true" ]]; then
  echo "# DRY RUN - would create:"
  echo "$MANIFEST"
  exit 0
fi

# Output manifest to file if requested
if [[ -n "$OUT_FILE" ]]; then
  echo "$MANIFEST" > "$OUT_FILE"
  echo "Wrote manifest to: $OUT_FILE" >&2
fi

# Apply to cluster if requested
if [[ "$APPLY" == "true" ]]; then
  if [[ "$FORCE" == "true" ]]; then
    echo "$MANIFEST" | kubectl apply -f -
  else
    echo "$MANIFEST" | kubectl create -f -
  fi
  echo "Secret '$SECRET_NAME' created in namespace '$NAMESPACE'" >&2
elif [[ -z "$OUT_FILE" ]]; then
  # No --apply and no --output: print to stdout
  echo "$MANIFEST"
fi
