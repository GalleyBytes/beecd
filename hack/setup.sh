#!/usr/bin/env bash
# The e2e testing harness is not yet complete. This is a setup script
# that prepares the environment for e2e tests.
#
# Run from repo root
set -euo pipefail

echo "=== BeeCD E2E Setup ==="
echo ""

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-k3d-mycluster}"
E2E_NAMESPACE="${E2E_NAMESPACE:-beecd-test}"
DEPLOY_NAMESPACE="${DEPLOY_NAMESPACE:-beecd}"
HIVE_PASSWORD="${HIVE_PASSWORD:-LxsWR00gl@zxiithzLWwoEsWLwbHfDHWEgxj7JJ%EvS1ffO*FskGM1XXkHp&KdPoYBuF%zwAZpKVFQd5^oI%9QltJ%m8z#lIGoYPskwrS&%5o4*2gcrSyBnWfT!NgLH7Lj^@lalqtZb@jGRvrU%GJ8T^Z6VEKY9*#3G#o&AVKa7GWWx6BKMtRDI*h^gXhpUoFxz7BVXas8kE542wSDV9Lzblb%0nY%eammzFs@iANydWv&IbtL7LoaA!1QQ79bnB}"

echo "Configuration:"
echo "  CLUSTER_NAME: $CLUSTER_NAME"
echo "  E2E_NAMESPACE: $E2E_NAMESPACE"
echo "  DEPLOY_NAMESPACE: $DEPLOY_NAMESPACE"
echo ""

# 1. Database initialization
echo "Step 1/5: Initializing database..."
if ! command -v psql >/dev/null 2>&1; then
    echo "  ⚠️  psql not found, skipping database setup"
    echo "  Run ./hack/setup-dev-db.sh manually if needed"
else
    ./hack/setup-dev-db.sh
fi
echo ""

# 2. Create namespace for stack
echo "Step 2/5: Creating deploy namespace '$DEPLOY_NAMESPACE'..."
kubectl create namespace "$DEPLOY_NAMESPACE" 2>/dev/null || echo "  (already exists)"
echo ""

# 3. Generate GPG secret
echo "Step 3/5: Generating GPG secret for SOPS..."
if ! command -v gpg >/dev/null 2>&1; then
    echo "  ⚠️  gpg not found, skipping GPG secret generation"
    echo "  Run ./hack/generate-sops-gpg-secret.sh --namespace $DEPLOY_NAMESPACE --apply --force manually"
else
    ./hack/generate-sops-gpg-secret.sh --namespace "$DEPLOY_NAMESPACE" --apply --force
fi
echo ""

# 3b. Generate JWT secret
echo "Step 3b/5: Generating JWT secret..."
./hack/generate-jwt-secret.sh --namespace "$DEPLOY_NAMESPACE" --apply --force
echo ""

# 4. Create agent user
echo "Step 4/5: Creating agent user in database..."
if ! command -v psql >/dev/null 2>&1; then
    echo "  ⚠️  psql not found, skipping agent user creation"
    echo "  Run ./hack/create-agent-user.sh manually"
else
    DB_HOST="${DB_HOST:-localhost}" \
    DB_PORT="${DB_PORT:-5432}" \
        ./hack/create-agent-user.sh "$CLUSTER_NAME" "$HIVE_PASSWORD"
fi
echo ""

# 5. Create test namespace
echo "Step 5/5: Creating test namespace '$E2E_NAMESPACE'..."
kubectl create namespace "$E2E_NAMESPACE" 2>/dev/null || echo "  (already exists)"
kubectl label namespace "$E2E_NAMESPACE" beecd/register=true --overwrite
echo ""

echo "=== Setup Complete ==="

## TODO Create the e2e testing harness
