#!/bin/bash
# Setup MinIO for testing
# This script creates the required test bucket in MinIO

set -e

MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
MINIO_USER="${MINIO_USER:-minioadmin}"
MINIO_PASSWORD="${MINIO_PASSWORD:-minioadmin}"
TEST_BUCKET="${TEST_BUCKET:-test-bucket}"

echo "Waiting for MinIO to be ready..."
max_attempts=30
attempt=0
while ! curl -s -f "${MINIO_ENDPOINT}/minio/health/live" > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ $attempt -ge $max_attempts ]; then
        echo "MinIO failed to start after $max_attempts attempts"
        exit 1
    fi
    echo "Attempt $attempt/$max_attempts: MinIO not ready yet, waiting..."
    sleep 2
done

echo "✓ MinIO is ready"

# Configure MinIO client
export MC_HOST_minio="${MINIO_ENDPOINT}"
export AWS_ACCESS_KEY_ID="${MINIO_USER}"
export AWS_SECRET_ACCESS_KEY="${MINIO_PASSWORD}"

# Create test bucket if it doesn't exist
echo "Creating test bucket: ${TEST_BUCKET}"
docker exec beecd-minio-test mc mb minio/${TEST_BUCKET} || echo "Bucket may already exist"

echo "✓ MinIO setup complete"
echo ""
echo "Environment variables for testing:"
echo "  export AWS_ENDPOINT_URL=${MINIO_ENDPOINT}"
echo "  export AWS_ACCESS_KEY_ID=${MINIO_USER}"
echo "  export AWS_SECRET_ACCESS_KEY=${MINIO_PASSWORD}"
echo "  export AWS_REGION=us-east-1"
echo ""
echo "Run tests with:"
echo "  cargo test --test minio_integration_tests -- --ignored --nocapture"
echo "  cargo test --test error_handling_tests -- --ignored --nocapture"
