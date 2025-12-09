#!/bin/bash
set -e

echo "🚀 Starting MinIO for storage testing..."

# Navigate to script directory
cd "$(dirname "$0")"

# Start MinIO
docker-compose -f docker-compose.minio.yml up -d

echo "⏳ Waiting for MinIO to be healthy..."
until docker-compose -f docker-compose.minio.yml ps | grep -q "healthy"; do
    sleep 1
done

echo "✅ MinIO is ready!"
echo ""
echo "MinIO Console: http://localhost:9001"
echo "Login: minioadmin / minioadmin"
echo ""
echo "To run integration tests:"
echo "  export AWS_ENDPOINT_URL=http://localhost:9000"
echo "  export AWS_ACCESS_KEY_ID=minioadmin"
echo "  export AWS_SECRET_ACCESS_KEY=minioadmin"
echo "  export AWS_REGION=us-east-1"
echo "  cargo test --test minio_integration_tests -- --ignored"
echo ""
echo "To stop MinIO:"
echo "  cd tests/docker && docker-compose -f docker-compose.minio.yml down"
