#!/usr/bin/env bash
set -e

# Create or update agent user credentials for authentication with Hive.
# Usage: ./create-agent-user.sh CLUSTER_NAME PASSWORD

if [ $# -ne 2 ]; then
  echo "Usage: $0 CLUSTER_NAME PASSWORD"
  echo "Example: $0 my-cluster my-secure-password"
  exit 1
fi

CLUSTER_NAME="$1"
PASSWORD="$2"

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-hive_user}
DB_PASSWORD=${DB_PASSWORD:-pass}
DB_NAME=${DB_NAME:-hive}

echo "Creating/updating agent user '$CLUSTER_NAME' in database '$DB_NAME'..."

PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -p "$DB_PORT" \
  -v cluster_name="$CLUSTER_NAME" \
  -v password="$PASSWORD" \
<< 'SQL'
-- Enable pgcrypto extension if not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Insert or update the agent user with bcrypt-hashed password
INSERT INTO users (id, name, hash)
VALUES (
  gen_random_uuid(),
  :'cluster_name',
  crypt(:'password', gen_salt('bf', 13))
)
ON CONFLICT (name) DO UPDATE SET hash = EXCLUDED.hash;
SQL

echo "✓ Agent user '$CLUSTER_NAME' created/updated successfully"
echo ""
echo "Configure your agent with these environment variables:"
echo "  export CLUSTER_NAME=$CLUSTER_NAME"
echo "  export HIVE_PASSWORD=$PASSWORD"

