#!/usr/bin/env bash
set -e

# Basic development database setup for Bee CD.
# - Starts postgres via docker compose if available.
# - Creates databases/users and grants permissions.
# - Runs the initial hive migration.
# Run from anywhere; it will cd to the repo root.

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$SCRIPT_DIR/.."

DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_SUPERUSER=${DB_SUPERUSER:-pg}
DB_SUPERPASSWORD=${DB_SUPERPASSWORD:-pass}
CRUD_DB=${CRUD_DB:-crud}

HIVE_DB=${HIVE_DB:-hive}
HIVE_USER=${HIVE_USER:-hive_user}
HIVE_PASSWORD=${HIVE_PASSWORD:-pass}

HQ_USER=${HQ_USER:-hq_user}
HQ_PASSWORD=${HQ_PASSWORD:-pass}

AVERSION_DB=${AVERSION_DB:-aversion}
AVERSION_USER=${AVERSION_USER:-aversion}
AVERSION_PASSWORD=${AVERSION_PASSWORD:-pass}

echo "Checking for psql..."
if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required. Install postgres client tools and retry." >&2
  exit 1
fi

echo "Checking database connectivity at $DB_HOST:$DB_PORT..."
if ! PGPASSWORD="$DB_SUPERPASSWORD" psql -h "$DB_HOST" -U "$DB_SUPERUSER" -p "$DB_PORT" -d postgres -c "SELECT 1" >/dev/null 2>&1; then
  echo "No database reachable at $DB_HOST:$DB_PORT."
  if [ -f docker-compose.yaml ] || [ -f docker-compose.yml ]; then
    read -r -p "Start postgres here with docker compose? [y/N]: " answer
    case "$answer" in
      y|Y)
        if command -v docker >/dev/null 2>&1; then
          if docker compose version >/dev/null 2>&1; then
            docker compose up -d
          elif command -v docker-compose >/dev/null 2>&1; then
            docker-compose up -d
          else
            echo "docker compose not found; start postgres yourself." >&2
            exit 1
          fi
        else
          echo "docker not found; start postgres yourself." >&2
          exit 1
        fi
      ;;
      *)
        echo "Database not started. Exiting." >&2
        exit 1
      ;;
    esac
    echo "Waiting for database to become available..."
    for i in {1..10}; do
      if PGPASSWORD="$DB_SUPERPASSWORD" psql -h "$DB_HOST" -U "$DB_SUPERUSER" -p "$DB_PORT" -d postgres -c "SELECT 1" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  else
    echo "No compose file found here. Start a database at $DB_HOST:$DB_PORT and rerun." >&2
    exit 1
  fi
fi

export PGPASSWORD="$DB_SUPERPASSWORD"

psql_super() {
  local db="$1"; shift
  local cmd="$*"
  psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$DB_SUPERUSER" -p "$DB_PORT" -d "$db" -c "$cmd"
}

echo "Creating databases and users..."

# create databases (cannot be done inside DO)
if ! psql_super postgres "SELECT 1 FROM pg_database WHERE datname='$HIVE_DB'" | grep -q 1; then
  psql_super postgres "CREATE DATABASE \"$HIVE_DB\""
fi
if ! psql_super postgres "SELECT 1 FROM pg_database WHERE datname='$AVERSION_DB'" | grep -q 1; then
  psql_super postgres "CREATE DATABASE \"$AVERSION_DB\""
fi

# create/update roles
if ! psql_super postgres "SELECT 1 FROM pg_roles WHERE rolname='$HIVE_USER'" | grep -q 1; then
  psql_super postgres "CREATE USER $HIVE_USER WITH PASSWORD '$HIVE_PASSWORD'"
else
  psql_super postgres "ALTER ROLE $HIVE_USER WITH PASSWORD '$HIVE_PASSWORD'"
fi
if ! psql_super postgres "SELECT 1 FROM pg_roles WHERE rolname='$HQ_USER'" | grep -q 1; then
  psql_super postgres "CREATE USER $HQ_USER WITH PASSWORD '$HQ_PASSWORD'"
else
  psql_super postgres "ALTER ROLE $HQ_USER WITH PASSWORD '$HQ_PASSWORD'"
fi
if ! psql_super postgres "SELECT 1 FROM pg_roles WHERE rolname='$AVERSION_USER'" | grep -q 1; then
  psql_super postgres "CREATE USER $AVERSION_USER WITH PASSWORD '$AVERSION_PASSWORD'"
else
  psql_super postgres "ALTER ROLE $AVERSION_USER WITH PASSWORD '$AVERSION_PASSWORD'"
fi

# grants for hive db
psql_super postgres "GRANT ALL PRIVILEGES ON DATABASE $HIVE_DB TO $HIVE_USER"
psql_super postgres "GRANT CONNECT ON DATABASE $HIVE_DB TO $HQ_USER"
psql_super "$HIVE_DB" "GRANT ALL ON SCHEMA public TO $HIVE_USER"
psql_super "$HIVE_DB" "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $HIVE_USER"
psql_super "$HIVE_DB" "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $HIVE_USER"
psql_super "$HIVE_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $HIVE_USER"
psql_super "$HIVE_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $HIVE_USER"
psql_super "$HIVE_DB" "GRANT ALL ON SCHEMA public TO $HQ_USER"
psql_super "$HIVE_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $HQ_USER"
psql_super "$HIVE_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $HQ_USER"

# grants for aversion db
psql_super postgres "GRANT ALL PRIVILEGES ON DATABASE $AVERSION_DB TO $AVERSION_USER"
psql_super "$AVERSION_DB" "GRANT ALL ON SCHEMA public TO $AVERSION_USER"
psql_super "$AVERSION_DB" "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $AVERSION_USER"
psql_super "$AVERSION_DB" "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $AVERSION_USER"
psql_super "$AVERSION_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $AVERSION_USER"
psql_super "$AVERSION_DB" "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $AVERSION_USER"

echo "Running initial hive migration..."
PGPASSWORD="$HIVE_PASSWORD" psql -v ON_ERROR_STOP=1 -h "$DB_HOST" -U "$HIVE_USER" -d "$HIVE_DB" -p "$DB_PORT" -f hive/migrations/20241215000001_initial_schema.sql

echo "Done"
