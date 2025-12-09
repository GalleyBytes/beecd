.PHONY: test test-db-start test-db-stop test-db-migrate test-unit test-hive test-api test-agent test-all clean help

# ============================================================================
# Database Configuration
# ============================================================================
# Find an available port starting from 5432
POSTGRES_PORT := $(shell for port in $$(seq 5432 5532); do ! nc -z localhost $$port 2>/dev/null && echo $$port && break; done)
POSTGRES_USER := pg
POSTGRES_PASSWORD := pass
POSTGRES_DB := beecd_test
DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:$(POSTGRES_PORT)/$(POSTGRES_DB)
CONTAINER_NAME := beecd-test-db-$(POSTGRES_PORT)

# ============================================================================
# Test Database Management
# ============================================================================
test-db-start:
	@echo "Starting test database on port $(POSTGRES_PORT)..."
	@docker run -d \
		--name $(CONTAINER_NAME) \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRES_DB=$(POSTGRES_DB) \
		-p $(POSTGRES_PORT):5432 \
		postgres:16.4 > /dev/null 2>&1 || true
	@echo "Waiting for database to be ready..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if docker exec $(CONTAINER_NAME) pg_isready -U $(POSTGRES_USER) > /dev/null 2>&1; then \
			echo "Database is ready on port $(POSTGRES_PORT)"; \
			break; \
		fi; \
		sleep 1; \
	done

test-db-migrate: test-db-start
	@echo "Running migrations..."
	@sleep 2
	@for f in $$(ls hive/migrations/*.sql | sort); do \
		echo "Applying $$f"; \
		PGPASSWORD=$(POSTGRES_PASSWORD) psql -v ON_ERROR_STOP=1 -h localhost -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT) \
			-f $$f > /dev/null; \
	done
	@echo "Migrations completed"

test-db-stop:
	@echo "Stopping and removing test databases..."
	@docker ps -a --filter "name=beecd-test-db-" --format "{{.Names}}" | xargs -r docker stop > /dev/null 2>&1 || true
	@docker ps -a --filter "name=beecd-test-db-" --format "{{.Names}}" | xargs -r docker rm > /dev/null 2>&1 || true
	@echo "Test database cleaned up"

# ============================================================================
# Test Targets
# ============================================================================

# Run all tests (default target)
test: test-db-migrate
	@echo "Running all workspace tests with DATABASE_URL=$(DATABASE_URL)..."
	@set -e; \
	trap '$(MAKE) test-db-stop' EXIT; \
	DATABASE_URL=$(DATABASE_URL) cargo test --workspace

# Run only unit tests (no database required)
test-unit:
	@echo "Running unit tests (no database)..."
	@cargo test --workspace --lib

# Run hive server tests
test-hive: test-db-migrate
	@echo "Running hive tests with DATABASE_URL=$(DATABASE_URL)..."
	@set -e; \
	trap '$(MAKE) test-db-stop' EXIT; \
	DATABASE_URL=$(DATABASE_URL) cargo test -p hive

# Run API tests
test-api: test-db-migrate
	@echo "Running API tests with DATABASE_URL=$(DATABASE_URL)..."
	@set -e; \
	trap '$(MAKE) test-db-stop' EXIT; \
	DATABASE_URL=$(DATABASE_URL) cargo test -p api

# Run agent tests (no database required)
test-agent:
	@echo "Running agent tests..."
	@cargo test -p agent

# Run all integration tests (same as test, but explicit name)
test-integration: test

# Load test fixtures for manual testing
test-fixtures: test-db-migrate
	@echo "Loading test fixtures..."
	@PGPASSWORD=$(POSTGRES_PASSWORD) psql -h localhost -U $(POSTGRES_USER) -d $(POSTGRES_DB) -p $(POSTGRES_PORT) \
		-f hive/fixtures/test_fixtures.sql
	@echo "Fixtures loaded. Database running on port $(POSTGRES_PORT)"
	@echo "DATABASE_URL=$(DATABASE_URL)"
	@echo "Run 'make test-db-stop' to cleanup"

# ============================================================================
# Build Targets
# ============================================================================
build:
	@cargo build --workspace

build-release:
	@cargo build --workspace --release

build-ui:
	@echo "Building React UI..."
	@cd hive-hq/ui && npm install && npm run build
	@echo "UI build complete (output in hive-hq/ui/dist/)"

build-all: build build-ui
	@echo "All builds complete"

check:
	@cargo check --workspace

fmt:
	@cargo fmt --all

fmt-check:
	@cargo fmt --all -- --check

clippy:
	@cargo clippy --workspace -- -D warnings

# ============================================================================
# Development Helpers
# ============================================================================

# Start dev database (persistent, uses docker-compose)
dev-db:
	@./hack/setup-dev-db.sh

# Start React UI dev server
dev-ui:
	@echo "Starting UI dev server..."
	@cd hive-hq/ui && npm run dev

# Clean up test artifacts
clean:
	@echo "Cleaning up test databases and build artifacts..."
	@docker ps -a --filter "name=beecd-test-db-" --format "{{.Names}}" | xargs -r docker stop > /dev/null 2>&1 || true
	@docker ps -a --filter "name=beecd-test-db-" --format "{{.Names}}" | xargs -r docker rm > /dev/null 2>&1 || true
	@cargo clean
	@rm -rf hive-hq/ui/dist hive-hq/ui/node_modules
	@echo "Cleanup completed"

# ============================================================================
# Help
# ============================================================================
help:
	@echo "BeeCD Makefile"
	@echo ""
	@echo "Test targets:"
	@echo "  make test            - Run all tests (starts temp DB, runs tests, cleans up)"
	@echo "  make test-unit       - Run unit tests only (no database)"
	@echo "  make test-hive       - Run hive server tests"
	@echo "  make test-api        - Run API tests"
	@echo "  make test-agent      - Run agent tests"
	@echo "  make test-fixtures   - Start DB with test fixtures (for manual testing)"
	@echo ""
	@echo "Database targets:"
	@echo "  make test-db-start   - Start test database"
	@echo "  make test-db-stop    - Stop and remove test database"
	@echo "  make dev-db          - Setup persistent dev database (docker-compose)"
	@echo ""
	@echo "Build targets:"
	@echo "  make build           - Build all Rust packages (debug)"
	@echo "  make build-release   - Build all Rust packages (release)"
	@echo "  make build-ui        - Build React UI"
	@echo "  make build-all       - Build Rust + UI"
	@echo "  make check           - Check all packages"
	@echo "  make fmt             - Format code"
	@echo "  make clippy          - Run clippy lints"
	@echo ""
	@echo "Development:"
	@echo "  make dev-ui          - Start React UI dev server"
	@echo ""
	@echo "  make clean           - Clean up test DBs and build artifacts"
	@echo "  make help            - Show this help"
