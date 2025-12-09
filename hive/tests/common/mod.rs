#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;

/// Set up a test database pool for integration tests.
///
/// This expects a PostgreSQL database to be available. Set the DATABASE_URL
/// environment variable to point to your test database:
///
/// ```bash
/// export DATABASE_URL="postgres://pg:pass@localhost:5432/crud_test"
/// ```
///
/// The Makefile automatically sets up a test database on an available port.
pub async fn setup_test_db() -> PgPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for integration tests. Run with: make test-integration");

    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Clean up test data after each test run.
/// This function can be extended to clean specific tables if needed.
pub async fn cleanup_test_data(pool: &PgPool, cluster_name: &str) {
    // Delete hive_errors first to avoid FK constraint violations
    let _ = sqlx::query(
        "DELETE FROM hive_errors WHERE cluster_id IN (SELECT id FROM clusters WHERE name = $1)",
    )
    .bind(cluster_name)
    .execute(pool)
    .await;

    // Clean up clusters created during tests
    let _ = sqlx::query("DELETE FROM clusters WHERE name = $1")
        .bind(cluster_name)
        .execute(pool)
        .await;
}

/// Helper to create a test cluster in the database
pub async fn create_test_cluster(pool: &PgPool, name: &str) -> uuid::Uuid {
    sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO clusters (name, metadata) VALUES ($1, $2) RETURNING id",
    )
    .bind(name)
    .bind("{}")
    .fetch_one(pool)
    .await
    .expect("Failed to create test cluster")
}

/// Helper to create a test user in the database
pub async fn create_test_user(pool: &PgPool, name: &str, password_hash: &str) -> uuid::Uuid {
    sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO users (name, hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(name)
    .bind(password_hash)
    .fetch_one(pool)
    .await
    .expect("Failed to create test user")
}
