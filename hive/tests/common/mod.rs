#![allow(dead_code)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

/// Test tenant ID for isolation. Created during first test run.
pub static TEST_TENANT_ID: std::sync::LazyLock<Uuid> = std::sync::LazyLock::new(Uuid::new_v4);

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

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Ensure test tenant exists (insert or do nothing - tests share the same tenant)
    let tenant_subdomain = format!("hive-test-{}", &TEST_TENANT_ID.to_string()[..8]);
    let _ = sqlx::query(
        r#"
        INSERT INTO tenants (id, name, domain)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(*TEST_TENANT_ID)
    .bind(&format!("Hive Test Tenant {}", tenant_subdomain))
    .bind(&tenant_subdomain)
    .execute(&pool)
    .await;

    pool
}

/// Get the test tenant ID
pub fn get_test_tenant_id() -> Uuid {
    *TEST_TENANT_ID
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
pub async fn create_test_cluster(pool: &PgPool, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO clusters (name, metadata, tenant_id) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind("{}")
    .bind(*TEST_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("Failed to create test cluster")
}

/// Helper to create a test user in the database
pub async fn create_test_user(pool: &PgPool, name: &str, password_hash: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (name, hash, tenant_id) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(name)
    .bind(password_hash)
    .bind(*TEST_TENANT_ID)
    .fetch_one(pool)
    .await
    .expect("Failed to create test user")
}
