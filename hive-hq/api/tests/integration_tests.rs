mod integration;

use integration::test_env::*;
use uuid::Uuid;

// Tests must run serially to avoid port-forward conflicts
// Run with: cargo test --test integration_tests -- --ignored --nocapture --test-threads=1

#[tokio::test]
#[ignore] // Run with: cargo test --test integration_tests -- --ignored --nocapture
async fn test_sync_cluster_releases_basic_flow() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create test fixtures
    let cluster_id = create_test_cluster(&env.pool).await;
    let namespace_id = create_test_namespace(&env.pool, cluster_id).await;
    let (_, branch_id) = create_test_repo(&env.pool).await;

    // Create initial release
    let release_id = create_test_release(&env.pool, namespace_id, branch_id, "test-app").await;

    // Verify release was created
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE id = $1")
        .bind(release_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to query release");

    assert_eq!(count.0, 1, "Release should exist in database");

    env.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn test_transaction_atomicity_on_error() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool).await;
    let namespace_id = create_test_namespace(&env.pool, cluster_id).await;
    let (_, branch_id) = create_test_repo(&env.pool).await;

    // Start a transaction
    let mut tx = env.pool.begin().await.expect("Failed to start transaction");

    // Insert a release within the transaction
    let release_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO releases (
            id, namespace_id, name, path, repo_branch_id,
            hash, version, git_sha
        )
        VALUES ($1, $2, 'test-app', '/test/path', $3, 'hash123', 'v1.0', 'abc123')
        "#,
    )
    .bind(release_id)
    .bind(namespace_id)
    .bind(branch_id)
    .execute(&mut *tx)
    .await
    .expect("Failed to insert release");

    // Intentionally roll back the transaction instead of committing
    tx.rollback().await.expect("Failed to rollback transaction");

    // Verify no releases were created after rollback
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE namespace_id = $1")
        .bind(namespace_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to query releases");

    assert_eq!(
        count.0, 0,
        "No releases should exist after rolled back transaction"
    );

    env.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn test_batch_operations_within_limits() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool).await;
    let namespace_id = create_test_namespace(&env.pool, cluster_id).await;
    let (_, branch_id) = create_test_repo(&env.pool).await;

    // Create 100 releases to test batch operations
    for i in 0..100 {
        create_test_release(
            &env.pool,
            namespace_id,
            branch_id,
            &format!("test-app-{}", i),
        )
        .await;
    }

    // Verify all releases were created
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE namespace_id = $1")
        .bind(namespace_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to query releases");

    assert_eq!(count.0, 100, "All 100 releases should exist");

    // Test batch query with ANY()
    let release_names: Vec<String> = (0..100).map(|i| format!("test-app-{}", i)).collect();

    let results: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM releases WHERE namespace_id = $1 AND name = ANY($2)")
            .bind(namespace_id)
            .bind(&release_names)
            .fetch_all(&env.pool)
            .await
            .expect("Failed to query releases with ANY()");

    assert_eq!(
        results.len(),
        100,
        "Batch query should return all 100 releases"
    );

    env.cleanup().await;
}

#[tokio::test]
#[ignore]
async fn test_namespace_isolation() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool).await;

    // Create two namespaces
    let ns1_id = create_test_namespace(&env.pool, cluster_id).await;
    let ns2_id = create_test_namespace(&env.pool, cluster_id).await;

    let (_, branch_id) = create_test_repo(&env.pool).await;

    // Create releases in both namespaces
    create_test_release(&env.pool, ns1_id, branch_id, "app-ns1").await;
    create_test_release(&env.pool, ns2_id, branch_id, "app-ns2").await;

    // Verify namespace 1 only has its own release
    let ns1_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE namespace_id = $1")
        .bind(ns1_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to query ns1 releases");

    assert_eq!(ns1_count.0, 1, "Namespace 1 should have exactly 1 release");

    // Verify namespace 2 only has its own release
    let ns2_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE namespace_id = $1")
        .bind(ns2_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to query ns2 releases");

    assert_eq!(ns2_count.0, 1, "Namespace 2 should have exactly 1 release");

    env.cleanup().await;
}
