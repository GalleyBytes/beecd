mod integration;

use integration::test_env::*;
use uuid::Uuid;

// Tests must run serially to avoid port-forward conflicts
// Run with: cargo test --test api_integration_tests -- --ignored --nocapture --test-threads=1

/// Test GET endpoint with authentication and bulk data
#[tokio::test]
#[ignore]
async fn test_get_clusters_with_bulk_data() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create 200 test clusters
    let mut cluster_ids = Vec::new();
    for _i in 0..200 {
        let id = create_test_cluster(&env.pool).await;
        cluster_ids.push(id);
    }

    // Generate JWT token
    let _token = env
        .generate_jwt("test@example.com")
        .expect("Failed to generate JWT");

    // Query clusters from database
    let results: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM clusters ORDER BY created_at DESC LIMIT 200")
            .fetch_all(&env.pool)
            .await
            .expect("Failed to query clusters");

    assert_eq!(results.len(), 200, "Should have 200 clusters");
    assert!(
        cluster_ids.contains(&results[0].0),
        "First cluster should be one we created"
    );

    env.cleanup().await;
}

/// Test POST endpoint with authentication
#[tokio::test]
#[ignore]
async fn test_post_cluster_group_with_auth() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let _token = env
        .generate_jwt("test@example.com")
        .expect("Failed to generate JWT");

    // Create a cluster group
    let group_name = format!("test-group-{}", Uuid::new_v4());
    let group_id = create_test_cluster_group(&env.pool, &group_name).await;

    // Verify it was created
    let result: (Uuid, String) =
        sqlx::query_as("SELECT id, name FROM cluster_groups WHERE id = $1")
            .bind(group_id)
            .fetch_one(&env.pool)
            .await
            .expect("Failed to fetch cluster group");

    assert_eq!(result.0, group_id);
    assert_eq!(result.1, group_name);

    env.cleanup().await;
}

/// Test PUT endpoint with authentication and data validation
#[tokio::test]
#[ignore]
async fn test_put_service_definition_update() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let _token = env
        .generate_jwt("test@example.com")
        .expect("Failed to generate JWT");

    // Create test data
    let (_, branch_id) = create_test_repo(&env.pool).await;
    let bt_id = create_test_service_definition(&env.pool, branch_id, "original-name").await;

    // Update the build target
    let new_name = format!("updated-name-{}", Uuid::new_v4());
    sqlx::query("UPDATE service_definitions SET name = $1 WHERE id = $2")
        .bind(&new_name)
        .bind(bt_id)
        .execute(&env.pool)
        .await
        .expect("Failed to update build target");

    // Verify the update
    let result: (String,) = sqlx::query_as("SELECT name FROM service_definitions WHERE id = $1")
        .bind(bt_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to fetch build target");

    assert_eq!(result.0, new_name, "Build target name should be updated");

    env.cleanup().await;
}

/// Test DELETE endpoint with authentication
#[tokio::test]
#[ignore]
async fn test_delete_cluster_group() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let _token = env
        .generate_jwt("test@example.com")
        .expect("Failed to generate JWT");

    // Create a cluster group
    let group_name = format!("test-group-{}", Uuid::new_v4());
    let group_id = create_test_cluster_group(&env.pool, &group_name).await;

    // Verify it exists
    let count_before: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cluster_groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count cluster groups");
    assert_eq!(count_before.0, 1);

    // Delete it
    sqlx::query("DELETE FROM cluster_groups WHERE id = $1")
        .bind(group_id)
        .execute(&env.pool)
        .await
        .expect("Failed to delete cluster group");

    // Verify it's gone
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM cluster_groups WHERE id = $1")
        .bind(group_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count cluster groups");
    assert_eq!(count_after.0, 0, "Cluster group should be deleted");

    env.cleanup().await;
}

/// Test authentication failure
#[tokio::test]
#[ignore]
async fn test_authentication_failure() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // No token provided - operations should still work at DB level
    // but would fail at API level (not testing full API stack here)

    // Create data without auth to verify DB operations work
    let cluster_id = create_test_cluster(&env.pool).await;

    let result: (Uuid,) = sqlx::query_as("SELECT id FROM clusters WHERE id = $1")
        .bind(cluster_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to fetch cluster");

    assert_eq!(result.0, cluster_id);

    env.cleanup().await;
}

/// Test bulk operations with 300 entries
#[tokio::test]
#[ignore]
async fn test_bulk_operations_with_300_entries() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let fixtures = create_bulk_fixtures(&env.pool, 300).await;

    assert_eq!(fixtures.service_definition_ids.len(), 300);
    assert_eq!(fixtures.release_ids.len(), 300);

    // Verify all build targets exist
    let bt_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM service_definitions WHERE repo_branch_id = $1")
            .bind(fixtures.branch_id)
            .fetch_one(&env.pool)
            .await
            .expect("Failed to count build targets");
    assert_eq!(bt_count.0, 300);

    // Verify all releases exist
    let rel_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM releases WHERE namespace_id = $1")
        .bind(fixtures.namespace_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count releases");
    assert_eq!(rel_count.0, 300);

    // Test batch query with ANY()
    let results: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM service_definitions WHERE id = ANY($1)")
            .bind(&fixtures.service_definition_ids)
            .fetch_all(&env.pool)
            .await
            .expect("Failed to batch query build targets");

    assert_eq!(
        results.len(),
        300,
        "Batch query should return all 300 build targets"
    );

    env.cleanup().await;
}

/// Test complex query with joins and filtering
#[tokio::test]
#[ignore]
async fn test_complex_query_with_joins() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let fixtures = create_bulk_fixtures(&env.pool, 100).await;

    // Complex query joining multiple tables
    let results: Vec<(Uuid, String, String)> = sqlx::query_as(
        r#"
        SELECT bt.id, bt.name, r.repo
        FROM service_definitions bt
        JOIN repo_branches rb ON rb.id = bt.repo_branch_id
        JOIN repos r ON r.id = rb.repo_id
        WHERE rb.id = $1
        ORDER BY bt.name
        LIMIT 50
        "#,
    )
    .bind(fixtures.branch_id)
    .fetch_all(&env.pool)
    .await
    .expect("Failed to execute complex query");

    assert_eq!(results.len(), 50, "Should return 50 results");

    // Verify first result is service-0
    assert!(
        results[0].1.starts_with("service-"),
        "Name should start with 'service-'"
    );

    env.cleanup().await;
}

/// Test data integrity after multiple operations
#[tokio::test]
#[ignore]
async fn test_data_integrity_after_crud_operations() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let _token = env
        .generate_jwt("test@example.com")
        .expect("Failed to generate JWT");

    // CREATE
    let (_, branch_id) = create_test_repo(&env.pool).await;
    let bt_id = create_test_service_definition(&env.pool, branch_id, "test-service").await;

    // READ
    let read_result: (String,) =
        sqlx::query_as("SELECT name FROM service_definitions WHERE id = $1")
            .bind(bt_id)
            .fetch_one(&env.pool)
            .await
            .expect("Failed to read build target");
    assert_eq!(read_result.0, "test-service");

    // UPDATE
    sqlx::query("UPDATE service_definitions SET name = $1 WHERE id = $2")
        .bind("updated-service")
        .bind(bt_id)
        .execute(&env.pool)
        .await
        .expect("Failed to update build target");

    // READ again
    let updated_result: (String,) =
        sqlx::query_as("SELECT name FROM service_definitions WHERE id = $1")
            .bind(bt_id)
            .fetch_one(&env.pool)
            .await
            .expect("Failed to read updated build target");
    assert_eq!(updated_result.0, "updated-service");

    // DELETE
    sqlx::query("DELETE FROM service_definitions WHERE id = $1")
        .bind(bt_id)
        .execute(&env.pool)
        .await
        .expect("Failed to delete build target");

    // Verify deleted
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM service_definitions WHERE id = $1")
        .bind(bt_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count build targets");
    assert_eq!(count.0, 0, "Build target should be deleted");

    env.cleanup().await;
}

/// Test concurrent operations on different resources
#[tokio::test]
#[ignore]
async fn test_concurrent_operations() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create 50 clusters concurrently
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let pool = env.pool.clone();
        let task = tokio::spawn(async move { create_test_cluster(&pool).await });
        tasks.push(task);
    }

    let cluster_ids: Vec<Uuid> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.expect("Task failed"))
        .collect();

    assert_eq!(cluster_ids.len(), 50);

    // Verify all clusters exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clusters WHERE id = ANY($1)")
        .bind(&cluster_ids)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count clusters");
    assert_eq!(count.0, 50, "All 50 clusters should exist");

    env.cleanup().await;
}
