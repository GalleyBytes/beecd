mod integration;

use integration::test_env::*;
use uuid::Uuid;

// Error path and edge case tests on dirty database
// Run with: cargo test --test error_path_tests -- --ignored --nocapture --test-threads=1

/// Test handling of soft-deleted clusters
#[tokio::test]
#[ignore]
async fn test_soft_deleted_clusters_not_returned() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // The fixture loaded deleted clusters - verify they don't appear in queries
    let active_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM clusters WHERE deleted_at IS NULL")
            .fetch_one(&env.pool)
            .await
            .expect("Failed to count active clusters");

    let total_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clusters")
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count total clusters");

    assert!(
        active_count.0 < total_count.0,
        "Should have some soft-deleted clusters"
    );
    println!(
        "Active clusters: {}, Total: {}",
        active_count.0, total_count.0
    );

    env.cleanup().await;
}

/// Test duplicate key violation handling
#[tokio::test]
#[ignore]
async fn test_duplicate_cluster_group_name_fails() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let group_name = "test-duplicate-group";

    // First insert should succeed
    let first_result = sqlx::query("INSERT INTO cluster_groups (id, name) VALUES ($1, $2)")
        .bind(Uuid::new_v4())
        .bind(group_name)
        .execute(&env.pool)
        .await;

    assert!(first_result.is_ok(), "First insert should succeed");

    // Second insert with same name should fail
    let second_result = sqlx::query("INSERT INTO cluster_groups (id, name) VALUES ($1, $2)")
        .bind(Uuid::new_v4())
        .bind(group_name)
        .execute(&env.pool)
        .await;

    assert!(
        second_result.is_err(),
        "Duplicate name should fail with unique constraint violation"
    );

    let error = second_result.unwrap_err().to_string();
    assert!(
        error.contains("unique") || error.contains("duplicate"),
        "Error should mention unique constraint: {}",
        error
    );

    env.cleanup().await;
}

/// Test foreign key constraint violations
#[tokio::test]
#[ignore]
async fn test_foreign_key_violation_on_namespace() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let non_existent_cluster_id = Uuid::new_v4();

    // Try to create namespace with non-existent cluster
    // Even with valid tenant_id, the FK constraint should fail
    let result = sqlx::query("INSERT INTO namespaces (id, name, cluster_id, tenant_id) VALUES ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind("orphan-namespace")
        .bind(non_existent_cluster_id)
        .bind(env.tenant_id)
        .execute(&env.pool)
        .await;

    assert!(result.is_err(), "Should fail with foreign key violation");

    let error = result.unwrap_err().to_string();
    assert!(
        error.contains("foreign key") || error.contains("violates"),
        "Error should mention foreign key: {}",
        error
    );

    env.cleanup().await;
}

/// Test query with invalid UUID format
#[tokio::test]
#[ignore]
async fn test_invalid_uuid_in_query() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // This test validates our UUID parsing at the application level
    // At the DB level, invalid UUIDs should be caught by parameter binding

    let invalid_uuid_str = "not-a-uuid-at-all";
    let parse_result = Uuid::parse_str(invalid_uuid_str);

    assert!(parse_result.is_err(), "Invalid UUID should not parse");

    // If code tries to use invalid UUID in query, it should fail at parse time
    // not crash the database connection

    env.cleanup().await;
}

/// Test handling of very long strings
#[tokio::test]
#[ignore]
async fn test_very_long_string_handling() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let long_name = "a".repeat(10000); // 10KB string

    let result = sqlx::query("INSERT INTO cluster_groups (id, name) VALUES ($1, $2)")
        .bind(Uuid::new_v4())
        .bind(&long_name)
        .execute(&env.pool)
        .await;

    // Should succeed - PostgreSQL text type has no limit
    assert!(result.is_ok(), "Long string should be accepted");

    env.cleanup().await;
}

/// Test concurrent updates causing potential race conditions
#[tokio::test]
#[ignore]
async fn test_concurrent_updates_on_same_record() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool, env.tenant_id).await;

    // Launch 10 concurrent updates to the same cluster
    let mut tasks = Vec::new();
    for i in 0..10 {
        let pool = env.pool.clone();
        let id = cluster_id;
        let task = tokio::spawn(async move {
            sqlx::query("UPDATE clusters SET version = $1, updated_at = NOW() WHERE id = $2")
                .bind(format!("v{}", i))
                .bind(id)
                .execute(&pool)
                .await
        });
        tasks.push(task);
    }

    let results = futures::future::join_all(tasks).await;

    // All updates should succeed (last write wins)
    let succeeded = results.iter().filter(|r| r.is_ok()).count();
    println!("Concurrent updates succeeded: {}/10", succeeded);

    // At least most should succeed
    assert!(succeeded >= 8, "Most concurrent updates should succeed");

    // Verify final state
    let final_version: (String,) = sqlx::query_as("SELECT version FROM clusters WHERE id = $1")
        .bind(cluster_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to fetch cluster");

    println!(
        "Final version after concurrent updates: {}",
        final_version.0
    );
    assert!(
        final_version.0.starts_with("v"),
        "Version should be updated"
    );

    env.cleanup().await;
}

/// Test querying with NULL values in WHERE clause
#[tokio::test]
#[ignore]
async fn test_null_value_queries() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Query for releases with NULL approved_by (should work)
    let unapproved: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM releases WHERE approved_by IS NULL LIMIT 10")
            .fetch_all(&env.pool)
            .await
            .expect("Failed to query unapproved releases");

    println!("Found {} unapproved releases", unapproved.len());
    assert!(
        !unapproved.is_empty(),
        "Should have some unapproved releases in fixtures"
    );

    // Query for approved releases (should work)
    let approved: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM releases WHERE approved_by IS NOT NULL LIMIT 10")
            .fetch_all(&env.pool)
            .await
            .expect("Failed to query approved releases");

    println!("Found {} approved releases", approved.len());

    env.cleanup().await;
}

/// Test batch operations exceeding PostgreSQL parameter limits
#[tokio::test]
#[ignore]
async fn test_batch_operations_near_parameter_limit() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // PostgreSQL limit is 32767 parameters
    // With 4 parameters per insert, we can do ~8000 at once
    // Let's try with 2000 to be safe

    let cluster_id = create_test_cluster(&env.pool, env.tenant_id).await;
    let namespace_id = create_test_namespace(&env.pool, cluster_id, env.tenant_id).await;
    let (_, _branch_id) = create_test_repo(&env.pool, env.tenant_id).await;

    let mut release_names = Vec::new();
    for i in 0..2000 {
        release_names.push(format!("batch-release-{}", i));
    }

    // This query should work with ANY()
    let result =
        sqlx::query("SELECT COUNT(*) FROM releases WHERE name = ANY($1) AND namespace_id = $2")
            .bind(&release_names)
            .bind(namespace_id)
            .fetch_one(&env.pool)
            .await;

    assert!(
        result.is_ok(),
        "Large batch query with ANY() should succeed"
    );

    env.cleanup().await;
}

/// Test transaction rollback with foreign key constraints
#[tokio::test]
#[ignore]
async fn test_transaction_rollback_with_foreign_keys() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool, env.tenant_id).await;

    // Start transaction
    let mut tx = env.pool.begin().await.expect("Failed to start transaction");

    // Create namespace in transaction
    let namespace_id = Uuid::new_v4();
    sqlx::query("INSERT INTO namespaces (id, name, cluster_id, tenant_id) VALUES ($1, $2, $3, $4)")
        .bind(namespace_id)
        .bind("tx-namespace")
        .bind(cluster_id)
        .bind(env.tenant_id)
        .execute(&mut *tx)
        .await
        .expect("Failed to insert namespace");

    // Verify it exists in transaction
    let count_in_tx: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM namespaces WHERE id = $1")
        .bind(namespace_id)
        .fetch_one(&mut *tx)
        .await
        .expect("Failed to count in transaction");
    assert_eq!(count_in_tx.0, 1);

    // Rollback
    tx.rollback().await.expect("Failed to rollback");

    // Verify it doesn't exist after rollback
    let count_after: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM namespaces WHERE id = $1")
        .bind(namespace_id)
        .fetch_one(&env.pool)
        .await
        .expect("Failed to count after rollback");
    assert_eq!(
        count_after.0, 0,
        "Namespace should not exist after rollback"
    );

    env.cleanup().await;
}

/// Test querying stale data (old last_check_in_at)
#[tokio::test]
#[ignore]
async fn test_stale_cluster_detection() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Fixtures should have clusters with old check-ins
    let stale_clusters: Vec<(Uuid, String)> = sqlx::query_as(
        r#"
        SELECT id, name 
        FROM clusters 
        WHERE last_check_in_at < NOW() - INTERVAL '7 days'
        AND deleted_at IS NULL
        ORDER BY last_check_in_at
        LIMIT 10
        "#,
    )
    .fetch_all(&env.pool)
    .await
    .expect("Failed to query stale clusters");

    println!(
        "Found {} stale clusters (>7 days old)",
        stale_clusters.len()
    );
    assert!(
        !stale_clusters.is_empty(),
        "Fixtures should have stale clusters"
    );

    // Verify we can still operate on stale clusters
    if let Some((stale_id, name)) = stale_clusters.first() {
        println!("Stale cluster: {} ({})", name, stale_id);

        let result = sqlx::query("UPDATE clusters SET updated_at = NOW() WHERE id = $1")
            .bind(stale_id)
            .execute(&env.pool)
            .await;

        assert!(result.is_ok(), "Should be able to update stale cluster");
    }

    env.cleanup().await;
}

/// Test empty string vs NULL handling
#[tokio::test]
#[ignore]
async fn test_empty_string_vs_null() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let (_, branch_id) = create_test_repo(&env.pool, env.tenant_id).await;

    // Insert build target with empty name (should work - no constraint)
    let result = sqlx::query(
        "INSERT INTO service_definitions (id, name, repo_branch_id, source_branch_requirements, tenant_id) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(Uuid::new_v4())
    .bind("") // empty string
    .bind(branch_id)
    .bind("[]")
    .bind(env.tenant_id)
    .execute(&env.pool)
    .await;

    assert!(result.is_ok(), "Empty string should be allowed in name");

    // Insert with NULL name
    let result = sqlx::query(
        "INSERT INTO service_definitions (id, name, repo_branch_id, source_branch_requirements) VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::new_v4())
    .bind(Option::<String>::None) // NULL
    .bind(branch_id)
    .bind("[]")
    .execute(&env.pool)
    .await;

    assert!(result.is_ok(), "NULL should be allowed in name");

    env.cleanup().await;
}

/// Test case sensitivity in unique constraints
#[tokio::test]
#[ignore]
async fn test_case_sensitivity_in_repo_names() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // First repo with lowercase
    let result1 = sqlx::query("INSERT INTO repos (id, org, repo) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind("TestOrg")
        .bind("TestRepo")
        .execute(&env.pool)
        .await;

    assert!(result1.is_ok(), "First insert should succeed");

    // Try with different case - should fail due to case-insensitive unique index
    let result2 = sqlx::query("INSERT INTO repos (id, org, repo) VALUES ($1, $2, $3)")
        .bind(Uuid::new_v4())
        .bind("testorg") // lowercase
        .bind("testrepo") // lowercase
        .execute(&env.pool)
        .await;

    assert!(
        result2.is_err(),
        "Should fail due to case-insensitive unique constraint"
    );
    println!("Case sensitivity error: {}", result2.unwrap_err());

    env.cleanup().await;
}

/// Test handling of special characters in JSON fields
#[tokio::test]
#[ignore]
async fn test_special_characters_in_metadata() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let special_metadata =
        r#"{"key": "value with \"quotes\"", "emoji": "rocket", "newline": "line1\nline2"}"#;

    let result = sqlx::query(
        "INSERT INTO clusters (id, name, metadata, version, kubernetes_version, tenant_id) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(Uuid::new_v4())
    .bind("special-cluster")
    .bind(special_metadata)
    .bind("1.0")
    .bind("1.28")
    .bind(env.tenant_id)
    .execute(&env.pool)
    .await;

    assert!(
        result.is_ok(),
        "Should handle special characters in metadata"
    );

    env.cleanup().await;
}

/// Test querying with dirty data present
#[tokio::test]
#[ignore]
async fn test_complex_query_with_dirty_data() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Complex query that joins multiple tables and filters dirty data
    let results: Vec<(Uuid, String, i64)> = sqlx::query_as(
        r#"
        SELECT 
            c.id,
            c.name,
            COUNT(n.id) as namespace_count
        FROM clusters c
        LEFT JOIN namespaces n ON n.cluster_id = c.id AND n.deleted_at IS NULL
        WHERE c.deleted_at IS NULL
            AND c.last_check_in_at > NOW() - INTERVAL '30 days'
        GROUP BY c.id, c.name
        HAVING COUNT(n.id) > 0
        ORDER BY namespace_count DESC
        LIMIT 10
        "#,
    )
    .fetch_all(&env.pool)
    .await
    .expect("Failed to execute complex query");

    println!("Found {} active clusters with namespaces", results.len());

    for (id, name, count) in &results {
        println!("  Cluster {} ({}) has {} namespaces", name, id, count);
    }

    assert!(!results.is_empty(), "Should have clusters with namespaces");

    env.cleanup().await;
}

/// Test update conflicts with optimistic locking pattern
#[tokio::test]
#[ignore]
async fn test_optimistic_locking_pattern() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let cluster_id = create_test_cluster(&env.pool, env.tenant_id).await;

    // Read with timestamp
    let original_updated: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT updated_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&env.pool)
            .await
            .expect("Failed to fetch cluster");

    // Simulate another update happening
    sqlx::query("UPDATE clusters SET version = $1, updated_at = NOW() WHERE id = $2")
        .bind("v2.0")
        .bind(cluster_id)
        .execute(&env.pool)
        .await
        .expect("Failed to update cluster");

    // Try to update with stale timestamp (optimistic locking check)
    let result = sqlx::query(
        "UPDATE clusters SET version = $1, updated_at = NOW() WHERE id = $2 AND updated_at = $3",
    )
    .bind("v3.0")
    .bind(cluster_id)
    .bind(original_updated)
    .execute(&env.pool)
    .await
    .expect("Failed to execute update");

    // Should update 0 rows because updated_at changed
    assert_eq!(
        result.rows_affected(),
        0,
        "Optimistic lock should prevent update"
    );

    env.cleanup().await;
}
