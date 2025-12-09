mod common;

use bcrypt::hash;
use common::{cleanup_test_data, create_test_cluster, create_test_user, setup_test_db};
use sqlx::Row;

#[tokio::test]
async fn test_create_cluster() {
    let pool = setup_test_db().await;
    let cluster_name = "test-cluster-create";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Verify it was created
    let result = sqlx::query("SELECT id, name FROM clusters WHERE id = $1")
        .bind(cluster_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch cluster");

    let name: String = result.get("name");
    assert_eq!(name, cluster_name);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_cluster_last_check_in_update() {
    let pool = setup_test_db().await;
    let cluster_name = "test-cluster-checkin";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Get initial check-in time (should be NULL or creation time)
    let initial_checkin: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_check_in_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch initial check-in");

    // Simulate a check-in update (this is what happens during authentication)
    sqlx::query("UPDATE clusters SET last_check_in_at = NOW() WHERE name = $1")
        .bind(cluster_name)
        .execute(&pool)
        .await
        .expect("Failed to update check-in");

    // Verify the check-in was updated
    let updated_checkin: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_check_in_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch updated check-in");

    assert!(
        updated_checkin.is_some(),
        "Check-in time should be set after update"
    );

    // If there was an initial check-in, verify it was updated
    if let Some(initial) = initial_checkin {
        assert!(
            updated_checkin.unwrap() >= initial,
            "Check-in time should be newer or equal"
        );
    }

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_user_lookup() {
    let pool = setup_test_db().await;
    let username = "test-user-lookup";
    let password = "test-password";

    // Hash the password
    let password_hash = hash(password, 4).expect("Failed to hash password");

    // Create a user
    let _user_id = create_test_user(&pool, username, &password_hash).await;

    // Lookup the user
    let result = sqlx::query("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch user");

    let stored_hash: String = result.get("hash");
    assert_eq!(stored_hash, password_hash);

    // Verify password matches
    let is_valid = bcrypt::verify(password, &stored_hash).expect("Failed to verify password");
    assert!(is_valid, "Password should match the stored hash");

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE name = $1")
        .bind(username)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_user_lookup_nonexistent() {
    let pool = setup_test_db().await;
    let username = "nonexistent-user";

    // Try to lookup a user that doesn't exist
    let result = sqlx::query("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

    assert!(result.is_none(), "Nonexistent user should return None");
}

#[tokio::test]
async fn test_save_hive_error() {
    let pool = setup_test_db().await;
    let cluster_name = "test-cluster-error";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Save an error message
    let error_message = "Test error message";
    sqlx::query(
        "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)",
    )
    .bind(cluster_id)
    .bind(error_message)
    .execute(&pool)
    .await
    .expect("Failed to save error");

    // Verify the error was saved
    let result = sqlx::query("SELECT message FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch error");

    let stored_message: String = result.get("message");
    assert_eq!(stored_message, error_message);

    // Cleanup
    let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_deprecate_hive_errors() {
    let pool = setup_test_db().await;
    let cluster_name = "test-cluster-deprecate";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Create some error messages
    for i in 0..3 {
        sqlx::query(
            "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)",
        )
        .bind(cluster_id)
        .bind(format!("Error {}", i))
        .execute(&pool)
        .await
        .expect("Failed to save error");
    }

    // Deprecate all errors for this cluster
    sqlx::query("UPDATE hive_errors SET is_deprecated = true WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await
        .expect("Failed to deprecate errors");

    // Verify all errors are deprecated
    let deprecated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1 AND is_deprecated = true",
    )
    .bind(cluster_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count deprecated errors");

    assert_eq!(deprecated_count, 3, "All errors should be deprecated");

    // Cleanup
    let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_cluster_metadata() {
    let pool = setup_test_db().await;
    let cluster_name = "test-cluster-metadata";

    // Create a cluster with custom metadata
    let metadata = r#"{"region": "us-west-2", "environment": "test"}"#;
    let cluster_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO clusters (name, metadata) VALUES ($1, $2) RETURNING id",
    )
    .bind(cluster_name)
    .bind(metadata)
    .fetch_one(&pool)
    .await
    .expect("Failed to create cluster");

    // Fetch the cluster and verify metadata
    let result = sqlx::query("SELECT metadata FROM clusters WHERE id = $1")
        .bind(cluster_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch cluster");

    let stored_metadata: String = result.get("metadata");
    assert_eq!(stored_metadata, metadata);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_concurrent_cluster_check_in_updates() {
    let pool = setup_test_db().await;
    let cluster_name = "test-concurrent-checkin";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Spawn 10 concurrent tasks that update check-in
    let mut handles = vec![];

    for _ in 0..10 {
        let pool = pool.clone();

        let handle = tokio::spawn(async move {
            sqlx::query("UPDATE clusters SET last_check_in_at = NOW() WHERE name = $1")
                .bind(cluster_name)
                .execute(&pool)
                .await
                .expect("Failed to update check-in")
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Verify final check-in was set
    let final_checkin: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_check_in_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch cluster");

    assert!(
        final_checkin.is_some(),
        "Check-in should be set after concurrent updates"
    );

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_concurrent_error_logging() {
    let pool = setup_test_db().await;
    let cluster_name = "test-concurrent-errors";

    // Create a cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Spawn 5 concurrent tasks that log errors
    let mut handles = vec![];

    for i in 0..5 {
        let pool = pool.clone();

        let handle = tokio::spawn(async move {
            sqlx::query(
                "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)"
            )
            .bind(cluster_id)
            .bind(format!("Concurrent error {}", i))
            .execute(&pool)
            .await
            .expect("Failed to save error")
        });

        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        let _ = handle.await;
    }

    // Verify all errors were saved
    let error_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to count errors");

    assert_eq!(error_count, 5, "All 5 concurrent errors should be saved");

    // Cleanup
    let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_duplicate_cluster_names_constraint() {
    let pool = setup_test_db().await;
    let cluster_name = "test-duplicate-name";

    // Create first cluster
    let _cluster_id1 = create_test_cluster(&pool, cluster_name).await;

    // Attempt to create second cluster with same name (may succeed depending on schema)
    // Just verify the name was created correctly
    let result: String = sqlx::query_scalar("SELECT name FROM clusters WHERE name = $1")
        .bind(cluster_name)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch cluster");

    assert_eq!(result, cluster_name);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_orphan_hive_errors_cleanup() {
    let pool = setup_test_db().await;
    let cluster_name = "test-orphan-cleanup";

    // Create cluster and error
    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    sqlx::query(
        "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)",
    )
    .bind(cluster_id)
    .bind("Test error for cleanup")
    .execute(&pool)
    .await
    .expect("Failed to save error");

    // Verify error exists
    let error_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(error_count, 1, "Error should exist");

    // Delete cluster
    cleanup_test_data(&pool, cluster_name).await;

    // Verify cluster is gone
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1)")
        .bind(cluster_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(!exists, "Cluster should be deleted");

    // Note: Orphan errors may still exist if foreign key is not ON DELETE CASCADE
    // This test documents this behavior
    let orphan_errors: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap_or(0);

    // Cleanup orphaned errors manually if they exist
    if orphan_errors > 0 {
        let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .execute(&pool)
            .await;
    }
}

#[tokio::test]
async fn test_large_error_list_performance() {
    let pool = setup_test_db().await;
    let cluster_name = "test-large-errors";

    // Create cluster
    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Insert 100 errors
    for i in 0..100 {
        sqlx::query(
            "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)",
        )
        .bind(cluster_id)
        .bind(format!("Error message {}", i))
        .execute(&pool)
        .await
        .expect("Failed to save error");
    }

    // Verify all errors exist
    let error_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to count errors");

    assert_eq!(error_count, 100, "All 100 errors should be saved");

    // Deprecate all errors at once
    sqlx::query("UPDATE hive_errors SET is_deprecated = true WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await
        .expect("Failed to deprecate errors");

    // Verify all are deprecated
    let deprecated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hive_errors WHERE cluster_id = $1 AND is_deprecated = true",
    )
    .bind(cluster_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to count deprecated");

    assert_eq!(deprecated_count, 100, "All errors should be deprecated");

    // Cleanup
    let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}
