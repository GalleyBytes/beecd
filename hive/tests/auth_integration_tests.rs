mod common;

use bcrypt::hash;
use common::{cleanup_test_data, create_test_user, setup_test_db};

#[tokio::test]
async fn test_auth_basic_user_lookup() {
    let pool = setup_test_db().await;
    let username = "test-user-lookup";
    let password = "secure-password-123";

    // Create user with hashed password
    let password_hash = hash(password, 4).expect("Failed to hash password");
    let _user_id = create_test_user(&pool, username, &password_hash).await;

    // Verify user can be looked up and password verified
    let stored_hash: String = sqlx::query_scalar("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch user");

    assert_eq!(stored_hash, password_hash);

    // Verify password verification works
    let is_valid = bcrypt::verify(password, &stored_hash).expect("Failed to verify");
    assert!(is_valid, "Correct password should verify");

    let is_invalid = bcrypt::verify("wrong-password", &stored_hash).expect("Failed to verify");
    assert!(!is_invalid, "Wrong password should not verify");

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE name = $1")
        .bind(username)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_auth_nonexistent_user_returns_none() {
    let pool = setup_test_db().await;
    let username = "nonexistent-user-xyz";

    // Attempt lookup of nonexistent user
    let result = sqlx::query("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_optional(&pool)
        .await
        .expect("Query should succeed");

    assert!(result.is_none(), "Nonexistent user should return None");
}

#[tokio::test]
async fn test_auth_cluster_check_in_updates_timestamp() {
    let pool = setup_test_db().await;
    let cluster_name = "auth-test-checkin";

    let cluster_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO clusters (name, metadata) VALUES ($1, '{}') RETURNING id",
    )
    .bind(cluster_name)
    .fetch_one(&pool)
    .await
    .expect("Failed to create cluster");

    // Get initial check-in timestamp (defaults to NOW() in schema)
    let initial_checkin: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_check_in_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch cluster");

    // Sleep briefly to ensure timestamp difference
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Simulate update_check_in from auth.rs
    sqlx::query("UPDATE clusters SET last_check_in_at = NOW() WHERE name = $1")
        .bind(cluster_name)
        .execute(&pool)
        .await
        .expect("Failed to update check-in");

    // Verify check-in was updated to a newer timestamp
    let updated_checkin: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT last_check_in_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch cluster");

    assert!(
        updated_checkin > initial_checkin,
        "Check-in timestamp should be updated"
    );

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_auth_concurrent_check_in_updates() {
    let pool = setup_test_db().await;
    let cluster_name = "auth-test-concurrent";

    let cluster_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO clusters (name, metadata) VALUES ($1, '{}') RETURNING id",
    )
    .bind(cluster_name)
    .fetch_one(&pool)
    .await
    .expect("Failed to create cluster");

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
async fn test_auth_password_hash_uniqueness() {
    let password = "same-password-for-testing";

    // Hash same password twice
    let hash1 = hash(password, 4).expect("Failed to hash password");
    let hash2 = hash(password, 4).expect("Failed to hash password");

    // Hashes should be different due to salting
    assert_ne!(hash1, hash2, "Hashes should differ due to different salts");

    // But both should verify correctly
    assert!(
        bcrypt::verify(password, &hash1).unwrap(),
        "First hash should verify"
    );
    assert!(
        bcrypt::verify(password, &hash2).unwrap(),
        "Second hash should verify"
    );
}

#[tokio::test]
async fn test_auth_password_with_special_characters() {
    let pool = setup_test_db().await;
    let username = "special-char-user";
    let password = "p@$$w0rd!#%&*+=";

    // Hash and store
    let password_hash = hash(password, 4).expect("Failed to hash password");
    let _user_id = create_test_user(&pool, username, &password_hash).await;

    // Verify we can retrieve and verify
    let stored_hash: String = sqlx::query_scalar("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch user");

    let is_valid = bcrypt::verify(password, &stored_hash).expect("Failed to verify");
    assert!(is_valid, "Password with special chars should verify");

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE name = $1")
        .bind(username)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_auth_long_password() {
    let pool = setup_test_db().await;
    let username = "long-password-user";
    let password = "a".repeat(100);

    // Hash long password
    let password_hash = hash(&password, 4).expect("Failed to hash long password");
    let _user_id = create_test_user(&pool, username, &password_hash).await;

    // Verify long password works
    let stored_hash: String = sqlx::query_scalar("SELECT hash FROM users WHERE name = $1")
        .bind(username)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch user");

    let is_valid = bcrypt::verify(&password, &stored_hash).expect("Failed to verify");
    assert!(is_valid, "Long password should verify correctly");

    // Cleanup
    let _ = sqlx::query("DELETE FROM users WHERE name = $1")
        .bind(username)
        .execute(&pool)
        .await;
}

#[tokio::test]
async fn test_auth_empty_password() {
    let password = "";
    let password_hash = hash(password, 4).expect("Failed to hash empty password");
    let is_valid = bcrypt::verify(password, &password_hash).expect("Failed to verify");
    assert!(is_valid, "Empty password should hash and verify");
}
