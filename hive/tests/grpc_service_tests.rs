mod common;

use common::{cleanup_test_data, create_test_cluster, setup_test_db};
use sqlx::Row;
use uuid::Uuid;

// Helper to create test namespace
async fn create_test_namespace(pool: &sqlx::PgPool, cluster_id: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO namespaces (id, name, cluster_id) VALUES (gen_random_uuid(), $1, $2) RETURNING id"
    )
    .bind(name)
    .bind(cluster_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create test namespace")
}

// Helper to create test repository
async fn create_test_repo(pool: &sqlx::PgPool, org: &str, repo: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO repos (id, org, repo) VALUES (gen_random_uuid(), $1, $2) RETURNING id",
    )
    .bind(org)
    .bind(repo)
    .fetch_one(pool)
    .await
    .expect("Failed to create test repo")
}

// Helper to create test repo branch
async fn create_test_repo_branch(pool: &sqlx::PgPool, repo_id: Uuid, branch: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO repo_branches (id, repo_id, branch) VALUES (gen_random_uuid(), $1, $2) RETURNING id"
    )
    .bind(repo_id)
    .bind(branch)
    .fetch_one(pool)
    .await
    .expect("Failed to create test repo branch")
}

// Helper to create test release
async fn create_test_release(
    pool: &sqlx::PgPool,
    namespace_id: Uuid,
    repo_branch_id: Uuid,
    name: &str,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO releases (
            id, service_id, namespace_id, hash, path, name, version, repo_branch_id, git_sha, manually_selected_at
        ) VALUES (
            gen_random_uuid(), gen_random_uuid(), $1, 'testhash123', '/manifests/svc.yaml', $2, '1.0.0', $3, 'deadbeef', NOW()
        ) RETURNING id
        "#
    )
    .bind(namespace_id)
    .bind(name)
    .bind(repo_branch_id)
    .fetch_one(pool)
    .await
    .expect("Failed to create test release")
}

// Helper to save hive error
async fn save_hive_error(pool: &sqlx::PgPool, cluster_id: Uuid, message: &str) {
    sqlx::query(
        "INSERT INTO hive_errors (cluster_id, message, is_deprecated) VALUES ($1, $2, false)",
    )
    .bind(cluster_id)
    .bind(message)
    .execute(pool)
    .await
    .expect("Failed to save hive error");
}

#[tokio::test]
async fn test_grpc_setup_creates_cluster() {
    let pool = setup_test_db().await;
    let cluster_name = "test-grpc-cluster";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Verify cluster was created
    let result = sqlx::query("SELECT id, name FROM clusters WHERE id = $1")
        .bind(cluster_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch cluster");

    let name: String = result.get("name");
    assert_eq!(name, cluster_name);
    assert_eq!(result.get::<Uuid, _>("id"), cluster_id);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_grpc_setup_cleanup_removes_cluster() {
    let pool = setup_test_db().await;
    let cluster_name = "test-grpc-cleanup";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;

    // Verify cluster exists
    let exists_before: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1)")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(exists_before);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;

    // Verify cluster is removed
    let exists_after: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM clusters WHERE id = $1)")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!exists_after);
}

#[tokio::test]
async fn test_service_status_stores_release_in_db() {
    let pool = setup_test_db().await;
    let cluster_name = "test-service-status";
    let ns_name = "default";
    let release_name = "test-service";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, ns_name).await;
    let repo_id = create_test_repo(&pool, "acme", "services").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;
    let release_id = create_test_release(&pool, namespace_id, repo_branch_id, release_name).await;

    // Verify release was created with JOIN to get namespace name
    let result: (String, String) = sqlx::query_as(
        "SELECT r.name, n.name FROM releases r JOIN namespaces n ON r.namespace_id = n.id WHERE r.id = $1"
    )
    .bind(release_id)
    .fetch_one(&pool)
    .await
    .expect("Failed to fetch release");

    assert_eq!(result.0, release_name);
    assert_eq!(result.1, ns_name);

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_log_hive_error_saves_error_to_db() {
    let pool = setup_test_db().await;
    let cluster_name = "test-hive-error";
    let error_message = "Test error: service failed to deploy";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    save_hive_error(&pool, cluster_id, error_message).await;

    // Verify error was saved
    let stored_message: String =
        sqlx::query_scalar("SELECT message FROM hive_errors WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch error");

    assert_eq!(stored_message, error_message);

    // Cleanup
    let _ = sqlx::query("DELETE FROM hive_errors WHERE cluster_id = $1")
        .bind(cluster_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_log_release_error_creates_error_record() {
    let pool = setup_test_db().await;
    let cluster_name = "test-release-error";
    let ns_name = "default";
    let release_name = "test-app";
    let error_msg = "Failed to pull image: image not found";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, ns_name).await;
    let repo_id = create_test_repo(&pool, "myorg", "myrepo").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "develop").await;
    let release_id = create_test_release(&pool, namespace_id, repo_branch_id, release_name).await;

    // Simulate logging a release error
    sqlx::query("INSERT INTO release_errors (release_id, message) VALUES ($1, $2)")
        .bind(release_id)
        .bind(error_msg)
        .execute(&pool)
        .await
        .expect("Failed to insert release error");

    // Verify error was stored
    let stored_error: String =
        sqlx::query_scalar("SELECT message FROM release_errors WHERE release_id = $1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch release error");

    assert_eq!(stored_error, error_msg);

    // Cleanup
    let _ = sqlx::query("DELETE FROM release_errors WHERE release_id = $1")
        .bind(release_id)
        .execute(&pool)
        .await;
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_installation_status_tracks_lifecycle() {
    let pool = setup_test_db().await;
    let cluster_name = "test-install-lifecycle";
    let ns_name = "default";
    let release_name = "test-service";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, ns_name).await;
    let repo_id = create_test_repo(&pool, "app", "myapp").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;
    let release_id = create_test_release(&pool, namespace_id, repo_branch_id, release_name).await;

    // Simulate starting first install
    sqlx::query("UPDATE releases SET started_first_install_at = NOW() WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to update started_first_install_at");

    let started: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT started_first_install_at FROM releases WHERE id = $1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch started_first_install_at");

    assert!(started.is_some(), "started_first_install_at should be set");

    // Simulate completing install
    sqlx::query(
        "UPDATE releases SET completed_first_install_at = NOW(), last_sync_at = NOW() WHERE id = $1"
    )
    .bind(release_id)
    .execute(&pool)
    .await
    .expect("Failed to update completed_first_install_at");

    let completed: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT completed_first_install_at FROM releases WHERE id = $1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch completed_first_install_at");

    assert!(
        completed.is_some(),
        "completed_first_install_at should be set"
    );

    // Cleanup
    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_installation_status_update_path() {
    let pool = setup_test_db().await;
    let cluster_name = "test-install-update";
    let ns_name = "default";
    let release_name = "update-service";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, ns_name).await;
    let repo_id = create_test_repo(&pool, "update-org", "update-repo").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;
    let release_id = create_test_release(&pool, namespace_id, repo_branch_id, release_name).await;

    // Set first install as completed
    sqlx::query(
        "UPDATE releases SET started_first_install_at = NOW() - interval '5 minutes', completed_first_install_at = NOW() - interval '4 minutes' WHERE id = $1"
    )
    .bind(release_id)
    .execute(&pool)
    .await
    .expect("Failed to set first install completed");

    // Simulate starting update
    sqlx::query("UPDATE releases SET started_update_install_at = NOW() WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to start update");

    // Verify update started
    let update_started: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT started_update_install_at FROM releases WHERE id = $1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch release");

    assert!(update_started.is_some(), "Update install should be started");

    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_installation_status_deletion_path() {
    let pool = setup_test_db().await;
    let cluster_name = "test-install-deletion";
    let ns_name = "default";
    let release_name = "delete-service";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, ns_name).await;
    let repo_id = create_test_repo(&pool, "delete-org", "delete-repo").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;
    let release_id = create_test_release(&pool, namespace_id, repo_branch_id, release_name).await;

    // Mark for deletion
    sqlx::query("UPDATE releases SET marked_for_deletion_at = NOW() WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to mark for deletion");

    // Simulate starting deletion
    sqlx::query("UPDATE releases SET started_delete_at = NOW() WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to start deletion");

    // Verify deletion started
    let delete_started: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT started_delete_at FROM releases WHERE id = $1")
            .bind(release_id)
            .fetch_one(&pool)
            .await
            .expect("Failed to fetch release");

    assert!(delete_started.is_some(), "Deletion should be started");

    cleanup_test_data(&pool, cluster_name).await;
}
