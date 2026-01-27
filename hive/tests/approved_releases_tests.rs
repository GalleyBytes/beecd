mod common;

use common::{cleanup_test_data, create_test_cluster, setup_test_db, get_test_tenant_id};
use uuid::Uuid;

// Helper to create test namespace
async fn create_test_namespace(pool: &sqlx::PgPool, cluster_id: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO namespaces (id, name, cluster_id, tenant_id) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id"
    )
    .bind(name)
    .bind(cluster_id)
    .bind(get_test_tenant_id())
    .fetch_one(pool)
    .await
    .expect("Failed to create test namespace")
}

// Helper to create test repository
async fn create_test_repo(pool: &sqlx::PgPool, org: &str, repo: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO repos (id, org, repo, tenant_id) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id",
    )
    .bind(org)
    .bind(repo)
    .bind(get_test_tenant_id())
    .fetch_one(pool)
    .await
    .expect("Failed to create test repo")
}

// Helper to create test repo branch
async fn create_test_repo_branch(pool: &sqlx::PgPool, repo_id: Uuid, branch: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO repo_branches (id, repo_id, branch, tenant_id) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id"
    )
    .bind(repo_id)
    .bind(branch)
    .bind(get_test_tenant_id())
    .fetch_one(pool)
    .await
    .expect("Failed to create test repo branch")
}

// Helper to create approved release
async fn create_approved_release(
    pool: &sqlx::PgPool,
    namespace_id: Uuid,
    repo_branch_id: Uuid,
    name: &str,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO releases (
            id, service_id, namespace_id, hash, path, name, version, repo_branch_id, 
            git_sha, approved_at, approved_by, tenant_id
        ) VALUES (
            gen_random_uuid(), gen_random_uuid(), $1, 'hash123', '/manifests/svc.yaml', 
            $2, '1.0.0', $3, 'deadbeef', NOW(), 'admin', $4
        ) RETURNING id
        "#,
    )
    .bind(namespace_id)
    .bind(name)
    .bind(repo_branch_id)
    .bind(get_test_tenant_id())
    .fetch_one(pool)
    .await
    .expect("Failed to create approved release")
}

#[tokio::test]
async fn test_get_approved_releases_query() {
    let pool = setup_test_db().await;
    let cluster_name = "test-approved-releases";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, "production").await;
    let repo_id = create_test_repo(&pool, "myorg-test1", "myrepo-test1").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;

    // Create approved release
    let _release_id = create_approved_release(&pool, namespace_id, repo_branch_id, "app-v1").await;

    // Query for approved releases (same logic as get_approved_releases)
    let query = r#"
        SELECT id
        FROM releases
        WHERE
            approved_at IS NOT NULL
            AND (marked_for_deletion_at IS NULL OR approved_at > marked_for_deletion_at)
            AND (unapproved_at, deprecated_at, deleted_at) IS NULL
            AND namespace_id IN (
                SELECT id
                FROM namespaces
                WHERE cluster_id = $1
            )
        "#;

    let result = sqlx::query(query)
        .bind(cluster_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch approved releases");

    assert_eq!(result.len(), 1, "Should have 1 approved release");

    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_approved_releases_excludes_unapproved() {
    let pool = setup_test_db().await;
    let cluster_name = "test-unapproved";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, "staging").await;
    let repo_id = create_test_repo(&pool, "org-test2", "repo-test2").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "develop").await;

    // Create approved then unapproved release
    let release_id = create_approved_release(&pool, namespace_id, repo_branch_id, "app-v2").await;

    sqlx::query("UPDATE releases SET unapproved_at = NOW(), unapproved_by = 'admin' WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to unapprove release");

    // Query for approved releases
    let query = r#"
        SELECT id
        FROM releases
        WHERE
            approved_at IS NOT NULL
            AND (unapproved_at, deprecated_at, deleted_at) IS NULL
            AND namespace_id IN (
                SELECT id
                FROM namespaces
                WHERE cluster_id = $1
            )
        "#;

    let result = sqlx::query(query)
        .bind(cluster_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch approved releases");

    assert_eq!(result.len(), 0, "Unapproved release should not be included");

    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_approved_releases_excludes_marked_for_deletion() {
    let pool = setup_test_db().await;
    let cluster_name = "test-marked-deletion";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let namespace_id = create_test_namespace(&pool, cluster_id, "prod").await;
    let repo_id = create_test_repo(&pool, "company-test3", "service-test3").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;

    // Create approved release then mark for deletion
    let release_id = create_approved_release(&pool, namespace_id, repo_branch_id, "app-v3").await;

    // Mark for deletion AFTER approval
    sqlx::query("UPDATE releases SET marked_for_deletion_at = NOW() WHERE id = $1")
        .bind(release_id)
        .execute(&pool)
        .await
        .expect("Failed to mark for deletion");

    // Auto-unapprove query (from get_approved_releases)
    let auto_unapprove = r#"
        UPDATE releases
        SET approved_at = NULL
        WHERE
            approved_at IS NOT NULL
            AND marked_for_deletion_at IS NOT NULL
            AND marked_for_deletion_at > approved_at
            AND (unapproved_at, deprecated_at, deleted_at) IS NULL
            AND namespace_id IN (
                SELECT id
                FROM namespaces
                WHERE cluster_id = $1
            )
        "#;

    sqlx::query(auto_unapprove)
        .bind(cluster_id)
        .execute(&pool)
        .await
        .expect("Failed to auto-unapprove");

    // Query for approved releases
    let query = r#"
        SELECT id
        FROM releases
        WHERE
            approved_at IS NOT NULL
            AND (marked_for_deletion_at IS NULL OR approved_at > marked_for_deletion_at)
            AND (unapproved_at, deprecated_at, deleted_at) IS NULL
            AND namespace_id IN (
                SELECT id
                FROM namespaces
                WHERE cluster_id = $1
            )
        "#;

    let result = sqlx::query(query)
        .bind(cluster_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch approved releases");

    assert_eq!(
        result.len(),
        0,
        "Release marked for deletion should be auto-unapproved"
    );

    cleanup_test_data(&pool, cluster_name).await;
}

#[tokio::test]
async fn test_approved_releases_multiple_namespaces() {
    let pool = setup_test_db().await;
    let cluster_name = "test-multi-namespace";

    let cluster_id = create_test_cluster(&pool, cluster_name).await;
    let ns1_id = create_test_namespace(&pool, cluster_id, "ns1").await;
    let ns2_id = create_test_namespace(&pool, cluster_id, "ns2").await;
    let repo_id = create_test_repo(&pool, "acme-test4", "services-test4").await;
    let repo_branch_id = create_test_repo_branch(&pool, repo_id, "main").await;

    // Create approved releases in both namespaces
    let _r1 = create_approved_release(&pool, ns1_id, repo_branch_id, "svc1").await;
    let _r2 = create_approved_release(&pool, ns2_id, repo_branch_id, "svc2").await;

    // Query for approved releases
    let query = r#"
        SELECT id
        FROM releases
        WHERE
            approved_at IS NOT NULL
            AND (marked_for_deletion_at IS NULL OR approved_at > marked_for_deletion_at)
            AND (unapproved_at, deprecated_at, deleted_at) IS NULL
            AND namespace_id IN (
                SELECT id
                FROM namespaces
                WHERE cluster_id = $1
            )
        "#;

    let result = sqlx::query(query)
        .bind(cluster_id)
        .fetch_all(&pool)
        .await
        .expect("Failed to fetch approved releases");

    assert_eq!(
        result.len(),
        2,
        "Should have 2 approved releases across namespaces"
    );

    cleanup_test_data(&pool, cluster_name).await;
}
