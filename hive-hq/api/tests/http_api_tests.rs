mod integration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use integration::test_env::*;
use serde_json::{json, Value};
use std::time::Instant;
use tower::ServiceExt;
use uuid::Uuid;

// Tests must run serially to avoid port-forward conflicts
// Run with: cargo test --test http_api_tests -- --ignored --nocapture --test-threads=1

/// Test public version endpoint (no auth required)
#[tokio::test]
#[ignore]
async fn test_version_endpoint_no_auth() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/version")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let version: String = String::from_utf8(body.to_vec()).unwrap();

    assert!(version.contains("test-1.0.0") || !version.is_empty());
    println!("✓ Version endpoint returned: {}", version);

    env.cleanup().await;
}

/// Test GET /api/clusters with valid authentication
#[tokio::test]
#[ignore]
async fn test_get_clusters_with_auth() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create test clusters
    for _ in 0..10 {
        create_test_cluster(&env.pool).await;
    }

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Expected 200 OK for authenticated request"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let clusters: Value = serde_json::from_slice(&body).unwrap();

    assert!(clusters.is_array(), "Response should be an array");
    let cluster_array = clusters.as_array().unwrap();
    assert!(
        cluster_array.len() >= 10,
        "Should have at least 10 clusters, got {}",
        cluster_array.len()
    );

    println!(
        "✓ GET /api/clusters returned {} clusters",
        cluster_array.len()
    );

    env.cleanup().await;
}

/// Test GET /api/clusters WITHOUT authentication - should return 401
#[tokio::test]
#[ignore]
async fn test_get_clusters_no_auth_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/clusters")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized when no auth header provided"
    );

    println!("✓ GET /api/clusters correctly returned 401 without auth");

    env.cleanup().await;
}

/// Test with INVALID token - should return 401
#[tokio::test]
#[ignore]
async fn test_invalid_token_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", "Bearer invalid_token_here")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized for invalid token"
    );

    println!("✓ Invalid token correctly returned 401");

    env.cleanup().await;
}

/// Test with EXPIRED token - should return 401
#[tokio::test]
#[ignore]
async fn test_expired_token_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();
    let expired_token = env
        .generate_expired_jwt("test@galleybytes.com")
        .expect("Failed to generate expired JWT");

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", expired_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized for expired token"
    );

    println!("✓ Expired token correctly returned 401");

    env.cleanup().await;
}

/// Test with wrong secret (token signed with different key) - should return 401
#[tokio::test]
#[ignore]
async fn test_wrong_signature_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Generate token with wrong secret
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use types::Claim;

    let expiration =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3600);

    let claims = Claim {
        email: "test@galleybytes.com".to_string(),
        exp: expiration.as_secs() as usize,
        roles: vec!["admin".to_string()],
    };

    let wrong_token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"wrong_secret_key_that_doesnt_match"),
    )
    .unwrap();

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", wrong_token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized for token with wrong signature"
    );

    println!("✓ Token with wrong signature correctly returned 401");

    env.cleanup().await;
}

/// Test with invalid email domain - should return 401
#[tokio::test]
#[ignore]
async fn test_invalid_email_domain_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Generate token with email from non-allowed domain
    let token = env
        .generate_jwt("test@unauthorized-domain.com")
        .expect("Failed to generate JWT");

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 Unauthorized for email with non-allowed domain"
    );

    println!("✓ Invalid email domain correctly returned 401");

    env.cleanup().await;
}

/// Test POST /api/repos with valid JSON body
#[tokio::test]
#[ignore]
async fn test_post_repo_with_valid_data() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    let repo_data = json!({
        "url": "https://github.com/test-org/test-repo"
    });

    let request = Request::builder()
        .uri("/api/repos")
        .method("POST")
        .header("Authorization", format!("Bearer {}", token))
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_string(&repo_data).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should return 200 or 201
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::CREATED,
        "Expected 200 or 201 for successful repo creation, got {}",
        response.status()
    );

    // Verify repo was created in database
    let result: Option<(String, String)> =
        sqlx::query_as("SELECT org, repo FROM repos WHERE org = 'test-org' AND repo = 'test-repo'")
            .fetch_optional(&env.pool)
            .await
            .expect("Failed to query repo");

    assert!(result.is_some(), "Repo should exist in database");
    let (org, repo) = result.unwrap();
    assert_eq!(org, "test-org");
    assert_eq!(repo, "test-repo");

    println!(
        "✓ POST /api/repos successfully created repo: {}/{}",
        org, repo
    );

    env.cleanup().await;
}

/// Test GET /api/cluster-groups with performance measurement
#[tokio::test]
#[ignore]
async fn test_get_cluster_groups_with_performance() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create 50 cluster groups with unique names
    for _ in 0..50 {
        let unique_name = format!("perf-group-{}", Uuid::new_v4());
        create_test_cluster_group(&env.pool, &unique_name).await;
    }

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    let start = Instant::now();

    let request = Request::builder()
        .uri("/api/cluster-groups")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(response.status(), StatusCode::OK);

    // Performance assertion: should complete in under 1 second
    assert!(
        elapsed.as_millis() < 1000,
        "GET /api/cluster-groups took {:?}, expected <1s",
        elapsed
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let groups: Value = serde_json::from_slice(&body).unwrap();
    let groups_array = groups.as_array().unwrap();

    assert!(
        groups_array.len() >= 50,
        "Should have at least 50 groups, got {}",
        groups_array.len()
    );

    println!(
        "✓ GET /api/cluster-groups returned {} groups in {:?}",
        groups_array.len(),
        elapsed
    );

    env.cleanup().await;
}

/// Test GET /api/clusters with bulk data and performance assertion
#[tokio::test]
#[ignore]
async fn test_get_clusters_bulk_with_performance() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create 200 clusters
    println!("Creating 200 test clusters...");
    let create_start = Instant::now();
    for _ in 0..200 {
        create_test_cluster(&env.pool).await;
    }
    let create_elapsed = create_start.elapsed();
    println!("✓ Created 200 clusters in {:?}", create_elapsed);

    // Performance assertion for cluster creation
    assert!(
        create_elapsed.as_secs() < 10,
        "Creating 200 clusters took {:?}, expected <10s",
        create_elapsed
    );

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    let start = Instant::now();

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let query_elapsed = start.elapsed();

    assert_eq!(response.status(), StatusCode::OK);

    // Performance assertion: query should complete in under 2 seconds
    assert!(
        query_elapsed.as_millis() < 2000,
        "GET /api/clusters took {:?}, expected <2s",
        query_elapsed
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let clusters: Value = serde_json::from_slice(&body).unwrap();
    let cluster_count = clusters.as_array().unwrap().len();

    assert!(
        cluster_count >= 200,
        "Should have at least 200 clusters, got {}",
        cluster_count
    );

    println!(
        "✓ GET /api/clusters returned {} clusters in {:?}",
        cluster_count, query_elapsed
    );

    env.cleanup().await;
}

/// Test DELETE /api/clusters/{id} with authentication
#[tokio::test]
#[ignore]
async fn test_delete_cluster() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    // Create a test cluster
    let cluster_id = create_test_cluster(&env.pool).await;

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    let request = Request::builder()
        .uri(format!("/api/clusters/{}", cluster_id))
        .method("DELETE")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::NO_CONTENT,
        "Expected 200 or 204 for successful deletion, got {}",
        response.status()
    );

    // Verify cluster is soft-deleted (has deleted_at timestamp)
    let result: Option<(Option<chrono::DateTime<chrono::Utc>>,)> =
        sqlx::query_as("SELECT deleted_at FROM clusters WHERE id = $1")
            .bind(cluster_id)
            .fetch_optional(&env.pool)
            .await
            .expect("Failed to query cluster");

    assert!(result.is_some(), "Cluster should still exist");
    let (deleted_at,) = result.unwrap();
    assert!(
        deleted_at.is_some(),
        "Cluster should have deleted_at timestamp"
    );

    println!(
        "✓ DELETE /api/clusters/{} successfully soft-deleted cluster",
        cluster_id
    );

    env.cleanup().await;
}

/// Test missing Authorization header format (no "Bearer" prefix)
#[tokio::test]
#[ignore]
async fn test_malformed_auth_header_returns_401() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();
    let token = env
        .generate_jwt("test@galleybytes.com")
        .expect("Failed to generate JWT");

    // Send token without "Bearer " prefix
    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", token) // Missing "Bearer " prefix
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Expected 401 for malformed auth header without 'Bearer' prefix"
    );

    println!("✓ Malformed auth header (no Bearer prefix) correctly returned 401");

    env.cleanup().await;
}
