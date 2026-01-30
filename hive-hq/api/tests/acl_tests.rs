mod integration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use integration::test_env::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use types::Claim;
use uuid::Uuid;

// Tests must run serially to avoid port-forward conflicts
// Run with: cargo test --test acl_tests -- --ignored --nocapture --test-threads=1

fn generate_test_jwt(jwt_secret: &str, roles: Vec<String>, tenant_id: Uuid) -> String {
    let secret_bytes = jwt_secret.as_bytes();

    let expiration =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(12 * 60 * 60);

    let claims = Claim {
        email: "test@galleybytes.com".to_string(),
        exp: expiration.as_secs() as usize,
        roles,
        tenant_id: tenant_id.to_string(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret_bytes),
    )
    .unwrap()
}

#[cfg(not(feature = "dev-mode"))]
#[tokio::test]
#[ignore]
async fn test_free_token_blocked_in_production() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/free-token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    println!("✓ Free token endpoint blocked in production mode");

    env.cleanup().await;
}

#[cfg(feature = "dev-mode")]
#[tokio::test]
#[ignore]
async fn test_free_token_works_in_dev_mode() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/free-token")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token = String::from_utf8(body.to_vec()).unwrap();

    assert!(!token.is_empty());
    println!("✓ Free token endpoint works in dev mode");

    env.cleanup().await;
}

/// Test that aversion endpoint requires aversion role
#[tokio::test]
#[ignore]
async fn test_aversion_endpoint_requires_role() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token without aversion role
    let token = generate_test_jwt(&env.jwt_secret, vec!["some-other-role".to_string()], env.tenant_id);

    let request = Request::builder()
        .uri("/api/aversion/clusters/test-cluster/namespaces")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    println!("✓ Aversion endpoint correctly rejects non-aversion role");

    env.cleanup().await;
}

/// Test that aversion endpoint accepts aversion role
#[tokio::test]
#[ignore]
async fn test_aversion_endpoint_accepts_aversion_role() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token with aversion role
    let token = generate_test_jwt(&env.jwt_secret, vec!["aversion".to_string()], env.tenant_id);

    let request = Request::builder()
        .uri("/api/aversion/clusters/test-cluster/namespaces")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should not be FORBIDDEN (might be 404 or 500 if cluster doesn't exist, but not 403)
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    println!("✓ Aversion endpoint accepts aversion role");

    env.cleanup().await;
}

/// Test that aversion endpoint accepts admin role
#[tokio::test]
#[ignore]
async fn test_aversion_endpoint_accepts_admin_role() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token with admin role
    let token = generate_test_jwt(&env.jwt_secret, vec!["admin".to_string()], env.tenant_id);

    let request = Request::builder()
        .uri("/api/aversion/clusters/test-cluster/namespaces")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should not be FORBIDDEN (might be 404 or 500 if cluster doesn't exist, but not 403)
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    println!("✓ Aversion endpoint accepts admin role");

    env.cleanup().await;
}

/// Test that admin role can access regular protected endpoints
#[tokio::test]
#[ignore]
async fn test_admin_role_accesses_protected_endpoints() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token with admin role
    let token = generate_test_jwt(&env.jwt_secret, vec!["admin".to_string()], env.tenant_id);

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    println!("✓ Admin role can access protected endpoints");

    env.cleanup().await;
}

/// Test that aversion role can access regular protected endpoints
#[tokio::test]
#[ignore]
async fn test_aversion_role_accesses_protected_endpoints() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token with aversion role
    let token = generate_test_jwt(&env.jwt_secret, vec!["aversion".to_string()], env.tenant_id);

    let request = Request::builder()
        .uri("/api/clusters")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    println!("✓ Aversion role can access protected endpoints");

    env.cleanup().await;
}

/// Test that multiple roles work correctly
#[tokio::test]
#[ignore]
async fn test_multiple_roles() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    // Create token with multiple roles
    let token = generate_test_jwt(
        &env.jwt_secret,
        vec!["admin".to_string(), "aversion".to_string()],
        env.tenant_id,
    );

    let request = Request::builder()
        .uri("/api/clusters/test-cluster/namespaces")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    // Should not be FORBIDDEN
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    println!("✓ Multiple roles work correctly");

    env.cleanup().await;
}

/// Test that no auth token is rejected
#[tokio::test]
#[ignore]
async fn test_aversion_endpoint_no_auth() {
    let env = TestEnvironment::setup()
        .await
        .expect("Failed to setup test environment");

    let app = env.create_test_app();

    let request = Request::builder()
        .uri("/api/clusters/test-cluster/namespaces")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    println!("✓ Aversion endpoint rejects requests without auth");

    env.cleanup().await;
}
