#![allow(dead_code)]

use axum::{
    routing::{delete, get, post},
    Router,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use sqlx::PgPool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use types::Claim;
use uuid::Uuid;

pub struct TestEnvironment {
    pub namespace: String,
    pub pool: PgPool,
    pub jwt_secret: String,
}

impl TestEnvironment {
    pub async fn setup() -> Result<Self, Box<dyn std::error::Error>> {
        let namespace = std::env::var("TEST_NAMESPACE")
            .expect("TEST_NAMESPACE environment variable must be set");

        // Use the fixed port from setup script
        let db_port = std::env::var("TEST_DB_PORT").unwrap_or_else(|_| "15432".to_string());

        println!("Setting up test environment in namespace: {}", namespace);
        println!("Using database port: {}", db_port);

        // Wait a bit to ensure port-forward is stable
        sleep(Duration::from_millis(500)).await;

        // Create database connection pool with custom settings
        let database_url = format!(
            "postgres://test_user:test_pass@localhost:{}/test_hive",
            db_port
        );

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&database_url)
            .await?;

        // Generate test JWT secret
        let jwt_secret =
            "test_jwt_secret_for_integration_tests_minimum_length_required".to_string();

        println!("✓ Test environment ready");

        Ok(Self {
            namespace,
            pool,
            jwt_secret,
        })
    }

    pub async fn cleanup(self) {
        println!("Cleaning up test environment...");

        // Close database connections
        self.pool.close().await;

        // Note: namespace cleanup is handled by cleanup script
        println!("✓ Test environment cleaned up");
    }

    pub fn generate_jwt(&self, email: &str) -> Result<String, Box<dyn std::error::Error>> {
        let expiration =
            SystemTime::now().duration_since(UNIX_EPOCH)? + Duration::from_secs(12 * 60 * 60);

        let claims = Claim {
            email: email.to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec!["admin".to_string()],
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn generate_expired_jwt(&self, email: &str) -> Result<String, Box<dyn std::error::Error>> {
        let expiration = SystemTime::now().duration_since(UNIX_EPOCH)? - Duration::from_secs(3600); // Expired 1 hour ago

        let claims = Claim {
            email: email.to_string(),
            exp: expiration.as_secs() as usize,
            roles: vec!["admin".to_string()],
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    /// Creates a test Axum app with all routes and middleware configured
    /// This mirrors the production app setup but with test database connections
    pub fn create_test_app(&self) -> Router {
        // Import the handler module from the main crate
        use api::handler;
        use api::ServerState;
        use tower_http::cors::{Any, CorsLayer};

        let server_state = ServerState {
            pool: self.pool.clone(),
            readonly_pool: self.pool.clone(), // Use same pool for tests
            agent_manifest_template: "test-template".to_string(),
            agent_default_image: Some("test-image:latest".to_string()),
            hive_default_grpc_server: Some("test-grpc:50051".to_string()),
            version: "test-1.0.0".to_string(),
            gh_token: "test-token".to_string(),
            github_api_url: "https://api.github.com".to_string(),
            jwt_secret_bytes: self.jwt_secret.clone().into_bytes(),
            read_replica_wait_in_ms: 0, // No wait for tests
            github_webhook_callback_url: None,
        };

        let cors = CorsLayer::new().allow_origin(Any);

        // Build protected routes with auth middleware
        let protected_routes = Router::new()
            .layer(cors)
            .route("/api/clusters", get(handler::get_clusters))
            .route("/api/count/errors", get(handler::get_error_count))
            .route(
                "/api/clusters/{id}",
                get(handler::get_cluster).delete(handler::delete_cluster),
            )
            .route(
                "/api/clusters/{id}/namespaces",
                get(handler::get_cluster_namespaces).post(handler::post_create_cluster_namespaces),
            )
            .route(
                "/api/clusters/{id}/groups",
                get(handler::get_cluster_cluster_groups),
            )
            .route(
                "/api/clusters/{id}/groups/{cluster_group_id}",
                delete(handler::delete_group_relationship),
            )
            .route(
                "/api/cluster-groups",
                get(handler::get_cluster_groups).post(handler::add_cluster_groups),
            )
            .route(
                "/api/cluster-groups/{id}",
                get(handler::get_cluster_group)
                    .delete(handler::delete_cluster_group)
                    .put(handler::put_cluster_group),
            )
            .route(
                "/api/cluster-groups/{id}/clusters",
                get(handler::get_cluster_group_cluster_association)
                    .post(handler::post_subscribe_clusters),
            )
            .route(
                "/api/cluster-groups/{id}/service-definitions",
                get(handler::get_cluster_group_service_definitions)
                    .post(handler::post_subscribe_service_definitions)
                    .put(handler::put_subscribe_service_definitions),
            )
            .route(
                "/api/service-definitions/{id}",
                get(handler::get_service_definition)
                    .put(handler::put_service_definition)
                    .delete(handler::delete_service_definitions),
            )
            .route(
                "/api/repos",
                get(handler::get_repos).post(handler::post_repo),
            )
            .route("/api/repos/{id}", get(handler::get_repo))
            .route(
                "/api/repos/{id}/service-definitions",
                get(handler::get_repo_service_definitions).post(handler::post_global_repo_service),
            )
            .route(
                "/api/repos/{id}/branches",
                get(handler::get_branches).post(handler::post_branch),
            )
            .route(
                "/api/branches/{id}/service-definitions",
                get(handler::get_branch_service_definitions).post(handler::post_branch_service),
            )
            .route(
                "/api/users",
                post(handler::post_user).put(handler::put_user),
            )
            .with_state(server_state.clone())
            .layer(axum::middleware::from_fn_with_state(
                server_state.clone(),
                handler::validate_auth,
            ));

        // Build public routes
        let mut public_routes = Router::new().route("/api/version", get(handler::version));

        #[cfg(feature = "dev-mode")]
        {
            public_routes = public_routes.route("/api/free-token", get(handler::free_token));
        }

        let public_routes = public_routes.with_state(server_state.clone());

        // Routes specifically for aversion service - requires aversion or admin role
        let aversion_routes = Router::new()
            .route(
                "/api/aversion/clusters/{cluster_name}/namespaces",
                get(handler::get_namespaces_via_cluster_name),
            )
            .with_state(server_state.clone())
            .layer(axum::middleware::from_fn_with_state(
                server_state.clone(),
                handler::validate_auth_aversion,
            ));

        // Merge public, aversion, and protected routes
        public_routes.merge(aversion_routes).merge(protected_routes)
    }
}

// Test fixture helpers
pub async fn create_test_cluster(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("test-cluster-{}", Uuid::new_v4());
    sqlx::query(
        r#"
        INSERT INTO clusters (id, name, metadata, version, kubernetes_version)
        VALUES ($1, $2, 'test', '1.0', '1.28')
        "#,
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await
    .expect("Failed to create test cluster");
    id
}

pub async fn create_test_namespace(pool: &PgPool, cluster_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let name = format!("test-namespace-{}", Uuid::new_v4());
    sqlx::query(
        r#"
        INSERT INTO namespaces (id, name, cluster_id)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(cluster_id)
    .execute(pool)
    .await
    .expect("Failed to create test namespace");
    id
}

pub async fn create_test_repo(pool: &PgPool) -> (Uuid, Uuid) {
    let repo_id = Uuid::new_v4();
    let org = format!("test-org-{}", Uuid::new_v4());
    let repo = format!("test-repo-{}", Uuid::new_v4());
    sqlx::query(
        r#"
        INSERT INTO repos (id, org, repo)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(repo_id)
    .bind(&org)
    .bind(&repo)
    .execute(pool)
    .await
    .expect("Failed to create test repo");

    let branch_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO repo_branches (id, branch, repo_id)
        VALUES ($1, 'main', $2)
        "#,
    )
    .bind(branch_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("Failed to create test repo branch");

    (repo_id, branch_id)
}

pub async fn create_test_service_definition(
    pool: &PgPool,
    repo_branch_id: Uuid,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO service_definitions (id, name, repo_branch_id, source_branch_requirements)
        VALUES ($1, $2, $3, '[]')
        "#,
    )
    .bind(id)
    .bind(name)
    .bind(repo_branch_id)
    .execute(pool)
    .await
    .expect("Failed to create test build target");
    id
}

pub async fn create_test_cluster_group(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO cluster_groups (id, name)
        VALUES ($1, $2)
        "#,
    )
    .bind(id)
    .bind(name)
    .execute(pool)
    .await
    .expect("Failed to create test cluster group");
    id
}

pub async fn create_test_release(
    pool: &PgPool,
    namespace_id: Uuid,
    repo_branch_id: Uuid,
    name: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO releases (
            id, namespace_id, name, path, repo_branch_id,
            hash, version, git_sha
        )
        VALUES ($1, $2, $3, '/test/path', $4, 'hash123', 'v1.0', 'abc123')
        "#,
    )
    .bind(id)
    .bind(namespace_id)
    .bind(name)
    .bind(repo_branch_id)
    .execute(pool)
    .await
    .expect("Failed to create test release");
    id
}

// Bulk fixture creation for performance testing
pub async fn create_bulk_fixtures(pool: &PgPool, count: usize) -> BulkFixtures {
    println!("Creating {} bulk test fixtures...", count);

    // Create base cluster and repo
    let cluster_id = create_test_cluster(pool).await;
    let namespace_id = create_test_namespace(pool, cluster_id).await;
    let (repo_id, branch_id) = create_test_repo(pool).await;

    let mut service_definition_ids = Vec::new();
    let mut release_ids = Vec::new();

    // Batch create build targets and releases
    for i in 0..count {
        let bt_id =
            create_test_service_definition(pool, branch_id, &format!("service-{}", i)).await;
        service_definition_ids.push(bt_id);

        let rel_id =
            create_test_release(pool, namespace_id, branch_id, &format!("release-{}", i)).await;
        release_ids.push(rel_id);
    }

    println!("✓ Created {} build targets and releases", count);

    BulkFixtures {
        cluster_id,
        namespace_id,
        repo_id,
        branch_id,
        service_definition_ids,
        release_ids,
    }
}

pub struct BulkFixtures {
    pub cluster_id: Uuid,
    pub namespace_id: Uuid,
    pub repo_id: Uuid,
    pub branch_id: Uuid,
    pub service_definition_ids: Vec<Uuid>,
    pub release_ids: Vec<Uuid>,
}
