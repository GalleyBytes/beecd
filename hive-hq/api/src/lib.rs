// Library exports for testing
// This file makes the API components available for integration testing

pub mod handler;
pub mod util;

#[cfg(test)]
mod auth_tests;

#[derive(Clone)]
pub struct ServerState {
    pub pool: sqlx::Pool<sqlx::Postgres>,
    pub readonly_pool: sqlx::Pool<sqlx::Postgres>,
    pub agent_manifest_template: String,
    pub agent_default_image: Option<String>,
    pub hive_default_grpc_server: Option<String>,
    pub version: String,
    pub gh_token: String,
    pub github_api_url: String,
    /// JWT secret bytes - either decoded from base64 or raw UTF-8 bytes
    pub jwt_secret_bytes: Vec<u8>,
    pub read_replica_wait_in_ms: u64,
    /// GitHub webhook callback URL.
    /// This must be externally reachable by GitHub, e.g.:
    ///   https://hive-hq.example.com/api/webhooks/github
    pub github_webhook_callback_url: Option<String>,
}
