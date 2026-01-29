// Library exports for testing
// This file makes the API components available for integration testing

pub mod handler;
pub mod util;

#[cfg(test)]
mod auth_tests;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Application state shared across all API handlers.
#[derive(Clone)]
pub struct ServerState {
    pub pool: sqlx::Pool<sqlx::Postgres>,
    pub readonly_pool: sqlx::Pool<sqlx::Postgres>,
    pub agent_manifest_template: String,
    pub agent_default_image: Option<String>,
    pub hive_default_grpc_server: Option<String>,
    /// Explicit TLS override for HIVE_DEFAULT_GRPC_SERVER (None = infer from scheme)
    pub hive_default_grpc_tls: Option<bool>,
    pub version: String,
    /// JWT secret bytes - either decoded from base64 or raw UTF-8 bytes
    pub jwt_secret_bytes: Vec<u8>,
    pub read_replica_wait_in_ms: u64,
    /// GitHub webhook callback URL.
    /// This must be externally reachable by GitHub, e.g.:
    ///   https://hive-hq.example.com/api/webhooks/github
    pub github_webhook_callback_url: Option<String>,
    /// In-memory, per-tenant encrypted secret cache. No DB persistence.
    pub secret_cache: Arc<
        RwLock<
            HashMap<(uuid::Uuid, String), (Vec<u8>, Vec<u8>, i16, chrono::DateTime<chrono::Utc>)>,
        >,
    >,
}
