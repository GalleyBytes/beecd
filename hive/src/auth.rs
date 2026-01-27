#![allow(clippy::result_large_err)]

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use http::Request as HttpRequest;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::Postgres, Executor, Pool};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;
use tower::{Layer, Service};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Tenant context extracted from JWT claims.
/// This is inserted into tonic request extensions by the auth interceptor.
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub cluster_id: Uuid,
    pub username: String,
    pub tenant_domain: Option<String>, // Queried lazily when needed for logging
}

impl TenantContext {
    /// Extract tenant context from tonic request extensions.
    /// Returns an error if the request is not authenticated.
    pub fn from_request<T>(request: &tonic::Request<T>) -> Result<Self, Status> {
        request
            .extensions()
            .get::<TenantContext>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("Missing tenant context"))
    }
}

/// Set tenant context for RLS in a database transaction or connection.
/// This must be called at the start of any transaction that accesses tenant-scoped data.
pub async fn set_tenant_context<'e, E>(executor: E, tenant_id: Uuid) -> Result<(), Status>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query("SELECT set_config('app.tenant_id', $1::text, true)")
        .bind(tenant_id.to_string())
        .execute(executor)
        .await
        .map_err(|e| Status::internal(format!("Failed to set tenant context: {}", e)))?;
    Ok(())
}

/// Decode JWT secret from environment variable.
/// Supports both base64-encoded secrets (e.g., from `openssl rand -base64 32`)
/// and raw string secrets for backward compatibility.
fn decode_jwt_secret() -> Result<Vec<u8>, Status> {
    let secret = std::env::var("JWT_SECRET_KEY")
        .map_err(|_| Status::internal("JWT_SECRET_KEY must be set"))?;

    // Try to decode as base64 first (preferred for cryptographically random secrets)
    // Fall back to raw UTF-8 bytes for backward compatibility
    let (bytes, secret_type) = match STANDARD.decode(secret.trim()) {
        Ok(decoded) if decoded.len() >= 32 => {
            let msg = format!(
                "base64-encoded binary ({} bytes decoded from {} char string)",
                decoded.len(),
                secret.trim().len()
            );
            (decoded, msg)
        }
        Ok(decoded) => {
            let raw_bytes = secret.clone().into_bytes();
            let msg = format!(
                "raw UTF-8 string ({} bytes) - base64 decoded to only {} bytes (too short)",
                raw_bytes.len(),
                decoded.len()
            );
            (raw_bytes, msg)
        }
        Err(_) => {
            let raw_bytes = secret.clone().into_bytes();
            let msg = format!("raw UTF-8 string ({} bytes)", raw_bytes.len());
            (raw_bytes, msg)
        }
    };

    debug!("JWT_SECRET_KEY: Loaded as {}", secret_type);

    if bytes.len() >= 32 {
        Ok(bytes)
    } else {
        Err(Status::internal(format!(
            "JWT_SECRET_KEY must be at least 32 bytes, got {} bytes",
            bytes.len()
        )))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // Subject: username
    pub tenant_id: String,  // Tenant UUID (for RLS context)
    pub cluster_id: String, // Cluster UUID
    pub user_id: String,    // User UUID
    pub iat: i64,           // Issued at (Unix timestamp)
    pub exp: i64,           // Expiration (Unix timestamp)
    pub nbf: i64,           // Not before (Unix timestamp)
    pub jti: String,        // JWT ID (unique identifier for this token)
}

/// Tower Layer for JWT authentication
#[derive(Clone)]
pub struct AuthLayer {
    db: Pool<Postgres>,
}

impl AuthLayer {
    pub fn new(db: Pool<Postgres>) -> Self {
        Self { db }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            db: self.db.clone(),
        }
    }
}

/// Tower Service middleware for JWT authentication
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    db: Pool<Postgres>,
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for AuthMiddleware<S>
where
    S: Service<HttpRequest<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: HttpRequest<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let db = self.db.clone();

        Box::pin(async move {
            let uri_path = req.uri().path();

            // Exempt authentication endpoints from auth requirements
            // These endpoints need to be callable without existing credentials
            if uri_path == "/beecd.Worker/Login"
                || uri_path == "/beecd.Worker/RefreshToken"
                || uri_path == "/beecd.Worker/Logout"
            {
                info!("Auth bypass for authentication endpoint: {}", uri_path);
                return inner.call(req).await;
            }

            // Check for Bearer token (JWT)
            if let Some(auth_header) = req.headers().get("authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        // Validate JWT
                        match validate_access_token(token) {
                            Ok(claims) => {
                                debug!("[tenant:{}] JWT auth success: user={}, path={}", claims.tenant_id, claims.sub, uri_path);

                                // Update cluster check-in time with tenant context for RLS
                                if let (Ok(cluster_id), Ok(tenant_id)) = (
                                    Uuid::parse_str(&claims.cluster_id),
                                    Uuid::parse_str(&claims.tenant_id),
                                ) {
                                    if !cluster_id.is_nil() {
                                        // Best-effort update in transaction with RLS context
                                        if let Ok(mut tx) = db.begin().await {
                                            let _ = set_tenant_context(&mut *tx, tenant_id).await;
                                            let _ = sqlx::query(
                                                "UPDATE clusters SET last_check_in_at = NOW() WHERE id = $1",
                                            )
                                            .bind(cluster_id)
                                            .execute(&mut *tx)
                                            .await;
                                            let _ = tx.commit().await;
                                        }
                                    }
                                }

                                // Note: TenantContext is injected by tonic interceptor (auth_interceptor)
                                // The tower layer only handles cluster check-in updates

                                return inner.call(req).await;
                            }
                            Err(e) => {
                                warn!("JWT validation failed for path={}: {}", uri_path, e);
                                let response = http::Response::builder()
                                    .status(http::StatusCode::UNAUTHORIZED)
                                    .header("content-type", "application/grpc")
                                    .body(ResBody::default())
                                    .unwrap();
                                return Ok(response);
                            }
                        }
                    }
                }
            }

            warn!("No valid authentication provided for path={}", uri_path);
            let response = http::Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .header("content-type", "application/grpc")
                .body(ResBody::default())
                .unwrap();
            Ok(response)
        })
    }
}

// JWT signing key (load from env or secret manager)
fn get_jwt_secret() -> Result<EncodingKey, Status> {
    let secret_bytes = decode_jwt_secret()?;
    Ok(EncodingKey::from_secret(&secret_bytes))
}

fn get_jwt_decoding_key() -> Result<DecodingKey, Status> {
    let secret_bytes = decode_jwt_secret()?;
    Ok(DecodingKey::from_secret(&secret_bytes))
}

// Internal function that accepts secret for testing
#[allow(dead_code)]
fn create_access_token_with_secret(
    username: &str,
    user_id: Uuid,
    tenant_id: Uuid,
    cluster_id: Uuid,
    secret: &str,
) -> Result<String, Status> {
    let now = Utc::now();
    let ttl = std::env::var("ACCESS_TOKEN_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900); // Default 15 minutes
    let expiration = now + Duration::seconds(ttl);

    let claims = Claims {
        sub: username.to_string(),
        tenant_id: tenant_id.to_string(),
        user_id: user_id.to_string(),
        cluster_id: cluster_id.to_string(),
        iat: now.timestamp(),
        exp: expiration.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    encode(&Header::default(), &claims, &encoding_key)
        .map_err(|e| Status::internal(format!("Token generation failed: {}", e)))
}

// Generate JWT access token (production)
pub fn create_access_token(
    username: &str,
    user_id: Uuid,
    tenant_id: Uuid,
    cluster_id: Uuid,
) -> Result<String, Status> {
    let now = Utc::now();
    let ttl = std::env::var("ACCESS_TOKEN_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900); // Default 15 minutes
    let expiration = now + Duration::seconds(ttl);

    let claims = Claims {
        sub: username.to_string(),
        tenant_id: tenant_id.to_string(),
        user_id: user_id.to_string(),
        cluster_id: cluster_id.to_string(),
        iat: now.timestamp(),
        exp: expiration.timestamp(),
        nbf: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
    };

    encode(&Header::default(), &claims, &get_jwt_secret()?)
        .map_err(|e| Status::internal(format!("Token generation failed: {}", e)))
}

// Validate JWT access token
pub fn validate_access_token(token: &str) -> Result<Claims, Status> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_nbf = true;

    let token_data = decode::<Claims>(token, &get_jwt_decoding_key()?, &validation)
        .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims)
}

// Generate a cryptographically random refresh token
pub fn generate_refresh_token() -> String {
    Uuid::new_v4().to_string()
}

// Hash refresh token for storage (defense in depth)
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// Test-only: Create access token with custom secret (no env var needed)
// This is public so integration tests in main.rs can use it
#[allow(dead_code)]
pub fn create_access_token_for_test(
    username: &str,
    user_id: Uuid,
    tenant_id: Uuid,
    cluster_id: Uuid,
    secret: &str,
) -> Result<String, Status> {
    create_access_token_with_secret(username, user_id, tenant_id, cluster_id, secret)
}

// Test-only: Validate token with custom secret (no env var needed)
// This is public so integration tests in main.rs can use it
#[allow(dead_code)]
pub fn validate_access_token_for_test(token: &str, secret: &str) -> Result<Claims, Status> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_nbf = true;

    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| Status::unauthenticated(format!("Invalid token: {}", e)))?;

    Ok(token_data.claims)
}

/// Tonic interceptor that extracts JWT claims and injects TenantContext into request extensions.
/// This interceptor should be applied to the gRPC service.
///
/// Note: This interceptor works in conjunction with the tower AuthLayer.
/// The tower layer handles path-based auth bypass (Login, RefreshToken, Logout)
/// and returns 401 for truly unauthenticated requests to protected endpoints.
/// This interceptor only extracts claims from valid tokens and injects TenantContext.
pub fn auth_interceptor(mut req: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
    // Extract Bearer token from authorization header
    // If no auth header present, let the request through - the tower layer already
    // handled path-based bypass for Login/RefreshToken/Logout endpoints.
    let token = match req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(t) => t,
        None => {
            // No auth header - tower layer already allowed this through
            // (either it's an auth endpoint, or tower layer would have rejected it)
            return Ok(req);
        }
    };

    // Validate JWT and extract claims
    let claims = validate_access_token(token)?;

    // Parse UUIDs from claims
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| Status::internal("Invalid tenant_id in token"))?;
    let user_id = Uuid::parse_str(&claims.user_id)
        .map_err(|_| Status::internal("Invalid user_id in token"))?;
    let cluster_id = Uuid::parse_str(&claims.cluster_id)
        .map_err(|_| Status::internal("Invalid cluster_id in token"))?;

    // Create and inject tenant context
    let tenant_ctx = TenantContext {
        tenant_id,
        user_id,
        cluster_id,
        username: claims.sub.clone(),
        tenant_domain: None, // Queried later when needed for logging
    };

    debug!(
        "Auth interceptor: user={}, tenant={}, cluster={}",
        claims.sub, tenant_id, cluster_id
    );

    req.extensions_mut().insert(tenant_ctx);
    Ok(req)
}
