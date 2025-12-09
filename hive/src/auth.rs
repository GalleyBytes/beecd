#![allow(clippy::result_large_err)]

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use http::Request as HttpRequest;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::Postgres, Pool};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;
use tower::{Layer, Service};
use tracing::{debug, info, warn};
use uuid::Uuid;

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
                                debug!("JWT auth success: user={}, path={}", claims.sub, uri_path);

                                // Update cluster check-in time
                                if let Ok(cluster_id) = Uuid::parse_str(&claims.cluster_id) {
                                    if !cluster_id.is_nil() {
                                        let _ = sqlx::query(
                                            "UPDATE clusters SET last_check_in_at = NOW() WHERE id = $1",
                                        )
                                        .bind(cluster_id)
                                        .execute(&db)
                                        .await;
                                    }
                                }

                                // TODO: Inject claims into request extensions for downstream use
                                // req.extensions_mut().insert(claims);

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
    cluster_id: Uuid,
    secret: &str,
) -> Result<String, Status> {
    create_access_token_with_secret(username, user_id, cluster_id, secret)
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
