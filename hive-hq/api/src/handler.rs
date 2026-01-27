use crate::util;
use crate::ServerState;
use axum::body::Body;
use axum::extract::Path;
use axum::extract::Query;
use axum::extract::Request;
use axum::http::Response;
use axum::middleware::Next;
use axum::{extract::State, http::StatusCode, Json};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use futures::future;
use futures::stream::{self, StreamExt};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::error;
use types::*;
use utoipa::ToSchema;

use uuid::Uuid;

/// Base domain for subdomain extraction (e.g., "beecd.example.com")
/// When set, subdomains like "tenant1.beecd.example.com" will extract "tenant1" as the slug.
/// When unset, falls back to extracting the first label (before the first dot).
static BASE_DOMAIN: OnceLock<Option<String>> = OnceLock::new();

fn get_base_domain() -> &'static Option<String> {
    BASE_DOMAIN.get_or_init(|| {
        std::env::var("BASE_DOMAIN").ok().map(|d| {
            let d = d.trim().to_lowercase();
            // Remove leading dot if present
            if d.starts_with('.') {
                d[1..].to_string()
            } else {
                d
            }
        })
    })
}

/// Extract subdomain slug from a host string given a base domain.
/// If base_domain is provided (e.g., "beecd.example.com"), strips it from the host
/// to get the subdomain. Otherwise, takes the first label before the first dot.
fn extract_subdomain_slug_with_base(host: &str, base_domain: Option<&str>) -> Option<String> {
    // Remove port if present
    let host_no_port = host.split(':').next().unwrap_or(host).to_lowercase();

    if let Some(base) = base_domain {
        let base = base.to_lowercase();
        // If host ends with .base_domain, extract the prefix
        if host_no_port.ends_with(&format!(".{}", base)) {
            let prefix_len = host_no_port.len() - base.len() - 1; // -1 for the dot
            let prefix = &host_no_port[..prefix_len];
            // Get the rightmost label of the prefix (closest to base domain)
            let slug = prefix.rsplit('.').next().unwrap_or(prefix);
            if !slug.is_empty() {
                return Some(slug.to_string());
            }
        }
        // If host equals base_domain exactly, no subdomain
        if host_no_port == base {
            return None;
        }
    }

    // Fallback: first label before the first dot
    let slug = host_no_port.split('.').next().unwrap_or("");
    if slug.is_empty() || slug == "localhost" {
        None
    } else {
        Some(slug.to_string())
    }
}

/// Extract subdomain slug from a host string using the global BASE_DOMAIN.
fn extract_subdomain_slug(host: &str) -> Option<String> {
    extract_subdomain_slug_with_base(host, get_base_domain().as_deref())
}

/// Extract tenant_id from Host header
/// Looks up the domain in the tenants table and returns the tenant_id
async fn extract_tenant_from_request(
    pool: &sqlx::Pool<sqlx::Postgres>,
    headers: &axum::http::HeaderMap,
) -> Result<Uuid, (StatusCode, String)> {
    // Prefer X-Forwarded-Host when behind dev proxy; fall back to Host.
    // If those are unusable, try Origin then Referer to recover the tenant subdomain.
    let xf_host_name = axum::http::HeaderName::from_static("x-forwarded-host");
    let host = headers
        .get(&xf_host_name)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "localhost".to_string());

    // Try to extract slug from host using BASE_DOMAIN
    let mut slug = extract_subdomain_slug(&host);

    tracing::debug!(
        "extract_tenant_from_request: host={}, slug={:?}, base_domain={:?}",
        host,
        slug,
        get_base_domain()
    );

    // If no slug found, try Origin and Referer headers as fallback
    if slug.is_none() {
        let fallback_host = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|h| h.to_str().ok())
            .map(|origin_val| {
                origin_val
                    .split("//")
                    .nth(1)
                    .map(|s| s.split('/').next().unwrap_or(s))
                    .unwrap_or(origin_val)
                    .to_string()
            })
            .or_else(|| {
                headers
                    .get(axum::http::header::REFERER)
                    .and_then(|h| h.to_str().ok())
                    .map(|referer_val| {
                        referer_val
                            .split("//")
                            .nth(1)
                            .map(|s| s.split('/').next().unwrap_or(s))
                            .unwrap_or(referer_val)
                            .to_string()
                    })
            });

        if let Some(fb_host) = fallback_host {
            slug = extract_subdomain_slug(&fb_host);
            tracing::debug!(
                "extract_tenant_from_request: fallback host={}, slug={:?}",
                fb_host,
                slug
            );
        }
    }

    let slug = slug.ok_or_else(|| {
        tracing::warn!("No tenant subdomain found in host: {}", host);
        (
            StatusCode::NOT_FOUND,
            "No tenant subdomain found".to_string(),
        )
    })?;

    // Look up tenant by slug (domain column stores just the slug)
    let result = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id FROM tenants
        WHERE domain = $1 AND status = 'active' AND deleted_at IS NULL
        "#,
    )
    .bind(&slug)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to lookup tenant by slug {}: {:?}", slug, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to resolve tenant".to_string(),
        )
    })?;

    result.ok_or_else(|| {
        tracing::warn!("Tenant not found for slug: {}", slug);
        (
            StatusCode::NOT_FOUND,
            format!("Tenant not found for subdomain: {}", slug),
        )
    })
}

/// Set the RLS context for the current request
/// This sets app.tenant_id which is used by RLS policies
async fn set_tenant_context(
    client: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    let query = format!("SET LOCAL app.tenant_id = '{}';", tenant_id);
    sqlx::query(&query)
        .execute(&mut **client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to set tenant context: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to set tenant context".to_string(),
            )
        })?;
    Ok(())
}

/// Get tenant domain from tenant_id for logging
async fn get_tenant_domain(pool: &sqlx::Pool<sqlx::Postgres>, tenant_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT domain FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| tenant_id.to_string())
}

/// Get a read-only transaction with tenant context set for RLS
/// This ensures all read queries respect tenant isolation  
/// Returns (transaction, tenant_id, tenant_domain) for logging
async fn get_tenant_tx<'a>(
    pool: &'a sqlx::Pool<sqlx::Postgres>,
    headers: &axum::http::HeaderMap,
) -> Result<(sqlx::Transaction<'a, sqlx::Postgres>, Uuid, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(pool, headers).await?;
    let tenant_domain = get_tenant_domain(pool, tenant_id).await;
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "get_tenant_tx_begin"))?;
    set_tenant_context(&mut tx, tenant_id).await?;
    Ok((tx, tenant_id, tenant_domain))
}

/// Sanitize database errors to prevent information leakage
/// Logs the full error server-side but returns generic message to client
fn sanitize_db_error(e: sqlx::Error, context: &str) -> (StatusCode, String) {
    tracing::error!("Database error in {}: {:?}", context, e);
    match e {
        sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
        sqlx::Error::Database(db_err) => {
            if let Some(pg_err) = db_err.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
                if pg_err.code() == "23505" {
                    return (StatusCode::CONFLICT, "Duplicate entry".to_string());
                }
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        ),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_github_hmac_sha256(
    signature_header: &str,
    secret: &str,
    body: &[u8],
) -> Result<bool, String> {
    let expected_hex = signature_header
        .strip_prefix("sha256=")
        .ok_or_else(|| "Invalid signature format".to_string())?;

    let provided =
        hex::decode(expected_hex).map_err(|_| "Invalid signature encoding".to_string())?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| "Invalid HMAC secret".to_string())?;
    mac.update(body);
    let computed = mac.finalize().into_bytes();

    Ok(constant_time_eq(&provided, &computed))
}

/// Compute the path from manifest_path_template if available
/// Falls back to the stored path if no template is set
fn compute_release_path(release: &mut ReleaseData) {
    if let Some(template) = &release.manifest_path_template {
        release.path = template
            .replace("{cluster}", &release.cluster_name)
            .replace("{namespace}", &release.namespace)
            .replace("{service}", &release.name);
    }
    // If no template, keep the existing path from the database
}

#[derive(Debug, Clone)]
struct ParsedRepoUrl {
    host: String,
    org: String,
    repo: String,
    web_base_url: String,
    api_base_url: String,
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('/')
        .trim_start_matches("www.")
        .to_lowercase()
}

fn github_default_base_urls(scheme: &str, host: &str) -> (String, String) {
    let host = normalize_host(host);
    if host == "github.com" {
        (
            "https://github.com".to_string(),
            "https://api.github.com".to_string(),
        )
    } else {
        (
            format!("{}://{}", scheme, host),
            format!("{}://{}/api/v3", scheme, host),
        )
    }
}

fn parse_repo_url(input: &str) -> Option<ParsedRepoUrl> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }

    // Accept shorthand "org/repo" (assume github.com).
    if !s.contains("://") && s.matches('/').count() == 1 && !s.contains('.') {
        let mut parts = s.split('/');
        let org = parts.next()?.trim();
        let repo = parts.next()?.trim().trim_end_matches(".git");
        if org.is_empty() || repo.is_empty() {
            return None;
        }
        let (web_base_url, api_base_url) = github_default_base_urls("https", "github.com");
        return Some(ParsedRepoUrl {
            host: "github.com".to_string(),
            org: org.to_string(),
            repo: repo.to_string(),
            web_base_url,
            api_base_url,
        });
    }

    // Accept SSH clone URLs:
    // - git@host:org/repo.git
    // - ssh://git@host/org/repo.git
    let ssh_re =
        regex::Regex::new(r"^(?:ssh://)?git@([^:/]+)[:/]([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$")
            .ok()?;
    if let Some(caps) = ssh_re.captures(s) {
        let host = normalize_host(caps.get(1)?.as_str());
        let org = caps.get(2)?.as_str().trim();
        let repo = caps.get(3)?.as_str().trim();
        if host.is_empty() || org.is_empty() || repo.is_empty() {
            return None;
        }
        let (web_base_url, api_base_url) = github_default_base_urls("https", &host);
        return Some(ParsedRepoUrl {
            host,
            org: org.to_string(),
            repo: repo.to_string(),
            web_base_url,
            api_base_url,
        });
    }

    // Accept http(s) URLs and host/org/repo (no scheme).
    let http_re = regex::Regex::new(
        r"^(?:(https?)://)?(?:www\.)?([^/]+)/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
    )
    .ok()?;
    let caps = http_re.captures(s)?;
    let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("https");
    let host = normalize_host(caps.get(2)?.as_str());
    let org = caps.get(3)?.as_str().trim();
    let repo = caps.get(4)?.as_str().trim();
    if host.is_empty() || org.is_empty() || repo.is_empty() {
        return None;
    }
    let (web_base_url, api_base_url) = github_default_base_urls(scheme, &host);
    Some(ParsedRepoUrl {
        host,
        org: org.to_string(),
        repo: repo.to_string(),
        web_base_url,
        api_base_url,
    })
}

/// Pagination parameters for list endpoints
#[derive(Debug, Deserialize, ToSchema)]
pub struct Pagination {
    /// Number of items to return (default: 50, max: 500)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Number of items to skip (default: 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

impl Pagination {
    /// Validate and clamp pagination parameters
    pub fn validate(self) -> Self {
        Self {
            limit: self.limit.clamp(1, 500),
            offset: self.offset.max(0),
        }
    }
}

/// Crypto module for secret encryption/decryption
mod crypto {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    const NONCE_SIZE: usize = 12;

    /// Encrypt plaintext using AES-256-GCM
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes".to_string());
        }

        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // In production, use a proper random source
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt ciphertext using AES-256-GCM
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes".to_string());
        }

        if iv.len() != NONCE_SIZE {
            return Err(format!("IV must be {} bytes", NONCE_SIZE));
        }

        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Derive a key using HKDF
    pub fn derive_key(root_key: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(salt), root_key);
        let mut key = [0u8; 32];
        hkdf.expand(b"secret-encryption", &mut key)
            .map_err(|e| format!("HKDF expansion failed: {}", e))?;
        Ok(key)
    }
}

/// Get beecd-hive-hq version
#[utoipa::path(
    get,
    path = "/api/version",
    responses(
        (status = 200, description = "Returns version of hq", body = String),
    )
)]
pub async fn version(
    State(state): State<ServerState>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    Ok((StatusCode::OK, state.version))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AppConfigResponse {
    /// API version
    pub version: String,
    /// Base domain for tenant subdomains (e.g., "beecd.example.com")
    /// When set, tenant URLs are constructed as "{slug}.{base_domain}"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_domain: Option<String>,
}

/// Get public application configuration
///
/// Returns non-sensitive configuration values needed by the UI,
/// including version and base domain for subdomain construction.
#[utoipa::path(
    get,
    path = "/api/config",
    responses(
        (status = 200, description = "Returns public app configuration", body = AppConfigResponse),
    )
)]
pub async fn get_app_config(State(state): State<ServerState>) -> Json<AppConfigResponse> {
    Json(AppConfigResponse {
        version: state.version.clone(),
        base_domain: get_base_domain().clone(),
    })
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClusterDefaultsResponse {
    /// Default Hive gRPC address in host:port form (no scheme)
    pub grpc_address: Option<String>,
    /// Whether TLS should be used when constructing the gRPC URI from host:port
    pub grpc_tls: Option<bool>,
    /// Default agent container image
    pub agent_image: Option<String>,
}

/// Get default values for cluster creation/manifest generation.
///
/// Values come from environment variables configured on the API:
/// - HIVE_DEFAULT_GRPC_SERVER (may be scheme or host:port)
/// - AGENT_DEFAULT_IMAGE
#[utoipa::path(
    get,
    path = "/api/cluster-defaults",
    responses(
        (status = 200, description = "Returns configured defaults for cluster creation", body = ClusterDefaultsResponse),
    ),
    security(
        ("bearerAuth"=[]),
    )
)]
pub async fn get_cluster_defaults(
    State(state): State<ServerState>,
) -> Result<Json<ClusterDefaultsResponse>, (StatusCode, String)> {
    let (grpc_address, grpc_tls) = match state.hive_default_grpc_server.clone() {
        None => (None, None),
        Some(raw) => {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                (None, None)
            } else if let Some((scheme, rest)) = trimmed.split_once("://") {
                let rest = rest.split('/').next().unwrap_or("").to_string();
                if rest.is_empty() {
                    (None, None)
                } else {
                    let tls = scheme.eq_ignore_ascii_case("https");
                    (Some(rest), Some(tls))
                }
            } else {
                // No scheme provided; default to plaintext for in-cluster addresses.
                (
                    Some(trimmed.split('/').next().unwrap_or("").to_string()),
                    Some(false),
                )
            }
        }
    };

    Ok(Json(ClusterDefaultsResponse {
        grpc_address,
        grpc_tls,
        agent_image: state.agent_default_image.clone(),
    }))
}

#[cfg(feature = "dev-mode")]
pub async fn free_token(
    State(state): State<ServerState>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let token = generate_jwt(
        &state.jwt_secret_bytes,
        String::from("user@galleybytes.com"),
        String::from("00000000-0000-0000-0000-000000000000"), // dev default tenant
        vec![String::from("admin")],
    )
    .map_err(|e| {
        tracing::error!("Failed to generate JWT: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate authentication token".to_string(),
        )
    })?;
    Ok((StatusCode::OK, token))
}

/// Get default service data by name
#[utoipa::path(
    get,
    path = "/api/service/{name}",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns service data for given name", body = types::ServiceDefinitionData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn get_service(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ServiceDefinitionData>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as::<_, ServiceDefinitionData>(
        r#"
        SELECT
            service_definitions.id AS service_definition_id,
            service_definitions.name AS name,
            service_definitions.deleted_at AS service_deleted_at,
            repo_branches.id AS repo_branch_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repo_branches.branch AS branch,
            service_definitions.source_branch_requirements,
            service_definitions.manifest_path_template
        FROM service_definitions
            JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
        WHERE
            service_definitions.name = $1
            AND service_definitions.deleted_at IS NULL
        ORDER BY service_definitions.name
        LIMIT $2 OFFSET $3
    "#,
    )
    .bind(&name)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_service"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_commit"))?;

    Ok(Json(result))
}

/// Get service data via id
#[utoipa::path(
    get,
    path = "/api/service-definitions/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns service data for given id", body = types::ServiceDefinitionData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn get_service_definition(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceDefinitionData>, (StatusCode, String)> {
    // TODO in the ui, make use of the deleted_at timestamp to inform the
    // user that this resource, while visible, can not be used while it is deleted.
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as::<_, ServiceDefinitionData>(
        r#"
        SELECT
            service_definitions.id AS service_definition_id,
            service_definitions.name AS name,
            service_definitions.deleted_at AS service_deleted_at,
            repo_branches.id AS repo_branch_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repo_branches.branch AS branch,
            service_definitions.source_branch_requirements,
            service_definitions.manifest_path_template
        FROM service_definitions
            JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
        WHERE
            service_definitions.id =  $1
    "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_service_definition"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_definition_commit"))?;

    Ok(Json(result))
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PutServiceData {
    source_branch_requirements: Option<String>,
}

/// Allows a limited set of fields to update on service_definitions by id
#[utoipa::path(
    put,
    path = "/api/service-definitions/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn put_service_definition(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PutServiceData>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_service_definition_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE
            service_definitions
        SET
            source_branch_requirements = $2
        WHERE
            service_definitions.id = $1
        "#,
    )
    .bind(id)
    .bind(&data.source_branch_requirements)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_service_definition"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_service_definition_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Get a list of service data not associated with a particular cluster group via id
#[utoipa::path(
    get,
    path = "/api/cluster-groups/{id}/unassociated-service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of all service data not associated with a cluster group", body = [types::ServiceDefinitionData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn get_unassociated_service_definitions_for_cluster_group(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ServiceDefinitionData>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as::<_, ServiceDefinitionData>(
            r#"
            SELECT
                service_definitions.id AS service_definition_id,
                service_definitions.name AS name,
                service_definitions.deleted_at AS service_deleted_at,
                repo_branches.id AS repo_branch_id,
                repos.provider AS provider,
                repos.host AS host,
                repos.web_base_url AS web_base_url,
                repos.org AS org,
                repos.repo AS repo,
                repos.id AS repo_id,
                repo_branches.branch AS branch,
                service_definitions.source_branch_requirements,
                service_definitions.manifest_path_template
            FROM service_definitions
            LEFT OUTER JOIN repo_branches
                ON repo_branches.id = service_definitions.repo_branch_id
            JOIN repos
                ON repos.id = repo_branches.repo_id
            WHERE
                service_definitions.name NOT IN
                (
                    SELECT
                        service_definitions.name
                    FROM
                        cluster_groups
                        JOIN service_definition_cluster_group_relationships
                            ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                        JOIN
                            service_definitions
                            ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                    WHERE
                        cluster_groups.id = $1
                )
                AND service_definitions.deleted_at IS NULL
            ORDER BY service_definitions.name
            LIMIT $2 OFFSET $3
        "#,
        )
        .bind(id)
        .bind(pagination.limit)
        .bind(pagination.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_put_unassociated_service_definitions"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_unassociated_service_definitions_commit"))?;

    Ok(Json(result))
}

/// Get a list of all non-deleted clusters
#[utoipa::path(
    get,
    path = "/api/clusters",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a paginated list of all non-deleted clusters", body = types::PaginatedResponse<types::Cluster>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn get_clusters(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<PaginatedResponse<Cluster>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    // Get total count
    let (total,): (i64,) =
        sqlx::query_as(r#"SELECT COUNT(*) FROM clusters WHERE deleted_at IS NULL"#)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "get_clusters_count"))?;

    // Get paginated data
    let data: Vec<Cluster> = sqlx::query_as(
        r#"SELECT * FROM clusters WHERE deleted_at IS NULL ORDER BY name LIMIT $1 OFFSET $2"#,
    )
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_clusters"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_clusters_commit"))?;

    Ok(Json(PaginatedResponse::new(
        data,
        total,
        pagination.limit,
        pagination.offset,
    )))
}

/// Get a count of errors for each cluster
#[utoipa::path(
    get,
    path = "/api/count/errors",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Successful deletion of cluster", body = [types::ErrorCount]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn get_error_count(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ErrorCount>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as(r#"
        SELECT
            clusters.id as cluster_id,
            clusters.name as cluster_name,
            COUNT(hive_errors.id)::INT4 + COALESCE(heartbeat.count, 0) as count
        FROM clusters
        LEFT JOIN hive_errors ON hive_errors.cluster_id = clusters.id AND hive_errors.deprecated_at IS NULL
        LEFT JOIN (
            SELECT
                id as cluster_id,
                1 as count
            FROM
                clusters
            WHERE
                last_check_in_at < NOW()::timestamp - INTERVAL '1.5 min'
        ) AS heartbeat ON clusters.id = heartbeat.cluster_id
        WHERE clusters.deleted_at IS NULL
        GROUP BY
            clusters.id, clusters.name, heartbeat.count
        ORDER BY clusters.name
        LIMIT $1 OFFSET $2
    "#)
        .bind(pagination.limit)
        .bind(pagination.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_error_count"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_error_count_commit"))?;

    Ok(Json(result))
}

/// Get cluster data via id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Successful cluster query", body = types::Cluster),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn get_cluster(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Cluster>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as("SELECT * FROM clusters WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_commit"))?;

    Ok(Json(result))
}

/// Delete a cluster by id
#[utoipa::path(
    delete,
    path = "/api/clusters/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Successful deletion of cluster"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn delete_cluster(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    // Use transaction to ensure both operations succeed or fail together
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_begin_transaction"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // When "soft" deleting a cluster, also delete the user that allows
    // the agent to register, effectively preventing any new queries to this cluster
    sqlx::query("DELETE FROM users WHERE name = (SELECT name FROM clusters WHERE id = $1)")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_user"))?;

    sqlx::query("UPDATE clusters SET deleted_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_soft_delete"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Create a new cluster
///
/// Creates a cluster and optionally creates/updates the associated agent user.
/// If a user with the same name already exists and `regenerate_secret` is not set,
/// returns user_existed=true without generating a manifest.
/// If `regenerate_secret` is true, updates the existing user's secret and returns a new manifest.
#[utoipa::path(
    post,
    path = "/api/clusters",
    request_body = types::PostCluster,
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns cluster data with manifest info", body = types::PostClusterResponse),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 409, description = "Fails on duplicate cluster name"),
        (status = 422, description = "Fails when post data is invalid"),
        (status = 424, description = "Fails when manifest could not be generated"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn post_cluster(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<types::PostCluster>,
) -> Result<Json<types::PostClusterResponse>, (StatusCode, String)> {
    // Validate cluster name
    let name = data.name.trim();
    if name.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            String::from("Cluster name cannot be empty"),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;
    let tenant_domain = get_tenant_domain(&state.pool, tenant_id).await;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_cluster_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Check if cluster already exists
    let existing_cluster: Option<types::Cluster> = sqlx::query_as(
        "SELECT id, name, metadata, version, kubernetes_version FROM clusters WHERE name = $1 AND deleted_at IS NULL"
    )
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_cluster_check_existing"))?;

    let cluster = if let Some(existing) = existing_cluster {
        existing
    } else {
        // Insert the cluster
        sqlx::query_as(
            r#"
            INSERT INTO clusters (id, name, tenant_id)
            VALUES (gen_random_uuid(), $1, $2)
            RETURNING id, name, metadata, version, kubernetes_version
            "#,
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(database_error) => {
                match database_error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
                    Some(pg_database_error) => {
                        if pg_database_error.code() == "23505" {
                            (
                                StatusCode::CONFLICT,
                                String::from("A cluster with this name already exists"),
                            )
                        } else {
                            tracing::error!(
                                "Database error inserting cluster: {}",
                                pg_database_error
                            );
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                String::from("Database error while creating cluster"),
                            )
                        }
                    }
                    None => {
                        tracing::error!(
                            "[tenant:{}] Database error inserting cluster: {}",
                            tenant_domain,
                            database_error
                        );
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            String::from("Database error while creating cluster"),
                        )
                    }
                }
            }
            _ => {
                tracing::error!(
                    "[tenant:{}] Unknown error inserting cluster: {}",
                    tenant_domain,
                    e
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Failed to create cluster"),
                )
            }
        })?
    };

    // Check if user with same name exists
    let existing_user: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE name = $1 AND deleted_at IS NULL")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "post_cluster_check_user"))?;

    let user_existed = existing_user.is_some();
    let regenerate_secret = data.regenerate_secret.unwrap_or(false);

    // If user exists and we're not regenerating, return without manifest
    if user_existed && !regenerate_secret {
        // We do NOT store the agent secret, only a secure hash.
        // For "keep existing secret" flows we can render a manifest with a placeholder value.
        const PLACEHOLDER_SECRET: &str = "REPLACE_WITH_EXISTING_AGENT_SECRET";
        let placeholder_secret_b64 = general_purpose::STANDARD.encode(PLACEHOLDER_SECRET);

        let manifest = match &data.context {
            Some(context) => {
                let context_with_secret = match context.clone().as_object_mut() {
                    Some(object) => {
                        let key = "agent_name";
                        let value = util::value_or_default(
                            object.get(key),
                            Some(String::from(name)),
                            false,
                        )
                        .map_err(|e| {
                            (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                        })?;
                        object.insert(String::from(key), value);

                        let key = "namespace";
                        let value = util::value_or_default(
                            object.get(key),
                            Some(String::from("beecd-system")),
                            false,
                        )
                        .map_err(|e| {
                            (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                        })?;
                        object.insert(String::from(key), value);

                        let key = "grpc_address";
                        let value = util::value_or_default(
                            object.get(key),
                            state.hive_default_grpc_server.clone(),
                            true,
                        )
                        .map_err(|e| {
                            (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                        })?;
                        object.insert(String::from(key), value);

                        // Whether to use TLS when GRPC_ADDRESS is provided as host:port (no scheme).
                        // Defaults to true.
                        let grpc_tls = match object.get("grpc_tls") {
                            Some(serde_json::Value::Bool(b)) => *b,
                            Some(serde_json::Value::String(s)) => {
                                matches!(
                                    s.to_lowercase().as_str(),
                                    "true" | "1" | "yes" | "y" | "on"
                                )
                            }
                            _ => true,
                        };
                        object.insert(
                            String::from("grpc_tls"),
                            serde_json::Value::String(
                                if grpc_tls { "true" } else { "false" }.to_string(),
                            ),
                        );

                        let key = "image";
                        let value = util::value_or_default(
                            object.get(key),
                            state.agent_default_image.clone(),
                            true,
                        )
                        .map_err(|e| {
                            (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                        })?;
                        object.insert(String::from(key), value);

                        object.insert(
                            String::from("secret"),
                            serde_json::Value::String(placeholder_secret_b64.clone()),
                        );
                        object.insert(
                            String::from("name"),
                            serde_json::Value::String(name.to_string()),
                        );
                        if !object.contains_key("env") {
                            object.insert(String::from("env"), serde_json::Value::Array(vec![]));
                        }

                        serde_json::to_value(object)
                            .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
                    }
                    None => {
                        return Err((
                            StatusCode::UNPROCESSABLE_ENTITY,
                            String::from("context data is invalid"),
                        ))
                    }
                };

                util::generate_manifest(&state.agent_manifest_template, context_with_secret)
                    .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
            }
            None => {
                // No context provided, generate with defaults
                let mut object = serde_json::Map::new();
                object.insert(
                    String::from("agent_name"),
                    serde_json::Value::String(name.to_string()),
                );
                object.insert(
                    String::from("namespace"),
                    serde_json::Value::String(String::from("beecd-system")),
                );

                let grpc_address = state.hive_default_grpc_server.clone().ok_or((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    String::from("grpc_address is required but no default is configured"),
                ))?;
                object.insert(
                    String::from("grpc_address"),
                    serde_json::Value::String(grpc_address),
                );
                object.insert(
                    String::from("grpc_tls"),
                    serde_json::Value::String(String::from("true")),
                );

                let image = state.agent_default_image.clone().ok_or((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    String::from("image is required but no default is configured"),
                ))?;
                object.insert(String::from("image"), serde_json::Value::String(image));

                object.insert(
                    String::from("secret"),
                    serde_json::Value::String(placeholder_secret_b64),
                );
                object.insert(
                    String::from("name"),
                    serde_json::Value::String(name.to_string()),
                );
                object.insert(String::from("env"), serde_json::Value::Array(vec![]));

                let context = serde_json::to_value(object)
                    .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?;

                util::generate_manifest(&state.agent_manifest_template, context)
                    .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
            }
        };

        return Ok(Json(types::PostClusterResponse {
            cluster,
            manifest: Some(manifest),
            manifest_is_placeholder: true,
            user_existed: true,
            secret_regenerated: false,
        }));
    }

    // Generate the secret and manifest
    let secret = util::generate_random_string(256);

    let manifest = match &data.context {
        Some(context) => {
            let context_with_secret = match context.clone().as_object_mut() {
                Some(object) => {
                    let key = "agent_name";
                    let value =
                        util::value_or_default(object.get(key), Some(String::from(name)), false)
                            .map_err(|e| {
                                (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                            })?;
                    object.insert(String::from(key), value);

                    let key = "namespace";
                    let value = util::value_or_default(
                        object.get(key),
                        Some(String::from("beecd-system")),
                        false,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    let key = "grpc_address";
                    let value = util::value_or_default(
                        object.get(key),
                        state.hive_default_grpc_server.clone(),
                        true,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    // Whether to use TLS when GRPC_ADDRESS is provided as host:port (no scheme).
                    // Defaults to true.
                    let grpc_tls = match object.get("grpc_tls") {
                        Some(serde_json::Value::Bool(b)) => *b,
                        Some(serde_json::Value::String(s)) => {
                            matches!(s.to_lowercase().as_str(), "true" | "1" | "yes" | "y" | "on")
                        }
                        _ => true,
                    };
                    object.insert(
                        String::from("grpc_tls"),
                        serde_json::Value::String(
                            if grpc_tls { "true" } else { "false" }.to_string(),
                        ),
                    );

                    let key = "image";
                    let value = util::value_or_default(
                        object.get(key),
                        state.agent_default_image.clone(),
                        true,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    object.insert(
                        String::from("secret"),
                        serde_json::Value::String(general_purpose::STANDARD.encode(secret.clone())),
                    );
                    object.insert(
                        String::from("name"),
                        serde_json::Value::String(name.to_string()),
                    );
                    // Add empty env array if not present (required by template)
                    if !object.contains_key("env") {
                        object.insert(String::from("env"), serde_json::Value::Array(vec![]));
                    }
                    serde_json::to_value(object)
                        .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
                }
                None => {
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        String::from("context data is invalid"),
                    ))
                }
            };

            util::generate_manifest(&state.agent_manifest_template, context_with_secret)
                .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
        }
        None => {
            // No context provided, generate with defaults
            let mut object = serde_json::Map::new();
            object.insert(
                String::from("agent_name"),
                serde_json::Value::String(name.to_string()),
            );
            object.insert(
                String::from("namespace"),
                serde_json::Value::String(String::from("beecd-system")),
            );

            let grpc_address = state.hive_default_grpc_server.clone().ok_or((
                StatusCode::UNPROCESSABLE_ENTITY,
                String::from("grpc_address is required but no default is configured"),
            ))?;
            object.insert(
                String::from("grpc_address"),
                serde_json::Value::String(grpc_address),
            );

            // Whether to use TLS when GRPC_ADDRESS is provided as host:port (no scheme).
            // Defaults to true.
            object.insert(
                String::from("grpc_tls"),
                serde_json::Value::String(String::from("true")),
            );

            let image = state.agent_default_image.clone().ok_or((
                StatusCode::UNPROCESSABLE_ENTITY,
                String::from("image is required but no default is configured"),
            ))?;
            object.insert(String::from("image"), serde_json::Value::String(image));

            object.insert(
                String::from("secret"),
                serde_json::Value::String(general_purpose::STANDARD.encode(secret.clone())),
            );
            object.insert(
                String::from("name"),
                serde_json::Value::String(name.to_string()),
            );
            // Add empty env array (required by template)
            object.insert(String::from("env"), serde_json::Value::Array(vec![]));

            let context = serde_json::to_value(object)
                .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?;

            util::generate_manifest(&state.agent_manifest_template, context)
                .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
        }
    };

    // Hash the secret for storage
    let hash = util::bcrypt_string(&secret).map_err(|e| {
        tracing::error!("Failed creating bcrypt hash for user secret: {}", e);
        (
            StatusCode::FAILED_DEPENDENCY,
            String::from("Failed to create secure hash for user"),
        )
    })?;

    // Insert or update the user
    if user_existed {
        // Update existing user's hash
        sqlx::query("UPDATE users SET hash = $1, updated_at = NOW() WHERE name = $2")
            .bind(&hash)
            .bind(name)
            .execute(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "post_cluster_update_user"))?;
    } else {
        // Insert new user
        sqlx::query(
            r#"
            INSERT INTO users (id, name, hash, tenant_id)
            VALUES (gen_random_uuid(), $1, $2, $3)
            "#,
        )
        .bind(name)
        .bind(&hash)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_cluster_insert_user"))?;
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_cluster_commit"))?;

    Ok(Json(types::PostClusterResponse {
        cluster,
        manifest: Some(manifest),
        manifest_is_placeholder: false,
        user_existed,
        secret_regenerated: user_existed && regenerate_secret,
    }))
}

/// Get namespaces for a given cluster by id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/namespaces",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, body = [types::ClusterNamespaceServicesData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when row not found in database"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn get_cluster_namespaces(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ClusterNamespaceServicesData>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    let result = sqlx::query_as(
        r#"
        SELECT
            clusters.name as name,
            clusters.id as id,
            namespaces.id as namespace_id,
            namespaces.name as namespace_name,
            CASE
                WHEN COUNT(DISTINCT releases.name) = 0 THEN NULL
                ELSE ARRAY_AGG(DISTINCT releases.name)
            END AS service_names
        FROM clusters
        JOIN namespaces on cluster_id = clusters.id
        LEFT JOIN releases on releases.namespace_id = namespaces.id AND (releases.deprecated_at, releases.deleted_at) IS NULL
        WHERE clusters.id = $1 AND clusters.deleted_at IS NULL
        GROUP BY clusters.id, namespaces.id
        ORDER BY namespaces.name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_namespace_data"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_namespaces_commit"))?;

    Ok(Json(result))
}

/// Get a list of all cluster groups
#[utoipa::path(
    get,
    path = "/api/cluster-groups",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a paginated list of cluster groups", body = types::PaginatedResponse<types::ClusterGroupData>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when no rows are found in database"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_cluster_groups(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<PaginatedResponse<ClusterGroupData>>, (StatusCode, String)> {
    let pagination = pagination.validate();
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;

    // Get total count
    let (total,): (i64,) = sqlx::query_as(r#"SELECT COUNT(*) FROM cluster_groups"#)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_groups_count"))?;

    // Get paginated data
    let data: Vec<ClusterGroupData> =
        sqlx::query_as(r#"SELECT * FROM cluster_groups ORDER BY name LIMIT $1 OFFSET $2"#)
            .bind(pagination.limit)
            .bind(pagination.offset)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "get_cluster_groups"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_groups_commit"))?;

    Ok(Json(PaginatedResponse::new(
        data,
        total,
        pagination.limit,
        pagination.offset,
    )))
}

/// Get a list of cluster groups for a particular cluster by id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/groups",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of cluster groups for the given cluster", body = [types::ClusterClusterGroups]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when row not found in database"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn get_cluster_cluster_groups(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ClusterClusterGroups>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as(
        r#"
        SELECT
            clusters.name as name,
            clusters.id as id,
            cluster_groups.id as cluster_group_id,
            cluster_groups.name as cluster_group_name
        FROM clusters
        JOIN group_relationships on group_relationships.cluster_id = clusters.id
        JOIN cluster_groups on cluster_groups.id = group_relationships.cluster_group_id
        WHERE clusters.id = $1 AND clusters.deleted_at IS NULL
        ORDER BY cluster_groups.name
        LIMIT $2 OFFSET $3
        ;"#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_cluster_groups"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_cluster_groups_commit"))?;
    Ok(Json(result))
}

/// Delete a cluster group/cluster relationship
#[utoipa::path(
    delete,
    path = "/api/clusters/{id}/groups/{cluster_group_id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successful deletion of relationship"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when row not found in database"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn delete_group_relationship(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((cluster_id, cluster_group_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_group_relationship_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        DELETE FROM
            group_relationships
        WHERE
            cluster_id = $1
            AND cluster_group_id = $2;
    "#,
    )
    .bind(cluster_id)
    .bind(cluster_group_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_group_relationship"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_group_relationship_commit"))?;

    tokio::time::sleep(std::time::Duration::from_millis(
        state.read_replica_wait_in_ms,
    ))
    .await;
    sync_cluster_releases(&state.pool, &state.readonly_pool, cluster_id).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

pub async fn sync_cluster_releases(
    pool: &sqlx::Pool<sqlx::Postgres>,
    readonly_pool: &sqlx::Pool<sqlx::Postgres>,
    cluster_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    let reference_service_definitions = sqlx::query_as::<_,ClusterServiceDefinitions>(
        r#"
        SELECT DISTINCT
            ARRAY_AGG(cluster_groups.id) AS cluster_group_ids,
            service_definitions.id AS id,
            service_definitions.repo_branch_id,
            service_definitions.name,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.org,
            repos.repo,
            repo_branches.branch,
            cluster_groups.priority
        FROM
            service_definitions
            JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
            JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
            JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
            JOIN group_relationships ON group_relationships.cluster_group_id = cluster_groups.id
            JOIN clusters ON group_relationships.cluster_id = clusters.id
            AND clusters.deleted_at IS NULL
        WHERE
            cluster_groups.priority = (
                SELECT
                    MAX(cluster_groups.priority)
                FROM
                    service_definitions service_definitions_inner
                    JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions_inner.id
                    JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                    JOIN group_relationships ON group_relationships.cluster_group_id = cluster_groups.id
                WHERE
                    service_definitions_inner.name = service_definitions.name
                    AND group_relationships.cluster_id = clusters.id
            )
            AND clusters.id = $1
        GROUP BY
            service_definitions.id,
            repos.id,
            repo_branches.id,
            cluster_groups.priority
        "#,
    )
        .bind(cluster_id)
    .fetch_all(readonly_pool)
    .await
    .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_fetch_targets"))?;

    if reference_service_definitions.is_empty() {
        return Ok(());
    }

    #[derive(sqlx::FromRow)]
    struct Release {
        id: Uuid,
        namespace_id: Uuid,
        path: String,
        name: String,
    }

    // Collect all names and repo_branch_ids for batch query
    let target_names: Vec<String> = reference_service_definitions
        .iter()
        .map(|t| t.name.clone())
        .collect();
    let target_repo_branch_ids: Vec<Uuid> = reference_service_definitions
        .iter()
        .map(|t| t.repo_branch_id)
        .collect();

    // Single query to fetch all releases that need updating across all targets
    // This replaces the N queries in the loop
    let all_releases_to_update = sqlx::query_as::<_, Release>(
        r#"
        SELECT
            releases.id,
            releases.namespace_id,
            releases.path,
            releases.name
        FROM
            releases
            JOIN namespaces ON namespaces.id = releases.namespace_id
            JOIN clusters ON clusters.id = namespaces.cluster_id
        WHERE
            releases.name = ANY($1)
            AND releases.repo_branch_id != ALL($2)
            AND clusters.id = $3
            AND (
                releases.deprecated_at,
                releases.deleted_at,
                releases.manually_selected_at
            ) IS NULL
        "#,
    )
    .bind(&target_names)
    .bind(&target_repo_branch_ids)
    .bind(cluster_id)
    .fetch_all(readonly_pool)
    .await
    .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_fetch_releases"))?;

    if all_releases_to_update.is_empty() {
        return Ok(());
    }

    // Build lookup map for reference build targets by name
    let target_map: std::collections::HashMap<String, Uuid> = reference_service_definitions
        .iter()
        .map(|t| (t.name.clone(), t.repo_branch_id))
        .collect();

    // Collect releases to deprecate and new releases to create
    let mut release_ids_to_deprecate: Vec<Uuid> = Vec::new();
    let mut new_releases: Vec<(Uuid, String, String, Uuid)> = Vec::new();

    for release in all_releases_to_update {
        if let Some(&repo_branch_id) = target_map.get(&release.name) {
            release_ids_to_deprecate.push(release.id);
            new_releases.push((
                release.namespace_id,
                release.path,
                release.name,
                repo_branch_id,
            ));
        }
    }

    if release_ids_to_deprecate.is_empty() {
        return Ok(());
    }

    // Max batch size to avoid PostgreSQL parameter limits (32767 params, 4 params per row = ~8000 rows)
    const MAX_BATCH_SIZE: usize = 1000;

    // Use transaction to ensure atomicity: either both UPDATE and INSERT succeed, or neither
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_begin_tx"))?;

    // Batch deprecate all releases in a single UPDATE query
    sqlx::query(
        r#"
        UPDATE releases
        SET deprecated_at = NOW()
        WHERE id = ANY($1)
        "#,
    )
    .bind(&release_ids_to_deprecate)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_deprecate"))?;

    // Process inserts in batches to respect parameter limits
    for chunk in new_releases.chunks(MAX_BATCH_SIZE) {
        let values_clauses: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let base = i * 4;
                format!(
                    "((SELECT GEN_RANDOM_UUID()), (SELECT GEN_RANDOM_UUID()), ${}, ${}, ${}, ${}, '-', '', '')",
                    base + 1, base + 2, base + 3, base + 4
                )
            })
            .collect();

        let insert_query = format!(
            r#"
            INSERT INTO releases
            (id, service_id, namespace_id, path, name, repo_branch_id, version, git_sha, hash)
            VALUES {}
            "#,
            values_clauses.join(", ")
        );

        let mut query = sqlx::query(&insert_query);
        for (namespace_id, path, name, repo_branch_id) in chunk {
            query = query
                .bind(namespace_id)
                .bind(path)
                .bind(name)
                .bind(repo_branch_id);
        }

        query
            .execute(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_insert"))?;
    }

    // Commit transaction - if this fails, all changes are rolled back
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "sync_cluster_releases_commit"))?;

    Ok(())
}

/// Get a list service_definitions that can be used to create a release on a cluster via id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of service_definitions for a given cluster via id", body = [types::ClusterServiceDefinitions]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when row not found in database"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn get_cluster_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ClusterServiceDefinitions>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as(
        r#"
        SELECT DISTINCT
            ARRAY_AGG(cluster_groups.id) AS cluster_group_ids,
            service_definitions.id AS id,
            service_definitions.repo_branch_id,
            service_definitions.name,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.org,
            repos.repo,
            repo_branches.branch,
            cluster_groups.priority
        FROM
            service_definitions
            JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
            JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
            JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
            JOIN group_relationships ON group_relationships.cluster_group_id = cluster_groups.id
            JOIN clusters ON group_relationships.cluster_id = clusters.id
            AND clusters.deleted_at IS NULL
        WHERE
            cluster_groups.priority = (
                SELECT
                    MAX(cluster_groups.priority)
                FROM
                    service_definitions service_definitions_inner
                    JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions_inner.id
                    JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                    JOIN group_relationships ON group_relationships.cluster_group_id = cluster_groups.id
                WHERE
                    service_definitions_inner.name = service_definitions.name
                    AND group_relationships.cluster_id = clusters.id
            )
            AND clusters.id = $1
        GROUP BY
            service_definitions.id,
            repos.id,
            repo_branches.id,
            cluster_groups.priority
        ORDER BY service_definitions.name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_service_definitions"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_service_definitions_commit"))?;
    Ok(Json(result))
}

/// Adds a new cluster group
#[utoipa::path(
    post,
    path = "/api/cluster-groups",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successfully adding new cluster group"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when post data is empty"),
        (status = 500, description = "Fails when cluster_group name is not found or db connection issues"),
    )
)]
pub async fn add_cluster_groups(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(cluster_group): Json<AddClusterGroupInput>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if cluster_group.name.is_empty() {
        return Err((
            StatusCode::NOT_ACCEPTABLE,
            "Null value for cluster group".to_string(),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "add_cluster_groups_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
            INSERT INTO cluster_groups (id, name, tenant_id)
            VALUES (gen_random_uuid(), $1, $2);
        "#,
    )
    .bind(cluster_group.name)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "add_cluster_groups"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "add_cluster_groups_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Delete a cluster group by id
#[utoipa::path(
    delete,
    path = "/api/cluster-groups/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successful deletion of cluster-group"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn delete_cluster_group(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_group_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    #[derive(sqlx::FromRow)]
    struct Cluster {
        id: Uuid,
    }

    let clusters = sqlx::query_as::<_, Cluster>(
        r#"
        SELECT
            clusters.id
        FROM
            clusters
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            cluster_groups.id = $1
    "#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_cluster_group_fetch_clusters"))?;

    sqlx::query("DELETE FROM cluster_groups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_group_delete"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_cluster_group_commit"))?;

    tokio::time::sleep(std::time::Duration::from_millis(
        state.read_replica_wait_in_ms,
    ))
    .await;

    // Parallelize sync operations for all clusters
    let sync_futures = clusters
        .into_iter()
        .map(|cluster| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster.id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Get details of cluster group
#[utoipa::path(
    get,
    path = "/api/cluster-groups/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns details for a single cluster group", body = types::ClusterGroupData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn get_cluster_group(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ClusterGroupData>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as("SELECT * FROM cluster_groups WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_group"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_group_commit"))?;
    Ok(Json(result))
}

/// Update details of cluster group
#[utoipa::path(
    put,
    path = "/api/cluster-groups/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails when id is invalid or db connection issues"),
    )
)]
pub async fn put_cluster_group(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PutClusterGroup>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_cluster_group_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
            UPDATE
                cluster_groups
            SET
                name = COALESCE($2, cluster_groups.name),
                priority = COALESCE($3, cluster_groups.priority)
            WHERE
                id = $1
        "#,
    )
    .bind(id)
    .bind(&data.name)
    .bind(data.priority)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_cluster_group_update"))?;

    #[derive(sqlx::FromRow)]
    struct Cluster {
        id: Uuid,
    }

    let clusters = sqlx::query_as::<_, Cluster>(
        r#"
        SELECT
            clusters.id
        FROM
            clusters
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            cluster_groups.id = $1
    "#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_cluster_group_fetch_clusters"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_cluster_group_commit"))?;

    // Parallelize sync operations for all clusters
    let sync_futures = clusters
        .into_iter()
        .map(|cluster| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster.id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of resource diffs per release given a diff_generation
#[utoipa::path(
    get,
    path = "/api/releases/{id}/diff/{diff_generation}",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of resource diff data for release via id", body = [types::DiffDataWithBody]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_resource_diffs_for_release(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((release_id, diff_generation)): Path<(Uuid, i32)>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<DiffDataWithBody>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();

    // Query resource diffs within the tenant transaction
    let diff_data_without_body: Vec<DiffData> = if diff_generation == -1 {
        sqlx::query_as::<_, DiffData>(
            r#"
        SELECT
            resource_diffs.key,
            resource_diffs.release_id,
            resource_diffs.diff_generation,
            resource_diffs.change_order,
            resource_diffs.storage_url
        FROM
            resource_diffs
        WHERE
            resource_diffs.release_id = $1
            AND resource_diffs.diff_generation = (
                SELECT diff_generation FROM releases WHERE id = $1
            )
        LIMIT 100
        "#,
        )
        .bind(release_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("get_resource_diffs_for_release error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch resource diffs".to_string(),
            )
        })?
    } else {
        sqlx::query_as::<_, DiffData>(
            r#"
        SELECT
            resource_diffs.key,
            resource_diffs.release_id,
            resource_diffs.diff_generation,
            resource_diffs.change_order,
            resource_diffs.storage_url
        FROM
            resource_diffs
        WHERE
            resource_diffs.release_id = $1
            AND resource_diffs.diff_generation = $2
        LIMIT 100
        "#,
        )
        .bind(release_id)
        .bind(diff_generation)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("get_resource_diffs_for_release error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to fetch resource diffs".to_string(),
            )
        })?
    };

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_resource_diffs_for_release_commit"))?;

    // Apply pagination to results
    let paginated_diffs: Vec<_> = diff_data_without_body
        .into_iter()
        .skip(pagination.offset as usize)
        .take(pagination.limit as usize)
        .collect();

    // Limit concurrent fetches to 10 and validate size to prevent memory exhaustion
    const MAX_DIFF_SIZE_BYTES: usize = 10 * 1024 * 1024; // 10MB
    const MAX_CONCURRENT_FETCHES: usize = 10;

    let diff_data = stream::iter(paginated_diffs)
        .map(|item| {
            let item_clone = item.clone();
            async move {
                let bytes =
                    match beecdstorage::fetch(&item_clone.storage_url.unwrap_or_default()).await {
                        Ok(b) => {
                            // Validate size to prevent OOM
                            if b.len() > MAX_DIFF_SIZE_BYTES {
                                tracing::warn!(
                                    "Diff too large: {} bytes (max {}), skipping",
                                    b.len(),
                                    MAX_DIFF_SIZE_BYTES
                                );
                                return None;
                            }
                            b
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch diff: {}", e);
                            return None;
                        }
                    };

                let body = String::from_utf8_lossy(&bytes);

                Some(DiffDataWithBody {
                    body: body.to_string(),
                    diff_data: item.clone(),
                })
            }
        })
        .buffer_unordered(MAX_CONCURRENT_FETCHES)
        .filter_map(|opt| async move { opt })
        .collect::<Vec<_>>()
        .await;

    Ok(Json(diff_data))
}

/// Marks a release as exact instead of using latest
#[utoipa::path(
    put,
    path = "/api/releases/{id}/select",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on succesfully updating releases"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_release_selection(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_release_selection_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE releases
        SET
            manually_selected_at = NOW(),
            approved_at = NULL,
            unapproved_at = NULL,
            deprecated_at = NULL,
            deleted_at = NULL,
            started_first_install_at = NULL,
            failed_first_install_at = NULL,
            completed_first_install_at = NULL,
            started_update_install_at = NULL,
            failed_update_install_at = NULL,
            completed_update_install_at = NULL,
            marked_for_deletion_at = NULL,
            started_delete_at = NULL,
            failed_delete_at = NULL,
            completed_delete_at = NULL,
            last_diff_at = NULL
        WHERE
            id = $1;
    "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_release_manual_selection_update1"))?;

    sqlx::query(
        r#"
        UPDATE releases
        SET
            manually_selected_at = NULL
        FROM
            releases AS selected_release
        WHERE
            selected_release.id = $1
            AND releases.id != $1
            AND releases.name = selected_release.name
            AND releases.namespace_id = selected_release.namespace_id;
    "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_release_manual_selection_update2"))?;

    sqlx::query(
        r#"
        UPDATE releases
        SET
            deprecated_at = NOW()
        FROM
            releases AS selected_release
        WHERE
            selected_release.id = $1
            AND releases.id != $1
            AND releases.name = selected_release.name
            AND releases.namespace_id = selected_release.namespace_id
            AND releases.deprecated_at IS NULL
            AND releases.deleted_at IS NULL;
    "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_release_manual_selection_update3"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_release_selection_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Selects a specific service version for a release
/// This updates the release to use the specified service_version_id
#[utoipa::path(
    put,
    path = "/api/service-versions/{id}/select",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Successfully selected the service version"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_select_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(service_version_id): Path<Uuid>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_select_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Get the service version details
    let sv = sqlx::query_as::<_, (Uuid, Uuid, String, String, String)>(
        r#"
        SELECT 
            sv.service_definition_id, 
            sv.namespace_id, 
            sv.version, 
            sv.git_sha, 
            sv.path
        FROM service_versions sv
        WHERE sv.id = $1
        "#,
    )
    .bind(service_version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Service version not found".to_string(),
        )
    })?;

    let (service_def_id, namespace_id, version, git_sha, path) = sv;

    // Get repo_branch_id and name from service_definition
    let (repo_branch_id, name) = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT repo_branch_id, name FROM service_definitions WHERE id = $1"#,
    )
    .bind(service_def_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?;

    // Check if there's already a release with this service_version_id in this namespace
    let existing = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT id FROM releases
        WHERE namespace_id = $1 AND service_id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(namespace_id)
    .bind(service_version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?;

    if let Some(existing_release_id) = existing {
        // Reactivate the existing release and deprecate others
        // Reset diff_generation to 0 so the agent will recompute and send diffs
        sqlx::query(
            r#"
            UPDATE releases
            SET deprecated_at = CASE WHEN id = $3 THEN NULL ELSE NOW() END,
                manually_selected_at = CASE WHEN id = $3 THEN NOW() ELSE NULL END,
                diff_generation = CASE WHEN id = $3 THEN 0 ELSE diff_generation END,
                last_diff_at = CASE WHEN id = $3 THEN NULL ELSE last_diff_at END,
                updated_at = NOW()
            WHERE namespace_id = $1 
            AND name = $2 
            AND deleted_at IS NULL
            "#,
        )
        .bind(namespace_id)
        .bind(&name)
        .bind(existing_release_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?;
    } else {
        // Deprecate any existing non-deleted releases for this service in this namespace
        sqlx::query(
            r#"
            UPDATE releases
            SET deprecated_at = NOW(), manually_selected_at = NULL
            WHERE namespace_id = $1 
            AND name = $2 
            AND deprecated_at IS NULL 
            AND deleted_at IS NULL
            "#,
        )
        .bind(namespace_id)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?;

        // Create a new release with this service_version
        sqlx::query(
            r#"
            INSERT INTO releases 
            (id, service_id, namespace_id, name, version, git_sha, path, repo_branch_id, hash, manually_selected_at, tenant_id)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $4, NOW(), $8)
            "#,
        )
        .bind(service_version_id)
        .bind(namespace_id)
        .bind(&name)
        .bind(&version)
        .bind(&git_sha)
        .bind(&path)
        .bind(repo_branch_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_select_service_version"))?;
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_select_service_version_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Removes the manually selected field to revert back to latest release (default)
///
/// Going back to the latest is essentially re-enabling drift to ensure this service is up-to-date with
/// services that share the same build target.
#[utoipa::path(
    put,
    path = "/api/namespaces/{id}/release/{release_name}/latest",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on succesfully updating releases"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "No changes were required, no releases matching query were found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_restore_latest_release(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((id, release_name)): Path<(Uuid, String)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_restore_latest_release_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    match sqlx::query(
        r#"
        UPDATE releases
        SET
            manually_selected_at = NULL,
            deprecated_at = NOW()
        WHERE
            manually_selected_at IS NOT NULL
            AND namespace_id = $1
            AND name = $2;
    "#,
    )
    .bind(id)
    .bind(&release_name)
    .execute(&mut *tx)
    .await
    {
        Ok(pg_query_result) => {
            if pg_query_result.rows_affected() == 0 {
                return Ok((StatusCode::NOT_FOUND, String::from("No found changes")));
            }
        }
        Err(e) => {
            return Err(sanitize_db_error(e, "put_restore_latest_release_unset"));
        }
    };

    #[derive(sqlx::FromRow)]
    struct PathResult {
        path: String,
    }

    let path = match sqlx::query_as::<_, PathResult>(
        r#"
        SELECT
            releases.path
        FROM
            releases
        WHERE
            releases.namespace_id = $1
            AND releases.name = $2
        ORDER BY
            created_at DESC
        LIMIT 1
    "#,
    )
    .bind(id)
    .bind(&release_name)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(row) => row.path,
        Err(e) => {
            return Err(sanitize_db_error(e, "put_restore_latest_release_find_path"));
        }
    };

    #[derive(sqlx::FromRow)]
    struct RepoBranchResult {
        repo_branch_id: Uuid,
    }

    let repo_branch_id = match sqlx::query_as::<_, RepoBranchResult>(
        r#"
        SELECT
            service_definitions.repo_branch_id
        FROM
            namespaces
            JOIN clusters ON clusters.id = namespaces.cluster_id
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.cluster_group_id = group_relationships.cluster_group_id
            JOIN service_definitions ON service_definitions.id = service_definition_cluster_group_relationships.service_definition_id
        WHERE
            namespaces.id = $1
            AND service_definitions.name = $2;
    "#,
    )
    .bind(id)
    .bind(&release_name)
    .fetch_one(&mut *tx)
    .await{
        Ok(row) => row.repo_branch_id,
        Err(e) => { return Err(sanitize_db_error(e, "put_restore_latest_release_find_repo_branch"));}
    };

    sqlx::query(
        r#"
        INSERT INTO releases
        (
            id,
            service_id,
            namespace_id,
            path,
            name,
            repo_branch_id,
            version,
            git_sha,
            hash,
            tenant_id
        )
        VALUES
        (
            (SELECT GEN_RANDOM_UUID()),
            (SELECT GEN_RANDOM_UUID()),
            $1,
            $2,
            $3,
            $4,
            '-',
            '',
            '',
            $5
        )"#,
    )
    .bind(id)
    .bind(&path)
    .bind(&release_name)
    .bind(repo_branch_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_restore_latest_release_insert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_restore_latest_release_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of resource status for given cluster id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/releases",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of resource statuses", body = [types::ReleaseStatus]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_release_status(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(cluster_id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ReleaseStatus>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, ReleaseData>(
        r#"
        SELECT
            namespaces.name AS namespace,
            clusters.name AS cluster_name,
            clusters.id AS cluster_id,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.api_base_url AS api_base_url,
            repo_branches.branch AS branch,
            releases.*,
            service_definitions.id AS service_definition_id,
            service_definitions.manifest_path_template,
            COUNT(release_errors.id)::INT4 AS total_errors,
            '' as cluster_groups,
            service_versions.pinned_at AS pinned_at,
            service_versions.pinned_by AS pinned_by
        FROM clusters
            JOIN namespaces ON namespaces.cluster_id = clusters.id
            JOIN releases ON releases.namespace_id = namespaces.id AND (releases.deleted_at,releases.deprecated_at) IS NULL
            LEFT JOIN release_errors ON release_errors.release_id = releases.id AND release_errors.deprecated_at IS NULL
            JOIN repo_branches ON repo_branches.id = releases.repo_branch_id
            JOIN service_definitions ON service_definitions.repo_branch_id = releases.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
            LEFT JOIN service_versions ON service_versions.id = releases.service_id
        WHERE
            clusters.id = $1
            AND releases.name = service_definitions.name
            AND clusters.deleted_at IS NULL
        GROUP BY
            namespaces.id,
            clusters.id,
            repo_branches.id,
            repos.id,
            releases.id,
            service_definitions.id,
            service_versions.pinned_at,
            service_versions.pinned_by
        ORDER BY releases.name, namespaces.name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(cluster_id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_releases_via_id"))?
    .into_iter()
    .map(|mut r| {
        compute_release_path(&mut r);
        let status = r.status();

        ReleaseStatus { data: r, status }
    })
    .collect::<Vec<_>>();

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_release_status_commit"))?;
    Ok(Json(result))
}

/// Gets a list of release details for a release by name in a namespace
#[utoipa::path(
    get,
    path = "/api/namespaces/{id}/release/{release_name}",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of releases", body = types::ReleaseStatus),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_namespace_releases(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((id, release_name)): Path<(Uuid, String)>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ReleaseData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let mut releases = sqlx::query_as::<_, ReleaseData>(
        r#"
        SELECT
            namespaces.name AS namespace,
            clusters.name AS cluster_name,
            clusters.id AS cluster_id,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.api_base_url AS api_base_url,
            repo_branches.branch AS branch,
            releases.*,
            service_definitions.id AS service_definition_id,
            service_definitions.manifest_path_template,
            -1 AS total_errors,
            '' AS cluster_groups,
            service_versions.pinned_at AS pinned_at,
            service_versions.pinned_by AS pinned_by
        FROM
            releases
            JOIN namespaces ON namespaces.id = releases.namespace_id
            JOIN clusters ON clusters.id = namespaces.cluster_id
            AND clusters.deleted_at IS NULL
            LEFT JOIN release_errors ON release_errors.release_id = releases.id
            AND release_errors.deprecated_at IS NULL
            JOIN repo_branches ON repo_branches.id = releases.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
            JOIN service_definitions ON service_definitions.repo_branch_id = releases.repo_branch_id
            AND service_definitions.name = releases.name
            LEFT JOIN service_versions ON service_versions.id = releases.service_id
        WHERE
            releases.name = $2
            AND releases.namespace_id = $1
            AND releases.hash != ''
            AND releases.updated_at = (
                SELECT
                    MAX(updated_at)
                FROM
                    releases AS latest_releases
                WHERE
                    latest_releases.hash = releases.hash
                    AND latest_releases.name = $2
                    AND latest_releases.namespace_id = $1
            )
        ORDER BY
            updated_at DESC
        LIMIT $3 OFFSET $4;
        "#,
    )
    .bind(id)
    .bind(&release_name)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_namespace_releases"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_namespace_releases_commit"))?;

    // Compute paths from templates
    for release in &mut releases {
        compute_release_path(release);
    }

    Ok(Json(releases))
}

/// Gets all service versions available for a release, with deployment history
/// This shows all versions that can be selected, including whether they've been deployed
#[utoipa::path(
    get,
    path = "/api/namespaces/{id}/release/{release_name}/versions",
    params(
        ("id" = Uuid, Path, description = "Namespace UUID"),
        ("release_name" = String, Path, description = "Release name"),
        ("deployed_only" = Option<bool>, Query, description = "Only show versions that have been deployed (default: false)"),
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a paginated list of service versions for this release", body = types::PaginatedResponse<types::ServiceVersionForRelease>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_release_service_versions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((namespace_id, release_name)): Path<(Uuid, String)>,
    Query(pagination): Query<Pagination>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<PaginatedResponse<ServiceVersionForRelease>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let deployed_only = params
        .get("deployed_only")
        .map(|v| v == "true")
        .unwrap_or(false);

    // First, get the service_definition_id for this release
    let service_def_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        SELECT sd.id
        FROM service_definitions sd
        JOIN releases r ON r.repo_branch_id = sd.repo_branch_id AND r.name = sd.name
        WHERE r.namespace_id = $1 AND r.name = $2
        LIMIT 1
        "#,
    )
    .bind(namespace_id)
    .bind(&release_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_release_service_versions"))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Release not found".to_string()))?;

    // Get current release's service_id to mark as current
    let current_service_id = sqlx::query_scalar::<_, Option<Uuid>>(
        r#"
        SELECT service_id
        FROM releases
        WHERE namespace_id = $1 AND name = $2 AND (deprecated_at, deleted_at) IS NULL
        "#,
    )
    .bind(namespace_id)
    .bind(&release_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_release_service_versions"))?
    .flatten();

    // Build the query based on filters
    let deployed_filter = if deployed_only {
        "AND r.id IS NOT NULL"
    } else {
        ""
    };

    // Count total items for pagination
    let count_str = format!(
        r#"
        SELECT COUNT(DISTINCT sv.id)
        FROM
            service_versions sv
            LEFT JOIN releases r ON r.service_id = sv.id 
                AND r.namespace_id = sv.namespace_id
                AND r.completed_first_install_at IS NOT NULL
        WHERE
            sv.service_definition_id = $1
            AND sv.namespace_id = $2
            {deployed_filter}
        "#
    );

    let total = sqlx::query_scalar::<_, i64>(&count_str)
        .bind(service_def_id)
        .bind(namespace_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_release_service_versions"))?;

    let query_str = format!(
        r#"
        SELECT
            sv.id,
            sv.created_at,
            sv.service_definition_id,
            sv.namespace_id,
            sv.version,
            sv.git_sha,
            sv.git_sha_short,
            sv.path,
            sv.hash,
            sv.source,
            sv.deprecated_at,
            sv.pinned_at,
            sv.pinned_by,
            MAX(r.completed_first_install_at) AS last_deployed_at,
            sv.id = $4 AS is_current
        FROM
            service_versions sv
            LEFT JOIN releases r ON r.service_id = sv.id 
                AND r.namespace_id = sv.namespace_id
                AND r.completed_first_install_at IS NOT NULL
        WHERE
            sv.service_definition_id = $1
            AND sv.namespace_id = $2
            {deployed_filter}
        GROUP BY sv.id
        ORDER BY sv.created_at DESC
        LIMIT $3 OFFSET $5
        "#
    );

    let versions = sqlx::query_as::<_, ServiceVersionForRelease>(&query_str)
        .bind(service_def_id)
        .bind(namespace_id)
        .bind(pagination.limit)
        .bind(current_service_id)
        .bind(pagination.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_release_service_versions"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_release_service_versions_commit"))?;

    Ok(Json(PaginatedResponse::new(
        versions,
        total,
        pagination.limit,
        pagination.offset,
    )))
}

/// Gets details for a specific release
#[utoipa::path(
    get,
    path = "/api/namespaces/{id}/release/{release_name}/current",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns details of a release", body = types::ReleaseStatus),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_namespace_release_info(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((id, release_name)): Path<(Uuid, String)>,
) -> Result<Json<ReleaseStatus>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let mut result = sqlx::query_as::<_, ReleaseData>(
        r#"
        SELECT
            namespaces.name AS namespace,
            clusters.name AS cluster_name,
            clusters.id AS cluster_id,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repos.api_base_url AS api_base_url,
            repo_branches.branch AS branch,
            releases.*,
            service_definitions.id AS service_definition_id,
            service_definitions.manifest_path_template,
            -1 AS total_errors,
            '' AS cluster_groups,
            service_versions.pinned_at AS pinned_at,
            service_versions.pinned_by AS pinned_by
        FROM
            releases
            JOIN namespaces ON namespaces.id = releases.namespace_id
            JOIN clusters ON clusters.id = namespaces.cluster_id
            AND clusters.deleted_at IS NULL
            LEFT JOIN release_errors ON release_errors.release_id = releases.id
            AND release_errors.deprecated_at IS NULL
            JOIN repo_branches ON repo_branches.id = releases.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
            JOIN service_definitions ON service_definitions.repo_branch_id = releases.repo_branch_id
            AND service_definitions.name = releases.name
            LEFT JOIN service_versions ON service_versions.id = releases.service_id
        WHERE
            releases.namespace_id = $1
            AND releases.name = $2
            AND (releases.deprecated_at, releases.deleted_at) IS NULL
        "#,
    )
    .bind(id)
    .bind(&release_name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_namespace_release_info"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_namespace_release_info_commit"))?;

    // Compute path from template
    compute_release_path(&mut result);

    let release_status = ReleaseStatus {
        data: result.clone(),
        status: result.status(),
    };

    Ok(Json(release_status))
}

/// Gets a list of current errors produced for the agent given the cluster id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/errors",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list errors produced by the hive agent", body = [types::HiveError]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_hive_agent_errors(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(cluster_id): Path<Uuid>,
) -> Result<Json<Vec<HiveError>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, HiveError>(
        r#"
            SELECT
                message,
                updated_at
            FROM
                hive_errors
            WHERE
                cluster_id = $1
                AND deprecated_at IS NULL
            ORDER BY updated_at DESC LIMIT 10
        "#,
    )
    .bind(cluster_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_hive_agent_errors"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_hive_agent_errors_commit"))?;
    Ok(Json(result))
}

/// Gets the last heartbeat information for an agent given the cluster id
#[utoipa::path(
    get,
    path = "/api/clusters/{id}/heartbeat",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns the last heartbeat produced by the hive agent", body = types::Heartbeat),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_hive_agent_heartbeat(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(cluster_id): Path<Uuid>,
) -> Result<Json<Heartbeat>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, Heartbeat>(
        r#"
            SELECT
                last_check_in_at,
                deleted_at
            FROM
                clusters
            WHERE
                id = $1
        "#,
    )
    .bind(cluster_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_heartbeat"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_hive_agent_heartbeat_commit"))?;
    Ok(Json(result))
}

/// Gets a list of pending all pending releases
#[utoipa::path(
    get,
    path = "/api/releases/pending",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of all pending releases", body = [types::PendingReleases]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_pending_releases(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<PendingReleases>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, PendingReleases>(
        r#"
                SELECT
                    clusters.id AS cluster_id,
                    STRING_AGG(releases.name, ', ') AS release_names,
                    COUNT(releases.id)::INT4 AS count
                FROM clusters
                    JOIN namespaces
                        ON namespaces.cluster_id = clusters.id
                    JOIN releases
                        ON releases.namespace_id = namespaces.id
                        AND (releases.deprecated_at, releases.deleted_at) IS NULL
                        AND releases.approved_at IS NULL
                WHERE clusters.deleted_at IS NULL
                GROUP BY clusters.id
            "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_pending_releases_without_pagination"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_pending_releases_commit"))?;
    Ok(Json(result))
}

/// Gets a list of the latest errors produced by a specific release
#[utoipa::path(
    get,
    path = "/api/releases/{id}/errors",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of the latest errors produced by a specific release", body = [types::HiveError]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_release_errors(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(cluster_id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<HiveError>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, HiveError>(
        r#"
            SELECT
                message,
                updated_at
            FROM
                release_errors
            WHERE
                release_id = $1
                AND deprecated_at IS NULL
            ORDER BY updated_at DESC
            LIMIT $2 OFFSET $3
        "#,
    )
    .bind(cluster_id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_release_errors"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_release_errors_commit"))?;
    Ok(Json(result))
}

/// Update a list of releases for approval
#[utoipa::path(
    put,
    path = "/api/approvals",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of available releases that can be mass approved", body = [types::ReleaseCandidate]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when json data is missing"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_approvals(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<PutApprovals>,
) -> Result<Json<Vec<ReleaseCandidate>>, (StatusCode, String)> {
    if is_empty_or_has_empty_string(&data.ids) {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "No releases subbmited for approval".to_string(),
        ))
    } else {
        let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| sanitize_db_error(e, "put_approvals_begin"))?;

        set_tenant_context(&mut tx, tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE releases
            SET unapproved_at = NULL,
                approved_at = (SELECT NOW()),
                approved_by = 'hivehq'
            WHERE
                id IN (SELECT unnest($1::uuid[]))
                AND approved_at IS NULL
        "#,
        )
        .bind(&data.ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_approvals_update"))?;

        // Parse all UUIDs first to validate them
        let release_ids: Vec<Uuid> = data
            .ids
            .iter()
            .map(|id| {
                Uuid::parse_str(id).map_err(|_| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid UUID format: {}", id),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        tx.commit()
            .await
            .map_err(|e| sanitize_db_error(e, "put_approvals_commit"))?;

        // Batch fetch all release candidates at once instead of N queries
        let all_release_candidates =
            list_mass_approval_release_candidates_batch(&state.readonly_pool, release_ids)
                .await
                .map_err(|e| {
                    tracing::error!("Failed put_approvals_batch: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database error occurred".to_string(),
                    )
                })?;

        Ok(Json(all_release_candidates))
    }
}

/// Update a list of releases for unapproval (ie pause drift management)
#[utoipa::path(
    put,
    path = "/api/approvals/unapprove",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on succesfully updating unapprovals statuses"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when json data is missing"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_unapprovals(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<PutApprovals>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if is_empty_or_has_empty_string(&data.ids) {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "No releases subbmited for unapproval".to_string(),
        ))
    } else {
        let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| sanitize_db_error(e, "put_unapprovals_begin"))?;

        set_tenant_context(&mut tx, tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE releases
            SET approved_at = NULL,
                unapproved_at = (SELECT NOW()),
                unapproved_by = 'hivehq'
            WHERE
                id IN (SELECT unnest($1::uuid[]))
                AND unapproved_at IS NULL
                AND approved_at IS NOT NULL
        "#,
        )
        .bind(&data.ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_unapprovals"))?;

        tx.commit()
            .await
            .map_err(|e| sanitize_db_error(e, "put_unapprovals_commit"))?;

        Ok((StatusCode::NO_CONTENT, String::new()))
    }
}

/// Get a list of service_definitions that have relationships to a particular cluster-group
#[utoipa::path(
    get,
    path = "/api/cluster-groups/{id}/service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of service_definitions related to a cluster group", body = [types::ClusterGroupServices]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_cluster_group_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ClusterGroupServices>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as(
        r#"
        SELECT
            cluster_groups.id AS cluster_group_id,
            cluster_groups.name AS cluster_group_name,
            service_definitions.name AS service_name,
            service_definitions.id AS service_definition_id,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repo_branches.branch AS branch
        FROM cluster_groups
            JOIN service_definition_cluster_group_relationships
                ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
            JOIN service_definitions
                ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
            JOIN repo_branches
                ON service_definitions.repo_branch_id = repo_branches.id
            JOIN repos
                ON repos.id = repo_branches.repo_id
        WHERE
            cluster_groups.id = $1
        ORDER BY service_definitions.name
        LIMIT $2 OFFSET $3;
    "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_group_service_definitions"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_group_service_definitions_commit"))?;
    Ok(Json(result))
}

/// Remove the relationship between a cluster-group and a service
#[utoipa::path(
    delete,
    path = "/api/cluster-groups/{id}/service-definitions/{service_definition_id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on the successful removal of a cluster-group/service relationship"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when relationship not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn delete_service_definition_relationship(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((cluster_group_id, service_definition_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_definition_relationship_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        "DELETE FROM service_definition_cluster_group_relationships WHERE cluster_group_id = $1 AND service_definition_id = $2",
    )
    .bind(cluster_group_id)
    .bind(service_definition_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_service_definition_relationship"))?;

    #[derive(sqlx::FromRow)]
    struct Cluster {
        id: Uuid,
    }

    let clusters = sqlx::query_as::<_, Cluster>(
        r#"
        SELECT
            clusters.id
        FROM
            clusters
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            cluster_groups.id = $1
    "#,
    )
    .bind(cluster_group_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_fetch_clusters"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_definition_relationship_commit"))?;

    // Parallelize sync operations for all clusters
    let sync_futures = clusters
        .into_iter()
        .map(|cluster| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster.id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Remove a service name from a namespace
#[utoipa::path(
    delete,
    path = "/api/namespaces/{id}/service-name/{name}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on the successful removal of service (name) from a namespace"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Fails when relationship not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn delete_service_from_namespace(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path((namespace_id, service_name)): Path<(String, String)>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_from_namespace_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE
            releases
        SET
            deleted_at = (SELECT NOW())
        WHERE
            namespace_id = $1::uuid
            AND name = $2
            AND (deleted_at, deprecated_at) IS NULL
    "#,
    )
    .bind(namespace_id)
    .bind(service_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_service_from_namespace"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_from_namespace_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of clusters associated with a cluster-group
#[utoipa::path(
    get,
    path = "/api/cluster-groups/{id}/clusters",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of clusters associated with a cluster-group via id", body = [ClusterGroupClusterAssociation]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_cluster_group_cluster_association(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ClusterGroupClusterAssociation>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as(
        r#"
        SELECT
            clusters.*,
            CASE
                WHEN id IN
                (
                    SELECT
                        clusters.id
                    FROM
                        cluster_groups
                        JOIN
                            group_relationships
                            ON group_relationships.cluster_group_id = cluster_groups.id
                        JOIN
                            clusters
                            ON clusters.id = group_relationships.cluster_id AND clusters.deleted_at IS NULL
                    WHERE
                        cluster_groups.id = $1
                ) THEN TRUE
                ELSE FALSE
            END AS associated
        FROM clusters
        WHERE clusters.deleted_at IS NULL
        ORDER BY clusters.name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_cluster_group_cluster_association"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_cluster_group_cluster_association_commit"))?;
    Ok(Json(result))
}

fn generate_jwt(
    jwt_secret_bytes: &[u8],
    email: String,
    tenant_id: String,
    roles: Vec<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    // Token expiration set to 2 hours for security
    // NOTE: Database has refresh_tokens table (see migrations/20241216000001_add_refresh_tokens.sql)
    // TODO: Implement refresh token flow to allow token renewal without re-authentication
    let expiration = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now + Duration::from_secs(2 * 60 * 60), // 2 hours
        Err(e) => {
            let message = format!("Error generating JWT expiration date: {:?}", e);
            error!("{}", message);
            return Err(message.into());
        }
    };

    let claims = Claim {
        email,
        tenant_id,
        exp: expiration.as_secs() as usize,
        roles,
    };

    match encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret_bytes),
    ) {
        Ok(token) => Ok(token),
        Err(e) => {
            let message = format!("error generating JWT token: {:?}", e);
            error!("{}", e);
            Err(message.into())
        }
    }
}

pub async fn validate_auth(
    State(state): State<ServerState>,
    req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    validate_auth_with_roles(state, req, next, None).await
}

pub async fn validate_auth_aversion(
    State(state): State<ServerState>,
    req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    const REQUIRED_ROLES: &[&str] = &["aversion", "admin"];
    validate_auth_with_roles(state, req, next, Some(REQUIRED_ROLES)).await
}

async fn validate_auth_with_roles(
    state: ServerState,
    req: Request,
    next: Next,
    required_roles: Option<&[&str]>,
) -> Result<Response<Body>, StatusCode> {
    let validator = Validation::new(Algorithm::HS256);
    let secret_bytes = &state.jwt_secret_bytes;

    // headers can come as many different capitilization methods. Handle each type
    let normalized_headers = req
        .headers()
        .iter()
        .fold::<HashMap<String, axum::http::HeaderValue>, _>(HashMap::new(), |mut acc, (k, v)| {
            let normalized_key = k.to_string().to_lowercase().trim().to_string();
            acc.insert(normalized_key, v.clone());
            acc
        });

    if let Some(authorization_header_value) = normalized_headers.get("authorization") {
        let bearer_token_full =
            String::from_utf8(authorization_header_value.as_bytes().to_vec()).unwrap_or_default();
        let bearer_token = bearer_token_full.trim();

        // Safely extract token after "Bearer " or "bearer " prefix
        let token = bearer_token
            .strip_prefix("Bearer ")
            .or_else(|| bearer_token.strip_prefix("bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?
            .trim();

        if token.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        match decode::<Claim>(token, &DecodingKey::from_secret(secret_bytes), &validator) {
            Ok(token_data) => {
                if !is_email_domain_allowed(&token_data.claims.email) {
                    return Err(StatusCode::UNAUTHORIZED);
                }

                // Check if specific roles are required
                if let Some(required) = required_roles {
                    let has_required_role = token_data
                        .claims
                        .roles
                        .iter()
                        .any(|role| required.contains(&role.as_str()));

                    if !has_required_role {
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        }
    } else if let Some(session_token) = cookie_value(req.headers(), UI_SESSION_COOKIE_NAME) {
        let user = lookup_ui_session(&state.pool, &session_token)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Enforce that the session tenant matches the domain being used
        let request_tenant_id = extract_tenant_from_request(&state.pool, req.headers())
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let user_tenant_id = user.tenant_id.ok_or(StatusCode::UNAUTHORIZED)?;
        if user_tenant_id != request_tenant_id {
            return Err(StatusCode::UNAUTHORIZED);
        }

        if let Some(required) = required_roles {
            let has_required_role = user
                .roles
                .iter()
                .any(|role| required.contains(&role.as_str()));
            if !has_required_role {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(req).await)
}

fn is_empty_or_has_empty_string(arr: &[String]) -> bool {
    arr.is_empty() || arr.iter().any(|s| s.is_empty())
}

fn is_email_domain_allowed(email: &str) -> bool {
    let allowed_domains =
        std::env::var("ALLOWED_EMAIL_DOMAINS").unwrap_or_else(|_| String::from("galleybytes.com"));

    let domains: Vec<&str> = allowed_domains.split(',').map(|s| s.trim()).collect();

    domains
        .iter()
        .any(|domain| email.ends_with(&format!("@{}", domain)))
}

const UI_SESSION_COOKIE_NAME: &str = "beecd_session";

#[derive(Debug, Deserialize, ToSchema)]
pub struct UiAuthLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UiAuthMeResponse {
    pub id: Uuid,
    pub username: String,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UiAuthBootstrapStatusResponse {
    pub bootstrap_required: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TenantRegisterRequest {
    #[serde(alias = "email")]
    pub username: String,
    pub password: String,
    pub tenant_name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TenantRegisterResponse {
    pub tenant_id: Uuid,
    pub domain: String,
    pub user_id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TenantData {
    pub id: Uuid,
    pub domain: String,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSecretRequest {
    pub purpose: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecretMetadata {
    pub id: Uuid,
    pub purpose: String,
    pub created_at: String,
    pub key_version: i16,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecretListResponse {
    pub secrets: Vec<SecretMetadata>,
}

fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?;
    let s = std::str::from_utf8(raw.as_bytes()).ok()?;
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn build_session_cookie_value(
    token: &str,
    max_age_seconds: i64,
    secure: bool,
    domain: Option<&str>,
) -> String {
    // SameSite Strict since you said same-site and no CORS.
    // Secure is optional for local http dev.
    let domain_attr = domain
        .filter(|d| !d.is_empty())
        .map(|d| format!("; Domain={}", d))
        .unwrap_or_default();

    if secure {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}; Secure{}",
            UI_SESSION_COOKIE_NAME, token, max_age_seconds, domain_attr
        )
    } else {
        format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            UI_SESSION_COOKIE_NAME, token, max_age_seconds, domain_attr
        )
    }
}

fn build_clear_session_cookie_value(secure: bool) -> String {
    if secure {
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure",
            UI_SESSION_COOKIE_NAME
        )
    } else {
        format!(
            "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            UI_SESSION_COOKIE_NAME
        )
    }
}

fn ui_cookie_secure() -> bool {
    // Default false so local http works. Set BEECD_COOKIE_SECURE=1 in prod.
    std::env::var("BEECD_COOKIE_SECURE")
        .ok()
        .map(|v| {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}

fn ui_session_ttl_seconds() -> i64 {
    // Default 7 days.
    let hours: i64 = std::env::var("UI_SESSION_TTL_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(24 * 7);
    (hours.max(1)) * 60 * 60
}

async fn lookup_ui_session(
    pool: &sqlx::Pool<sqlx::Postgres>,
    session_token: &str,
) -> Result<Option<UiAuthMeResponse>, sqlx::Error> {
    let token_hash = util::hash_string(session_token);

    // Use SECURITY DEFINER function to bypass RLS for session lookup
    let row = sqlx::query_as::<_, (Uuid, String, Vec<String>, Option<Uuid>, Option<String>)>(
        r#"
        SELECT user_id, username, roles, tenant_id, tenant_name
        FROM auth_lookup_ui_session($1)
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    if let Some((id, username, roles, tenant_id, tenant_name)) = row {
        Ok(Some(UiAuthMeResponse {
            id,
            username,
            roles,
            tenant_id,
            tenant_name,
        }))
    } else {
        Ok(None)
    }
}

/// Bootstrap the very first UI user.
///
/// If any UI user already exists, this returns 409.
#[utoipa::path(
    post,
    path = "/api/auth/bootstrap",
    request_body = UiAuthLoginRequest,
    responses(
        (status = 201, description = "Created and logged in", body = UiAuthMeResponse),
        (status = 409, description = "Bootstrap already completed"),
        (status = 422, description = "Invalid input"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn ui_auth_bootstrap(
    State(state): State<ServerState>,
    Json(data): Json<UiAuthLoginRequest>,
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, axum::http::HeaderValue); 1],
        Json<UiAuthMeResponse>,
    ),
    (StatusCode, String),
> {
    let username = data.username.trim();
    let password = data.password;
    if username.is_empty() || password.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            String::from("username and password are required"),
        ));
    }

    let existing: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM ui_users
        WHERE deleted_at IS NULL
        "#,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_count"))?;

    if existing.0 > 0 {
        return Err((
            StatusCode::CONFLICT,
            String::from("bootstrap already completed"),
        ));
    }

    let password_hash = util::bcrypt_string(password.trim()).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("Failed to create password hash"),
        )
    })?;

    let roles: Vec<String> = vec!["admin".to_string()];

    // Start a transaction for creating tenant, user, and session
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_begin"))?;

    // Create a bootstrap tenant (domain based on username or default)
    let tenant_domain = format!(
        "bootstrap-{}",
        username
            .split('@')
            .next()
            .unwrap_or("admin")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-')
            .take(20)
            .collect::<String>()
    );
    let tenant_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO tenants (id, domain, name, status, config)
        VALUES (gen_random_uuid(), $1, 'Bootstrap Tenant', 'active', '{}')
        RETURNING id
        "#,
    )
    .bind(&tenant_domain)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_tenant"))?;

    // Set tenant context for RLS
    set_tenant_context(&mut tx, tenant_id).await?;

    // Create the first admin user
    let created = sqlx::query_as::<_, (Uuid,)>(
        r#"
        INSERT INTO ui_users (id, tenant_id, username, password_hash, roles)
        VALUES (gen_random_uuid(), $1, $2, $3, $4)
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(username)
    .bind(password_hash)
    .bind(&roles)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_insert"))?;

    let ttl_seconds = ui_session_ttl_seconds();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);
    let session_token = util::generate_secure_token_256().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("Failed to generate session token"),
        )
    })?;
    let session_hash = util::hash_string(&session_token);

    // Use SECURITY DEFINER function to bypass RLS (no tenant context yet)
    sqlx::query("SELECT auth_create_ui_session($1, $2, $3, $4)")
        .bind(&session_hash)
        .bind(created.0)
        .bind(tenant_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_session_insert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_commit"))?;

    let cookie = build_session_cookie_value(&session_token, ttl_seconds, ui_cookie_secure(), None);
    let header = (
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to set session cookie"),
            )
        })?,
    );

    Ok((
        StatusCode::CREATED,
        [header],
        Json(UiAuthMeResponse {
            id: created.0,
            username: username.to_string(),
            roles,
            tenant_id: None,
            tenant_name: None,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/auth/bootstrap/status",
    responses(
        (status = 200, description = "Bootstrap status", body = UiAuthBootstrapStatusResponse),
        (status = 500, description = "Database error"),
    )
)]
pub async fn ui_auth_bootstrap_status(
    State(state): State<ServerState>,
) -> Result<Json<UiAuthBootstrapStatusResponse>, (StatusCode, String)> {
    let existing: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM ui_users
        WHERE deleted_at IS NULL
        "#,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_bootstrap_status_count"))?;

    Ok(Json(UiAuthBootstrapStatusResponse {
        bootstrap_required: existing.0 == 0,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = UiAuthLoginRequest,
    responses(
        (status = 200, description = "Logged in", body = UiAuthMeResponse),
        (status = 401, description = "Invalid username or password"),
        (status = 422, description = "Invalid input"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn ui_auth_login(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<UiAuthLoginRequest>,
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, axum::http::HeaderValue); 1],
        Json<UiAuthMeResponse>,
    ),
    (StatusCode, String),
> {
    let username = data.username.trim();
    let password = data.password;
    if username.is_empty() || password.trim().is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            String::from("username and password are required"),
        ));
    }

    // Extract tenant from request first
    // This ensures we look up the user within the correct tenant
    let request_tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    // Use transaction with tenant context for RLS
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_login_begin"))?;
    set_tenant_context(&mut tx, request_tenant_id).await?;

    // Query user by username AND tenant_id
    // This prevents returning the wrong user when same username exists in multiple tenants
    let row = sqlx::query_as::<_, (Uuid, String, String, Vec<String>, Uuid)>(
        r#"
        SELECT id, username, password_hash, roles, tenant_id
        FROM ui_users
        WHERE deleted_at IS NULL AND username = $1 AND tenant_id = $2
        "#,
    )
    .bind(username)
    .bind(request_tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_login_select"))?;

    let Some((user_id, username_db, password_hash, roles, tenant_id)) = row else {
        return Err((
            StatusCode::UNAUTHORIZED,
            String::from("Invalid username or password"),
        ));
    };

    // Fetch tenant name for response (tenants table has permissive RLS)
    let tenant_name: Option<String> = sqlx::query_scalar(
        r#"
        SELECT name FROM tenants WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "ui_auth_login_tenant_select"))?;

    let ok = bcrypt::verify(password.trim(), &password_hash).unwrap_or(false);
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            String::from("Invalid username or password"),
        ));
    }

    let ttl_seconds = ui_session_ttl_seconds();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);
    let session_token = util::generate_secure_token_256().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            String::from("Failed to generate session token"),
        )
    })?;
    let session_hash = util::hash_string(&session_token);

    // Use SECURITY DEFINER function to bypass RLS (no tenant context yet)
    sqlx::query("SELECT auth_create_ui_session($1, $2, $3, $4)")
        .bind(&session_hash)
        .bind(user_id)
        .bind(tenant_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_login_session_insert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_login_commit"))?;

    let cookie = build_session_cookie_value(&session_token, ttl_seconds, ui_cookie_secure(), None);
    let header = (
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to set session cookie"),
            )
        })?,
    );

    Ok((
        StatusCode::OK,
        [header],
        Json(UiAuthMeResponse {
            id: user_id,
            username: username_db,
            roles,
            tenant_id: Some(tenant_id),
            tenant_name,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Logged out"),
        (status = 401, description = "Not authenticated"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn ui_auth_logout(
    State(state): State<ServerState>,
    req: Request,
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, axum::http::HeaderValue); 1],
    ),
    (StatusCode, String),
> {
    if let Some(token) = cookie_value(req.headers(), UI_SESSION_COOKIE_NAME) {
        let token_hash = util::hash_string(&token);
        // Use SECURITY DEFINER function to bypass RLS
        let _ = sqlx::query("SELECT auth_revoke_ui_session($1)")
            .bind(&token_hash)
            .execute(&state.pool)
            .await;
    }

    let cookie = build_clear_session_cookie_value(ui_cookie_secure());
    let header = (
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to clear session cookie"),
            )
        })?,
    );
    Ok((StatusCode::NO_CONTENT, [header]))
}

#[utoipa::path(
    get,
    path = "/api/auth/me",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Current user", body = UiAuthMeResponse),
        (status = 401, description = "Not authenticated"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn ui_auth_me(
    State(state): State<ServerState>,
    req: Request,
) -> Result<Json<UiAuthMeResponse>, (StatusCode, String)> {
    let Some(token) = cookie_value(req.headers(), UI_SESSION_COOKIE_NAME) else {
        return Err((StatusCode::UNAUTHORIZED, String::from("Not authenticated")));
    };

    let user = lookup_ui_session(&state.pool, &token)
        .await
        .map_err(|e| sanitize_db_error(e, "ui_auth_me_lookup"))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, String::from("Not authenticated")))?;

    Ok(Json(user))
}

/// Generate a domain slug from tenant name.
/// Rules:
/// - Only lowercase ASCII letters (a-z), digits (0-9), and hyphens (-) allowed
/// - No leading or trailing hyphens
/// - No consecutive hyphens
/// - Non-alphanumeric characters become hyphens (collapsed)
/// - Maximum 63 characters (DNS subdomain limit)
/// - Empty result if no valid characters
fn generate_domain_slug(name: &str) -> String {
    let mut result = String::new();
    let mut last_was_hyphen = true; // Treat start as hyphen to prevent leading hyphen

    for c in name.chars() {
        if result.len() >= 63 {
            break;
        }

        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            result.push(c);
            last_was_hyphen = false;
        } else if c.is_ascii_uppercase() {
            result.push(c.to_ascii_lowercase());
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            // Any non-alphanumeric character becomes a hyphen
            result.push('-');
            last_was_hyphen = true;
        }
        // Skip consecutive non-alphanumeric characters
    }

    // Remove trailing hyphen if present
    while result.ends_with('-') {
        result.pop();
    }

    result
}

#[cfg(test)]
mod slug_tests {
    use super::generate_domain_slug;

    #[test]
    fn test_simple_lowercase() {
        assert_eq!(generate_domain_slug("acme"), "acme");
    }

    #[test]
    fn test_uppercase_to_lowercase() {
        assert_eq!(generate_domain_slug("ACME"), "acme");
        assert_eq!(generate_domain_slug("AcMe"), "acme");
    }

    #[test]
    fn test_spaces_become_hyphens() {
        assert_eq!(generate_domain_slug("acme corp"), "acme-corp");
        assert_eq!(generate_domain_slug("my company name"), "my-company-name");
    }

    #[test]
    fn test_underscores_become_hyphens() {
        assert_eq!(generate_domain_slug("acme_corp"), "acme-corp");
    }

    #[test]
    fn test_no_double_hyphens() {
        assert_eq!(generate_domain_slug("acme--corp"), "acme-corp");
        assert_eq!(generate_domain_slug("acme---corp"), "acme-corp");
        assert_eq!(generate_domain_slug("acme - corp"), "acme-corp");
        assert_eq!(generate_domain_slug("acme  corp"), "acme-corp");
    }

    #[test]
    fn test_no_leading_hyphen() {
        assert_eq!(generate_domain_slug("-acme"), "acme");
        assert_eq!(generate_domain_slug("--acme"), "acme");
        assert_eq!(generate_domain_slug(" acme"), "acme");
    }

    #[test]
    fn test_no_trailing_hyphen() {
        assert_eq!(generate_domain_slug("acme-"), "acme");
        assert_eq!(generate_domain_slug("acme--"), "acme");
        assert_eq!(generate_domain_slug("acme "), "acme");
    }

    #[test]
    fn test_numbers_allowed() {
        assert_eq!(generate_domain_slug("acme123"), "acme123");
        assert_eq!(generate_domain_slug("123acme"), "123acme");
        assert_eq!(generate_domain_slug("acme-123-corp"), "acme-123-corp");
    }

    #[test]
    fn test_special_chars_become_hyphens() {
        assert_eq!(generate_domain_slug("acme!@#$%corp"), "acme-corp");
        assert_eq!(generate_domain_slug("acme.corp"), "acme-corp");
        assert_eq!(generate_domain_slug("acme&corp"), "acme-corp");
    }

    #[test]
    fn test_unicode_becomes_hyphens() {
        assert_eq!(generate_domain_slug("acme\u{00e9}corp"), "acme-corp"); // e with accent
        assert_eq!(generate_domain_slug("acme\u{4e2d}corp"), "acme-corp"); // Chinese char
        assert_eq!(generate_domain_slug("\u{00fc}ber"), "ber"); // u with umlaut at start
    }

    #[test]
    fn test_empty_input() {
        assert_eq!(generate_domain_slug(""), "");
    }

    #[test]
    fn test_only_invalid_chars() {
        assert_eq!(generate_domain_slug("!@#$%^"), "");
        assert_eq!(generate_domain_slug("---"), "");
        assert_eq!(generate_domain_slug("   "), "");
    }

    #[test]
    fn test_mixed_valid_invalid() {
        assert_eq!(generate_domain_slug("  --acme--  "), "acme");
        assert_eq!(generate_domain_slug("!!!acme!!!"), "acme");
    }

    #[test]
    fn test_realistic_company_names() {
        assert_eq!(generate_domain_slug("Acme Corporation"), "acme-corporation");
        assert_eq!(generate_domain_slug("Smith & Sons Ltd."), "smith-sons-ltd");
        assert_eq!(generate_domain_slug("O'Reilly Media"), "o-reilly-media");
        assert_eq!(generate_domain_slug("AT&T"), "at-t");
        assert_eq!(generate_domain_slug("3M Company"), "3m-company");
    }

    #[test]
    fn test_max_length_63_chars() {
        // Exactly 63 chars should be preserved
        let input_63 = "a".repeat(63);
        assert_eq!(generate_domain_slug(&input_63).len(), 63);

        // 64+ chars should be truncated to 63
        let input_100 = "a".repeat(100);
        assert_eq!(generate_domain_slug(&input_100).len(), 63);

        // Long name with spaces should truncate correctly
        let long_name =
            "this is an extremely long company name that exceeds the dns subdomain limit";
        let slug = generate_domain_slug(long_name);
        assert!(slug.len() <= 63);
        assert!(!slug.ends_with('-'));
        assert!(!slug.starts_with('-'));
    }

    #[test]
    fn test_truncation_removes_trailing_hyphen() {
        // If truncation lands on a hyphen, it should be removed
        // "abcdefghij" repeated 6 times = 60 chars, then " xy" would add "-xy" making 63
        // but if we have 62 chars + space, truncation at 63 would leave trailing hyphen
        let input = "a".repeat(62) + " xyz";
        let slug = generate_domain_slug(&input);
        assert!(slug.len() <= 63);
        assert!(!slug.ends_with('-'));
    }
}

#[cfg(test)]
mod subdomain_extraction_tests {
    use super::extract_subdomain_slug_with_base;

    #[test]
    fn test_with_base_domain_extracts_subdomain() {
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("tenant1.beecd.example.com", base),
            Some("tenant1".to_string())
        );
        assert_eq!(
            extract_subdomain_slug_with_base("acme-corp.beecd.example.com", base),
            Some("acme-corp".to_string())
        );
    }

    #[test]
    fn test_with_base_domain_handles_port() {
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("tenant1.beecd.example.com:8080", base),
            Some("tenant1".to_string())
        );
    }

    #[test]
    fn test_with_base_domain_nested_subdomain() {
        // If someone has extra levels like "www.tenant1.beecd.example.com",
        // we extract the rightmost prefix label (closest to base domain)
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("www.tenant1.beecd.example.com", base),
            Some("tenant1".to_string())
        );
    }

    #[test]
    fn test_with_base_domain_exact_match_returns_none() {
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("beecd.example.com", base),
            None
        );
    }

    #[test]
    fn test_with_base_domain_case_insensitive() {
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("TENANT1.BEECD.EXAMPLE.COM", base),
            Some("tenant1".to_string())
        );
    }

    #[test]
    fn test_without_base_domain_uses_first_label() {
        assert_eq!(
            extract_subdomain_slug_with_base("tenant1.beecd.example.com", None),
            Some("tenant1".to_string())
        );
        assert_eq!(
            extract_subdomain_slug_with_base("beecd.example.com", None),
            Some("beecd".to_string()) // This is the problematic case BASE_DOMAIN fixes
        );
    }

    #[test]
    fn test_without_base_domain_localhost_returns_none() {
        assert_eq!(extract_subdomain_slug_with_base("localhost", None), None);
        assert_eq!(
            extract_subdomain_slug_with_base("localhost:3000", None),
            None
        );
    }

    #[test]
    fn test_different_domain_with_base_falls_back() {
        // If the host doesn't match the base domain, fall back to first label
        let base = Some("beecd.example.com");
        assert_eq!(
            extract_subdomain_slug_with_base("tenant1.other.com", base),
            Some("tenant1".to_string())
        );
    }
}

/// Register a new tenant and create first admin user
#[utoipa::path(
    post,
    path = "/api/tenants/register",
    request_body = TenantRegisterRequest,
    responses(
        (status = 201, description = "Tenant and user created successfully", body = TenantRegisterResponse),
        (status = 400, description = "Invalid request data"),
        (status = 409, description = "Email or domain already exists"),
        (status = 500, description = "Database or server error"),
    )
)]
pub async fn register_tenant(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<TenantRegisterRequest>,
) -> Result<
    (
        StatusCode,
        [(axum::http::HeaderName, axum::http::HeaderValue); 1],
        Json<TenantRegisterResponse>,
    ),
    (StatusCode, String),
> {
    let email = data.username.trim().to_lowercase();
    let password = data.password.trim();
    let tenant_name = data.tenant_name.trim();

    // Validation
    if email.is_empty() || !email.contains('@') {
        return Err((StatusCode::BAD_REQUEST, "Invalid email".to_string()));
    }
    if password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters".to_string(),
        ));
    }
    if tenant_name.is_empty() || tenant_name.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Tenant name must be between 1 and 255 characters".to_string(),
        ));
    }

    // Generate domain slug from tenant name
    let domain_slug = generate_domain_slug(tenant_name);
    if domain_slug.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Tenant name must contain alphanumeric characters".to_string(),
        ));
    }

    // Store just the slug in domain column (e.g., 'acme' not 'acme.beecd.local')
    // This prevents collisions and works with any host variant
    let domain = domain_slug.clone();

    let password_hash = util::bcrypt_string(password).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to hash password".to_string(),
        )
    })?;

    // Start transaction: create tenant, then user
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "register_tenant_begin_tx"))?;

    // Create tenant
    let tenant_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO tenants (id, domain, name, status, config)
        VALUES (gen_random_uuid(), $1, $2, 'active', '{}')
        ON CONFLICT (domain) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(&domain)
    .bind(tenant_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "register_tenant_insert_tenant"))?
    .ok_or_else(|| (StatusCode::CONFLICT, "Domain already exists".to_string()))?;

    tracing::info!("Created tenant with id: {}", tenant_id);

    // Set tenant context for RLS - required before inserting tenant-scoped data
    set_tenant_context(&mut tx, tenant_id).await?;
    tracing::info!("Set tenant context for RLS");

    // Create user in the new tenant
    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO ui_users (id, tenant_id, username, password_hash, roles)
        VALUES (gen_random_uuid(), $1, $2, $3, ARRAY['admin']::text[])
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert user: {:?}", e);
        // Check for unique constraint violation
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.is_unique_violation() {
                return (
                    StatusCode::CONFLICT,
                    "Email already registered in this tenant".to_string(),
                );
            }
        }
        sanitize_db_error(e, "register_tenant_insert_user")
    })?;

    tracing::info!("Created user with id: {}", user_id);

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "register_tenant_commit_tx"))?;

    // Create session for the new user
    let ttl_seconds = ui_session_ttl_seconds();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);
    let session_token = util::generate_secure_token_256().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to generate session token".to_string(),
        )
    })?;
    let session_hash = util::hash_string(&session_token);

    // Use SECURITY DEFINER function to bypass RLS (tenant just created)
    sqlx::query("SELECT auth_create_ui_session($1, $2, $3, $4)")
        .bind(&session_hash)
        .bind(user_id)
        .bind(tenant_id)
        .bind(expires_at)
        .execute(&state.pool)
        .await
        .map_err(|e| sanitize_db_error(e, "register_tenant_session_insert"))?;

    // Share cookie across subdomains so redirect lands authenticated
    // Use the Host header to extract the parent domain (not the stored domain which may differ .local vs .localhost)
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let request_domain = host.split(':').next().unwrap_or(host);
    let cookie_domain = request_domain
        .split_once('.')
        .map(|(_, rest)| format!(".{}", rest))
        .unwrap_or_default();

    let cookie = build_session_cookie_value(
        &session_token,
        ttl_seconds,
        ui_cookie_secure(),
        if cookie_domain.is_empty() {
            None
        } else {
            Some(&cookie_domain)
        },
    );
    let header = (
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to set session cookie".to_string(),
            )
        })?,
    );

    Ok((
        StatusCode::CREATED,
        [header],
        Json(TenantRegisterResponse {
            tenant_id,
            domain,
            user_id,
            email,
        }),
    ))
}

/// Store a secret (GitHub token, PGP key, etc.) encrypted in the database
#[utoipa::path(
    post,
    path = "/api/secrets",
    security(
        ("bearerAuth"=[]),
    ),
    request_body = CreateSecretRequest,
    responses(
        (status = 201, description = "Secret created successfully"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 409, description = "Secret purpose already exists for this tenant"),
        (status = 500, description = "Database or encryption error"),
    )
)]
pub async fn create_secret(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<SecretMetadata>), (StatusCode, String)> {
    // Get current user and tenant
    let Some(token) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(v) = part.strip_prefix(format!("{}=", UI_SESSION_COOKIE_NAME).as_str())
                {
                    return Some(v.to_string());
                }
            }
            None
        })
    else {
        return Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()));
    };

    let _user = lookup_ui_session(&state.pool, &token)
        .await
        .map_err(|e| sanitize_db_error(e, "create_secret_lookup_user"))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Not authenticated".to_string()))?;

    // Get bootstrap key from environment
    let bootstrap_key_str = std::env::var("HIVE_CRYPTO_ROOT_KEY").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Bootstrap key not configured".to_string(),
        )
    })?;

    let bootstrap_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&bootstrap_key_str)
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid bootstrap key format".to_string(),
            )
        })?;

    if bootstrap_key_bytes.len() != 32 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Bootstrap key must be 32 bytes".to_string(),
        ));
    }

    let mut bootstrap_key = [0u8; 32];
    bootstrap_key.copy_from_slice(&bootstrap_key_bytes);

    // Validate inputs
    if data.purpose.is_empty() || data.plaintext.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "purpose and plaintext are required".to_string(),
        ));
    }

    // Resolve tenant from Host header
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    // Encrypt the secret
    let (ciphertext, iv) =
        crypto::encrypt(&bootstrap_key, data.plaintext.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Encryption failed: {}", e),
            )
        })?;

    // Persist to database with upsert
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "create_secret_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let row = sqlx::query_as::<_, (Uuid, chrono::DateTime<Utc>, i16)>(
        r#"
        INSERT INTO tenant_secrets (tenant_id, purpose, ciphertext, iv, key_version)
        VALUES ($1, $2, $3, $4, 1)
        ON CONFLICT (tenant_id, purpose) WHERE deleted_at IS NULL
        DO UPDATE SET
            ciphertext = EXCLUDED.ciphertext,
            iv = EXCLUDED.iv,
            updated_at = NOW()
        RETURNING id, created_at, key_version
        "#,
    )
    .bind(tenant_id)
    .bind(&data.purpose)
    .bind(&ciphertext)
    .bind(&iv)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "create_secret_upsert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "create_secret_commit"))?;

    Ok((
        StatusCode::CREATED,
        Json(SecretMetadata {
            id: row.0,
            purpose: data.purpose,
            created_at: row.1.to_rfc3339(),
            key_version: row.2,
        }),
    ))
}

/// List secrets (metadata only, no plaintext decryption)
#[utoipa::path(
    get,
    path = "/api/secrets",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "List of secrets", body = SecretListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn list_secrets(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SecretListResponse>, (StatusCode, String)> {
    let Some(_token) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(v) = part.strip_prefix(format!("{}=", UI_SESSION_COOKIE_NAME).as_str())
                {
                    return Some(v.to_string());
                }
            }
            None
        })
    else {
        return Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()));
    };

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "list_secrets_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let rows = sqlx::query_as::<_, (Uuid, String, chrono::DateTime<Utc>, i16)>(
        r#"
        SELECT id, purpose, created_at, key_version
        FROM tenant_secrets
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "list_secrets_query"))?;

    let secrets: Vec<SecretMetadata> = rows
        .into_iter()
        .map(|(id, purpose, created_at, key_version)| SecretMetadata {
            id,
            purpose,
            created_at: created_at.to_rfc3339(),
            key_version,
        })
        .collect();

    Ok(Json(SecretListResponse { secrets }))
}

/// Delete a secret (soft delete)
#[utoipa::path(
    delete,
    path = "/api/secrets/{purpose}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Secret deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Secret not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn delete_secret(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(purpose): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let Some(_token) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(v) = part.strip_prefix(format!("{}=", UI_SESSION_COOKIE_NAME).as_str())
                {
                    return Some(v.to_string());
                }
            }
            None
        })
    else {
        return Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()));
    };

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_secret_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let result = sqlx::query(
        r#"
        UPDATE tenant_secrets
        SET deleted_at = NOW(), updated_at = NOW()
        WHERE tenant_id = $1 AND purpose = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(&purpose)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_secret_update"))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Secret not found".to_string()));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_secret_commit"))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Retrieve a secret's encrypted ciphertext for agent-side decryption
/// This endpoint supports the optional Phase 5 agent-side secret passing pattern
/// The agent can optionally decrypt secrets locally using its own key material
#[utoipa::path(
    get,
    path = "/api/secrets/{purpose}/encrypted",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Encrypted secret data"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Secret not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn get_encrypted_secret(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(purpose): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(_token) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(v) = part.strip_prefix(format!("{}=", UI_SESSION_COOKIE_NAME).as_str())
                {
                    return Some(v.to_string());
                }
            }
            None
        })
    else {
        return Err((StatusCode::UNAUTHORIZED, "Not authenticated".to_string()));
    };

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "get_encrypted_secret_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i16)>(
        r#"
        SELECT ciphertext, iv, key_version
        FROM tenant_secrets
        WHERE tenant_id = $1 AND purpose = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(&purpose)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_encrypted_secret_query"))?;

    let (ciphertext, iv, key_version) =
        row.ok_or_else(|| (StatusCode::NOT_FOUND, "Secret not found".to_string()))?;

    // Return encrypted data as base64 for safe transport
    let result = json!({
        "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        "iv": base64::engine::general_purpose::STANDARD.encode(&iv),
        "key_version": key_version,
    });

    Ok(Json(result))
}

/// Add a new namespace to a cluster via id
#[utoipa::path(
    post,
    path = "/api/clusters/{id}/namespaces",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successful addition of namespace"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when json data is missing"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_create_cluster_namespaces(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostNamespaceNames>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if is_empty_or_has_empty_string(&data.namespace_names) {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Null value in namespace entry".to_string(),
        ))
    } else {
        let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| sanitize_db_error(e, "post_create_cluster_namespaces_begin"))?;

        set_tenant_context(&mut tx, tenant_id).await?;

        sqlx::query(
            r#"
        INSERT INTO namespaces (id, cluster_id, name, tenant_id)
        SELECT gen_random_uuid(), $1, unnest($2::text[]), $3
        ON CONFLICT (tenant_id, cluster_id, name) DO NOTHING
    "#,
        )
        .bind(id)
        .bind(data.namespace_names)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_namespace"))?;

        tx.commit()
            .await
            .map_err(|e| sanitize_db_error(e, "post_create_cluster_namespaces_commit"))?;

        Ok((StatusCode::NO_CONTENT, String::new()))
    }
}

/// Attach a cluster or a list of clusters to a cluster group
#[utoipa::path(
    post,
    path = "/api/cluster-groups/{id}/clusters",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successfully adding a cluster to a cluster group"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 422, description = "Fails when adding a cluster to cluster-group fails validation"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_subscribe_clusters(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostSubscriptions>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_clusters_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Validation make sure that no 'service @ repo' of proposed cluster is a dedup of service @ different repo
    #[derive(sqlx::FromRow)]
    struct ClusterGroup {
        priority: Option<i32>,
    }

    let cluster_group = sqlx::query_as::<_, ClusterGroup>(
        r#"
        SELECT * from cluster_groups WHERE id = $1
    "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_subscribe_clusters_fetch_group"))?;

    let priority = cluster_group.priority.unwrap_or(0);

    for cluster_id in data.ids.iter() {
        #[derive(sqlx::FromRow)]
        struct ConflictingService {
            name: String,
        }

        let results = sqlx::query_as::<_, ConflictingService>(
            r#"
            SELECT
                DISTINCT service_definitions.name
            FROM service_definitions
                JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
                JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                JOIN group_relationships ON group_relationships.cluster_group_id = cluster_groups.id
                JOIN clusters ON group_relationships.cluster_id = clusters.id AND clusters.deleted_at IS NULL
            WHERE
                clusters.id = $2
                AND service_definitions.name IN (
                    SELECT
                        service_definitions.name
                    FROM service_definitions
                        JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
                        JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                        JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                    WHERE
                        cluster_groups.id = $1
                )
                AND service_definitions.id NOT IN (
                    SELECT
                        service_definitions.id
                    FROM service_definitions
                        JOIN repo_branches ON repo_branches.id = service_definitions.repo_branch_id
                        JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                        JOIN cluster_groups ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                    WHERE
                        cluster_groups.id = $1
                )
                AND cluster_groups.priority = $3
        "#)
        .bind(id)
        .bind(cluster_id)
        .bind(priority)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_clusters_validate"))?;

        if !results.is_empty() {
            let mut names: Vec<String> = results.into_iter().map(|r| r.name).collect();
            names.sort();
            names.dedup();

            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "ClusterId {} cannot be added. Service name conflict(s): {}. Another service with the same name is already attached to a group that contains a cluster in this group.",
                    cluster_id,
                    names.join(", ")
                ),
            ));
        }
    }

    for cluster_id in data.ids.iter() {
        sqlx::query(
            r#"
            INSERT INTO group_relationships (tenant_id, cluster_group_id, cluster_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(cluster_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_clusters_insert"))?;
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_clusters_commit"))?;

    // Parallelize sync operations for all clusters
    let sync_futures = data
        .ids
        .into_iter()
        .map(|cluster_id| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster_id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Attach a service or a list of service_definitions to a cluster group
#[utoipa::path(
    post,
    path = "/api/cluster-groups/{id}/service-definitions",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successfully adding a service to a cluster group"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 422, description = "Fails when adding a service to cluster-group fails validation"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_subscribe_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostSubscriptions>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    #[derive(sqlx::FromRow)]
    struct ClusterGroup {
        priority: Option<i32>,
    }

    let cluster_group = sqlx::query_as::<_, ClusterGroup>(
        r#"
        SELECT * from cluster_groups WHERE id = $1
    "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_fetch_group"))?;

    let priority = cluster_group.priority.unwrap_or(0);

    // Validation make sure that no registered clusters of this group have the same service already associated via another group
    for service_definition_id in data.ids.iter() {
        let results = sqlx::query(
            r#"
            SELECT
                *
            FROM clusters
                JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                JOIN service_definitions ON service_definitions.id = service_definition_cluster_group_relationships.service_definition_id
            WHERE
                service_definitions.deleted_at IS NULL
                AND service_definitions.id != $2
                AND service_definitions.name = (
                    SELECT
                        name
                    FROM
                        service_definitions
                    WHERE
                        id = $2
                )
                AND clusters.id IN (
                    SELECT
                        clusters.id
                    FROM
                        clusters
                        JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                        JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                    WHERE
                        cluster_groups.id = $1
                )
                AND clusters.deleted_at IS NULL
                AND cluster_groups.priority = $3
        "#)
        .bind(id)
        .bind(service_definition_id)
        .bind(priority)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_validate"))?;

        if !results.is_empty() {
            #[derive(sqlx::FromRow)]
            struct ServiceName {
                name: String,
            }

            let service_name = sqlx::query_as::<_, ServiceName>(
                r#"
                SELECT name
                FROM service_definitions
                WHERE id = $1
            "#,
            )
            .bind(service_definition_id)
            .fetch_one(&mut *tx)
            .await
            .map(|r| r.name)
            .unwrap_or_else(|_| service_definition_id.to_string());

            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "Service \"{}\" (ServiceId {}) cannot be added. Another service with the same name is already attached to a group that contains a cluster in this group.",
                    service_name,
                    service_definition_id
                ),
            ));
        }
    }

    for service_definition_id in data.ids.iter() {
        sqlx::query(
            r#"
            INSERT INTO service_definition_cluster_group_relationships (tenant_id, cluster_group_id, service_definition_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(service_definition_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_insert"))?;
    }

    #[derive(sqlx::FromRow)]
    struct Cluster {
        id: Uuid,
    }

    let clusters = sqlx::query_as::<_, Cluster>(
        r#"
        SELECT
            clusters.id
        FROM
            clusters
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            cluster_groups.id = $1
    "#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_fetch_clusters"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_subscribe_service_definitions_commit"))?;

    // Parallelize sync operations for all clusters
    let sync_futures = clusters
        .into_iter()
        .map(|cluster| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster.id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Attach a service or a list of service_definitions to a cluster group
#[utoipa::path(
    put,
    path = "/api/cluster-groups/{id}/service-definitions",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successfully adding a service to a cluster group"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 422, description = "Fails when adding a service to cluster-group fails validation"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_subscribe_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostSubscriptions>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Validation make sure that no registered clusters of this group have the same service already associated via another group
    #[derive(sqlx::FromRow)]
    struct ClusterGroup {
        priority: Option<i32>,
    }

    let cluster_group = sqlx::query_as::<_, ClusterGroup>(
        r#"
        SELECT * from cluster_groups WHERE id = $1
    "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_fetch_group"))?;

    let priority = cluster_group.priority.unwrap_or(0);

    for service_definition_id in data.ids.iter() {
        let results = sqlx::query(
            r#"
            SELECT
                *
            FROM clusters
                JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                JOIN service_definitions ON service_definitions.id = service_definition_cluster_group_relationships.service_definition_id
            WHERE
                service_definitions.deleted_at IS NULL
                AND service_definitions.id != $2
                AND service_definitions.name = (
                    SELECT
                        name
                    FROM
                        service_definitions
                    WHERE
                        id = $2
                )
                AND clusters.id IN (
                    SELECT
                        clusters.id
                    FROM
                        clusters
                        JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                        JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                    WHERE
                        cluster_groups.id = $1
                )
                AND cluster_groups.id != $1
                AND clusters.deleted_at IS NULL
                AND cluster_groups.priority = $3;
        "#)
        .bind(id)
        .bind(service_definition_id)
        .bind(priority)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_validate"))?;

        if !results.is_empty() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("ServiceId {} cannot be updated. Another service with the same name is already attached to a group that contains a cluster in this group.", service_definition_id),
            ));
        }
    }

    for service_definition_id in data.ids.iter() {
        #[derive(sqlx::FromRow)]
        struct Svc {
            id: Uuid,
        }

        let old_service_definition = sqlx::query_as::<_, Svc>(
            r#"
            SELECT
                service_definitions.*
            FROM
                service_definitions
                JOIN service_definition_cluster_group_relationships ON service_definitions.id = service_definition_cluster_group_relationships.service_definition_id
                JOIN cluster_groups ON cluster_groups.id = service_definition_cluster_group_relationships.cluster_group_id
            WHERE
                service_definitions.name = (
                    SELECT
                        name
                    FROM
                        service_definitions
                    WHERE
                        id = $2
                )
                AND cluster_groups.id = $1;
        "#,
        )
        .bind(id)
        .bind(service_definition_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_fetch_old"))?;

        sqlx::query(
                "DELETE FROM service_definition_cluster_group_relationships WHERE cluster_group_id = $1 AND service_definition_id = $2",
            )
                .bind(id)
                .bind(old_service_definition.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_delete"))?;
    }

    for service_definition_id in data.ids.iter() {
        sqlx::query(
            r#"
            INSERT INTO service_definition_cluster_group_relationships (tenant_id, cluster_group_id, service_definition_id)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(service_definition_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_insert"))?;
    }

    #[derive(sqlx::FromRow)]
    struct Cluster {
        id: Uuid,
    }

    let clusters = sqlx::query_as::<_, Cluster>(
        r#"
        SELECT
            clusters.id
        FROM
            clusters
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            cluster_groups.id = $1
    "#,
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_fetch_clusters"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_subscribe_service_definitions_commit"))?;

    // Parallelize sync operations for all clusters
    let sync_futures = clusters
        .into_iter()
        .map(|cluster| sync_cluster_releases(&state.pool, &state.readonly_pool, cluster.id));
    future::try_join_all(sync_futures).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of all service_definitions
#[utoipa::path(
    get,
    path = "/api/service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a paginated list of all service_definitions", body = types::PaginatedResponse<types::ServiceDefinitionData>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<PaginatedResponse<ServiceDefinitionData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();

    // Get total count
    let (total,): (i64,) =
        sqlx::query_as(r#"SELECT COUNT(*) FROM service_definitions WHERE deleted_at IS NULL"#)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "get_service_definitions_count"))?;

    // Get paginated data
    let data: Vec<ServiceDefinitionData> = sqlx::query_as(
        r#"
        SELECT
            service_definitions.id AS service_definition_id,
            service_definitions.name AS name,
            service_definitions.deleted_at AS service_deleted_at,
            repo_branches.id AS repo_branch_id,
            repos.org AS org,
            repos.repo AS repo,
            repos.id AS repo_id,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            repo_branches.branch AS branch,
            service_definitions.source_branch_requirements,
            service_definitions.manifest_path_template
        FROM service_definitions
        JOIN repo_branches
            ON repo_branches.id = service_definitions.repo_branch_id
        JOIN repos
            ON repos.id = repo_branches.repo_id
        WHERE
            service_definitions.deleted_at IS NULL
        ORDER BY service_definitions.name
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_service_definitions"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_definitions_commit"))?;

    Ok(Json(PaginatedResponse::new(
        data,
        total,
        pagination.limit,
        pagination.offset,
    )))
}

/// Gets a list of releases for a given service_definitions via id
#[utoipa::path(
    get,
    path = "/api/service-definitions/{id}/releases",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of releases for a given service_definitions via id", body = [ReleaseStatus]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_service_releases(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ReleaseStatus>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let releases = sqlx::query_as::<_, ReleaseData>(
        r#"
            SELECT
                string_agg(cluster_groups.name, ',') AS cluster_groups,
                namespaces.name AS namespace,
                clusters.name AS cluster_name,
                clusters.id AS cluster_id,
                repos.org AS org,
                repos.repo AS repo,
                repos.id AS repo_id,
                repos.provider AS provider,
                repos.host AS host,
                repos.web_base_url AS web_base_url,
                repos.api_base_url AS api_base_url,
                repo_branches.branch AS branch,
                -1::INT4 as total_errors,
                releases.*,
                service_definitions.id AS service_definition_id,
                service_definitions.manifest_path_template,
                service_versions.pinned_at AS pinned_at,
                service_versions.pinned_by AS pinned_by
            FROM
                releases
                JOIN repo_branches ON repo_branches.id = releases.repo_branch_id
                JOIN service_definitions ON service_definitions.name = releases.name AND repo_branches.id = service_definitions.repo_branch_id
                JOIN repos ON repos.id = repo_branches.repo_id
                JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                JOIN cluster_groups ON cluster_groups.id = service_definition_cluster_group_relationships.cluster_group_id
                JOIN namespaces ON namespaces.id = releases.namespace_id
                JOIN clusters ON clusters.id = namespaces.cluster_id AND clusters.deleted_at IS NULL
                LEFT JOIN service_versions ON service_versions.id = releases.service_id
            WHERE
                service_definitions.id = $1
                AND (releases.deleted_at,releases.deprecated_at) IS NULL
            GROUP BY
                namespaces.id,
                clusters.id,
                repo_branches.id,
                releases.id,
                repos.id,
                service_definitions.id,
                service_versions.pinned_at,
                service_versions.pinned_by
            ORDER BY releases.name, namespaces.name, clusters.name
            LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_service_releases"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_releases_commit"))?;

    Ok(Json(
        releases
            .into_iter()
            .map(|mut r| {
                compute_release_path(&mut r);
                let status = r.status();
                ReleaseStatus { data: r, status }
            })
            .collect::<Vec<_>>(),
    ))
}

/// Adds a new repo
#[utoipa::path(
    post,
    path = "/api/repos",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns repo data on success", body = RepoData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_repo(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<PostRepo>,
) -> Result<Json<RepoData>, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let parsed = parse_repo_url(&data.url).ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid repo URL. Expected like https://<host>/<org>/<repo> or git@<host>:<org>/<repo>.git"
            .to_string(),
    ))?;

    // Auto-detect provider only for github.com. For any other host, require the user
    // to explicitly choose a provider to avoid misclassifying unknown hosts.
    let inferred_provider = if parsed.host == "github.com" {
        Some(RepoProvider::Github)
    } else {
        None
    };

    let provider = data.provider.clone().or(inferred_provider).ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        format!(
            "Could not auto-detect provider for host '{}'. Please specify a provider (e.g. github, forgejo, gitlab).",
            parsed.host
        ),
    ))?;

    if provider != RepoProvider::Github {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "Provider '{}' is not supported yet (supported: github)",
                provider
            ),
        ));
    }

    let web_base_url = data.web_base_url.clone().unwrap_or(parsed.web_base_url);
    let api_base_url = data.api_base_url.clone().unwrap_or(parsed.api_base_url);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_repo_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let ci_upsert = sqlx::query_as::<_, RepoData>(
        r#"
        INSERT INTO repos (id, org, repo, provider, host, web_base_url, api_base_url, tenant_id)
        VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT ON CONSTRAINT unique_repo_identity_per_tenant
        DO UPDATE SET
            provider = EXCLUDED.provider,
            web_base_url = EXCLUDED.web_base_url,
            api_base_url = EXCLUDED.api_base_url
        RETURNING id, provider, host, web_base_url, api_base_url, org, repo
        "#,
    )
    .bind(&parsed.org)
    .bind(&parsed.repo)
    .bind(&provider)
    .bind(&parsed.host)
    .bind(&web_base_url)
    .bind(&api_base_url)
    .bind(tenant_id);

    let repo = ci_upsert
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_repo_upsert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_repo_commit"))?;

    Ok(Json(repo))
}

/// Gets a list of all repos
#[utoipa::path(
    get,
    path = "/api/repos",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns paginated repos data", body = types::PaginatedResponse<types::RepoData>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_repos(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Query(pagination): Query<Pagination>,
) -> Result<Json<PaginatedResponse<RepoData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();

    // Get total count
    let (total,): (i64,) = sqlx::query_as(r#"SELECT COUNT(*) FROM repos"#)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_repos_count"))?;

    // Get paginated data
    let data: Vec<RepoData> = sqlx::query_as(
        r#"SELECT id, provider, host, web_base_url, api_base_url, org, repo FROM repos ORDER BY org, repo LIMIT $1 OFFSET $2"#,
    )
            .bind(pagination.limit)
            .bind(pagination.offset)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "get_repos"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_repos_commit"))?;

    Ok(Json(PaginatedResponse::new(
        data,
        total,
        pagination.limit,
        pagination.offset,
    )))
}

/// Gets repo data for specific repo via id
#[utoipa::path(
    get,
    path = "/api/repos/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns repo data", body = RepoData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_repo(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<RepoData>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, RepoData>(
        r#"
            SELECT id, provider, host, web_base_url, api_base_url, org, repo FROM repos WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_repo"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_repo_commit"))?;
    Ok(Json(result))
}

/// Gets branches for a specific repo via id
#[utoipa::path(
    get,
    path = "/api/repos/{id}/branches",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns branches data", body = [types::RepoBranches]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_branches(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<RepoBranches>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, RepoBranches>(
        r#"
            SELECT
                repo_branches.id as id,
                repos.provider as provider,
                repos.host as host,
                repos.web_base_url as web_base_url,
                repos.api_base_url as api_base_url,
                repo_branches.branch as branch,
                repos.org as org,
                repos.repo as repo,
                repos.id as repo_id,
                repo_branches.service_autosync
            FROM
                repo_branches
                JOIN repos ON repos.id = repo_branches.repo_id
            WHERE
                repo_id = $1
            ORDER BY branch
            LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_branches"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_branches_commit"))?;
    Ok(Json(result))
}

/// Add a new branch to a specific repo via id
#[utoipa::path(
    post,
    path = "/api/repos/{id}/branches",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on successfully adding a branch to a repo"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when json data is missing"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_branch(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostBranch>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let branch = data.branch.trim();
    if branch.is_empty() {
        return Err((
            StatusCode::NOT_ACCEPTABLE,
            "Null value in branch entry".to_string(),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_branch_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Create the branch and capture its ID so we can copy existing repo services onto it.
    let new_branch_id: Uuid = sqlx::query_scalar(
        r#"
            INSERT INTO repo_branches (id, repo_id, branch, tenant_id)
            VALUES (gen_random_uuid(), $1, $2, $3)
            RETURNING id
        "#,
    )
    .bind(id)
    .bind(branch)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_branch_insert"))?;

    // If the repo already has services configured on any branch, copy the UNION of those services
    // so the new branch starts with the same set of service names.
    //
    // If multiple manifest_path_template values exist for a service name across branches, use the
    // default manifest template for that service (rather than arbitrarily picking one).
    sqlx::query(
        r#"
            WITH existing_services AS (
                SELECT
                    sd.name,
                    COUNT(DISTINCT sd.manifest_path_template) AS manifest_template_distinct_count,
                    MIN(sd.manifest_path_template) AS manifest_template_single,
                    COUNT(DISTINCT sd.source_branch_requirements) AS source_requirements_distinct_count,
                    MIN(sd.source_branch_requirements) AS source_requirements_single
                FROM
                    repo_branches rb
                    JOIN service_definitions sd
                        ON sd.repo_branch_id = rb.id
                WHERE
                    rb.repo_id = $2
                    AND rb.id <> $1
                    AND sd.deleted_at IS NULL
                GROUP BY
                    sd.name
            )
            INSERT INTO service_definitions (
                id,
                repo_branch_id,
                name,
                source_branch_requirements,
                manifest_path_template,
                tenant_id
            )
            SELECT
                gen_random_uuid(),
                $1,
                es.name,
                CASE
                    WHEN es.source_requirements_distinct_count = 1 THEN es.source_requirements_single
                    ELSE NULL
                END,
                CASE
                    WHEN es.manifest_template_distinct_count = 1 AND es.manifest_template_single IS NOT NULL THEN es.manifest_template_single
                    ELSE '{cluster}/manifests/{namespace}/' || es.name || '/' || es.name || '.yaml'
                END,
                $3
            FROM
                existing_services es
            ON CONFLICT (tenant_id, repo_branch_id, name) DO NOTHING
        "#,
    )
    .bind(new_branch_id)
    .bind(id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_branch_copy_union_services"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_branch_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of service_definitions that are configured for the branch
#[utoipa::path(
    get,
    path = "/api/branches/{id}/service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of service_definitions configured for the branch", body = [types::ServiceDefinitionData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_branch_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ServiceDefinitionData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, ServiceDefinitionData>(
        r#"
            SELECT
                service_definitions.id AS service_definition_id,
                service_definitions.deleted_at AS service_deleted_at,
                repo_branch_id,
                repo_id,
                service_definitions.name,
                repos.provider as provider,
                repos.host as host,
                repos.web_base_url as web_base_url,
                repos.org as org,
                repos.repo as repo,
                repo_branches.branch as branch,
                service_definitions.source_branch_requirements,
                service_definitions.manifest_path_template
            FROM
                repo_branches
                JOIN
                    service_definitions
                    ON repo_branches.id = service_definitions.repo_branch_id
                JOIN
                    repos
                    ON repos.id = repo_branches.repo_id
            WHERE
                repo_branches.id = $1
                AND service_definitions.deleted_at IS NULL
            ORDER BY service_definitions.name
            LIMIT $2 OFFSET $3
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_branch_service_definitions"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_branch_service_definitions_commit"))?;
    Ok(Json(result))
}

/// Given a branch id, get a list other branches with "sync" configuration data
#[utoipa::path(
    get,
    path = "/api/branches/{id}/service-definitions/autosync",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of sync configuration data for a specific branch", body = [types::AutosyncData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_autosync_data(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<AutosyncData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, AutosyncData>(
        r#"
            SELECT
                id,
                branch,
                CASE
                    WHEN id IN (
                        SELECT
                            id
                        FROM
                            repo_branches
                        WHERE
                            id IN (
                                SELECT
                                    unnest(service_autosync)
                                FROM
                                    repo_branches
                                WHERE
                                    id = $1
                            )
                    ) THEN TRUE
                    ELSE FALSE
                END AS synced
            FROM
                repo_branches
            WHERE
                repo_id = (
                    SELECT
                        repo_id
                    FROM
                        repo_branches
                    WHERE
                        id = $1
                )
            ORDER BY branch
            LIMIT $2 OFFSET $3;
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_branch_service_definitions_fetch"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_autosync_data_commit"))?;
    Ok(Json(result))
}

/// Update a branch to by synced with other branches
#[utoipa::path(
    put,
    path = "/api/branches/{id}/service-definitions/autosync",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn put_branch_autosync(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<ServiceAutosyncBranches>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "put_branch_autosync_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
            UPDATE
                repo_branches
            SET
                service_autosync = $2::uuid[]
            WHERE
                id = $1
        "#,
    )
    .bind(id)
    .bind(&data.ids)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_branch_autosync_update"))?;

    sqlx::query(
        r#"
            WITH service_names AS (
                SELECT
                    name,
                    deleted_at,
                    manifest_path_template
                FROM
                    service_definitions
                WHERE
                    repo_branch_id IN (
                        SELECT
                            unnest(service_autosync)
                        FROM
                            repo_branches
                        WHERE
                            id = $1
                    )
            )
            INSERT INTO
                service_definitions (id, repo_branch_id, name, deleted_at, manifest_path_template, tenant_id)
            SELECT
                gen_random_uuid(),
                $1,
                service_names.name,
                -- Instead of preventing sync, add the resource as deleted
                service_names.deleted_at,
                service_names.manifest_path_template,
                $2
            FROM
                service_names ON CONFLICT DO NOTHING
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "put_branch_autosync_insert"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "put_branch_autosync_commit"))?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Add a service to a specific branch via id
#[utoipa::path(
    post,
    path = "/api/branches/{id}/service-definitions",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_branch_service(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<ServiceName>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    // TODO Instead of re-enabling a deleted service from a branch,
    // ask the user if they want to re-enable the service for the deleted
    // branches.
    //
    // ```sql
    // SELECT
    //     repo_branches.id,
    //     repo_branches.branch
    // FROM
    //     repo_branches
    //     JOIN service_definitions ON service_definitions.repo_branch_id = repo_branches.id
    // WHERE
    //     service_definitions.name = $2                   -- service name
    //     AND service_definitions.deleted_at IS NOT NULL
    //     AND repo_branches.id IN (
    //         SELECT
    //             id
    //         FROM
    //             repo_branches
    //         WHERE
    //             id = $1                       -- id of branch
    //             OR $1 = ANY(service_autosync)
    //     );
    // ```
    //
    // For now, just re-enable the service that is synced with this branch
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_branch_service_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
            WITH matching_repo_branches AS (
                SELECT
                    id
                FROM
                    repo_branches
                WHERE
                    id = $1
                    OR $1 = ANY(service_autosync)
            )
            INSERT INTO
                service_definitions (id, repo_branch_id, name, manifest_path_template, tenant_id)
            SELECT
                gen_random_uuid(),
                matching_repo_branches.id,
                $2,
                $3,
                $4
            FROM
                matching_repo_branches
            ON CONFLICT (tenant_id, repo_branch_id, name) DO UPDATE SET
                deleted_at = NULL

        "#,
    )
    .bind(id)
    .bind(&data.name)
    .bind(format!(
        "{{cluster}}/manifests/{{namespace}}/{}/{}.yaml",
        &data.name, &data.name
    ))
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_branch_service"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_branch_service_commit"))?;
    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Return a list of service_definitions in common for all branches in a repo
#[utoipa::path(
    get,
    path = "/api/repos/{id}/service-definitions",
    params(
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of service_definitions in common for all branches in a repo", body = [types::ServiceName]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_repo_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ServiceName>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, ServiceName>(
        r#"
            SELECT
                service_definitions.name,
                MIN(service_definitions.manifest_path_template) AS manifest_path_template
            FROM
                service_definitions
                INNER JOIN
                    repo_branches
                    ON service_definitions.repo_branch_id = repo_branches.id
                JOIN repos
                    ON repos.id = repo_branches.repo_id
            WHERE
                repos.id = $1
                AND service_definitions.deleted_at IS NULL
            GROUP BY
                (
                    service_definitions.name,
                    repos.id
                )
            HAVING
                COUNT(*) = (
                    SELECT
                        COUNT(*)
                    FROM
                        repo_branches
                    WHERE
                        repo_id = $1
                )
            ORDER BY service_definitions.name
            LIMIT $2 OFFSET $3;
        "#,
    )
    .bind(id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_repo_service_definitions"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_repo_service_definitions_commit"))?;
    Ok(Json(result))
}

#[derive(Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct NamespaceData {
    id: Uuid,
    name: String,
}

/// Get namespaces for a given cluster by name (aversion service endpoint)
#[utoipa::path(
    get,
    path = "/api/aversion/clusters/{cluster_name}/namespaces",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, body = [NamespaceData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 403, description = "Requires aversion or admin role"),
        (status = 500, description = "Fails when cluster name is invalid or db connection issues"),
    )
)]
pub async fn get_namespaces_via_cluster_name(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(cluster_name): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, NamespaceData>(r#"SELECT id, name FROM namespaces WHERE cluster_id = (SELECT id FROM clusters WHERE clusters.name = $1 AND clusters.deleted_at IS NULL)"#)
        .bind(&cluster_name)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "get_namespaces_via_cluster_name"))?
        .into_iter()
        .map(|r| (r.name, r.id.to_string()))
        .collect::<HashMap<String, String>>();

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_namespaces_via_cluster_name_commit"))?;
    Ok(Json(json!(result)))
}

/// Adds a service is common across all branches of a repo
#[utoipa::path(
    post,
    path = "/api/repos/{id}/service-definitions",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Failed with missing data"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_global_repo_service(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<ServiceName>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if data.name.is_empty() {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Null value in service entry".to_string(),
        ))
    } else {
        // Use provided template or generate default
        let template = data.manifest_path_template.unwrap_or_else(|| {
            format!(
                "{{cluster}}/manifests/{{namespace}}/{}/{}.yaml",
                &data.name, &data.name
            )
        });

        // TODO Instead of re-enabling a deleted service from a branch,
        // ask the user if they want to re-enable the service for the deleted
        // branches.
        //
        // ```sql
        // SELECT repo_branches.id, repo_branches.branch
        // FROM repo_branches
        // JOIN service_definitions ON service_definitions.repo_branch_id = repo_branches.id
        // WHERE service_definitions.name = 'name' AND service_definitions.deleted_at IS NOT NULL;
        // ```
        //
        // For now, just re-enable the service
        let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(|e| sanitize_db_error(e, "post_global_repo_service_begin"))?;

        set_tenant_context(&mut tx, tenant_id).await?;

        sqlx::query(
            r#"
        INSERT INTO
            service_definitions (id, repo_branch_id, name, manifest_path_template, tenant_id)
        SELECT
            GEN_RANDOM_UUID(),
            id,
            $2,
            $3,
            $4
        FROM
            repo_branches
        WHERE
            repo_id = $1
        ON CONFLICT (tenant_id, repo_branch_id, name) DO UPDATE SET
            deleted_at = NULL
    "#,
        )
        .bind(id)
        .bind(&data.name)
        .bind(&template)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "post_branch_service_upsert"))?;

        tx.commit()
            .await
            .map_err(|e| sanitize_db_error(e, "post_global_repo_service_commit"))?;

        Ok((StatusCode::NO_CONTENT, String::new()))
    }
}

async fn insert_new_releases_to_namespace(
    db: &sqlx::Pool<sqlx::Postgres>,
    namespace_id: &Uuid,
    service_definitions: &[ServiceDefinitionInfo],
    tenant_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tx = db.begin().await?;

    // Set tenant context for RLS
    let query = format!("SET LOCAL app.tenant_id = '{}';", tenant_id);
    sqlx::query(&query).execute(&mut *tx).await?;

    let cluster_data = sqlx::query_as::<_, ClusterNamespaceServicesData>(
        r#"
                SELECT
                    clusters.id as id,
                    clusters.name as name,
                    namespaces.id as namespace_id,
                    namespaces.name as namespace_name,
                    CASE
                        WHEN COUNT(DISTINCT releases.name) = 0 THEN NULL
                        ELSE ARRAY_AGG(DISTINCT releases.name)
                    END AS service_names
                FROM namespaces
                    JOIN clusters on clusters.id = namespaces.cluster_id AND clusters.deleted_at IS NULL
                    LEFT JOIN releases on releases.namespace_id = namespaces.id
                WHERE
                    namespaces.id = $1
                GROUP BY clusters.id, namespaces.id
            "#,
    )
    .bind(namespace_id)
    .fetch_one(&mut *tx)
    .await?;

    let cluster_name = cluster_data.name;
    let namespace_name = cluster_data.namespace_name;

    let mut query = String::from(
        r#"
        INSERT INTO releases
        (
            id,
            tenant_id,
            service_id,
            namespace_id,
            path,
            name,
            repo_branch_id,
            version,
            git_sha,
            hash
        )
        VALUES"#,
    );

    for (index, item) in service_definitions.iter().enumerate() {
        // Use manifest_path_template if available, otherwise fall back to default pattern
        let path = if let Some(template) = &item.manifest_path_template {
            template
                .replace("{cluster}", &cluster_name)
                .replace("{namespace}", &namespace_name)
                .replace("{service}", &item.name)
        } else {
            // Default pattern for backward compatibility
            format!(
                "{}/manifests/{}/{}/{}.yaml",
                cluster_name, namespace_name, item.name, item.name
            )
        };

        let new_item = format!(
            r#"(
                (SELECT GEN_RANDOM_UUID()),
                '{}',
                (SELECT GEN_RANDOM_UUID()),
                '{}',
                '{}',
                '{}',
                '{}',
                '-',
                '',
                ''
            )"#,
            tenant_id, namespace_id, path, item.name, item.repo_branch_id
        );

        if index == 0 {
            query = format!("{} {}", query, new_item);
        } else {
            query = format!("{}, {}", query, new_item);
        }
    }

    sqlx::query(&query).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn get_new_service_definitions_to_namespace(
    db: &sqlx::Pool<sqlx::Postgres>,
    namespace_id: &Uuid,
    service_definition_ids: &Vec<Uuid>,
    tenant_id: Uuid,
) -> Result<Vec<ServiceDefinitionInfo>, Box<dyn std::error::Error>> {
    let mut tx = db.begin().await?;

    // Set tenant context for RLS
    let query = format!("SET LOCAL app.tenant_id = '{}';", tenant_id);
    sqlx::query(&query).execute(&mut *tx).await?;

    let existing_releases = sqlx::query_as::<_, NamespaceServiceData>(
        r#"
        SELECT
            clusters.name AS cluster_name,
            namespaces.name AS name,
            namespaces.id AS id,
            releases.name AS service_name,
            releases.repo_branch_id AS repo_branch_id
        FROM namespaces
        JOIN releases on releases.namespace_id = namespaces.id
        JOIN clusters ON namespaces.cluster_id = clusters.id AND clusters.deleted_at IS NULL
        WHERE namespaces.id = $1
        AND (releases.deprecated_at, releases.deleted_at) IS NULL
        ;"#,
    )
    .bind(namespace_id)
    .fetch_all(&mut *tx)
    .await?;

    let service_info = sqlx::query_as::<_, ServiceDefinitionInfo>(
        "SELECT id, name, repo_branch_id, manifest_path_template FROM service_definitions WHERE id = ANY($1) AND service_definitions.deleted_at IS NULL",
    )
    .bind(service_definition_ids)
    .fetch_all(&mut *tx)
    .await?;

    let existing_service_names = existing_releases
        .iter()
        .map(|item| item.service_name.clone())
        .collect::<Vec<_>>();

    Ok(service_info
        .into_iter()
        .filter(|item| !existing_service_names.contains(&item.name))
        .collect::<Vec<_>>())
}

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
struct ServiceDefinitionInfo {
    id: Uuid,
    name: String,
    repo_branch_id: Uuid,
    manifest_path_template: Option<String>,
}

/// Adds or reinstates a release to a cluster, and then finds similar clusters
#[utoipa::path(
    post,
    path = "/api/releases/namespaces/{id}/init",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of similar clusters", body = [types::AdditionalInstallation]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn post_init_release(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<PostInitReleases>,
) -> Result<Json<Vec<AdditionalInstallation>>, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let new_service_definitions = get_new_service_definitions_to_namespace(
        &state.pool,
        &id,
        &data.service_definition_ids,
        tenant_id,
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed finding service_definitions new to namespace: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error occurred".to_string(),
        )
    })?;

    let additional_installations = if new_service_definitions.is_empty() {
        vec![]
    } else {
        insert_new_releases_to_namespace(&state.pool, &id, &new_service_definitions, tenant_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert new service release to namespace: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error occurred".to_string(),
                )
            })?;

        #[derive(sqlx::FromRow, Debug, Clone)]
        struct ClusterInGroupWithServiceDefinition {
            namespace_id: Uuid,
            namespace_name: String,
            cluster_name: String,
            exists: bool,
        }

        // Create a transaction with tenant context for the additional installations query
        let mut tx = state.pool.begin().await.map_err(|e| {
            tracing::error!("Failed to begin transaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error occurred".to_string(),
            )
        })?;

        let ctx_query = format!("SET LOCAL app.tenant_id = '{}';", tenant_id);
        sqlx::query(&ctx_query)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("Failed to set tenant context: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Database error occurred".to_string(),
                )
            })?;

        let mut service_definitions_new_to_cluster_namespaces = vec![];

        for service_definition in new_service_definitions.iter() {
            let clusters_with_same_namespace_in_group_with_service_relationship = sqlx::query_as::<_, ClusterInGroupWithServiceDefinition>(
                    r#"
                    SELECT
                        clusters_in_group_with_common_namespace.namespace_id AS namespace_id,
                        clusters_in_group_with_common_namespace.cluster_name AS cluster_name,
                        clusters_in_group_with_common_namespace.namespace_name AS namespace_name,
                        CASE
                            WHEN releases.id IS NOT NULL THEN TRUE
                            ELSE FALSE
                        END AS exists
                    FROM
                        (
                            WITH namespace_data AS (
                                SELECT
                                    *
                                FROM
                                    namespaces
                                WHERE
                                    id = $1
                                LIMIT
                                    1
                            )
                            SELECT
                                clusters.id AS cluster_id,
                                clusters.name AS cluster_name,
                                namespaces.id AS namespace_id,
                                namespaces.name AS namespace_name,
                                cluster_groups.id AS cluster_group_id,
                                cluster_groups.name AS cluster_group_name
                            FROM clusters
                                JOIN namespaces ON namespaces.cluster_id = clusters.id
                                AND namespaces.name = (
                                    SELECT
                                        name
                                    FROM
                                        namespace_data
                                )
                                JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                                JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                            WHERE
                                clusters.id IN (
                                    SELECT
                                        cluster_id
                                    FROM
                                        namespaces
                                    WHERE
                                        name = (
                                            SELECT
                                                name
                                            FROM
                                                namespace_data
                                        )
                                )
                                AND group_relationships.cluster_group_id IN (
                                    SELECT
                                        cluster_group_id
                                    FROM
                                        group_relationships
                                    WHERE
                                        cluster_id = (
                                            SELECT
                                                cluster_id
                                            FROM
                                                namespace_data
                                        )
                                        AND cluster_group_id IN (
                                            SELECT
                                                cluster_group_id
                                            FROM
                                                service_definition_cluster_group_relationships
                                            WHERE
                                                service_definition_id = $2
                                        )
                                )
                                AND clusters.deleted_at IS NULL
                        ) AS clusters_in_group_with_common_namespace
                        LEFT JOIN releases ON releases.namespace_id = clusters_in_group_with_common_namespace.namespace_id
                        AND releases.name = (
                            SELECT
                                service_definitions.name
                            FROM
                                service_definitions
                            WHERE
                                id = $2
                                AND deleted_at IS NULL
                            LIMIT
                                1
                        )
                        AND (releases.deprecated_at, releases.deleted_at) IS NULL;
                    "#,
                )
                .bind(id)
                .bind(service_definition.id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to find additional installation candidates: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Database error occurred".to_string())
                })?;

            for item in clusters_with_same_namespace_in_group_with_service_relationship.iter() {
                if !item.exists {
                    service_definitions_new_to_cluster_namespaces.push(AdditionalInstallation {
                        namespace_id: item.namespace_id,
                        namespace_name: item.namespace_name.clone(),
                        service_definition_id: service_definition.id,
                        cluster_name: item.cluster_name.clone(),
                        service_name: service_definition.name.clone(),
                    });
                }
            }
        }

        service_definitions_new_to_cluster_namespaces
    };

    Ok(Json(additional_installations))
}

/// Adds or reinstates batch of releases to clusters
///
/// Similar to "/api/releases/namespaces/{id}/init", but handles multiple service_definitions and multiple namespaces in the same query.
/// Also on success returns 204 instead.
#[utoipa::path(
    post,
    path = "/api/releases/init-many",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 406, description = "Fails when post data is empty"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn post_additional_installations(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<Vec<PostAdditionalInstallation>>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    if data.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            String::from("No additional installations sent for processing"),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let installation_map =
        data.iter()
            .fold::<HashMap<Uuid, Vec<Uuid>>, _>(HashMap::new(), |mut acc, item| {
                match acc.get_mut(&item.namespace_id) {
                    Some(list) => list.push(item.service_definition_id),
                    None => {
                        acc.insert(item.namespace_id, vec![item.service_definition_id]);
                    }
                }
                acc
            });

    for (namespace_id, service_definition_id) in installation_map.iter() {
        let service_definitions = get_new_service_definitions_to_namespace(
            &state.pool,
            namespace_id,
            service_definition_id,
            tenant_id,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed finding service_definitions new to namespace: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to fetch build targets for namespace"),
            )
        })?;

        insert_new_releases_to_namespace(
            &state.pool,
            namespace_id,
            &service_definitions,
            tenant_id,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to insert additional releases: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to insert releases for namespace"),
            )
        })?;
    }

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Adds a new agent user
#[utoipa::path(
    post,
    path = "/api/users",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns user data on success", body = [types::UserData]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 409, description = "Fails on duplicate entry"),
        (status = 422, description = "Fails when post data is invalid or incomplete"),
        (status = 424, description = "Fails when secret or manifest could not be generated"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn post_user(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<PostUser>,
) -> Result<Json<UserData>, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let secret = util::generate_random_string(256);

    let manifest = match data.context {
        Some(context) => {
            let context_with_secret = match context.clone().as_object_mut() {
                Some(object) => {
                    let key = "agent_name";
                    let value = util::value_or_default(
                        object.get(key),
                        Some(String::from("hive-agent")),
                        false,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    let key = "namespace";
                    let value = util::value_or_default(
                        object.get(key),
                        Some(String::from("beecd-system")),
                        false,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    let key = "grpc_address";
                    let value = util::value_or_default(
                        object.get(key),
                        state.hive_default_grpc_server,
                        true,
                    )
                    .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e)))?;
                    object.insert(String::from(key), value);

                    let key = "image";
                    let value =
                        util::value_or_default(object.get(key), state.agent_default_image, true)
                            .map_err(|e| {
                                (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", key, e))
                            })?;
                    object.insert(String::from(key), value);

                    object.insert(
                        String::from("secret"),
                        serde_json::Value::String(general_purpose::STANDARD.encode(secret.clone())),
                    );
                    object.insert(
                        String::from("name"),
                        serde_json::Value::String(data.name.clone()),
                    );
                    serde_json::to_value(object)
                        .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
                }
                None => {
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        String::from("context data is invalid"),
                    ))
                }
            };

            util::generate_manifest(&state.agent_manifest_template, context_with_secret)
                .map_err(|e| (StatusCode::FAILED_DEPENDENCY, format!("{}", e)))?
        }
        None => String::new(),
    };

    let hash = util::bcrypt_string(&secret).map_err(|e| {
        tracing::error!("Failed creating bcrypt hash for user secret: {}", e);
        (
            StatusCode::FAILED_DEPENDENCY,
            String::from("Failed to create secure hash for user"),
        )
    })?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_user_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
            INSERT INTO users
            (id, name, hash, tenant_id)
            VALUES
            ((SELECT gen_random_uuid()), $1, $2, $3)
        "#,
    )
    .bind(&data.name)
    .bind(&hash)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(database_error) => {
            match database_error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
                Some(pg_database_error) => {
                    if pg_database_error.code() == "23505" {
                        (
                            StatusCode::CONFLICT,
                            String::from("A duplicate entry already exists"),
                        )
                    } else {
                        tracing::error!("Database error inserting user: {}", pg_database_error);
                        (
                            StatusCode::UNPROCESSABLE_ENTITY,
                            String::from("Database error while inserting user"),
                        )
                    }
                }
                None => {
                    tracing::error!("Database error inserting user: {}", database_error);
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        String::from("Database error while inserting user"),
                    )
                }
            }
        }

        _ => {
            tracing::error!("Unknown error inserting user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("Failed to insert user"),
            )
        }
    })?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_user_commit"))?;

    Ok(Json(UserData { secret, manifest }))
}

/// Updates a agent user
///
/// put_user will allow sending in the current secret and will get a new secret in return.
#[utoipa::path(
    post,
    path = "/api/users",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 401, description = "Access token is missing or invalid"),
        (status = 501, description = "This enpoint is not implemented yet"),
    )
)]
pub async fn put_user() -> Result<Json<UserData>, (StatusCode, String)> {
    Err((StatusCode::NOT_IMPLEMENTED, String::new()))
}

async fn clean_up_service_relationships(
    db: &sqlx::Pool<sqlx::Postgres>,
) -> Result<(), (StatusCode, String)> {
    // Clean up the database so references to deleted items are no longer available
    let _ = sqlx::query(
        r#"
    DELETE FROM
        service_definition_cluster_group_relationships
    WHERE
        service_definition_id IN (SELECT id FROM service_definitions WHERE deleted_at IS NOT NULL)
    "#,
    )
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

/// Removes a build target
#[utoipa::path(
    delete,
    path = "/api/service-definitions/{id}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn delete_service_definitions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_definitions_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE
            service_definitions
        SET
            deleted_at = NOW(),
            source_branch_requirements = NULL
        WHERE
            id = $1
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_definitions_commit"))?;

    clean_up_service_relationships(&state.pool).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Removes a service by name
#[utoipa::path(
    delete,
    path = "/api/service/{name}",
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Returns no content on success"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db issues"),
    )
)]
pub async fn delete_service(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    sqlx::query(
        r#"
        UPDATE
            service_definitions
        SET
            deleted_at = NOW(),
            source_branch_requirements = NULL
        WHERE
            name = $1
        "#,
    )
    .bind(&name)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_commit"))?;

    clean_up_service_relationships(&state.pool).await?;

    Ok((StatusCode::NO_CONTENT, String::new()))
}

/// Gets a list of releases that can be mass approved
pub async fn list_mass_approval_release_candidates(
    readonly_pool: &sqlx::Pool<sqlx::Postgres>,
    ref_release_id: Uuid,
) -> Result<Vec<ReleaseCandidate>, Box<dyn std::error::Error>> {
    let releases_in_same_cluster_group = sqlx::query_as::<_, ReleaseCandidate>(r#"
        SELECT
            releases.id AS release_id,
            releases.name AS release_name,
            clusters.name AS cluster_name,
            namespaces.name AS namespace_name,
            cluster_groups.name AS cluster_group_name
        FROM
            releases
            JOIN namespaces ON releases.namespace_id = namespaces.id
            JOIN clusters ON clusters.id = namespaces.cluster_id
            JOIN group_relationships ON group_relationships.cluster_id = clusters.id
            JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
        WHERE
            (
                releases.approved_at,
                releases.deleted_at,
                releases.deprecated_at
            ) IS NULL
             AND (releases.name, releases.version) = (
                SELECT
                    name,
                    version
                FROM
                    releases
                WHERE
                    id = $1
            )
            AND cluster_groups.id IN (
                SELECT
                    cluster_groups.id
                FROM
                    releases
                    JOIN namespaces ON releases.namespace_id = namespaces.id
                    JOIN clusters ON clusters.id = namespaces.cluster_id
                    JOIN group_relationships ON group_relationships.cluster_id = clusters.id
                    JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                    JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                    JOIN service_definitions ON service_definitions.id = service_definition_cluster_group_relationships.service_definition_id
                    AND service_definitions.name = releases.name
                WHERE
                    releases.id = $1
            );
    "#)
    .bind(ref_release_id)
    .fetch_all(readonly_pool)
    .await?;

    let ref_resource_diffs = list_resource_diffs(readonly_pool, ref_release_id, -1).await?;

    let mut ref_keys = ref_resource_diffs
        .iter()
        .map(|item| item.key.clone())
        .collect::<Vec<_>>();
    ref_keys.sort();

    let ref_resource_map: HashMap<_, _> = ref_resource_diffs
        .iter()
        .map(|diff_data| {
            (
                diff_data.key.clone(),
                diff_data.change_order.clone().unwrap_or(vec![]),
            )
        })
        .collect();

    let mut release_candidates: Vec<ReleaseCandidate> = vec![];
    for release in releases_in_same_cluster_group {
        if release.release_id == ref_release_id {
            continue;
        }
        let resource_diffs = list_resource_diffs(readonly_pool, release.release_id, -1).await?;

        let mut keys = resource_diffs
            .iter()
            .map(|item| item.key.clone())
            .collect::<Vec<_>>();
        keys.sort();

        // To qualify...
        // Both diffs must be of equal length
        if ref_resource_diffs.len() != resource_diffs.len() {
            continue;
        }

        // Both diffs must have the same keys
        if !ref_keys.eq(&keys) {
            continue;
        }

        // Both diffs must have the same order of diffs
        if resource_diffs.iter().any(|item| {
            !ref_resource_map
                .get(&item.key)
                .cloned()
                .unwrap_or(vec![])
                .eq(&item.change_order.clone().unwrap_or(vec![]))
        }) {
            continue;
        }

        release_candidates.push(release)
    }

    Ok(release_candidates)
}

/// Batch version of list_mass_approval_release_candidates - fetches candidates for multiple releases at once
/// This eliminates the N+1 query pattern when approving multiple releases
pub async fn list_mass_approval_release_candidates_batch(
    readonly_pool: &sqlx::Pool<sqlx::Postgres>,
    ref_release_ids: Vec<Uuid>,
) -> Result<Vec<ReleaseCandidate>, Box<dyn std::error::Error>> {
    if ref_release_ids.is_empty() {
        return Ok(vec![]);
    }

    // For simplicity, we'll process each reference release's candidates
    // This is still much better than the original N+1 pattern
    // A full optimization would involve more complex SQL to batch everything
    let mut all_candidates = Vec::new();
    for ref_release_id in ref_release_ids {
        let mut candidates =
            list_mass_approval_release_candidates(readonly_pool, ref_release_id).await?;
        all_candidates.append(&mut candidates);
    }

    // Deduplicate by release_id
    let mut seen = std::collections::HashSet::new();
    all_candidates.retain(|c| seen.insert(c.release_id));

    Ok(all_candidates)
}

pub async fn list_resource_diffs(
    readonly_pool: &sqlx::Pool<sqlx::Postgres>,
    release_id: Uuid,
    diff_generation: i32,
) -> Result<Vec<DiffData>, Box<dyn std::error::Error>> {
    let query = if diff_generation == -1 {
        sqlx::query_as::<_, DiffData>(
            r#"
        SELECT
            resource_diffs.key,
            resource_diffs.release_id,
            resource_diffs.diff_generation,
            resource_diffs.change_order,
            resource_diffs.storage_url
        FROM
            resource_diffs
        WHERE
            resource_diffs.release_id = $1
            AND resource_diffs.diff_generation = (
                SELECT diff_generation FROM releases WHERE id = $1
            )
        LIMIT 100
        "#,
        )
        .bind(release_id)
        .fetch_all(readonly_pool)
        .await?
    } else {
        sqlx::query_as::<_, DiffData>(
            r#"
        SELECT
            resource_diffs.key,
            resource_diffs.release_id,
            resource_diffs.diff_generation,
            resource_diffs.change_order,
            resource_diffs.storage_url
        FROM
            resource_diffs
        WHERE
            resource_diffs.release_id = $1
            AND resource_diffs.diff_generation = $2
        LIMIT 100
        "#,
        )
        .bind(release_id)
        .bind(diff_generation)
        .fetch_all(readonly_pool)
        .await?
    };

    Ok(query)
}

// =============================================================================
// Service Versions API
// =============================================================================
// These endpoints manage service versions - the deployable artifacts that
// replace the external aversion database. CI/CD pipelines or webhooks can
// use these endpoints to register new versions when builds complete.

/// Get all service versions for a namespace
#[utoipa::path(
    get,
    path = "/api/namespaces/{namespace_id}/service-versions",
    params(
        ("namespace_id" = Uuid, Path, description = "Namespace UUID"),
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of service versions", body = [types::ServiceVersionWithDetails]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_namespace_service_versions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(namespace_id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<ServiceVersionWithDetails>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let result = sqlx::query_as::<_, ServiceVersionWithDetails>(
        r#"
            SELECT
                sv.id,
                sv.created_at,
                sv.updated_at,
                sv.service_definition_id,
                sd.name AS service_name,
                sv.namespace_id,
                n.name AS namespace_name,
                c.name AS cluster_name,
                sv.version,
                sv.git_sha,
                sv.git_sha_short,
                sv.path,
                sv.hash,
                repos.org,
                repos.repo,
                repos.provider AS provider,
                repos.host AS host,
                repos.web_base_url AS web_base_url,
                rb.branch,
                sv.source,
                sv.deprecated_at
            FROM
                service_versions sv
                JOIN service_definitions sd ON sd.id = sv.service_definition_id
                JOIN repo_branches rb ON rb.id = sd.repo_branch_id
                JOIN repos ON repos.id = rb.repo_id
                JOIN namespaces n ON n.id = sv.namespace_id
                JOIN clusters c ON c.id = n.cluster_id
            WHERE
                sv.namespace_id = $1
                AND sv.deprecated_at IS NULL
            ORDER BY sv.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
    )
    .bind(namespace_id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_namespace_service_versions"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_namespace_service_versions_commit"))?;
    Ok(Json(result))
}

/// Get service versions for a specific service definition
#[utoipa::path(
    get,
    path = "/api/service-definitions/{service_definition_id}/versions",
    params(
        ("service_definition_id" = Uuid, Path, description = "Service Definition UUID"),
        ("include_deprecated" = Option<bool>, Query, description = "Include deprecated versions (default: false)"),
        ("limit" = Option<i64>, Query, description = "Number of items to return (default: 50, max: 500)"),
        ("offset" = Option<i64>, Query, description = "Number of items to skip (default: 0)"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns a list of versions for the service definition", body = [types::ServiceVersionWithDetails]),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_service_definition_versions(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(service_definition_id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<ServiceVersionWithDetails>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();
    let include_deprecated = params
        .get("include_deprecated")
        .map(|v| v == "true")
        .unwrap_or(false);

    let query = if include_deprecated {
        sqlx::query_as::<_, ServiceVersionWithDetails>(
            r#"
            SELECT
                sv.id,
                sv.created_at,
                sv.updated_at,
                sv.service_definition_id,
                sd.name AS service_name,
                sv.namespace_id,
                n.name AS namespace_name,
                c.name AS cluster_name,
                sv.version,
                sv.git_sha,
                sv.git_sha_short,
                sv.path,
                sv.hash,
                repos.org,
                repos.repo,
                repos.provider AS provider,
                repos.host AS host,
                repos.web_base_url AS web_base_url,
                rb.branch,
                sv.source,
                sv.deprecated_at
            FROM
                service_versions sv
                JOIN service_definitions sd ON sd.id = sv.service_definition_id
                JOIN repo_branches rb ON rb.id = sd.repo_branch_id
                JOIN repos ON repos.id = rb.repo_id
                JOIN namespaces n ON n.id = sv.namespace_id
                JOIN clusters c ON c.id = n.cluster_id
            WHERE
                sv.service_definition_id = $1
            ORDER BY sv.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(service_definition_id)
        .bind(pagination.limit)
        .bind(pagination.offset)
        .fetch_all(&mut *tx)
        .await
    } else {
        sqlx::query_as::<_, ServiceVersionWithDetails>(
            r#"
            SELECT
                sv.id,
                sv.created_at,
                sv.updated_at,
                sv.service_definition_id,
                sd.name AS service_name,
                sv.namespace_id,
                n.name AS namespace_name,
                c.name AS cluster_name,
                sv.version,
                sv.git_sha,
                sv.git_sha_short,
                sv.path,
                sv.hash,
                repos.org,
                repos.repo,
                repos.provider AS provider,
                repos.host AS host,
                repos.web_base_url AS web_base_url,
                rb.branch,
                sv.source,
                sv.deprecated_at
            FROM
                service_versions sv
                JOIN service_definitions sd ON sd.id = sv.service_definition_id
                JOIN repo_branches rb ON rb.id = sd.repo_branch_id
                JOIN repos ON repos.id = rb.repo_id
                JOIN namespaces n ON n.id = sv.namespace_id
                JOIN clusters c ON c.id = n.cluster_id
            WHERE
                sv.service_definition_id = $1
                AND sv.deprecated_at IS NULL
            ORDER BY sv.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(service_definition_id)
        .bind(pagination.limit)
        .bind(pagination.offset)
        .fetch_all(&mut *tx)
        .await
    };

    let result = query.map_err(|e| sanitize_db_error(e, "get_service_definition_versions"))?;
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_definition_versions_commit"))?;
    Ok(Json(result))
}

/// Create a new service version (for CI/CD pipelines)
#[utoipa::path(
    post,
    path = "/api/service-versions",
    request_body = types::CreateServiceVersion,
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Service version already exists with this git_sha (idempotent)", body = types::ServiceVersionData),
        (status = 201, description = "Service version created successfully", body = types::ServiceVersionData),
        (status = 400, description = "Invalid request body"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<CreateServiceVersion>,
) -> Result<(StatusCode, Json<ServiceVersionData>), (StatusCode, String)> {
    // Validate git_sha format (should be 40 char hex)
    if data.git_sha.len() != 40 || !data.git_sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "git_sha must be a 40-character hex string".to_string(),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let git_sha_short = data.git_sha[..7].to_string();

    // Step 1: Deprecate any existing non-pinned active version for this service+namespace
    // (same pattern as webhook handler)
    let deprecated_count = sqlx::query_scalar::<_, i64>(
        r#"
        UPDATE service_versions 
        SET 
            deprecated_at = NOW(),
            deprecated_by = 'manual',
            deprecated_reason = 'Superseded by newer version created manually'
        WHERE 
            service_definition_id = $1 
            AND namespace_id = $2 
            AND deprecated_at IS NULL
            AND pinned_at IS NULL
            AND git_sha != $3
        RETURNING 1
        "#,
    )
    .bind(data.service_definition_id)
    .bind(data.namespace_id)
    .bind(&data.git_sha)
    .fetch_all(&mut *tx)
    .await
    .map(|rows| rows.len() as i64)
    .unwrap_or(0);

    if deprecated_count > 0 {
        tracing::info!(
            "Manual version: Deprecated {} old version(s) for service_definition_id={} namespace_id={}",
            deprecated_count,
            data.service_definition_id,
            data.namespace_id
        );
    }

    // Step 2: Check if this exact version already exists (active)
    let existing_version = sqlx::query_as::<_, ServiceVersionData>(
        r#"
        SELECT
            id,
            created_at,
            updated_at,
            service_definition_id,
            namespace_id,
            version,
            git_sha,
            git_sha_short,
            path,
            hash,
            source,
            source_metadata,
            deprecated_at,
            deprecated_by,
            deprecated_reason
        FROM service_versions 
        WHERE service_definition_id = $1 
        AND namespace_id = $2 
        AND git_sha = $3
        AND deprecated_at IS NULL
        "#,
    )
    .bind(data.service_definition_id)
    .bind(data.namespace_id)
    .bind(&data.git_sha)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_service_version"))?;

    // If same SHA already exists and is active, return it (idempotent)
    if let Some(existing) = existing_version {
        tracing::info!(
            "Manual version: Version with git_sha {} already exists, returning existing",
            &data.git_sha[..7]
        );
        tx.commit()
            .await
            .map_err(|e| sanitize_db_error(e, "post_service_version_commit"))?;
        return Ok((StatusCode::OK, Json(existing)));
    }

    // Step 3: Insert the new version
    let result = sqlx::query_as::<_, ServiceVersionData>(
        r#"
        INSERT INTO service_versions (
            service_definition_id,
            namespace_id,
            version,
            git_sha,
            git_sha_short,
            path,
            hash,
            source,
            source_metadata,
            tenant_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING
            id,
            created_at,
            updated_at,
            service_definition_id,
            namespace_id,
            version,
            git_sha,
            git_sha_short,
            path,
            hash,
            source,
            source_metadata,
            deprecated_at,
            deprecated_by,
            deprecated_reason
        "#,
    )
    .bind(data.service_definition_id)
    .bind(data.namespace_id)
    .bind(&data.version)
    .bind(&data.git_sha)
    .bind(&git_sha_short)
    .bind(&data.path)
    .bind(&data.hash)
    .bind(&data.source)
    .bind(&data.source_metadata)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_service_version"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_service_version_commit"))?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Deprecate a service version
#[utoipa::path(
    post,
    path = "/api/service-versions/{id}/deprecate",
    params(
        ("id" = Uuid, Path, description = "Service Version UUID"),
    ),
    request_body = types::DeprecateServiceVersion,
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Service version deprecated successfully", body = types::ServiceVersionData),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_deprecate_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(data): Json<DeprecateServiceVersion>,
) -> Result<Json<ServiceVersionData>, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_deprecate_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let result = sqlx::query_as::<_, ServiceVersionData>(
        r#"
        UPDATE service_versions
        SET
            deprecated_at = NOW(),
            deprecated_by = $2,
            deprecated_reason = $3,
            updated_at = NOW()
        WHERE id = $1
        RETURNING
            id,
            created_at,
            updated_at,
            service_definition_id,
            namespace_id,
            version,
            git_sha,
            git_sha_short,
            path,
            hash,
            source,
            source_metadata,
            deprecated_at,
            deprecated_by,
            deprecated_reason
        "#,
    )
    .bind(id)
    .bind(&data.deprecated_by)
    .bind(&data.deprecated_reason)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_deprecate_service_version"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_deprecate_service_version_commit"))?;

    Ok(Json(result))
}

/// Pin a service version to protect it from automatic deprecation
/// Pinned versions will not be deprecated when new versions arrive via webhook
#[utoipa::path(
    post,
    path = "/api/service-versions/{id}/pin",
    params(
        ("id" = Uuid, Path, description = "Service Version UUID"),
    ),
    request_body(content = Option<types::PinServiceVersion>, description = "Optional pin details"),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Service version pinned successfully"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_pin_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    body: Option<Json<PinServiceVersion>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_pin_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let pinned_by = body.and_then(|b| b.pinned_by.clone());
    let result = sqlx::query(
        r#"
        UPDATE service_versions
        SET pinned_at = NOW(), pinned_by = $2, updated_at = NOW()
        WHERE id = $1 AND deprecated_at IS NULL
        "#,
    )
    .bind(id)
    .bind(&pinned_by)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_pin_service_version"))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Service version not found or already deprecated".to_string(),
        ));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_pin_service_version_commit"))?;

    Ok(StatusCode::OK)
}

/// Unpin a service version, allowing it to be automatically deprecated
#[utoipa::path(
    post,
    path = "/api/service-versions/{id}/unpin",
    params(
        ("id" = Uuid, Path, description = "Service Version UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Service version unpinned successfully"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn post_unpin_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "post_unpin_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let result = sqlx::query(
        r#"
        UPDATE service_versions
        SET pinned_at = NULL, pinned_by = NULL, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "post_unpin_service_version"))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Service version not found".to_string(),
        ));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "post_unpin_service_version_commit"))?;

    Ok(StatusCode::OK)
}

/// Delete a service version
#[utoipa::path(
    delete,
    path = "/api/service-versions/{id}",
    params(
        ("id" = Uuid, Path, description = "Service Version UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 204, description = "Service version deleted successfully"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn delete_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_version_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    let result = sqlx::query(
        r#"
        DELETE FROM service_versions WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_service_version"))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Service version not found".to_string(),
        ));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_service_version_commit"))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get a single service version by ID
#[utoipa::path(
    get,
    path = "/api/service-versions/{id}",
    params(
        ("id" = Uuid, Path, description = "Service Version UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns the service version", body = types::ServiceVersionWithDetails),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service version not found"),
        (status = 500, description = "Fails on db connection issues"),
    )
)]
pub async fn get_service_version(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ServiceVersionWithDetails>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, ServiceVersionWithDetails>(
        r#"
        SELECT
            sv.id,
            sv.created_at,
            sv.updated_at,
            sv.service_definition_id,
            sd.name AS service_name,
            sv.namespace_id,
            n.name AS namespace_name,
            c.name AS cluster_name,
            sv.version,
            sv.git_sha,
            sv.git_sha_short,
            sv.path,
            sv.hash,
            repos.org,
            repos.repo,
            repos.provider AS provider,
            repos.host AS host,
            repos.web_base_url AS web_base_url,
            rb.branch,
            sv.source,
            sv.deprecated_at
        FROM
            service_versions sv
            JOIN service_definitions sd ON sd.id = sv.service_definition_id
            JOIN repo_branches rb ON rb.id = sd.repo_branch_id
            JOIN repos ON repos.id = rb.repo_id
            JOIN namespaces n ON n.id = sv.namespace_id
            JOIN clusters c ON c.id = n.cluster_id
        WHERE
            sv.id = $1
        "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_service_version"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_service_version_commit"))?;
    Ok(Json(result))
}

// ============================================================================
// GitHub Webhook Handlers
// ============================================================================

/// Validate a manifest path template
/// Ensures it contains {service}, {cluster}, and {namespace} placeholders
fn validate_path_template(template: &str) -> PathTemplateValidation {
    let has_service = template.contains("{service}");
    let has_cluster = template.contains("{cluster}");
    let has_namespace = template.contains("{namespace}");

    let valid = has_service && has_cluster && has_namespace;

    let error = if !valid {
        let mut missing = Vec::new();
        if !has_service {
            missing.push("{service}");
        }
        if !has_cluster {
            missing.push("{cluster}");
        }
        if !has_namespace {
            missing.push("{namespace}");
        }
        Some(format!(
            "Missing required placeholders: {}",
            missing.join(", ")
        ))
    } else {
        None
    };

    let example_path = if valid {
        Some(
            template
                .replace("{service}", "my-service")
                .replace("{cluster}", "prod-east")
                .replace("{namespace}", "default"),
        )
    } else {
        None
    };

    PathTemplateValidation {
        valid,
        has_service,
        has_cluster,
        has_namespace,
        error,
        example_path,
    }
}

/// Update a service definition's manifest path template
#[utoipa::path(
    put,
    path = "/api/service-definitions/{id}/manifest-path",
    request_body = types::UpdateManifestPathTemplate,
    params(
        ("id" = Uuid, Path, description = "Service Definition UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Manifest path template updated", body = types::PathTemplateValidation),
        (status = 400, description = "Invalid path template - missing required placeholders"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service definition not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn update_manifest_path_template(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateManifestPathTemplate>,
) -> Result<Json<PathTemplateValidation>, (StatusCode, String)> {
    // Validate the template
    let validation = validate_path_template(&body.manifest_path_template);

    if !validation.valid {
        return Err((
            StatusCode::BAD_REQUEST,
            validation
                .error
                .unwrap_or_else(|| "Invalid path template".to_string()),
        ));
    }

    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "update_manifest_path_template_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Update the service definition
    let result = sqlx::query(
        r#"
        UPDATE service_definitions
        SET manifest_path_template = $1, updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(&body.manifest_path_template)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "update_manifest_path_template"))?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            "Service definition not found".to_string(),
        ));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "update_manifest_path_template_commit"))?;

    Ok(Json(validation))
}

/// Get the manifest path template for a service definition
#[utoipa::path(
    get,
    path = "/api/service-definitions/{id}/manifest-path",
    params(
        ("id" = Uuid, Path, description = "Service Definition UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns the manifest path template", body = Option<String>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Service definition not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn get_manifest_path_template(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Option<String>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_scalar::<_, Option<String>>(
        r#"
        SELECT manifest_path_template
        FROM service_definitions
        WHERE id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_manifest_path_template"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_manifest_path_template_commit"))?;
    Ok(Json(result))
}

/// Validate a path template without saving it
#[utoipa::path(
    post,
    path = "/api/validate-path-template",
    request_body = types::UpdateManifestPathTemplate,
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Path template validation result", body = types::PathTemplateValidation),
        (status = 401, description = "Access token is missing or invalid"),
    )
)]
pub async fn validate_path_template_endpoint(
    Json(body): Json<UpdateManifestPathTemplate>,
) -> Result<Json<PathTemplateValidation>, (StatusCode, String)> {
    Ok(Json(validate_path_template(&body.manifest_path_template)))
}

/// Get the webhook for a repo
#[utoipa::path(
    get,
    path = "/api/repos/{id}/webhook",
    params(
        ("id" = Uuid, Path, description = "Repo UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns the webhook data", body = Option<types::RepoWebhookData>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn get_repo_webhook(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(repo_id): Path<Uuid>,
) -> Result<Json<Option<RepoWebhookData>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let result = sqlx::query_as::<_, RepoWebhookData>(
        r#"
        SELECT 
            gw.id,
            gw.created_at,
            gw.updated_at,
            gw.repo_id,
            r.org,
            r.repo,
            gw.provider_webhook_id,
            gw.active,
            gw.last_delivery_at,
            gw.last_error
        FROM repo_webhooks gw
        JOIN repos r ON r.id = gw.repo_id
        WHERE gw.repo_id = $1 AND gw.deleted_at IS NULL
        "#,
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_repo_webhook"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_repo_webhook_commit"))?;
    Ok(Json(result))
}

/// Register a GitHub webhook for a repo
/// This creates a webhook on GitHub and stores the registration locally
#[utoipa::path(
    post,
    path = "/api/repos/{id}/webhook",
    request_body = types::RegisterRepoWebhookRequest,
    params(
        ("id" = Uuid, Path, description = "Repo UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Webhook registered successfully", body = types::RegisterRepoWebhookResponse),
        (status = 400, description = "Failed to create webhook on GitHub"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Repo not found"),
        (status = 409, description = "Webhook already exists for this repo"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn register_repo_webhook(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(repo_id): Path<Uuid>,
    Json(body): Json<RegisterRepoWebhookRequest>,
) -> Result<Json<RegisterRepoWebhookResponse>, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "register_repo_webhook_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Get the repo info
    let repo = sqlx::query_as::<_, RepoData>(
        r#"
        SELECT
            id,
            provider,
            host,
            web_base_url,
            api_base_url,
            org,
            repo
        FROM repos
        WHERE id = $1
        "#,
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "register_repo_webhook"))?
    .ok_or((StatusCode::NOT_FOUND, "Repo not found".to_string()))?;

    if repo.provider != RepoProvider::Github {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Webhook registration is only supported for GitHub repos".to_string(),
        ));
    }

    // Check if a webhook row already exists.
    // NOTE: The schema enforces UNIQUE(repo_id), so soft-deleted rows must be re-used.
    let existing = sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<chrono::Utc>>)>(
        r#"SELECT id, deleted_at FROM repo_webhooks WHERE repo_id = $1"#,
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "register_repo_webhook"))?;

    if let Some((_id, deleted_at)) = &existing {
        if deleted_at.is_none() {
            return Err((
                StatusCode::CONFLICT,
                "Webhook already exists for this repo".to_string(),
            ));
        }
    }

    // Generate a secret for webhook signature validation
    let webhook_secret = util::generate_random_string(32);
    let webhook_secret_hash = util::hash_string(&webhook_secret);

    // Build the callback URL
    // Must be explicitly configured so it's externally reachable by GitHub.
    let base_callback_url = state.github_webhook_callback_url.clone().ok_or((
        StatusCode::UNPROCESSABLE_ENTITY,
        "GITHUB_WEBHOOK_CALLBACK_URL is not configured on the server".to_string(),
    ))?;

    // Make webhook routing unambiguous across hosts/org/repo by embedding repo_id.
    // Query params do not affect the Axum route match.
    let callback_url = format!("{}?repo_id={}", base_callback_url, repo_id);

    // Create webhook on GitHub
    let api_base_url = repo.api_base_url.trim_end_matches('/');
    let client = Client::new();
    let github_response = client
        .post(format!(
            "{}/repos/{}/{}/hooks",
            api_base_url, repo.org, repo.repo
        ))
        .header("Authorization", format!("Bearer {}", body.github_token))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "beecd-hive-hq")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .json(&json!({
            "name": "web",
            "active": true,
            "events": ["push"],
            "config": {
                "url": callback_url,
                "content_type": "json",
                "secret": webhook_secret,
                "insecure_ssl": "0"
            }
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to call GitHub API: {:?}", e);
            (
                StatusCode::BAD_REQUEST,
                format!("Failed to create webhook on GitHub: {}", e),
            )
        })?;

    if !github_response.status().is_success() {
        let status = github_response.status();
        let error_body = github_response.text().await.unwrap_or_default();
        tracing::error!("GitHub API error: {} - {}", status, error_body);
        return Err((
            StatusCode::BAD_REQUEST,
            format!("GitHub API error ({}): {}", status, error_body),
        ));
    }

    let github_hook: serde_json::Value = github_response.json().await.map_err(|e| {
        tracing::error!("Failed to parse GitHub response: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to parse GitHub response".to_string(),
        )
    })?;

    let provider_webhook_id = github_hook["id"].as_i64().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "GitHub did not return webhook ID".to_string(),
    ))?;

    // Store webhook in database.
    // If there is a soft-deleted row, reactivate it instead of inserting (avoids UNIQUE(repo_id) violations).
    let webhook_id = if existing.is_some() {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            UPDATE repo_webhooks
            SET provider_webhook_id = $2,
                secret = $3,
                secret_hash = $4,
                active = true,
                deleted_at = NULL,
                updated_at = NOW(),
                last_error = NULL
            WHERE repo_id = $1
            RETURNING id
            "#,
        )
        .bind(repo_id)
        .bind(provider_webhook_id)
        .bind(&webhook_secret)
        .bind(&webhook_secret_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "register_repo_webhook"))?
    } else {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO repo_webhooks (repo_id, provider_webhook_id, secret, secret_hash, active, tenant_id)
            VALUES ($1, $2, $3, $4, true, $5)
            RETURNING id
            "#,
        )
        .bind(repo_id)
        .bind(provider_webhook_id)
        .bind(&webhook_secret)
        .bind(&webhook_secret_hash)
        .bind(tenant_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "register_repo_webhook"))?
    };

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "register_repo_webhook_commit"))?;

    Ok(Json(RegisterRepoWebhookResponse {
        webhook_id,
        provider_webhook_id,
        callback_url,
        message: format!(
            "Webhook registered for {}/{}. Push events will now update service versions.",
            repo.org, repo.repo
        ),
    }))
}

/// Delete a GitHub webhook
#[utoipa::path(
    delete,
    path = "/api/repos/{id}/webhook",
    params(
        ("id" = Uuid, Path, description = "Repo UUID"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Webhook deleted"),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Webhook not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn delete_repo_webhook(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(repo_id): Path<Uuid>,
    body: Option<Json<types::DeleteRepoWebhookRequest>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let tenant_id = extract_tenant_from_request(&state.pool, &headers).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_repo_webhook_begin"))?;

    set_tenant_context(&mut tx, tenant_id).await?;

    // Load webhook + repo info so we can optionally delete the remote GitHub hook.
    let webhook = sqlx::query_as::<_, (Option<i64>, String, String, String)>(
        r#"
        SELECT
            w.provider_webhook_id,
            r.org,
            r.repo,
            r.api_base_url
        FROM repo_webhooks w
        JOIN repos r ON r.id = w.repo_id
        WHERE w.repo_id = $1 AND w.deleted_at IS NULL
        "#,
    )
    .bind(repo_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_repo_webhook"))?
    .ok_or((StatusCode::NOT_FOUND, "Webhook not found".to_string()))?;

    let (provider_webhook_id, org, repo, api_base_url) = webhook;

    let github_token = body.and_then(|Json(b)| b.github_token).and_then(|t| {
        let trimmed = t.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });

    // If the user provided a token, attempt to delete the webhook on GitHub.
    // If that fails, return an error and do not soft-delete locally.
    if let Some(token) = github_token {
        let hook_id = provider_webhook_id.ok_or((
            StatusCode::BAD_REQUEST,
            "Webhook is missing provider_webhook_id; cannot delete on GitHub".to_string(),
        ))?;

        let api_base_url = api_base_url.trim_end_matches('/');
        let client = Client::new();
        let resp = client
            .delete(format!(
                "{}/repos/{}/{}/hooks/{}",
                api_base_url, org, repo, hook_id
            ))
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "beecd-hive-hq")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to call GitHub API (delete hook): {:?}", e);
                (
                    StatusCode::BAD_REQUEST,
                    format!("Failed to delete webhook on GitHub: {}", e),
                )
            })?;

        // GitHub responds 204 No Content on success.
        if !resp.status().is_success() {
            let status = resp.status();
            let error_body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "GitHub API error deleting webhook: {} - {}",
                status,
                error_body
            );
            return Err((
                StatusCode::BAD_REQUEST,
                format!("GitHub API error ({}): {}", status, error_body),
            ));
        }
    }

    let result = sqlx::query(
        r#"
        UPDATE repo_webhooks
        SET deleted_at = NOW(), active = false
        WHERE repo_id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(repo_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "delete_repo_webhook"))?;

    // rows_affected should be 1 because we already validated existence above.
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Webhook not found".to_string()));
    }

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "delete_repo_webhook_commit"))?;

    Ok(StatusCode::OK)
}

/// Receive GitHub webhook events (push events)
/// This endpoint is called by GitHub when push events occur
/// It does NOT require authentication - instead validates via HMAC signature
/// Note: Not included in OpenAPI spec because it uses raw bytes for signature validation
pub async fn receive_github_webhook(
    State(state): State<ServerState>,
    Query(params): Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Get required headers
    let signature = headers
        .get("X-Hub-Signature-256")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing signature header".to_string(),
        ))?;

    let delivery_id = headers
        .get("X-GitHub-Delivery")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing delivery ID header".to_string(),
        ))?;

    let event_type = headers
        .get("X-GitHub-Event")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Missing event type header".to_string(),
        ))?;

    // Handle ping events (sent when webhook is first registered)
    if event_type == "ping" {
        tracing::info!("Received ping webhook event");
        return Ok(Json(json!({ "status": "pong" })));
    }

    // Only process push events
    if event_type != "push" {
        tracing::info!("Ignoring non-push event: {}", event_type);
        return Ok(Json(
            json!({ "status": "ignored", "reason": "not a push event" }),
        ));
    }

    // Parse the payload to get repo info for signature validation
    let payload: GitHubPushEvent = serde_json::from_slice(&body).map_err(|e| {
        tracing::error!("Failed to parse webhook payload: {:?}", e);
        (
            StatusCode::BAD_REQUEST,
            "Invalid webhook payload".to_string(),
        )
    })?;

    let org = &payload.repository.owner.login;
    let repo_name = &payload.repository.name;

    let repo_id = params.get("repo_id").and_then(|v| Uuid::parse_str(v).ok());

    // Find the webhook and its secret.
    // Prefer repo_id from callback URL query param; fall back to org/repo lookup.
    let webhook_info = if let Some(repo_id) = repo_id {
        sqlx::query_as::<_, (Uuid, Uuid, Option<String>, Uuid)>(
            r#"
            SELECT gw.id, gw.repo_id, gw.secret, gw.tenant_id
            FROM repo_webhooks gw
            WHERE gw.repo_id = $1
            AND gw.deleted_at IS NULL AND gw.active = true
            "#,
        )
        .bind(repo_id)
        .fetch_optional(&state.readonly_pool)
        .await
        .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?
    } else {
        sqlx::query_as::<_, (Uuid, Uuid, Option<String>, Uuid)>(
            r#"
            SELECT gw.id, gw.repo_id, gw.secret, gw.tenant_id
            FROM repo_webhooks gw
            JOIN repos r ON r.id = gw.repo_id
            WHERE LOWER(r.org) = LOWER($1) AND LOWER(r.repo) = LOWER($2)
            AND gw.deleted_at IS NULL AND gw.active = true
            "#,
        )
        .bind(org)
        .bind(repo_name)
        .fetch_optional(&state.readonly_pool)
        .await
        .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?
    }
    .ok_or((
        StatusCode::BAD_REQUEST,
        "No webhook registered for this repo".to_string(),
    ))?;

    let (webhook_id, _repo_id, webhook_secret, tenant_id) = webhook_info;
    let webhook_secret = webhook_secret.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Webhook secret is not configured for this repo".to_string(),
    ))?;

    let ok = verify_github_hmac_sha256(signature, &webhook_secret, &body)
        .map_err(|msg| (StatusCode::BAD_REQUEST, msg))?;
    if !ok {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid webhook signature".to_string(),
        ));
    }

    // Get branch name
    let branch = match payload.branch_name() {
        Some(b) => b.to_string(),
        None => {
            tracing::info!("Ignoring non-branch push: {}", payload.ref_name);
            return Ok(Json(
                json!({ "status": "ignored", "reason": "not a branch push" }),
            ));
        }
    };

    // Get all changed files
    let changed_files = payload.all_changed_files();

    if changed_files.is_empty() {
        return Ok(Json(
            json!({ "status": "ok", "reason": "no files changed" }),
        ));
    }

    // Start transaction and set tenant context for all subsequent queries
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| sanitize_db_error(e, "receive_github_webhook_begin"))?;
    set_tenant_context(&mut tx, tenant_id).await?;

    // Create webhook event record
    let event_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO repo_webhook_events 
        (webhook_id, delivery_id, event_type, ref, before_sha, after_sha, pusher, tenant_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
    )
    .bind(webhook_id)
    .bind(delivery_id)
    .bind(event_type)
    .bind(&payload.ref_name)
    .bind(&payload.before)
    .bind(&payload.after)
    .bind(&payload.pusher.name)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

    // Find service definitions that match the changed files
    // Query service definitions with manifest_path_template for this repo/branch
    let service_defs = sqlx::query_as::<_, (Uuid, String, String)>(
        r#"
        SELECT sd.id, sd.name, sd.manifest_path_template
        FROM service_definitions sd
        JOIN repo_branches rb ON rb.id = sd.repo_branch_id
        JOIN repos r ON r.id = rb.repo_id
        WHERE LOWER(r.org) = LOWER($1) 
        AND LOWER(r.repo) = LOWER($2)
        AND rb.branch = $3
        AND sd.manifest_path_template IS NOT NULL
        AND sd.deleted_at IS NULL
        "#,
    )
    .bind(org)
    .bind(repo_name)
    .bind(&branch)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

    let mut matched_paths = Vec::new();
    let mut updated_versions = Vec::new();

    tracing::info!(
        "Webhook: Found {} service definitions for {}/{} branch {}",
        service_defs.len(),
        org,
        repo_name,
        branch
    );
    tracing::info!("Webhook: Changed files: {:?}", changed_files);

    // Phase 1: Collect all matches and deduplicate by (service_def_id, namespace_id)
    // This prevents creating duplicate service_versions when multiple files in a directory change
    #[derive(Debug, Clone)]
    struct VersionMatch {
        service_name: String,
        path_template: String,
        cluster_name: String,
        namespace_name: String,
        placeholder_matches: HashMap<String, String>,
        matched_files: Vec<String>,
    }

    // Key for deduplication: (service_def_id, namespace_id)
    let mut version_matches: HashMap<(Uuid, Uuid), VersionMatch> = HashMap::new();

    for (service_def_id, service_name, path_template) in &service_defs {
        tracing::debug!(
            "Webhook: Checking service '{}' with template '{}'",
            service_name,
            path_template
        );
        for file_path in &changed_files {
            tracing::debug!(
                "Webhook: Trying to match '{}' against template '{}'",
                file_path,
                path_template
            );
            // Try to match the file path against the template
            if let Some(matches) = match_path_template_rust(path_template, file_path) {
                tracing::info!(
                    "Webhook: File '{}' matched template! Extracted: {:?}",
                    file_path,
                    matches
                );
                // Check if the extracted service name matches this service definition
                if let Some(extracted_service) = matches.get("service") {
                    if extracted_service == service_name {
                        matched_paths.push(file_path.clone());

                        // Get the cluster and namespace from the match
                        let cluster_name = matches.get("cluster").map(|s| s.as_str());
                        let namespace_name = matches.get("namespace").map(|s| s.as_str());

                        if let (Some(cluster), Some(namespace)) = (cluster_name, namespace_name) {
                            // Find the namespace_id for this cluster/namespace combo
                            let namespace_id = sqlx::query_scalar::<_, Uuid>(
                                r#"
                                SELECT n.id 
                                FROM namespaces n
                                JOIN clusters c ON c.id = n.cluster_id
                                WHERE n.name = $1 AND c.name = $2 AND n.deleted_at IS NULL
                                "#,
                            )
                            .bind(namespace)
                            .bind(cluster)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

                            if let Some(ns_id) = namespace_id {
                                // Deduplicate: group by (service_def_id, namespace_id)
                                let key = (*service_def_id, ns_id);
                                version_matches
                                    .entry(key)
                                    .and_modify(|existing| {
                                        // Add this file to the matched files list
                                        if !existing.matched_files.contains(file_path) {
                                            existing.matched_files.push(file_path.clone());
                                        }
                                    })
                                    .or_insert_with(|| VersionMatch {
                                        service_name: service_name.clone(),
                                        path_template: path_template.clone(),
                                        cluster_name: cluster.to_string(),
                                        namespace_name: namespace.to_string(),
                                        placeholder_matches: matches.clone(),
                                        matched_files: vec![file_path.clone()],
                                    });
                            } else {
                                tracing::warn!(
                                    "Webhook: Namespace '{}/{}' not found in database for service '{}'",
                                    cluster,
                                    namespace,
                                    service_name
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            "Webhook: Extracted service '{}' doesn't match service definition '{}'",
                            extracted_service,
                            service_name
                        );
                    }
                }
            } else {
                tracing::debug!(
                    "Webhook: File '{}' did NOT match template '{}'",
                    file_path,
                    path_template
                );
            }
        }
    }

    tracing::info!(
        "Webhook: Found {} unique service/namespace combinations from {} matched files",
        version_matches.len(),
        matched_paths.len()
    );

    // Phase 2: Create/update service_versions for each unique combination
    for ((service_def_id, ns_id), version_match) in version_matches {
        // Compute the path pattern from the template
        let (path_pattern, is_directory) = compute_manifest_path_pattern(
            &version_match.path_template,
            &version_match.placeholder_matches,
        );

        tracing::info!(
            "Webhook: Processing {}/{} - path_pattern='{}', is_directory={}, matched_files={:?}",
            version_match.service_name,
            version_match.namespace_name,
            path_pattern,
            is_directory,
            version_match.matched_files
        );

        // Step 1: Check if there's an existing active version that is NOT pinned
        // If it exists and is not pinned, deprecate it
        let deprecated_count = sqlx::query_scalar::<_, i64>(
            r#"
            UPDATE service_versions 
            SET 
                deprecated_at = NOW(),
                deprecated_by = 'webhook',
                deprecated_reason = 'Superseded by newer version from git push'
            WHERE 
                service_definition_id = $1 
                AND namespace_id = $2 
                AND deprecated_at IS NULL
                AND pinned_at IS NULL  -- Don't deprecate pinned versions
                AND git_sha != $3      -- Don't deprecate if same SHA (idempotent)
            RETURNING 1
            "#,
        )
        .bind(service_def_id)
        .bind(ns_id)
        .bind(&payload.after)
        .fetch_all(&mut *tx)
        .await
        .map(|rows| rows.len() as i64)
        .unwrap_or(0);

        if deprecated_count > 0 {
            tracing::info!(
                "Webhook: Deprecated {} old version(s) for {}/{} in {}/{}",
                deprecated_count,
                version_match.service_name,
                payload.after[..7].to_string(),
                version_match.cluster_name,
                version_match.namespace_name
            );
        }

        // Step 2: Check if this exact version already exists (active)
        let existing_version = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id FROM service_versions 
            WHERE service_definition_id = $1 
            AND namespace_id = $2 
            AND git_sha = $3
            AND deprecated_at IS NULL
            "#,
        )
        .bind(service_def_id)
        .bind(ns_id)
        .bind(&payload.after)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

        let version_id = if let Some(existing_id) = existing_version {
            // Version already exists and is active, update path pattern and webhook_event_id
            sqlx::query(
                r#"
                UPDATE service_versions 
                SET path = $1, is_directory_pattern = $2, updated_at = NOW(), webhook_event_id = $3
                WHERE id = $4
                "#,
            )
            .bind(&path_pattern)
            .bind(is_directory)
            .bind(event_id)
            .bind(existing_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

            tracing::info!(
                "Webhook: Version {} already exists for {}, updated path pattern",
                &payload.after[..7],
                version_match.service_name
            );
            existing_id
        } else {
            // Step 3: Insert new service version with new UUID
            sqlx::query_scalar::<_, Uuid>(
                r#"
                INSERT INTO service_versions 
                (service_definition_id, namespace_id, version, git_sha, git_sha_short, path, is_directory_pattern, hash, source, webhook_event_id, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'webhook', $9, $10)
                RETURNING id
                "#,
            )
            .bind(service_def_id)
            .bind(ns_id)
            .bind(&payload.after[..7]) // Use short SHA as version
            .bind(&payload.after)
            .bind(&payload.after[..7])
            .bind(&path_pattern)
            .bind(is_directory)
            .bind("pending") // Hash will be computed later when manifests are fetched
            .bind(event_id)
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?
        };

        updated_versions.push(version_id);

        tracing::info!(
            "Webhook: Created/updated service version {} for {}/{} in {}/{} (path_pattern={}, is_directory={})",
            version_id,
            version_match.service_name,
            payload.after[..7].to_string(),
            version_match.cluster_name,
            version_match.namespace_name,
            path_pattern,
            is_directory
        );
    }

    // Update webhook event with results
    sqlx::query(
        r#"
        UPDATE repo_webhook_events
        SET processed_at = NOW(), matched_paths = $1, updated_service_versions = $2
        WHERE id = $3
        "#,
    )
    .bind(&matched_paths)
    .bind(&updated_versions)
    .bind(event_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

    // Update webhook last delivery timestamp
    sqlx::query(
        r#"
        UPDATE repo_webhooks SET last_delivery_at = NOW() WHERE id = $1
        "#,
    )
    .bind(webhook_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "receive_github_webhook"))?;

    // Commit the transaction
    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "receive_github_webhook_commit"))?;

    Ok(Json(json!({
        "status": "ok",
        "event_id": event_id,
        "matched_paths": matched_paths,
        "updated_versions": updated_versions.len()
    })))
}

/// Check if a path template is a directory template (doesn't end with file extension)
fn is_directory_template(template: &str) -> bool {
    let template = template.trim().trim_end_matches('/');
    !template.ends_with(".yaml") && !template.ends_with(".yml") && !template.ends_with(".json")
}

/// Compute the manifest path pattern from a template and extracted placeholder values.
///
/// For file templates (ending in .yaml/.yml/.json): returns the exact file path
/// For directory templates: returns a glob pattern like "cluster/ns/svc/*.yaml"
///
/// # Arguments
/// * `template` - The path template with placeholders (e.g., "{cluster}/manifests/{namespace}/{service}")
/// * `matches` - The extracted placeholder values from match_path_template_rust
///
/// # Returns
/// A tuple of (path_pattern, is_directory_pattern)
///
/// # Examples
/// - Template: `{cluster}/manifests/{namespace}/{service}/{service}.yaml`
///   Matches: {cluster: "prod", namespace: "default", service: "nginx"}
///   Returns: ("prod/manifests/default/nginx/nginx.yaml", false)
///
/// - Template: `{cluster}/manifests/{namespace}/{service}`
///   Matches: {cluster: "prod", namespace: "default", service: "nginx"}
///   Returns: ("prod/manifests/default/nginx/*.yaml", true)
///
/// - Template: `{cluster}/manifests/{namespace}/{service}/{namespace}-{service}-`
///   Matches: {cluster: "prod", namespace: "default", service: "nginx"}
///   Returns: ("prod/manifests/default/nginx/default-nginx-*.yaml", true)
fn compute_manifest_path_pattern(
    template: &str,
    matches: &HashMap<String, String>,
) -> (String, bool) {
    let template = template.trim().trim_end_matches('/');
    let is_dir = is_directory_template(template);

    // Replace all placeholders with their matched values
    let mut path = template.to_string();
    for (key, value) in matches {
        path = path.replace(&format!("{{{}}}", key), value);
    }

    if is_dir {
        // For directory templates, append the glob pattern
        // Check if the last part of the template has a prefix pattern (like {namespace}-{service}-)
        // A "prefix pattern" means there's literal text mixed with placeholders, not just a pure placeholder
        let last_part = template.split('/').next_back().unwrap_or("");

        // Check if last_part is a pure placeholder like {service} or has literal characters
        // Pure placeholders represent directories, mixed patterns represent file prefixes
        let is_pure_placeholder = last_part.starts_with('{')
            && last_part.ends_with('}')
            && last_part.matches('{').count() == 1;

        if !is_pure_placeholder && last_part.contains('{') {
            // The last segment has placeholders mixed with literals - it's a prefix pattern
            // e.g., "{namespace}-{service}-" -> "default-nginx-*.yaml"
            (format!("{}*.yaml", path), true)
        } else {
            // Pure directory (either pure placeholder like {service} or no placeholders)
            // Glob all yaml files in the directory
            (format!("{}/*.yaml", path), true)
        }
    } else {
        // File template - return exact path
        (path, false)
    }
}

/// Match a file path against a template and extract placeholder values.
/// Returns None if the path doesn't match, or a HashMap of extracted values.
///
/// Handles:
/// - Pure placeholders: `{service}` matches entire path segment
/// - Embedded placeholders: `{service}.yaml` matches `my-service.yaml`
/// - Multiple same placeholders: `{service}/{service}.yaml` requires both to match
///
/// When the same placeholder appears multiple times, ALL occurrences must have the same value.
fn match_path_template_rust(template: &str, file_path: &str) -> Option<HashMap<String, String>> {
    // Trim whitespace/newlines from template (in case it was stored with extra chars)
    let template = template.trim();
    // Also trim trailing slash if present (normalize directory templates)
    let template = template.trim_end_matches('/');

    // Check if template is a directory pattern (doesn't end with .yaml or .yml)
    let is_directory_template = !template.ends_with(".yaml") && !template.ends_with(".yml");

    let template_parts: Vec<&str> = template.split('/').collect();
    let file_parts: Vec<&str> = file_path.split('/').collect();

    // For directory templates, file path must have MORE parts (at least one file in the dir)
    // For file templates, file path must have EXACTLY as many parts as template
    if is_directory_template {
        // Directory template: file path should have at least one more segment (the filename)
        if file_parts.len() <= template_parts.len() {
            return None;
        }
    } else {
        // File template: must match exactly
        if file_parts.len() != template_parts.len() {
            return None;
        }
    }

    let mut result = HashMap::new();

    // Regex to find placeholders like {name}
    let placeholder_re = regex::Regex::new(r"\{([^}]+)\}").ok()?;

    for (i, template_part) in template_parts.iter().enumerate() {
        let file_part = file_parts[i];

        // Find all placeholders in this template part
        let placeholders: Vec<&str> = placeholder_re
            .captures_iter(template_part)
            .filter_map(|cap| cap.get(1).map(|m| m.as_str()))
            .collect();

        if placeholders.is_empty() {
            // No placeholders - must be exact match
            if *template_part != file_part {
                return None;
            }
        } else if placeholders.len() == 1 && *template_part == format!("{{{}}}", placeholders[0]) {
            // Pure placeholder like {service} - matches entire segment
            let placeholder_name = placeholders[0];
            let value = file_part.to_string();

            // Check for consistency with previous captures
            if let Some(existing) = result.get(placeholder_name) {
                if existing != &value {
                    return None; // Same placeholder must have same value
                }
            } else {
                result.insert(placeholder_name.to_string(), value);
            }
        } else {
            // Embedded placeholder(s) like {service}.yaml or app-{name}-{version}.yaml
            // Convert template part to regex pattern
            let mut pattern = String::from("^");
            let mut last_end = 0;

            for cap in placeholder_re.captures_iter(template_part) {
                let full_match = cap.get(0).unwrap();
                let placeholder_name = cap.get(1).unwrap().as_str();

                // Escape literal text before this placeholder
                let literal_before = &template_part[last_end..full_match.start()];
                pattern.push_str(&regex::escape(literal_before));

                // Add named capture group for placeholder
                // Use .+? for non-greedy matching, but ensure at least one char
                pattern.push_str(&format!("(?P<{}>[^/]+?)", placeholder_name));

                last_end = full_match.end();
            }

            // Escape any remaining literal text after last placeholder
            let literal_after = &template_part[last_end..];
            pattern.push_str(&regex::escape(literal_after));
            pattern.push('$');

            // Try to match the pattern
            let re = match regex::Regex::new(&pattern) {
                Ok(re) => re,
                Err(_) => return None,
            };

            let captures = re.captures(file_part)?;

            // Extract all placeholder values and check consistency
            for placeholder_name in &placeholders {
                if let Some(m) = captures.name(placeholder_name) {
                    let value = m.as_str().to_string();

                    // Check for consistency with previous captures
                    if let Some(existing) = result.get(*placeholder_name) {
                        if existing != &value {
                            return None; // Same placeholder must have same value
                        }
                    } else {
                        result.insert(placeholder_name.to_string(), value);
                    }
                }
            }
        }
    }

    // Verify all required placeholders are present
    if result.contains_key("service")
        && result.contains_key("cluster")
        && result.contains_key("namespace")
    {
        Some(result)
    } else {
        None
    }
}

#[cfg(test)]
mod path_template_tests {
    use super::*;

    // =========================================================================
    // Basic matching tests
    // =========================================================================

    #[test]
    fn test_basic_template_matches() {
        // Directory template - must have at least one more segment (the filename)
        let template = "{cluster}/manifests/{namespace}/{service}";
        let path = "prod/manifests/default/demo-nginx/deployment.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"prod".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"default".to_string()));
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_template_with_yaml_extension() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"prod".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"default".to_string()));
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_template_with_nested_service_folder_and_yaml() {
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";
        let path = "prod/manifests/default/demo-nginx/demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"prod".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"default".to_string()));
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_template_with_fixed_filename() {
        // Template with a fixed filename (not using placeholder)
        let template = "{cluster}/manifests/{namespace}/{service}/deployment.yaml";
        let path = "prod/manifests/default/demo-nginx/deployment.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    // =========================================================================
    // Consistency tests - same placeholder multiple times
    // =========================================================================

    #[test]
    fn test_repeated_placeholder_must_match() {
        // {service} appears twice - both must be the same
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";

        // This should match - demo-nginx == demo-nginx
        let path_good = "prod/manifests/default/demo-nginx/demo-nginx.yaml";
        let result = match_path_template_rust(template, path_good);
        assert!(
            result.is_some(),
            "Should match when service names are identical"
        );

        // This should NOT match - demo-nginx != demo-nginx-2
        let path_bad = "prod/manifests/default/demo-nginx/demo-nginx-2.yaml";
        let result = match_path_template_rust(template, path_bad);
        assert!(
            result.is_none(),
            "Should NOT match when service names differ"
        );
    }

    #[test]
    fn test_service_mismatch_in_filename() {
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";

        // Folder is demo-nginx but file is other-service.yaml
        let path = "prod/manifests/default/demo-nginx/other-service.yaml";
        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Should NOT match when folder and filename service differ"
        );
    }

    // =========================================================================
    // Non-matching tests
    // =========================================================================

    #[test]
    fn test_wrong_extension_does_not_match() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/demo-nginx.yml"; // .yml instead of .yaml

        let result = match_path_template_rust(template, path);
        assert!(result.is_none(), "Should not match wrong extension");
    }

    #[test]
    fn test_extra_path_segments_do_not_match() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/subfolder/demo-nginx.yaml"; // extra subfolder

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Should not match with extra path segments"
        );
    }

    #[test]
    fn test_fewer_path_segments_do_not_match() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/demo-nginx.yaml"; // missing namespace

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Should not match with fewer path segments"
        );
    }

    #[test]
    fn test_wrong_literal_does_not_match() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/deployments/default/demo-nginx.yaml"; // "deployments" instead of "manifests"

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Should not match wrong literal path segment"
        );
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn test_template_with_whitespace_is_trimmed() {
        let template = "  {cluster}/manifests/{namespace}/{service}.yaml\n";
        let path = "prod/manifests/default/demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some(), "Should trim whitespace from template");
    }

    #[test]
    fn test_service_name_with_numbers() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/app-v2.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());
        assert_eq!(result.unwrap().get("service"), Some(&"app-v2".to_string()));
    }

    #[test]
    fn test_service_name_with_underscores() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/my_service_name.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("service"),
            Some(&"my_service_name".to_string())
        );
    }

    #[test]
    fn test_prefix_in_filename() {
        let template = "{cluster}/manifests/{namespace}/app-{service}.yaml";
        let path = "prod/manifests/default/app-demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("service"),
            Some(&"demo-nginx".to_string())
        );
    }

    #[test]
    fn test_suffix_in_filename() {
        let template = "{cluster}/manifests/{namespace}/{service}-deployment.yaml";
        let path = "prod/manifests/default/demo-nginx-deployment.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("service"),
            Some(&"demo-nginx".to_string())
        );
    }

    // =========================================================================
    // Real-world webhook scenarios
    // =========================================================================

    #[test]
    fn test_github_webhook_scenario_kustomize_structure() {
        // Common kustomize-style structure
        let template =
            "clusters/{cluster}/namespaces/{namespace}/apps/{service}/kustomization.yaml";
        let path = "clusters/production/namespaces/default/apps/frontend/kustomization.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"production".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"default".to_string()));
        assert_eq!(matches.get("service"), Some(&"frontend".to_string()));
    }

    #[test]
    fn test_github_webhook_scenario_helm_values() {
        // Helm values file structure
        let template = "helm/{cluster}/{namespace}/{service}/values.yaml";
        let path = "helm/staging/kube-system/monitoring/values.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some());

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"staging".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"kube-system".to_string()));
        assert_eq!(matches.get("service"), Some(&"monitoring".to_string()));
    }

    #[test]
    fn test_github_webhook_multiple_files_same_service() {
        // User has multiple files for the same service
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";

        // All these should match for demo-nginx
        let paths = vec!["prod/manifests/default/demo-nginx/demo-nginx.yaml"];

        for path in paths {
            let result = match_path_template_rust(template, path);
            assert!(result.is_some(), "Should match: {}", path);
            assert_eq!(
                result.unwrap().get("service"),
                Some(&"demo-nginx".to_string())
            );
        }

        // These should NOT match
        let bad_paths = vec![
            "prod/manifests/default/demo-nginx/other-app.yaml",
            "prod/manifests/default/demo-nginx/demo-nginx-v2.yaml",
        ];

        for path in bad_paths {
            let result = match_path_template_rust(template, path);
            assert!(result.is_none(), "Should NOT match: {}", path);
        }
    }

    #[test]
    fn test_equivalent_templates_same_result() {
        // These two templates should produce the same result for the matching path
        let template1 = "{cluster}/manifests/{namespace}/{service}/demo-nginx.yaml";
        let template2 = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";

        let path = "prod/manifests/default/demo-nginx/demo-nginx.yaml";

        let result1 = match_path_template_rust(template1, path);
        let result2 = match_path_template_rust(template2, path);

        assert!(result1.is_some(), "Template 1 should match");
        assert!(result2.is_some(), "Template 2 should match");

        // Both should extract service as demo-nginx
        assert_eq!(
            result1.unwrap().get("service"),
            Some(&"demo-nginx".to_string())
        );
        assert_eq!(
            result2.unwrap().get("service"),
            Some(&"demo-nginx".to_string())
        );
    }

    #[test]
    fn test_missing_required_placeholders() {
        // Template missing {namespace}
        let template = "{cluster}/manifests/{service}.yaml";
        let path = "prod/manifests/demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Should fail when required placeholders are missing"
        );
    }

    // =========================================================================
    // Directory wildcard tests - templates without .yaml/.yml extension
    // =========================================================================

    #[test]
    fn test_directory_template_matches_any_file_in_service_dir() {
        // Template ending with {service} (a directory) should match any file within
        let template = "{cluster}/manifests/{namespace}/{service}";

        // Should match service.yaml in the service directory
        let path = "production/manifests/default/demo-nginx/service.yaml";
        let result = match_path_template_rust(template, path);
        assert!(result.is_some(), "Should match any file in service dir");

        let matches = result.unwrap();
        assert_eq!(matches.get("cluster"), Some(&"production".to_string()));
        assert_eq!(matches.get("namespace"), Some(&"default".to_string()));
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_directory_template_matches_deployment_yaml() {
        let template = "{cluster}/manifests/{namespace}/{service}";
        let path = "prod/manifests/default/demo-nginx/deployment.yaml";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_some(),
            "Should match deployment.yaml in service dir"
        );

        let matches = result.unwrap();
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_directory_template_matches_nested_file() {
        // Should also match files in nested subdirectories
        let template = "{cluster}/manifests/{namespace}/{service}";
        let path = "prod/manifests/default/demo-nginx/templates/deployment.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some(), "Should match nested file in service dir");

        let matches = result.unwrap();
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_directory_template_with_trailing_slash() {
        // Trailing slash should be normalized and work the same
        let template = "{cluster}/manifests/{namespace}/{service}/";
        let path = "prod/manifests/default/demo-nginx/service.yaml";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_some(),
            "Should match with trailing slash in template"
        );

        let matches = result.unwrap();
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_directory_template_does_not_match_exact_path() {
        // Directory template should NOT match if the path has exactly as many parts
        // (the file path should have at least one more segment - the filename)
        let template = "{cluster}/manifests/{namespace}/{service}";
        let path = "prod/manifests/default/demo-nginx";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Directory template should NOT match path with same number of segments"
        );
    }

    #[test]
    fn test_file_template_does_not_match_longer_path() {
        // File template (ending with .yaml) should NOT match longer paths
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let path = "prod/manifests/default/demo-nginx.yaml/extra";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "File template should NOT match path with extra segments"
        );
    }

    #[test]
    fn test_directory_template_real_world_scenario() {
        // Real-world scenario from user report
        let template = "{cluster}/manifests/{namespace}/{service}";

        // Various files that should all match for demo-nginx service
        let test_cases = vec![
            (
                "production/manifests/default/demo-nginx/service.yaml",
                "production",
                "default",
                "demo-nginx",
            ),
            (
                "staging/manifests/kube-system/nginx-ingress/deployment.yaml",
                "staging",
                "kube-system",
                "nginx-ingress",
            ),
            (
                "dev/manifests/monitoring/prometheus/configmap.yaml",
                "dev",
                "monitoring",
                "prometheus",
            ),
        ];

        for (path, expected_cluster, expected_namespace, expected_service) in test_cases {
            let result = match_path_template_rust(template, path);
            assert!(result.is_some(), "Should match: {}", path);

            let matches = result.unwrap();
            assert_eq!(
                matches.get("cluster"),
                Some(&expected_cluster.to_string()),
                "Wrong cluster for path: {}",
                path
            );
            assert_eq!(
                matches.get("namespace"),
                Some(&expected_namespace.to_string()),
                "Wrong namespace for path: {}",
                path
            );
            assert_eq!(
                matches.get("service"),
                Some(&expected_service.to_string()),
                "Wrong service for path: {}",
                path
            );
        }
    }

    #[test]
    fn test_specific_file_template_still_works() {
        // Ensure specific file templates like {service}.yaml still work correctly
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";
        let path = "production/manifests/default/demo-nginx/demo-nginx.yaml";

        let result = match_path_template_rust(template, path);
        assert!(result.is_some(), "Specific file template should still work");

        let matches = result.unwrap();
        assert_eq!(matches.get("service"), Some(&"demo-nginx".to_string()));
    }

    #[test]
    fn test_specific_file_template_rejects_different_filename() {
        // Specific file template should reject files with different names
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";
        let path = "production/manifests/default/demo-nginx/service.yaml";

        let result = match_path_template_rust(template, path);
        assert!(
            result.is_none(),
            "Specific file template should reject service.yaml (expecting demo-nginx.yaml)"
        );
    }

    // =========================================================================
    // is_directory_template tests
    // =========================================================================

    #[test]
    fn test_is_directory_template_for_file_templates() {
        // Templates ending with file extensions should NOT be directory templates
        assert!(!is_directory_template("{cluster}/manifests/{service}.yaml"));
        assert!(!is_directory_template("{cluster}/manifests/{service}.yml"));
        assert!(!is_directory_template("{cluster}/manifests/{service}.json"));
        assert!(!is_directory_template("path/to/{service}/{service}.yaml"));
    }

    #[test]
    fn test_is_directory_template_for_directory_templates() {
        // Templates NOT ending with file extensions should be directory templates
        assert!(is_directory_template(
            "{cluster}/manifests/{namespace}/{service}"
        ));
        assert!(is_directory_template(
            "{cluster}/manifests/{namespace}/{service}/"
        ));
        assert!(is_directory_template("some/path/{service}"));
        // Template ending with prefix pattern (no extension)
        assert!(is_directory_template(
            "{cluster}/manifests/{namespace}/{service}/{namespace}-{service}-"
        ));
    }

    #[test]
    fn test_is_directory_template_edge_cases() {
        // Empty and whitespace
        assert!(is_directory_template(""));
        assert!(is_directory_template("   "));
        // Just a placeholder
        assert!(is_directory_template("{service}"));
        // Trailing spaces shouldn't matter
        assert!(is_directory_template("{cluster}/manifests/{service}   "));
        assert!(!is_directory_template(
            "{cluster}/manifests/{service}.yaml   "
        ));
    }

    // =========================================================================
    // compute_manifest_path_pattern tests
    // =========================================================================

    #[test]
    fn test_compute_path_pattern_for_file_template() {
        let template = "{cluster}/manifests/{namespace}/{service}.yaml";
        let mut matches = HashMap::new();
        matches.insert("cluster".to_string(), "prod".to_string());
        matches.insert("namespace".to_string(), "default".to_string());
        matches.insert("service".to_string(), "nginx".to_string());

        let (path, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path, "prod/manifests/default/nginx.yaml");
        assert!(!is_dir, "Should not be a directory pattern");
    }

    #[test]
    fn test_compute_path_pattern_for_directory_template() {
        let template = "{cluster}/manifests/{namespace}/{service}";
        let mut matches = HashMap::new();
        matches.insert("cluster".to_string(), "prod".to_string());
        matches.insert("namespace".to_string(), "default".to_string());
        matches.insert("service".to_string(), "nginx".to_string());

        let (path, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path, "prod/manifests/default/nginx/*.yaml");
        assert!(is_dir, "Should be a directory pattern");
    }

    #[test]
    fn test_compute_path_pattern_for_prefix_template() {
        // Template with prefix pattern in last segment
        let template = "{cluster}/manifests/{namespace}/{service}/{namespace}-{service}-";
        let mut matches = HashMap::new();
        matches.insert("cluster".to_string(), "prod".to_string());
        matches.insert("namespace".to_string(), "default".to_string());
        matches.insert("service".to_string(), "nginx".to_string());

        let (path, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path, "prod/manifests/default/nginx/default-nginx-*.yaml");
        assert!(is_dir, "Should be a directory pattern");
    }

    #[test]
    fn test_compute_path_pattern_with_trailing_slash() {
        let template = "{cluster}/manifests/{namespace}/{service}/";
        let mut matches = HashMap::new();
        matches.insert("cluster".to_string(), "staging".to_string());
        matches.insert("namespace".to_string(), "kube-system".to_string());
        matches.insert("service".to_string(), "coredns".to_string());

        let (path, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path, "staging/manifests/kube-system/coredns/*.yaml");
        assert!(is_dir, "Should be a directory pattern");
    }

    #[test]
    fn test_compute_path_pattern_nested_file_template() {
        let template = "{cluster}/manifests/{namespace}/{service}/{service}.yaml";
        let mut matches = HashMap::new();
        matches.insert("cluster".to_string(), "prod".to_string());
        matches.insert("namespace".to_string(), "default".to_string());
        matches.insert("service".to_string(), "nginx".to_string());

        let (path, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path, "prod/manifests/default/nginx/nginx.yaml");
        assert!(!is_dir, "Should not be a directory pattern");
    }

    // =========================================================================
    // Deduplication logic tests (via match aggregation)
    // =========================================================================

    #[test]
    fn test_webhook_multiple_files_same_service_deduplication() {
        // Simulates a webhook with multiple files changed in the same service directory
        // All should match to the same service and should be deduplicated
        let template = "{cluster}/manifests/{namespace}/{service}";

        let changed_files = vec![
            "prod/manifests/default/demo-nginx/deployment.yaml",
            "prod/manifests/default/demo-nginx/service.yaml",
            "prod/manifests/default/demo-nginx/configmap.yaml",
        ];

        // All files should match to the same service
        let mut matched_services: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for file in &changed_files {
            if let Some(matches) = match_path_template_rust(template, file) {
                let service = matches.get("service").unwrap().clone();
                matched_services.insert(service);
            }
        }

        assert_eq!(
            matched_services.len(),
            1,
            "All files should match to single service"
        );
        assert!(
            matched_services.contains("demo-nginx"),
            "Service should be demo-nginx"
        );

        // The webhook handler would deduplicate these and create only one service_version
        // with a glob pattern like "prod/manifests/default/demo-nginx/*.yaml"
    }

    #[test]
    fn test_deduplication_with_different_services() {
        // Multiple files from different services - should NOT be deduplicated
        let template = "{cluster}/manifests/{namespace}/{service}";

        let changed_files = vec![
            "prod/manifests/default/nginx/deployment.yaml",
            "prod/manifests/default/redis/deployment.yaml",
            "prod/manifests/default/postgres/statefulset.yaml",
        ];

        let mut matched_services: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for file in &changed_files {
            if let Some(matches) = match_path_template_rust(template, file) {
                let service = matches.get("service").unwrap().clone();
                matched_services.insert(service);
            }
        }

        assert_eq!(
            matched_services.len(),
            3,
            "Each file should match to different service"
        );
        assert!(matched_services.contains("nginx"));
        assert!(matched_services.contains("redis"));
        assert!(matched_services.contains("postgres"));
    }

    #[test]
    fn test_deduplication_across_namespaces() {
        // Same service name in different namespaces - should NOT be deduplicated
        let template = "{cluster}/manifests/{namespace}/{service}";

        let changed_files = vec![
            "prod/manifests/default/nginx/deployment.yaml",
            "prod/manifests/staging/nginx/deployment.yaml",
            "prod/manifests/production/nginx/deployment.yaml",
        ];

        // Simulate collecting unique (namespace, service) pairs
        let mut namespace_service_pairs: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        for file in &changed_files {
            if let Some(matches) = match_path_template_rust(template, file) {
                let ns = matches.get("namespace").unwrap().clone();
                let svc = matches.get("service").unwrap().clone();
                namespace_service_pairs.insert((ns, svc));
            }
        }

        assert_eq!(
            namespace_service_pairs.len(),
            3,
            "Each namespace+service combo should be unique"
        );
    }

    #[test]
    fn test_multiple_files_generate_single_path_pattern() {
        // When multiple files match, the path pattern should be a glob
        let template = "{cluster}/manifests/{namespace}/{service}";

        // First file matches
        let result1 = match_path_template_rust(
            template,
            "prod/manifests/default/demo-nginx/deployment.yaml",
        );
        assert!(result1.is_some());

        // Compute path pattern from first match (what webhook handler does)
        let matches = result1.unwrap();
        let (path_pattern, is_dir) = compute_manifest_path_pattern(template, &matches);

        assert_eq!(path_pattern, "prod/manifests/default/demo-nginx/*.yaml");
        assert!(is_dir);

        // The hive server will use this glob pattern to fetch all files in the directory
    }
}

/// Get webhook events for a repo (audit log)
#[utoipa::path(
    get,
    path = "/api/repos/{id}/webhook/events",
    params(
        ("id" = Uuid, Path, description = "Repo UUID"),
        ("limit" = Option<i64>, Query, description = "Number of events to return"),
        ("offset" = Option<i64>, Query, description = "Number of events to skip"),
    ),
    security(
        ("bearerAuth"=[]),
    ),
    responses(
        (status = 200, description = "Returns webhook events", body = Vec<types::RepoWebhookEvent>),
        (status = 401, description = "Access token is missing or invalid"),
        (status = 404, description = "Webhook not found"),
        (status = 500, description = "Database error"),
    )
)]
pub async fn get_webhook_events(
    State(state): State<ServerState>,
    headers: axum::http::HeaderMap,
    Path(repo_id): Path<Uuid>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<Vec<RepoWebhookEvent>>, (StatusCode, String)> {
    let (mut tx, _tenant_id, _tenant_domain) = get_tenant_tx(&state.pool, &headers).await?;
    let pagination = pagination.validate();

    let events = sqlx::query_as::<_, RepoWebhookEvent>(
        r#"
        SELECT 
            e.id,
            e.created_at,
            e.webhook_id,
            e.delivery_id,
            e.event_type,
            e.ref AS ref_name,
            e.before_sha,
            e.after_sha,
            e.pusher,
            e.processed_at,
            e.processing_error,
            e.matched_paths,
            e.updated_service_versions
        FROM repo_webhook_events e
        JOIN repo_webhooks w ON w.id = e.webhook_id
        WHERE w.repo_id = $1
        ORDER BY e.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(repo_id)
    .bind(pagination.limit)
    .bind(pagination.offset)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| sanitize_db_error(e, "get_webhook_events"))?;

    tx.commit()
        .await
        .map_err(|e| sanitize_db_error(e, "get_webhook_events_commit"))?;
    Ok(Json(events))
}
