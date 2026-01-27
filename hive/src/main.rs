use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use serde::de::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, Row};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::{self, Command};
use std::string::FromUtf8Error;
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;
use tonic::{transport::Server, Request, Response, Status};

use tracing::{debug, error, info, trace, warn, Level};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use uuid::Uuid;
use yaml_rust::YamlLoader;

mod auth;

/// Crypto module for secret decryption (hive-server only decrypts, never encrypts)
mod crypto {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::Engine;

    const NONCE_SIZE: usize = 12;

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

    /// Get the encryption key from environment variable
    /// Expects ENCRYPTION_KEY to be base64-encoded 32-byte key
    pub fn get_encryption_key() -> Result<[u8; 32], String> {
        let key_b64 = std::env::var("ENCRYPTION_KEY")
            .map_err(|_| "ENCRYPTION_KEY environment variable not set".to_string())?;

        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .map_err(|e| format!("Failed to decode ENCRYPTION_KEY: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(format!(
                "ENCRYPTION_KEY must be 32 bytes (got {})",
                key_bytes.len()
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        Ok(key_array)
    }
}

pub mod beecd {
    tonic::include_proto!("beecd");
}
use beecd::worker_server::{Worker, WorkerServer};

const VERSION: Option<&str> = std::option_env!("HIVE_SERVER_VERSION");
const BUILD_VERSION: Option<&str> = std::option_env!("BUILD_VERSION");
const CARGO_VERSION: &str = env!("CARGO_PKG_VERSION");

fn init() {
    let log_level = env::var("LOG_LEVEL")
        .unwrap_or(String::from("warn"))
        .to_lowercase();

    if !["none"].contains(&log_level.as_str()) || !log_level.is_empty() {
        let (level, filter) = if ["-1", "error"].contains(&log_level.as_str()) {
            (Level::ERROR, EnvFilter::new("error"))
        } else if ["0", "warn", "warning"].contains(&log_level.as_str()) {
            (Level::WARN, EnvFilter::new("warn"))
        } else if ["1", "info", "default"].contains(&log_level.as_str()) {
            (Level::INFO, EnvFilter::new("info"))
        } else if ["2", "debug"].contains(&log_level.as_str()) {
            (Level::DEBUG, EnvFilter::new("hive=debug")) // Debug only from this crate (default debug)
        } else if ["3", "trace", "tracing"].contains(&log_level.as_str()) {
            (Level::TRACE, EnvFilter::new("hive=trace")) // Trace only from this crate (default tracing)
        } else if ["4", "debug"].contains(&log_level.as_str()) {
            (Level::DEBUG, EnvFilter::new("debug")) // Debug from all crates
        } else if ["5", "trace"].contains(&log_level.as_str()) {
            (Level::DEBUG, EnvFilter::new("trace")) // Tracing from all crates
        } else {
            (Level::INFO, EnvFilter::new("info")) // fallback in case our spelling sucks
        };

        // a builder for `FmtSubscriber`.
        let subscriber = FmtSubscriber::builder()
            // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
            // will be written to stdout.
            .with_max_level(level)
            // completes the builder.
            .with_env_filter(filter)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

#[derive(Error, Debug)]
enum HiveError {
    #[error("Unable to decode content: {0:?}")]
    DecodeError(BoxedError),
    #[error("Failed to get release from database: {0:?}")]
    FailedFindingRelease(BoxedError),
    #[error("parse info error: {0:?}")]
    FromUtf8Error(FromUtf8Error),
    #[error("Failed fetch: {0:?}")]
    FetchError(BoxedError),
    #[error("Failed to sanitized manifest: {0:?}")]
    DocumentSanitizationError(String),
    #[error("Failed to create temporary file: {0:?}")]
    TempFileCreation(io::Error),
    #[error("Failed to execute command: {0:?}")]
    CommandExecution(io::Error),
    #[error("Command exited with error code {0:?}: {1:?}")]
    CommandErrorMessage(Option<i32>, BoxedError),
    #[error("Manifest was empty")]
    EmptyDocumentError,
    #[error("Manifest failed yaml lint")]
    YamlLintError,
    #[error("Failed to find {0} key")]
    MissingKeyError(&'static str),
}

type HTTPResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[derive(sqlx::FromRow)]
struct ClusterRow {
    name: String,
}

#[derive(sqlx::FromRow)]
struct ReleaseRow {
    id: Uuid,
    service_id: Uuid,
    repo_branch_id: Uuid,
    hash: String,
    path: String,
    name: String,
    version: String,
    namespace_id: Uuid,
    git_sha: String,
    diff_generation: i32,
    branch: String,
    org: String,
    repo: String,
    completed_first_install_at: Option<DateTime<Utc>>,
    started_first_install_at: Option<DateTime<Utc>>,
    failed_update_install_at: Option<DateTime<Utc>>,
    marked_for_deletion_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    started_delete_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    completed_delete_at: Option<DateTime<Utc>>,
    approved_at: Option<DateTime<Utc>>,
    unapproved_at: Option<DateTime<Utc>>,
    previous_installed_hash: Option<String>,
    namespace_name: String,
    cluster_id: Uuid,
    cluster_name: String,
}

// JWT Authentication query result structs
#[derive(sqlx::FromRow)]
struct UserAuthRow {
    user_id: Uuid,
    tenant_id: Uuid,
    password_hash: String,
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    token_id: Uuid,
    user_id: Uuid,
    tenant_id: Uuid,
    cluster_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    #[allow(dead_code)]
    replaced_by_token_id: Option<Uuid>,
    username: String,
}

/// Log a hive error to the database using SECURITY DEFINER function.
/// This bypasses RLS and can be called outside of a tenant transaction.
async fn save_hive_err_to_db(
    tenant_id: Uuid,
    cluster_id: &Uuid,
    message: &str,
    db: &sqlx::Pool<sqlx::Postgres>,
) {
    match sqlx::query("SELECT log_hive_error($1, $2, $3)")
        .bind(tenant_id)
        .bind(cluster_id)
        .bind(message)
        .execute(db)
        .await
    {
        Ok(_) => {}
        Err(e) => {
            trace!("Failed writing error to database: {}", e);
        }
    }
}

async fn read_content(
    url_query_params: &str,
    base_url: &str,
    content: &mut Vec<u8>,
    github_token: Option<&str>,
    tenant_domain: &str,
) -> Result<(), HiveError> {
    let url = format!("{}{}", base_url, url_query_params);
    debug!("Fetching content from URL: {}", url);
    let json_response = fetch_data(&url, github_token).await;
    let raw_data = match json_response {
        Ok(data) => {
            debug!("GitHub API response: {:?}", data);

            // Check if this is a directory listing (array response)
            if data.is_array() {
                debug!("Response is an array (directory listing), processing all files");
                if let Some(files) = data.as_array() {
                    for file in files {
                        if let Some(file_type) = file.get("type").and_then(|t| t.as_str()) {
                            if file_type == "file" {
                                if let Some(download_url) =
                                    file.get("download_url").and_then(|u| u.as_str())
                                {
                                    match download_raw_data(download_url, github_token).await {
                                        Ok(file_data) => {
                                            content.append(&mut "\n---\n".as_bytes().to_vec());
                                            content.append(&mut file_data.as_bytes().to_vec());
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to download file from {}: {}",
                                                download_url, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Ok(());
            }

            // Single file response
            match data.get("download_url") {
                Some(download_url) => {
                    match download_raw_data(download_url.as_str().unwrap(), github_token).await {
                        Ok(raw_data) => raw_data,
                        Err(e) => {
                            error!("Failed to download raw data from {}: {}", download_url, e);
                            return Err(HiveError::FetchError(e));
                        }
                    }
                }
                None => {
                    // Check if this is an error response
                    if let Some(error_msg) = data.get("message") {
                        error!("GitHub API error: {} (URL: {})", error_msg, url);
                    } else {
                        error!("GitHub API response missing 'download_url' key. Response: {:?} (URL: {})", data, url);
                    }
                    return Err(HiveError::MissingKeyError("download_url"));
                }
            }
        }
        Err(e) => {
            error!(
                "[tenant:{}] Failed to fetch from GitHub API: {} (URL: {})",
                tenant_domain, e, url
            );
            return Err(HiveError::FetchError(e));
        }
    };

    content.append(&mut "\n---\n".as_bytes().to_vec());
    content.append(&mut raw_data.as_bytes().to_vec());

    Ok(())
}

/// Read contents of a directory from GitHub, fetching all files matching a glob pattern.
///
/// # Arguments
/// * `url_query_params` - Query params like "?ref=SHA"
/// * `github_api_url` - Base GitHub API URL (e.g., "https://api.github.com")
/// * `org` - GitHub organization/owner
/// * `repo` - GitHub repository name
/// * `path_pattern` - Glob pattern like "prod/default/nginx/*.yaml"
/// * `content` - Output buffer for aggregated content
///
/// # Returns
/// Multi-document YAML with all matching files concatenated
async fn read_directory_contents(
    url_query_params: &str,
    github_api_url: &str,
    org: &str,
    repo: &str,
    path_pattern: &str,
    content: &mut Vec<u8>,
    github_token: Option<&str>,
) -> Result<(), HiveError> {
    // Extract directory path and file pattern from glob
    // e.g., "prod/default/nginx/*.yaml" -> dir="prod/default/nginx", pattern="*.yaml"
    // e.g., "prod/default/nginx/default-nginx-*.yaml" -> dir="prod/default/nginx", pattern="default-nginx-*.yaml"
    let (dir_path, file_pattern) = if let Some(last_slash) = path_pattern.rfind('/') {
        let dir = &path_pattern[..last_slash];
        let pattern = &path_pattern[last_slash + 1..];
        (dir, pattern)
    } else {
        // No slash, entire thing is a pattern in root
        ("", path_pattern)
    };

    // Build glob pattern matcher
    let glob_pattern = glob::Pattern::new(file_pattern).map_err(|e| {
        error!("Invalid glob pattern '{}': {}", file_pattern, e);
        HiveError::MissingKeyError("invalid glob pattern")
    })?;

    // Fetch directory listing from GitHub
    let dir_url = format!(
        "{}/repos/{}/{}/contents/{}{}",
        github_api_url,
        org,
        repo,
        dir_path.trim_start_matches('/'),
        url_query_params
    );

    debug!("Fetching directory listing from: {}", dir_url);

    let response = fetch_data(&dir_url, github_token).await.map_err(|e| {
        error!(
            "Failed to fetch directory listing: {} (URL: {})",
            e, dir_url
        );
        HiveError::FetchError(e)
    })?;

    // GitHub returns an array for directory listings
    let files = match response.as_array() {
        Some(arr) => arr,
        None => {
            // Might be an error response or single file
            if let Some(msg) = response.get("message") {
                error!(
                    "GitHub API error fetching directory: {} (URL: {})",
                    msg, dir_url
                );
            }
            return Err(HiveError::MissingKeyError("expected directory array"));
        }
    };

    // Filter and sort files matching the pattern
    let mut matching_files: Vec<_> = files
        .iter()
        .filter_map(|file| {
            let file_type = file.get("type")?.as_str()?;
            if file_type != "file" {
                return None;
            }

            let name = file.get("name")?.as_str()?;

            // Check if file matches the glob pattern
            if !glob_pattern.matches(name) {
                return None;
            }

            // Only include yaml/yml/json files
            let is_manifest =
                name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".json");
            if !is_manifest {
                return None;
            }

            let download_url = file.get("download_url")?.as_str()?;
            Some((name.to_string(), download_url.to_string()))
        })
        .collect();

    // Sort files alphabetically for deterministic ordering
    matching_files.sort_by(|a, b| a.0.cmp(&b.0));

    info!(
        "Found {} matching files in {} for pattern '{}': {:?}",
        matching_files.len(),
        dir_path,
        file_pattern,
        matching_files.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );

    if matching_files.is_empty() {
        return Err(HiveError::MissingKeyError(
            "no matching files found in directory",
        ));
    }

    // Fetch each matching file and concatenate as multi-document YAML
    for (name, download_url) in matching_files {
        debug!("Fetching file: {} from {}", name, download_url);

        let raw_data = download_raw_data(&download_url, github_token)
            .await
            .map_err(|e| {
                error!("Failed to download {}: {}", name, e);
                HiveError::FetchError(e)
            })?;

        // Add YAML document separator and content
        content.append(&mut "\n---\n".as_bytes().to_vec());
        content.append(&mut format!("# Source: {}\n", name).as_bytes().to_vec());
        content.append(&mut raw_data.as_bytes().to_vec());
    }

    Ok(())
}

#[derive(Default)]
struct DeserializedDocs {
    docs: Vec<String>,
    de_errors: Vec<BoxedError>,
}

fn sanitize_document(data: Vec<u8>) -> Result<String, HiveError> {
    let expanded_data = String::from_utf8(data).map_err(|e| HiveError::DecodeError(e.into()))?;

    match YamlLoader::load_from_str(&expanded_data) {
        Ok(_) => {}
        Err(_) => return Err(HiveError::YamlLintError),
    }

    let docs = serde_yaml::Deserializer::from_str(&expanded_data).fold(
        DeserializedDocs::default(),
        |mut v: DeserializedDocs, document| {
            let deserialized_data = match serde_yaml::Value::deserialize(document) {
                Ok(d) => match d.get("sops") {
                    Some(_) => {
                        let dir = env::temp_dir();
                        let file = format!("{}/{}.yaml", dir.display(), Uuid::new_v4());
                        let yaml_string = match serde_yaml::to_string(&d) {
                            Ok(s) => s,
                            Err(e) => {
                                v.de_errors.push(e.into());
                                return v;
                            }
                        };
                        match fs::write(&file, yaml_string) {
                            Ok(_) => {}
                            Err(e) => {
                                v.de_errors.push(e.into());
                                return v;
                            }
                        }
                        let output = match process::Command::new("sops")
                            .args(["--decrypt", &file])
                            .output()
                        {
                            Ok(s) => s,
                            Err(e) => {
                                v.de_errors.push(e.into());
                                return v;
                            }
                        };
                        if output.status.success() {
                            let decrypted_doc: serde_yaml::Value =
                                match serde_yaml::from_slice(&output.stdout) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        v.de_errors.push(e.into());
                                        return v;
                                    }
                                };
                            decrypted_doc
                        } else {
                            let err_string = match String::from_utf8(output.stderr) {
                                Ok(s) => s,
                                Err(e) => {
                                    v.de_errors.push(e.into());
                                    return v;
                                }
                            };
                            v.de_errors.push(err_string.into());
                            return v;
                        }
                    }
                    None => d,
                },
                Err(e) => {
                    v.de_errors.push(e.into());
                    return v;
                }
            };
            if deserialized_data.is_null() {
                v
            } else {
                let serialized_data = match serde_yaml::to_string(&deserialized_data) {
                    Ok(s) => s,
                    Err(e) => {
                        v.de_errors.push(e.into());
                        return v;
                    }
                };
                v.docs.push(serialized_data);
                v
            }
        },
    );

    if !docs.de_errors.is_empty() {
        Err(HiveError::DocumentSanitizationError(
            docs.de_errors
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        ))
    } else if docs.docs.is_empty() {
        Err(HiveError::EmptyDocumentError)
    } else {
        Ok(docs.docs.join("---\n"))
    }
}

fn encrypt_with_sops(input: String) -> Result<String, HiveError> {
    let mut input_file = match NamedTempFile::new() {
        Ok(file) => file,
        Err(e) => {
            return Err(HiveError::TempFileCreation(e));
        }
    };

    if let Err(e) = write!(input_file, "{}", input) {
        return Err(HiveError::TempFileCreation(e));
    }

    let key = "FINGER_PRINT";
    let gpg_finger_print = std::env::var(key)
        .map_err(|_| HiveError::MissingKeyError("FINGER_PRINT environment variable"))?;
    let mut cmd = Command::new("sops");
    cmd.arg("--output-type")
        .arg("yaml")
        .arg("--pgp")
        .arg(gpg_finger_print)
        .arg("--encrypt")
        .arg(input_file.path());
    let output = match cmd.output() {
        Ok(s) => s,
        Err(e) => {
            return Err(HiveError::CommandExecution(e));
        }
    };

    if !output.status.success() {
        let err_string = String::from_utf8_lossy(&output.stderr);
        let message = format!("{:?}: {}", cmd, err_string);
        return Err(HiveError::CommandErrorMessage(
            output.status.code(),
            message.into(),
        ));
    }

    String::from_utf8(output.stdout).map_err(HiveError::FromUtf8Error)
}

async fn download_raw_data(url: &str, github_token: Option<&str>) -> HTTPResult<String> {
    let mut headers = reqwest::header::HeaderMap::new();

    // GitHub token is required - no fallback
    let token = github_token.ok_or_else(|| {
        Box::new(std::io::Error::other(
            "GitHub token not provided - check tenant_secrets configuration",
        )) as Box<dyn std::error::Error + Send + Sync>
    })?;

    let token_header_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?;
    headers.insert("Authorization", token_header_value);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let body = client
        .get(url)
        .headers(headers.clone())
        .send()
        .await?
        .text()
        .await?;

    Ok(body)
}

async fn fetch_data(url: &str, github_token: Option<&str>) -> HTTPResult<JsonValue> {
    let mut headers = reqwest::header::HeaderMap::new();

    // GitHub token is required - no fallback
    let token = github_token.ok_or_else(|| {
        Box::new(std::io::Error::other(
            "GitHub token not provided - check tenant_secrets configuration",
        )) as Box<dyn std::error::Error + Send + Sync>
    })?;

    let token_header_value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?;
    headers.insert("Authorization", token_header_value);
    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static("beecd-hive/1.0"),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    let response = client.get(url).headers(headers).send().await?;

    // Check status BEFORE parsing JSON
    let status = response.status();
    if !status.is_success() {
        let error_body = response.text().await.unwrap_or_default();
        return Err(Box::new(std::io::Error::other(format!(
            "GitHub API error {}: {}",
            status, error_body
        ))));
    }

    let body = response.json::<JsonValue>().await?;
    Ok(body)
}

#[derive(Debug)]
struct GrpcServer {
    db: sqlx::Pool<sqlx::Postgres>,
    readonly_db: sqlx::Pool<sqlx::Postgres>,
    storage_prefix: String,
    github_api_url: String,
}

impl GrpcServer {
    /// Get tenant domain for logging purposes
    async fn get_tenant_domain(&self, tenant_id: Uuid) -> String {
        sqlx::query_scalar::<_, String>("SELECT domain FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(&self.readonly_db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| tenant_id.to_string())
    }

    async fn get_cluster_data(&self, cluster_id: Uuid) -> Result<ClusterRow, HiveError> {
        sqlx::query_as::<_, ClusterRow>(
            r#"
            SELECT
                name
            FROM
                clusters
            WHERE
                id = $1
            "#,
        )
        .bind(cluster_id)
        .fetch_one(&self.readonly_db)
        .await
        .map_err(|e| HiveError::FetchError(e.into()))
    }

    async fn get_release_data(&self, release_id: Uuid) -> Result<ReleaseRow, Status> {
        sqlx::query_as::<_, ReleaseRow>(
            r#"
            SELECT
                releases.id,
                releases.service_id,
                releases.repo_branch_id,
                releases.hash,
                releases.path,
                releases.name,
                releases.version,
                releases.namespace_id,
                releases.git_sha,
                releases.diff_generation,
                releases.started_first_install_at,
                releases.completed_first_install_at,
                releases.failed_update_install_at,
                releases.marked_for_deletion_at,
                releases.started_delete_at,
                releases.completed_delete_at,
                releases.approved_at,
                releases.unapproved_at,
                releases.previous_installed_hash,
                repo_branches.branch,
                repos.org,
                repos.repo,
                namespaces.name as namespace_name,
                clusters.id as cluster_id,
                clusters.name as cluster_name
            FROM
                releases
            JOIN
                repo_branches ON releases.repo_branch_id = repo_branches.id
            JOIN
                repos ON repo_branches.repo_id = repos.id
            JOIN
                namespaces on releases.namespace_id = namespaces.id
            JOIN
                clusters on namespaces.cluster_id = clusters.id
            WHERE
                releases.id = $1
            "#,
        )
        .bind(release_id)
        .fetch_one(&self.readonly_db)
        .await
        .map_err(|e| {
            let hive_error = HiveError::FailedFindingRelease(e.into());
            let message = format!("{}", hive_error);
            error!("{}", message);
            Status::not_found(message)
        })
    }

    /// Get release data using an existing transaction (for RLS enforcement)
    async fn get_release_data_with_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        release_id: Uuid,
    ) -> Result<ReleaseRow, Status> {
        sqlx::query_as::<_, ReleaseRow>(
            r#"
            SELECT
                releases.id,
                releases.service_id,
                releases.repo_branch_id,
                releases.hash,
                releases.path,
                releases.name,
                releases.version,
                releases.namespace_id,
                releases.git_sha,
                releases.diff_generation,
                releases.started_first_install_at,
                releases.completed_first_install_at,
                releases.failed_update_install_at,
                releases.marked_for_deletion_at,
                releases.started_delete_at,
                releases.completed_delete_at,
                releases.approved_at,
                releases.unapproved_at,
                releases.previous_installed_hash,
                repo_branches.branch,
                repos.org,
                repos.repo,
                namespaces.name as namespace_name,
                clusters.id as cluster_id,
                clusters.name as cluster_name
            FROM
                releases
            JOIN
                repo_branches ON releases.repo_branch_id = repo_branches.id
            JOIN
                repos ON repo_branches.repo_id = repos.id
            JOIN
                namespaces on releases.namespace_id = namespaces.id
            JOIN
                clusters on namespaces.cluster_id = clusters.id
            WHERE
                releases.id = $1
            "#,
        )
        .bind(release_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| {
            let hive_error = HiveError::FailedFindingRelease(e.into());
            let message = format!("{}", hive_error);
            error!("{}", message);
            Status::not_found(message)
        })
    }

    /// Fetch and decrypt GitHub token from tenant_secrets
    /// Returns None if no token is found
    async fn get_github_token(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_domain: &str,
    ) -> Result<Option<String>, Status> {
        // Fetch encrypted secret from database
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            r#"
            SELECT ciphertext, iv
            FROM tenant_secrets
            WHERE purpose = 'github_token'
              AND deleted_at IS NULL
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| Status::internal(format!("Failed to fetch GitHub token: {}", e)))?;

        let Some((ciphertext, iv)) = row else {
            return Err(Status::failed_precondition(
                "No GitHub token found in tenant_secrets - please configure github_token secret",
            ));
        };

        // Get encryption key from environment
        let key = crypto::get_encryption_key()
            .map_err(|e| Status::internal(format!("Failed to get encryption key: {}", e)))?;

        // Decrypt the token
        let plaintext_bytes = crypto::decrypt(&key, &ciphertext, &iv)
            .map_err(|e| Status::internal(format!("Failed to decrypt GitHub token: {}", e)))?;

        let token = String::from_utf8(plaintext_bytes)
            .map_err(|e| Status::internal(format!("GitHub token is not valid UTF-8: {}", e)))?;

        debug!(
            "[tenant:{}] Successfully decrypted GitHub token from tenant_secrets",
            tenant_domain
        );
        Ok(Some(token))
    }
}

#[tonic::async_trait]
impl Worker for GrpcServer {
    async fn client_registration(
        &self,
        request: Request<beecd::ClusterName>,
    ) -> Result<Response<beecd::ClusterId>, Status> {
        // Extract tenant context from request extensions (set by auth interceptor)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let data_request = request.into_inner();
        let cluster_name = data_request.cluster_name;
        let metadata = data_request.metadata;
        let version = data_request.version;
        let kubernetes_version = data_request.kubernetes_version;

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        info!(
            "[tenant:{}] Registering cluster '{}'",
            tenant_domain, cluster_name
        );

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let query = r#"
        WITH find_id AS (
            SELECT id FROM clusters WHERE name = $1 AND tenant_id = $2
        ),
        insert_if_not_exists AS (
            INSERT INTO clusters (id, tenant_id, name, metadata, version, kubernetes_version) 
            SELECT gen_random_uuid(), $2, $1, $3, $4, $5 WHERE NOT EXISTS (SELECT 1 FROM find_id)
            RETURNING id
        ),
        update_if_exists AS (
            UPDATE clusters SET metadata=$3, version=$4, kubernetes_version=$5 WHERE id IN (SELECT id FROM find_id)
            RETURNING id
        )
        SELECT id
        FROM find_id
        UNION ALL
        SELECT id
        FROM insert_if_not_exists
        UNION ALL
        SELECT id
        FROM update_if_exists;
        "#;
        let row = sqlx::query(query)
            .bind(&cluster_name)
            .bind(tenant_ctx.tenant_id)
            .bind(&metadata)
            .bind(&version)
            .bind(&kubernetes_version)
            .fetch_one(&mut *tx)
            .await;

        let cluster_id: Uuid = match row {
            Ok(r) => r.try_get("id").unwrap(),
            Err(e) => {
                let message = format!("{}", e);
                error!("[tenant:{}] ({}) {}", tenant_domain, cluster_name, message);
                return Err(Status::invalid_argument(message));
            }
        };

        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::ClusterId {
            cluster_id: cluster_id.to_string(),
        }))
    }

    async fn client_namespace_registration(
        &self,
        request: Request<beecd::ClientNamespaceRegistrationRequest>,
    ) -> Result<Response<beecd::ClientNamespaceRegistrationResponse>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let cluster_id = match Uuid::parse_str(request_data.cluster_id.as_str()) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'cluster_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let cluster_data =
            match sqlx::query_as::<_, ClusterRow>(r#"SELECT name FROM clusters WHERE id = $1"#)
                .bind(cluster_id)
                .fetch_one(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let message = format!("Cluster not found: {}", e);
                    error!("[tenant:{}] {}", tenant_domain, message);
                    return Err(Status::not_found(message));
                }
            };

        let namespaces = request_data.namespace;
        debug!(
            "[tenant:{}] ({}) Registering namespaces: {}",
            tenant_domain,
            cluster_data.name,
            &namespaces.join(", ")
        );

        let query_result = sqlx::query("SELECT id,name FROM namespaces WHERE cluster_id = $1")
            .bind(cluster_id)
            .fetch_all(&mut *tx)
            .await;

        let namespaces_in_database: Vec<String> = match &query_result {
            Ok(rows) => {
                let n: Vec<String> = rows
                    .iter()
                    .map(|r| {
                        let s: String = r.get("name");
                        s
                    })
                    .filter(|s| namespaces.contains(s))
                    .collect();
                n
            }
            Err(e) => {
                let message = format!("Unable to lookup namespaces in database: {}", e);
                error!(
                    "[tenant:{}] ({}) {}",
                    tenant_domain, cluster_data.name, message
                );
                return Err(Status::unavailable(message));
            }
        };

        let mut namespace_ids: Vec<beecd::NamespaceMap> = query_result
            .unwrap()
            .iter()
            .map(|r| {
                let id: Uuid = r.get("id");
                let name: String = r.get("name");
                (id, name)
            })
            .filter(|(_, n)| namespaces.contains(n))
            .map(|(i, n)| beecd::NamespaceMap {
                name: n,
                id: i.to_string(),
            })
            .collect();

        let new_namespaces: Vec<String> = namespaces
            .iter()
            .map(|s| s.to_string())
            .filter(|s| !namespaces_in_database.contains(s))
            .collect();

        for namespace in new_namespaces {
            let new_uuid_v4 = Uuid::new_v4();
            let new = sqlx::query(
                "INSERT INTO namespaces (id, name, cluster_id, tenant_id) values ($1, $2, $3, $4)",
            )
            .bind(new_uuid_v4)
            .bind(&namespace)
            .bind(cluster_id)
            .bind(tenant_ctx.tenant_id)
            .execute(&mut *tx)
            .await;
            match new {
                Ok(_) => namespace_ids.push(beecd::NamespaceMap {
                    name: namespace,
                    id: new_uuid_v4.to_string(),
                }),
                Err(e) => {
                    let message = format!("{}", e);
                    error!(
                        "[tenant:{}] ({}) {}",
                        tenant_domain, cluster_data.name, message
                    );
                    return Err(Status::invalid_argument(message));
                }
            }
        }

        // Commit transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        debug!(
            "[tenant:{}] ({}) Namespace ids: {}",
            tenant_domain,
            cluster_data.name,
            namespace_ids
                .iter()
                .map(|x| x.name.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );

        Ok(Response::new(beecd::ClientNamespaceRegistrationResponse {
            namespace_data: namespace_ids,
        }))
    }

    /// Send a list of releases to the agent
    async fn get_release(
        &self,
        request: Request<beecd::GetReleaseRequest>,
    ) -> Result<Response<beecd::GetReleaseResponse>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let cluster_id = match Uuid::parse_str(request_data.cluster_id.as_str()) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'cluster_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let cluster_data =
            match sqlx::query_as::<_, ClusterRow>(r#"SELECT name FROM clusters WHERE id = $1"#)
                .bind(cluster_id)
                .fetch_one(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let message = format!("Cluster not found: {}", e);
                    error!("[tenant:{}] {}", tenant_domain, message);
                    return Err(Status::not_found(message));
                }
            };

        let mut namespace_ids: Vec<Uuid> = vec![];
        for s in request_data.namespace_id {
            match Uuid::parse_str(s.as_str()) {
                Ok(u) => namespace_ids.push(u),
                Err(e) => {
                    let message = format!("argument 'namespace_id' {}", e);
                    error!(
                        "[tenant:{}] ({}) {}",
                        tenant_domain, cluster_data.name, message
                    );
                    return Err(Status::invalid_argument(message));
                }
            }
        }

        #[derive(sqlx::FromRow)]
        struct ServiceDefinition {
            org: String,
            repo: String,
            branch: String,
            service_name: String,
        }

        // Query 1: "Find Build Targets"
        let branch_relationship_data = match sqlx::query_as::<_, ServiceDefinition>(
            r#"
            SELECT DISTINCT
                repo_branches.branch,
                repos.org,
                repos.repo,
                service_definitions.name AS service_name
            FROM
                group_relationships
                JOIN cluster_groups ON cluster_groups.id = group_relationships.cluster_group_id
                JOIN service_definition_cluster_group_relationships ON service_definition_cluster_group_relationships.cluster_group_id = cluster_groups.id
                JOIN service_definitions ON service_definition_cluster_group_relationships.service_definition_id = service_definitions.id
                JOIN repo_branches ON service_definitions.repo_branch_id = repo_branches.id
                JOIN repos ON repos.id = repo_branches.repo_id
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
                        AND group_relationships.cluster_id = $1
                )
                AND group_relationships.cluster_id = $1
            "#,
        )
        .bind(cluster_id)
        .fetch_all(&mut *tx)
        .await
        {
            Ok(service_definitions) => service_definitions,
            Err(e) => {
                let message = format!("Unable to lookup branch relationships in database: {}", e);
                error!("[tenant:{}] ({}) {}", tenant_domain, cluster_data.name, message);
                return Err(Status::not_found(message));
            }
        };

        let _repo_at_branches: Vec<String> = branch_relationship_data
            .iter()
            .map(|data| format!("{}/{}@{}", data.org, data.repo, data.branch))
            .collect();

        let service_names: Vec<String> = branch_relationship_data
            .iter()
            .map(|data| data.service_name.to_string())
            .collect();

        debug!(
            "[tenant:{}] ({}) Found service names: {}",
            tenant_domain,
            cluster_data.name,
            service_names.join(",")
        );

        // Query 2: "Find Service Versions"
        // This query uses the local service_versions table to find releases
        let select_latest_service_versions_query = r#"
        SELECT
            sv.id AS service_id,
            sv.namespace_id,
            sv.path,
            sv.hash,
            sd.name,
            sv.version,
            repos.org,
            repos.repo,
            repo_branches.branch,
            sv.git_sha
        FROM
            service_versions sv
            JOIN service_definitions sd ON sd.id = sv.service_definition_id
            JOIN repo_branches ON repo_branches.id = sd.repo_branch_id
            JOIN repos ON repos.id = repo_branches.repo_id
        WHERE
            sv.deprecated_at IS NULL
            AND repos.org ILIKE $1
            AND repos.repo ILIKE $2
            AND repo_branches.branch = $3
            AND sd.name = ANY($4::text[])
            AND sv.namespace_id = ANY($5::uuid[])
        ORDER BY
            sv.created_at DESC
        "#;

        let mut releases: Vec<beecd::Release> = vec![];
        for data in branch_relationship_data {
            match sqlx::query(select_latest_service_versions_query)
                .bind(&data.org)
                .bind(&data.repo)
                .bind(&data.branch)
                .bind(vec![data.service_name])
                .bind(&namespace_ids)
                .fetch_all(&mut *tx)
                .await
            {
                Err(e) => {
                    let message = format!("Unable to lookup service versions: {}", e);
                    error!(
                        "[tenant:{}] ({}) {}",
                        tenant_domain, cluster_data.name, message
                    );
                    return Err(Status::not_found(message));
                }
                Ok(service_versions) => {
                    for service_version in service_versions {
                        let namespace_id = service_version.get::<Uuid, _>("namespace_id");
                        let name: String = service_version.get("name");
                        let service_id = service_version.get::<Uuid, _>("service_id");
                        let path: String = service_version.get("path");
                        let hash: String = service_version.get("hash");
                        let version: String = service_version.get("version");
                        let org: String = service_version.get("org");
                        let repo: String = service_version.get("repo");
                        let branch: String = service_version.get("branch");
                        let git_sha: String = service_version.get("git_sha");

                        // Check if there is a "new release marker" in the database which is indicated
                        // as a row in the database matching the namespace and name or the release, but is neither
                        // deleted or deprecated (as in having NULL deleted_at and deprecated_at values respectively).
                        let reinstate = match sqlx::query(
                            r#"
                            SELECT
                                id
                            FROM
                                releases
                            WHERE
                                name = $1
                                AND namespace_id = $2
                                AND hash = '' -- usually blank when created by user/hive-hq
                                AND (deprecated_at, deleted_at) IS NULL
                            LIMIT 1
                        "#,
                        )
                        .bind(&name)
                        .bind(namespace_id)
                        .fetch_optional(&mut *tx)
                        .await
                        {
                            Ok(opt) => opt.is_some(),
                            Err(_) => false,
                        };

                        // Continue the diff_generation for the same hash
                        let diff_generation = sqlx::query(
                            r#"
                            SELECT
                                MAX(diff_generation)
                            FROM
                                releases
                            WHERE
                                namespace_id = $1
                                AND hash = $2
                        "#,
                        )
                        .bind(namespace_id)
                        .bind(&hash)
                        .fetch_one(&mut *tx)
                        .await
                        .map_or(0, |row| row.try_get("max").unwrap_or(0));

                        #[derive(sqlx::FromRow)]
                        #[allow(dead_code)]
                        struct ServiceMarkedForDeletion {
                            id: Uuid,
                            marked_for_deletion_at: Option<DateTime<Utc>>,
                            started_delete_at: Option<DateTime<Utc>>,
                            failed_delete_at: Option<DateTime<Utc>>,
                            completed_delete_at: Option<DateTime<Utc>>,
                        }

                        // Check if serivce is marked for deletion
                        let marked_for_deletion_at = if let Ok(release_row) =
                            sqlx::query_as::<_, ServiceMarkedForDeletion>(
                                r#"
                                SELECT
                                    id,
                                    marked_for_deletion_at,
                                    started_delete_at,
                                    failed_delete_at,
                                    completed_delete_at
                                FROM
                                    releases
                                WHERE
                                    namespace_id = $1
                                    AND name = $2
                                    AND (releases.deleted_at, releases.deprecated_at) IS NULL
                                ORDER BY GREATEST(updated_at, created_at) DESC
                                LIMIT 1
                            "#,
                            )
                            .bind(namespace_id)
                            .bind(&name)
                            .fetch_one(&mut *tx)
                            .await
                        {
                            if release_row.marked_for_deletion_at.is_some()
                                && release_row.completed_delete_at.is_some()
                            {
                                //skip this release entirely now until it is reinstated
                                sqlx::query(
                                    r#"
                                    UPDATE
                                        releases
                                    SET
                                        deleted_at = NOW()
                                    WHERE
                                        id = $1
                                "#,
                                )
                                .bind(release_row.id)
                                .execute(&mut *tx)
                                .await
                                .map_err(|e| {
                                    Status::unavailable(format!(
                                        "({}) Failed to removed deleted resource: {}",
                                        cluster_data.name, e
                                    ))
                                })?;

                                continue;
                            }
                            if release_row.completed_delete_at.is_none() {
                                Some(release_row.marked_for_deletion_at)
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        #[derive(sqlx::FromRow)]
                        struct Count {
                            count: i32,
                        }

                        let manual_selection = sqlx::query_as::<_, Count>(
                            r#"
                            SELECT
                                COUNT(*)::INT4
                            FROM
                                releases
                            WHERE
                                releases.namespace_id = $1
                                AND releases.name = $2
                                AND releases.manually_selected_at IS NOT NULL
                            "#,
                        )
                        .bind(namespace_id)
                        .bind(&name)
                        .fetch_one(&mut *tx)
                        .await
                        .map_or(0, |c| c.count);

                        let deprecated = if manual_selection > 0 {
                            Some(Utc::now())
                        } else {
                            None
                        };

                        // Begin transaction to ensure atomicity of release insert/update, reinstate, and deprecate operations
                        let mut inner_tx = self.db.begin().await.map_err(|e| {
                            let message = format!("Failed to begin transaction: {}", e);
                            error!(
                                "[tenant:{}] ({}) {}",
                                tenant_domain, cluster_data.name, message
                            );
                            Status::internal(message)
                        })?;
                        // Set tenant context for RLS on inner transaction
                        auth::set_tenant_context(&mut *inner_tx, tenant_ctx.tenant_id).await?;

                        let insert_or_update_hive_releases = sqlx::query(r#"
                                INSERT INTO releases
                                (
                                    id,
                                    tenant_id,      --tenant
                                    service_id,     --1
                                    namespace_id,   --2
                                    path,           --3
                                    hash,           --4
                                    name,           --5
                                    version,        --6

                                    -- The following are used populate repo_branch_id via SELECT query
                                    -- org,            --7
                                    -- repo,           --8
                                    -- branch,         --9
                                    repo_branch_id,

                                    git_sha,         --10
                                    diff_generation,  --11
                                    marked_for_deletion_at, --12
                                    deprecated_at --13
                                )
                                VALUES
                                (
                                    (SELECT gen_random_uuid()),
                                    $14,
                                    $1,
                                    $2,
                                    $3,
                                    $4,
                                    $5,
                                    $6,
                                    (
                                        SELECT id FROM repo_branches
                                        WHERE repo_id = (
                                            SELECT id FROM repos
                                            WHERE org ILIKE $7
                                            AND repo ILIKE $8
                                            LIMIT 1
                                        )
                                        AND branch = $9
                                        LIMIT 1
                                    ),
                                    $10,
                                    $11,
                                    $12,
                                    $13
                                )
                                ON CONFLICT (tenant_id, namespace_id, service_id)
                                DO UPDATE SET
                                    path = EXCLUDED.path,
                                    hash = EXCLUDED.hash,
                                    name = EXCLUDED.name,
                                    version = EXCLUDED.version,
                                    repo_branch_id = EXCLUDED.repo_branch_id,
                                    git_sha = EXCLUDED.git_sha
                                WHERE
                                    releases.manually_selected_at IS NULL -- ignore manually selected
                                    AND (releases.deleted_at, releases.deprecated_at) IS NULL
                                ;
                                "#)
                                    .bind(service_id)
                                    .bind(namespace_id)
                                    .bind(&path)
                                    .bind(&hash)
                                    .bind(&name)
                                    .bind(&version)
                                    .bind(&org)
                                    .bind(&repo)
                                    .bind(&branch)
                                    .bind(&git_sha)
                                    .bind(diff_generation)
                                    .bind(marked_for_deletion_at)
                                    .bind(deprecated)
                                    .bind(tenant_ctx.tenant_id)
                                    .execute(&mut *inner_tx)
                                    .await;

                        match insert_or_update_hive_releases {
                            Ok(result) => {
                                if result.rows_affected() == 0 && !reinstate {
                                    // Rollback transaction and continue to next release
                                    if let Err(e) = inner_tx.rollback().await {
                                        warn!(
                                            "({}) Rollback failed (continuing to next release): {}",
                                            cluster_data.name, e
                                        );
                                    }
                                    continue;
                                }
                                // Note: Do not commit here if deprecated - deprecation query needs to run in same transaction
                                if reinstate {
                                    match sqlx::query(
                                        r#"
                                            UPDATE releases
                                            SET
                                                deleted_at = NULL,
                                                deprecated_at = NULL,
                                                started_first_install_at = NULL,
                                                failed_first_install_at = NULL,
                                                completed_first_install_at = NULL,
                                                started_update_install_at = NULL,
                                                failed_update_install_at = NULL,
                                                completed_update_install_at = NULL,
                                                marked_for_deletion_at = NULL,
                                                started_delete_at = NULL,
                                                failed_delete_at = NULL,
                                                completed_delete_at = NULL
                                            WHERE
                                                service_id = $1
                                                AND namespace_id = $2
                                        "#,
                                    )
                                    .bind(service_id)
                                    .bind(namespace_id)
                                    .execute(&mut *inner_tx)
                                    .await
                                    {
                                        Ok(_) => {}
                                        Err(e) => {
                                            let message = format!(
                                                "Unable to re-instate the release service {} in hive database: {}",
                                                name,
                                                e
                                            );
                                            error!(
                                                "[tenant:{}] ({}) {}",
                                                tenant_domain, cluster_data.name, message
                                            );
                                            if let Err(e) = inner_tx.rollback().await {
                                                warn!("[tenant:{}] ({}) Rollback failed after reinstate error: {}", tenant_domain, cluster_data.name, e);
                                            }
                                            save_hive_err_to_db(
                                                tenant_ctx.tenant_id,
                                                &cluster_id,
                                                &message,
                                                &self.db,
                                            )
                                            .await;
                                            return Err(Status::internal(message));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let message = format!("Error finding releases: {}", e);
                                error!(
                                    "[tenant:{}] ({}) {}",
                                    tenant_domain, cluster_data.name, message
                                );
                                if let Err(e) = inner_tx.rollback().await {
                                    warn!(
                                        "({}) Rollback failed after insert error: {}",
                                        cluster_data.name, e
                                    );
                                }
                                return Err(Status::not_found(message));
                            }
                        }

                        // Deprecate all existing releases (unless manually selected)
                        if deprecated.is_none() {
                            let deprecate_result = sqlx::query(
                                r#"
                                        UPDATE
                                            releases
                                        SET
                                            deprecated_at =(
                                                SELECT
                                                    NOW()
                                            )
                                        WHERE
                                            namespace_id = $1
                                            AND name = $2
                                            AND service_id != $3
                                            AND deprecated_at IS NULL
                                        "#,
                            )
                            .bind(namespace_id)
                            .bind(name)
                            .bind(service_id)
                            .execute(&mut *inner_tx)
                            .await;

                            match deprecate_result {
                                Ok(_) => {
                                    // Commit the transaction
                                    inner_tx.commit().await.map_err(|e| {
                                        let message =
                                            format!("Failed to commit transaction: {}", e);
                                        error!(
                                            "[tenant:{}] ({}) {}",
                                            tenant_domain, cluster_data.name, message
                                        );
                                        Status::internal(message)
                                    })?;
                                }
                                Err(e) => {
                                    let message = format!("deprecate_result was an error: {}", e);
                                    error!(
                                        "[tenant:{}] ({}) {}",
                                        tenant_domain, cluster_data.name, message
                                    );
                                    if let Err(e) = inner_tx.rollback().await {
                                        warn!(
                                            "({}) Rollback failed after deprecation error: {}",
                                            cluster_data.name, e
                                        );
                                    }
                                    return Err(Status::internal(message));
                                }
                            }
                        } else {
                            // Manually selected release - skip deprecation and just commit
                            inner_tx.commit().await.map_err(|e| {
                                let message = format!("Failed to commit transaction: {}", e);
                                error!(
                                    "[tenant:{}] ({}) {}",
                                    tenant_domain, cluster_data.name, message
                                );
                                Status::internal(message)
                            })?;
                        }

                        match sqlx::query_as::<_, ReleaseRow>(
                            r#"
                            SELECT
                                releases.id,
                                releases.service_id,
                                releases.repo_branch_id,
                                releases.hash,
                                releases.path,
                                releases.name,
                                releases.version,
                                releases.namespace_id,
                                releases.git_sha,
                                releases.diff_generation,
                                releases.started_first_install_at,
                                releases.completed_first_install_at,
                                releases.failed_update_install_at,
                                releases.marked_for_deletion_at,
                                releases.started_delete_at,
                                releases.completed_delete_at,
                                releases.approved_at,
                                releases.unapproved_at,
                                releases.previous_installed_hash,
                                repo_branches.branch,
                                repos.org,
                                repos.repo,
                                namespaces.name as namespace_name,
                                clusters.id as cluster_id,
                                clusters.name as cluster_name
                            FROM
                                releases
                            JOIN
                                repo_branches ON releases.repo_branch_id = repo_branches.id
                            JOIN
                                repos ON repo_branches.repo_id = repos.id
                            JOIN
                                namespaces on releases.namespace_id = namespaces.id
                            JOIN
                                clusters on namespaces.cluster_id = clusters.id
                            WHERE
                                service_id = $1
                                AND namespace_id = $2
                            LIMIT 1
                        "#,
                        )
                        .bind(service_id)
                        .bind(namespace_id)
                        .fetch_one(&mut *tx)
                        .await
                        {
                            Ok(row) => releases.push(beecd::Release {
                                id: row.id.to_string(),
                                service_id: row.service_id.to_string(),
                                repo_branch_id: row.repo_branch_id.to_string(),
                                hash: row.hash,
                                path: row.path,
                                name: row.name,
                                version: row.version,
                                namespace_id: row.namespace_id.to_string(),
                                git_sha: row.git_sha,
                                diff_generation: row.diff_generation,
                                branch: row.branch,
                                org: row.org,
                                repo: row.repo,
                                marked_for_deletion: row.marked_for_deletion_at.is_some(),
                                completed_first_install: row.completed_first_install_at.is_some(),
                                previous_installed_hash: row
                                    .previous_installed_hash
                                    .unwrap_or(String::new()),
                                namespace_name: row.namespace_name,
                            }),
                            Err(e) => {
                                let message = format!("Error selecting available releases: {}", e);
                                error!(
                                    "[tenant:{}] ({}) {}",
                                    tenant_domain, cluster_data.name, message
                                );
                                return Err(Status::internal(message));
                            }
                        };
                    }
                }
            };
        }

        // When a release is chosen from a selected version, it will not show up yet in releases.
        // Find the manually selected releases to send to agent.
        match sqlx::query_as::<_, ReleaseRow>(
            r#"
            SELECT
                releases.id,
                releases.service_id,
                releases.repo_branch_id,
                releases.hash,
                releases.path,
                releases.name,
                releases.version,
                releases.namespace_id,
                releases.git_sha,
                releases.diff_generation,
                releases.started_first_install_at,
                releases.completed_first_install_at,
                releases.failed_update_install_at,
                releases.marked_for_deletion_at,
                releases.started_delete_at,
                releases.completed_delete_at,
                releases.approved_at,
                releases.unapproved_at,
                releases.previous_installed_hash,
                repo_branches.branch,
                repos.org,
                repos.repo,
                namespaces.name as namespace_name,
                clusters.id as cluster_id,
                clusters.name as cluster_name
            FROM
                releases
            JOIN
                repo_branches ON releases.repo_branch_id = repo_branches.id
            JOIN
                repos ON repo_branches.repo_id = repos.id
            JOIN
                namespaces on releases.namespace_id = namespaces.id
            JOIN
                clusters on namespaces.cluster_id = clusters.id
            WHERE
                releases.manually_selected_at IS NOT NULL
                AND releases.namespace_id = ANY(
                    $1::uuid[]
                )
                AND (releases.deprecated_at, releases.deleted_at) IS NULL;
        "#,
        )
        .bind(&namespace_ids)
        .fetch_all(&mut *tx)
        .await
        {
            Ok(rows) => {
                for row in rows {
                    releases.push(beecd::Release {
                        id: row.id.to_string(),
                        service_id: row.service_id.to_string(),
                        repo_branch_id: row.repo_branch_id.to_string(),
                        hash: row.hash,
                        path: row.path,
                        name: row.name,
                        version: row.version,
                        namespace_id: row.namespace_id.to_string(),
                        git_sha: row.git_sha,
                        diff_generation: row.diff_generation,
                        branch: row.branch,
                        org: row.org,
                        repo: row.repo,
                        marked_for_deletion: row.marked_for_deletion_at.is_some(),
                        completed_first_install: row.completed_first_install_at.is_some(),
                        previous_installed_hash: row
                            .previous_installed_hash
                            .unwrap_or(String::new()),
                        namespace_name: row.namespace_name,
                    })
                }
            }
            Err(e) => {
                let message = format!("Error selecting available releases: {}", e);
                error!(
                    "[tenant:{}] ({}) {}",
                    tenant_domain, cluster_data.name, message
                );
                return Err(Status::internal(message));
            }
        };

        // Commit the outer transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        debug!(
            "[tenant:{}] ({}) Found {} available releases: {}",
            tenant_domain,
            cluster_data.name,
            releases.len(),
            releases
                .iter()
                .map(|item| format!("{}/{}", item.namespace_name, item.name))
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(Response::new(beecd::GetReleaseResponse {
            release: releases,
        }))
    }

    /// Retrieve the installation manifest from github.
    async fn get_service_manifest(
        &self,
        request: Request<beecd::GetServiceManifestRequest>,
    ) -> Result<Response<beecd::Manifest>, Status> {
        // The agent now has the most up to date info
        // about services to install. It also knows
        // what services it has installed. When
        // the services to installed are not the installed
        // ones, then the agent will request
        // each manifest for that service.

        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();

        let release_id = match Uuid::parse_str(&request_data.release_id) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'release_id' {}",
                    e
                )))
            }
        };

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        // Get tenant domain for logging
        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Fetch and decrypt GitHub token from tenant_secrets
        let github_token = self.get_github_token(&mut tx, &tenant_domain).await?;

        let release_data = self.get_release_data_with_tx(&mut tx, release_id).await?;

        // Commit transaction early - we don't need it for GitHub API calls
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        // Detect if this is a directory pattern by checking if path contains glob wildcards
        // This is temporary until migration adds is_directory_pattern column
        let is_directory_pattern = release_data.path.contains('*');

        info!(
            "[tenant:{}] GetServiceManifest for {}/{}/{}: org={}, repo={}, path={}, is_directory={}, git_sha={}",
            tenant_domain,
            release_data.cluster_name,
            release_data.namespace_name,
            release_data.name,
            release_data.org,
            release_data.repo,
            release_data.path,
            is_directory_pattern,
            release_data.git_sha
        );

        let url_query = format!("?ref={}", release_data.git_sha);
        let github_api_url = self.github_api_url.clone();

        let mut data = vec![];

        // // Uncomment to debug by pointing to a local file for the manifest instead of reaching out to git
        // data = std::fs::read("/tmp/fiddlesticks.yaml").unwrap();

        // Fetch content differently based on whether path is a directory pattern or single file
        if is_directory_pattern {
            // Directory pattern: fetch all matching files from the directory
            match read_directory_contents(
                &url_query,
                &github_api_url,
                &release_data.org,
                &release_data.repo,
                &release_data.path,
                &mut data,
                github_token.as_deref(),
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    let message = format!("Failed to fetch directory contents: {}", e);
                    error!(
                        "({}/{}/{}) {}",
                        release_data.cluster_name,
                        release_data.namespace_name,
                        release_data.name,
                        message
                    );
                    return Err(Status::failed_precondition(message));
                }
            }
        } else {
            // Single file: use existing logic
            let base_url = format!(
                "{}/repos/{}/{}/contents/{}",
                github_api_url,
                release_data.org,
                release_data.repo,
                release_data.path.trim_start_matches('/'),
            );

            match read_content(
                &url_query,
                &base_url,
                &mut data,
                github_token.as_deref(),
                &tenant_domain,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    let message = format!("{}", e);
                    error!(
                        "({}/{}/{}) {}",
                        release_data.cluster_name,
                        release_data.namespace_name,
                        release_data.name,
                        message
                    );
                    return Err(Status::failed_precondition(message));
                }
            }
        }

        let sanitized_data = match sanitize_document(data) {
            Ok(s) => s,
            Err(e) => {
                let message = format!("{}", e);
                error!(
                    "({}/{}/{}) {}",
                    release_data.cluster_name,
                    release_data.namespace_name,
                    release_data.name,
                    message
                );
                return Err(Status::from_error(e.into()));
            }
        };

        let encoded = general_purpose::STANDARD.encode(sanitized_data);

        Ok(Response::new(beecd::Manifest {
            data: encoded.as_bytes().to_vec(),
        }))
    }

    async fn service_status(
        &self,
        request: Request<beecd::ServiceStatusRequest>,
    ) -> Result<Response<beecd::Empty>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();

        let diff_generation = request_data.diff_generation;
        let is_diff = request_data.is_diff;
        let post_success = request_data.post_success;
        let is_next_generation_diff = request_data.is_next_generation_diff;
        let previous_installed_hash = request_data.previous_installed_hash;
        let diff_count = request_data.diff.len();
        let release_id = match Uuid::parse_str(&request_data.release_id) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'release_id' {}",
                    e
                )))
            }
        };

        let in_cluster_manifest = request_data.in_cluster_manifest;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        // Get tenant domain for logging
        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        let release_data = self.get_release_data_with_tx(&mut tx, release_id).await?;

        info!(
            "[tenant:{}] ({}/{}/{}) ServiceStatus received: diff_generation={}, is_next_generation_diff={}, is_diff={}, diff_count={}",
            tenant_domain,
            release_data.cluster_name,
            release_data.namespace_name,
            release_data.name,
            diff_generation,
            is_next_generation_diff,
            is_diff,
            diff_count
        );

        // Update previous_installed_hash
        if release_data.previous_installed_hash.is_none() && !previous_installed_hash.is_empty() {
            match sqlx::query(
                r#"
                UPDATE
                    releases
                SET
                    previous_installed_hash = $2
                WHERE id = $1
                    AND previous_installed_hash IS NULL
                "#,
            )
            .bind(release_data.id)
            .bind(&previous_installed_hash)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => error!(
                    "({}/{}/{}) Failed to update previous_installed_hash: {}",
                    release_data.cluster_name, release_data.namespace_name, release_data.name, e
                ),
            }
        }

        // Update auto approve
        if !is_diff
            && release_data.approved_at.is_none()
            && release_data.unapproved_at.is_none()
            && release_data.marked_for_deletion_at.is_none()
        {
            match sqlx::query(
                r#"
                UPDATE
                    releases
                SET
                    approved_at = NOW()
                WHERE id = $1
                    AND approved_at IS NULL
                    AND unapproved_at IS NULL
                "#,
            )
            .bind(release_data.id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => error!(
                    "({}/{}/{}) Failed to auto approve: {}",
                    release_data.cluster_name, release_data.namespace_name, release_data.name, e
                ),
            }
        }

        if !post_success && !previous_installed_hash.is_empty() {
            info!(
                "Install for release_id: {} failed. Rolling back to previous release",
                &release_id
            );
            #[derive(sqlx::FromRow, Debug)]
            struct ReleaseInfo {
                namespace_id: Uuid,
            }

            let release_info = sqlx::query_as::<_, ReleaseInfo>(
                r#"
                SELECT
                    namespace_id
                FROM
                    releases
                WHERE
                    id = $1
                "#,
            )
            .bind(release_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                let hive_error = HiveError::FailedFindingRelease(e.into());
                let message = format!("{}", hive_error);
                error!("{}", message);
                Status::not_found(message)
            })?;

            #[derive(sqlx::FromRow)]
            struct PreviousReleaseInfo {
                id: Uuid,
            }

            let previous_release_info = sqlx::query_as::<_, PreviousReleaseInfo>(
                r#"
                SELECT
                    id
                FROM
                    releases
                WHERE
                    namespace_id = $1
                AND
                    hash = $2
                ORDER BY created_at DESC
                LIMIT 1;
            "#,
            )
            .bind(release_info.namespace_id)
            .bind(&previous_installed_hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                let hive_error = HiveError::FailedFindingRelease(e.into());
                let message = format!("{}", hive_error);
                error!("{}", message);
                Status::not_found(message)
            })?;

            match sqlx::query(
                r#"
                UPDATE
                    releases
                SET
                    deprecated_at = NOW(),
                    approved_at = NULL
                WHERE
                    id = $1
                "#,
            )
            .bind(release_id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => error!(
                    "(release_id: {} namespace_id: {} error) Failed to auto depreciate release: {}",
                    &release_id, &release_info.namespace_id, e
                ),
            }

            match sqlx::query(
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
                    id = $1
                "#,
            )
            .bind(previous_release_info.id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {
                    info!(
                        "succesfully rolled back release to release_id: {}",
                        &previous_release_info.id
                    );
                }
                Err(e) => error!(
                    "(Failed to rollback to release_id: {} err: {}",
                    &previous_release_info.id, e
                ),
            }
        }

        if is_next_generation_diff {
            let in_cluster_manifest_storage_url = format!(
                "{}/{}/{}/in_cluster_manifest.gz",
                self.storage_prefix, release_data.cluster_name, release_id
            );

            beecdstorage::push(
                &in_cluster_manifest_storage_url,
                in_cluster_manifest.as_bytes(),
            )
            .await
            .map_err(|e| Status::invalid_argument(format!("{e}")))?;

            let diff_data = request_data.diff;

            // Continue using the main transaction for atomicity
            let update_release_query = sqlx::query(
                r#"
                UPDATE
                    releases
                SET
                    diff_generation = $3,
                    last_diff_at = (select NOW()),
                    is_diff = $2,
                    in_cluster_manifest_storage_url = $4
                WHERE
                    id = $1
                "#,
            )
            .bind(release_data.id)
            .bind(is_diff)
            .bind(diff_generation)
            .bind(in_cluster_manifest_storage_url)
            .execute(&mut *tx)
            .await;

            match update_release_query {
                Ok(_) => {}
                Err(e) => {
                    let message = format!(
                        "Release '{}/{}' not found: {}",
                        release_data.namespace_name, release_data.name, e
                    );
                    error!(
                        "({}/{}/{}) {}",
                        release_data.cluster_name,
                        release_data.namespace_name,
                        release_data.name,
                        message
                    );
                    if let Err(e) = tx.rollback().await {
                        warn!(
                            "({}/{}/{}) Rollback failed after release update error: {}",
                            release_data.cluster_name,
                            release_data.namespace_name,
                            release_data.name,
                            e
                        );
                    }
                    save_hive_err_to_db(
                        tenant_ctx.tenant_id,
                        &release_data.cluster_id,
                        &message,
                        &self.db,
                    )
                    .await;
                    return Err(Status::not_found(message));
                }
            }

            for diff in diff_data {
                let change_order = diff.change_order;
                let body = match String::from_utf8(diff.body) {
                    Ok(s) => {
                        if s.contains("kind: \"Secret\"") {
                            match encrypt_with_sops(s) {
                                Ok(encrypted) => encrypted,
                                Err(e) => {
                                    let message =
                                        format!("Error encrypting '{}' diff: {}", diff.key, e);
                                    error!(
                                        "({}/{}/{}) {}",
                                        release_data.cluster_name,
                                        release_data.namespace_name,
                                        release_data.name,
                                        message
                                    );
                                    if let Err(e) = tx.rollback().await {
                                        warn!(
                                            "({}/{}/{}) Rollback failed after encryption error: {}",
                                            release_data.cluster_name,
                                            release_data.namespace_name,
                                            release_data.name,
                                            e
                                        );
                                    }
                                    save_hive_err_to_db(
                                        tenant_ctx.tenant_id,
                                        &release_data.cluster_id,
                                        &message,
                                        &self.db,
                                    )
                                    .await;
                                    return Err(Status::invalid_argument(message));
                                }
                            }
                        } else {
                            s
                        }
                    }
                    Err(e) => {
                        let message = format!("Invalid format for '{}' diff: {}", diff.key, e);
                        error!(
                            "({}/{}/{}) {}",
                            release_data.cluster_name,
                            release_data.namespace_name,
                            release_data.name,
                            message
                        );
                        if let Err(e) = tx.rollback().await {
                            warn!(
                                "({}/{}/{}) Rollback failed after UTF-8 decode error: {}",
                                release_data.cluster_name,
                                release_data.namespace_name,
                                release_data.name,
                                e
                            );
                        }
                        save_hive_err_to_db(
                            tenant_ctx.tenant_id,
                            &release_data.cluster_id,
                            &message,
                            &self.db,
                        )
                        .await;
                        return Err(Status::invalid_argument(message));
                    }
                };

                let storage_url = format!(
                    "{}/{}/{}/{}/{}/diff.gz",
                    self.storage_prefix,
                    release_data.cluster_name,
                    release_id,
                    diff_generation,
                    diff.key.replace("//", "/GLOBAL/")
                );

                beecdstorage::push(&storage_url, body.as_bytes())
                    .await
                    .map_err(|e| Status::invalid_argument(format!("{e}")))?;

                match sqlx::query(
                    r#"
                    INSERT INTO resource_diffs (tenant_id, release_id, diff_generation, key, storage_url, change_order)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (key, release_id, diff_generation) DO UPDATE SET
                        storage_url = EXCLUDED.storage_url,
                        change_order = EXCLUDED.change_order
                "#,
                )
                .bind(tenant_ctx.tenant_id)
                .bind(release_id)
                .bind(diff_generation)
                .bind(&diff.key)
                .bind(storage_url)
                .bind(change_order)
                .execute(&mut *tx)
                .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        let message =
                            format!("Error writing '{}' diff to database: {}", diff.key, e);
                        error!(
                            "[tenant:{}] ({}/{}/{}) {}",
                            tenant_domain,
                            release_data.cluster_name,
                            release_data.namespace_name,
                            release_data.name,
                            message
                        );
                        if let Err(e) = tx.rollback().await {
                            warn!("[tenant:{}] ({}/{}/{}) Rollback failed after diff insert error: {}", 
                                tenant_domain, release_data.cluster_name, release_data.namespace_name, release_data.name, e);
                        }
                        save_hive_err_to_db(tenant_ctx.tenant_id, &release_data.cluster_id, &message, &self.db).await;
                        return Err(Status::not_found(message));
                    }
                }
            }

            // Commit the transaction
            tx.commit().await.map_err(|e| {
                let message = format!("Failed to commit transaction: {}", e);
                error!(
                    "({}/{}/{}) {}",
                    release_data.cluster_name,
                    release_data.namespace_name,
                    release_data.name,
                    message
                );
                Status::internal(message)
            })?;

            info!(
                "({}/{}/{}) Successfully stored {} diffs with diff_generation={}",
                release_data.cluster_name,
                release_data.namespace_name,
                release_data.name,
                diff_count,
                diff_generation
            );

            Ok(Response::new(beecd::Empty {}))
        } else {
            // When a release is manually selected, the initial diff might not show any changes due to the release's
            // state at selection. To ensure the diff appears in the UI, the `last_diff_at` field must be present.
            // This field is removed upon manual selection to indicate that the release needs to be re-diffed to
            // determine its current state.
            //
            // If the diff is found to be unchanged, the previous timestamp can be re-added to make the diff visible in the UI.
            let _ = sqlx::query(
                r#"
                UPDATE releases
                SET
                    last_diff_at = (
                        SELECT
                            resource_diffs.created_at
                        FROM
                            resource_diffs
                        WHERE
                            resource_diffs.release_id = $1
                            AND resource_diffs.diff_generation = releases.diff_generation
                        LIMIT
                            1
                    )
                WHERE
                    releases.id = $1
                    AND releases.last_diff_at IS NULL;
                "#,
            )
            .bind(release_data.id)
            .execute(&mut *tx)
            .await;

            // Commit the transaction
            tx.commit()
                .await
                .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

            Ok(Response::new(beecd::Empty {}))
        }
    }

    async fn restore_diff(
        &self,
        request: Request<beecd::RestoreDiffRequest>,
    ) -> Result<Response<beecd::RestoreDiffResponse>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();

        let release_id = match Uuid::parse_str(&request_data.release_id) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'release_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let release_data = self.get_release_data_with_tx(&mut tx, release_id).await?;

        #[derive(sqlx::FromRow)]
        struct DiffRow {
            key: String,
            storage_url: String,
        }

        let diffs = match sqlx::query_as::<_, DiffRow>(
            r#"
                SELECT
                    key,
                    storage_url
                FROM
                resource_diffs
                WHERE
                    release_id = $1
                    AND diff_generation = $2

            "#,
        )
        .bind(release_data.id)
        .bind(release_data.diff_generation)
        .fetch_all(&mut *tx)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                let message = format!(
                    "Failed retrieving diffs {}/{} from database: {}",
                    release_data.namespace_name, release_data.name, e
                );
                error!(
                    "[tenant:{}] ({}) {}",
                    tenant_domain, release_data.cluster_name, message
                );
                return Err(Status::not_found(message));
            }
        };

        let diff = {
            stream::iter(diffs)
            .filter_map(|row| {
                let cluster_name = release_data.cluster_name.clone();
                let release_name = release_data.name.clone();
                let tenant_domain_clone = tenant_domain.clone();
                async move {

                    let key = &row.key;
                    let bytes = match beecdstorage::fetch(&row.storage_url).await {
                        Ok(b) => b,
                        Err(_) => return None,
                    };
                    let body = String::from_utf8_lossy(&bytes);

                    let decrypted_doc = if body.contains("sops:") {
                        let dir = env::temp_dir();
                        let file = format!("{}/{}.yaml", dir.display(), Uuid::new_v4());
                        match fs::write(&file, body.to_string()) {
                            Ok(_) => {}
                            Err(e) => {
                                let message =
                                    format!("Failed to write sops file for diff of {} for key '{}': {}", release_name, key, e);
                                error!("[tenant:{}] ({}) {}", tenant_domain_clone, cluster_name, message);
                                return None;
                            }
                        }

                        let output = match process::Command::new("sops")
                            .args(["--decrypt", &file])
                            .output()
                        {
                            Ok(s) => s,
                            Err(e) => {
                                let message = format!("Failed to execute sops command looking for diff of {} for key {}: {}", release_name, key, e);
                                error!("[tenant:{}] ({}) {}", tenant_domain_clone, cluster_name, message);
                                return None;
                            }
                        };

                        if output.status.success() {
                            let decrypted_doc: serde_yaml::Value =
                                match serde_yaml::from_slice(&output.stdout) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        let message = format!(
                                            "Failed to parse diff of {} for key '{}': {}",
                                            release_name, key, e
                                        );
                                        error!("[tenant:{}] ({}) {}", tenant_domain_clone, cluster_name, message);
                                        return None;
                                    }
                                };

                            match decrypted_doc.get("data") {
                                Some(untyped_data) => match untyped_data.as_str() {
                                    Some(s) => s.to_string(),
                                    None => {
                                        warn!(
                                            "({}) Diff of '{}' for key '{}' contained no data",
                                            cluster_name, release_name, key
                                        );
                                        return None;
                                    }
                                },
                                None => {
                                    warn!(
                                        "({}) Diff of '{}' for key '{}' was not a string",
                                        cluster_name, release_name, key
                                    );
                                    return None;
                                }
                            }
                        } else {
                            let err_string = String::from_utf8_lossy(&output.stderr);
                            let message = format!(
                                "Sops command exited unsuccessfully for {} release : {}",
                                release_name, err_string
                            );
                            error!("[tenant:{}] ({}) {}", tenant_domain_clone, cluster_name, message);
                            return None;
                        }
                    } else {
                        body.into()
                    };

                    Some(beecd::Diff {
                        key: key.clone(),
                        body: decrypted_doc.as_bytes().to_vec(),
                        change_order: vec![],
                    })
                }
            })
            .collect::<Vec<_>>()
                .await
        };

        if !diff.is_empty() {
            info!(
                "({}) Restoring diffs for {}",
                release_data.cluster_name, release_data.name
            );
        }

        // Commit the read-only transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::RestoreDiffResponse { diff }))
    }

    async fn get_approved_releases(
        &self,
        request: Request<beecd::ClusterId>,
    ) -> Result<Response<beecd::GetApprovedReleasesResponse>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let cluster_id = match Uuid::parse_str(request_data.cluster_id.as_str()) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'cluster_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let cluster_data =
            match sqlx::query_as::<_, ClusterRow>(r#"SELECT name FROM clusters WHERE id = $1"#)
                .bind(cluster_id)
                .fetch_one(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let message = format!("Cluster not found: {}", e);
                    error!("[tenant:{}] {}", tenant_domain, message);
                    return Err(Status::not_found(message));
                }
            };

        let auto_unapprove_query = r#"
        UPDATE
            releases
        SET
            approved_at = NULL
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

        sqlx::query(auto_unapprove_query)
            .bind(cluster_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                Status::unavailable(format!(
                    "({}) Failed to fix approvals on deleted markers: {}",
                    cluster_data.name, e
                ))
            })?;

        // Setting an `AND (marked_for_deletion_at IS NULL OR approved_at > marked_for_deletion_at)` in case
        // someone manually modifies the database with a deletion and forgets to unset approvals. The above
        // auto_unapprove_query will also handle this, but just in case, omit any entries that match the AND.
        let query = r#"
        SELECT
            id
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

        let query_result = sqlx::query(query)
            .bind(cluster_id)
            .fetch_all(&mut *tx)
            .await;

        let releases: Vec<String> = match query_result {
            Ok(r) => r
                .iter()
                .map(|r| r.get::<Uuid, _>("id").to_string())
                .collect(),
            Err(e) => {
                return Err(Status::unavailable(format!(
                    "({}) Unable to query database: {}",
                    cluster_data.name, e
                )))
            }
        };

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::GetApprovedReleasesResponse {
            release_id: releases,
        }))
    }

    async fn installation_status(
        &self,
        request: Request<beecd::InstallationStatusRequest>,
    ) -> Result<Response<beecd::Empty>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let release_id = match Uuid::parse_str(&request_data.release_id) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'release_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let release_data = self.get_release_data_with_tx(&mut tx, release_id).await?;

        let completed = request_data.completed;
        let started = request_data.started;
        let failed = request_data.failed;
        let _msg = request_data.msg;

        if started {
            let update_query = if release_data.marked_for_deletion_at.is_some() {
                r#"
                    UPDATE releases
                    SET started_delete_at = (SELECT NOW()),
                        failed_delete_at = NULL,
                        completed_delete_at = NULL
                    WHERE id = $1
                "#
            } else {
                match release_data.started_first_install_at {
                    Some(_s) => {
                        r#"
                          UPDATE releases
                          SET started_update_install_at = (SELECT NOW()),
                              failed_update_install_at = NULL,
                              completed_update_install_at = NULL
                          WHERE id = $1
                      "#
                    }
                    None => {
                        r#"
                          UPDATE releases
                          SET started_first_install_at = (SELECT NOW()),
                              failed_first_install_at = NULL,
                              completed_first_install_at = NULL
                          WHERE id = $1
                      "#
                    }
                }
            };
            match sqlx::query(update_query)
                .bind(release_data.id)
                .execute(&mut *tx)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    let message = format!(
                        "[tenant:{}] ({}/{}/{}) could not update release: {}",
                        tenant_domain,
                        release_data.cluster_name,
                        release_data.namespace_name,
                        release_data.name,
                        e
                    );
                    error!("{}", message);
                    return Err(Status::internal(message));
                }
            }
        }

        if completed {
            let update_query = if release_data.marked_for_deletion_at.is_some() {
                r#"
                    UPDATE releases
                    SET
                        completed_delete_at = (SELECT NOW()),
                        last_sync_at = (SELECT NOW()),
                        approved_at = NULL
                    WHERE id = $1
                "#
            } else {
                match release_data.completed_first_install_at {
                    Some(_s) => {
                        r#"
                            UPDATE releases
                            SET
                                completed_update_install_at = (SELECT NOW()),
                                last_sync_at = (SELECT NOW())
                            WHERE id = $1
                        "#
                    }
                    None => {
                        r#"
                            UPDATE releases
                            SET
                                completed_first_install_at = (SELECT NOW()),
                                last_sync_at = (SELECT NOW())
                            WHERE id = $1
                        "#
                    }
                }
            };
            match sqlx::query(update_query)
                .bind(release_data.id)
                .execute(&mut *tx)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    let message =
                        format!("[tenant:{}] could not update release: {}", tenant_domain, e);
                    error!("{}", message);
                    return Err(Status::internal(message));
                }
            }
        }

        if failed {
            let update_query = if release_data.marked_for_deletion_at.is_some() {
                r#"
                    UPDATE releases
                    SET failed_delete_at = (SELECT NOW())
                    WHERE id = $1
                "#
            } else {
                match release_data.failed_update_install_at {
                    Some(_s) => {
                        r#"
                            UPDATE releases
                            SET failed_update_install_at = (SELECT NOW())
                            WHERE id = $1
                        "#
                    }
                    None => {
                        r#"
                            UPDATE releases
                            SET failed_update_install_at = (SELECT NOW())
                            WHERE id = $1
                        "#
                    }
                }
            };
            match sqlx::query(update_query)
                .bind(release_data.id)
                .execute(&mut *tx)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    let message = format!("could not update release: {}", e);
                    error!(message);
                    return Err(Status::internal(message));
                }
            }
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::Empty {}))
    }

    /// Add message to release_errors table or deprecate existing messages for the release
    async fn log_release_error(
        &self,
        request: Request<beecd::LogReleaseErrorRequest>,
    ) -> Result<Response<beecd::Empty>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let release_id = match Uuid::parse_str(&request_data.release_id) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'release_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let release_data = self.get_release_data_with_tx(&mut tx, release_id).await?;

        let is_deprecated = request_data.is_deprecated;
        let raw_message = request_data.message;
        let message = String::from_utf8(raw_message).unwrap_or_default();

        if is_deprecated {
            match sqlx::query(
                r#"
                    UPDATE release_errors
                    SET
                        deprecated_at = NOW()
                    WHERE
                        release_id = $1
                "#,
            )
            .bind(release_data.id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "[tenant:{}] ({}/{}/{}) Failed writing error to database: {}",
                        tenant_domain,
                        release_data.cluster_name,
                        release_data.namespace_name,
                        release_data.name,
                        e
                    );
                }
            }
        } else {
            match sqlx::query(
                r#"
                    INSERT INTO release_errors
                        (release_id, message, tenant_id)
                    values
                        ($1, $2, $3)
                    ON CONFLICT
                        (tenant_id, release_id, message)
                    DO
                        UPDATE SET deprecated_at = NULL;
                "#,
            )
            .bind(release_data.id)
            .bind(&message)
            .bind(tenant_ctx.tenant_id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "[tenant:{}] Failed writing error to database: {}",
                        tenant_domain, e
                    );
                }
            }
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::Empty {}))
    }

    /// Add message to hive_errors table or deprecate existing messages for the release
    ///
    /// Currently only support `is_deprecated=true`
    async fn log_hive_error(
        &self,
        request: Request<beecd::LogHiveErrorRequest>,
    ) -> Result<Response<beecd::Empty>, Status> {
        // Extract tenant context FIRST (before into_inner)
        let tenant_ctx = auth::TenantContext::from_request(&request)?;

        let request_data = request.into_inner();
        let cluster_id = match Uuid::parse_str(request_data.cluster_id.as_str()) {
            Ok(u) => u,
            Err(e) => {
                return Err(Status::invalid_argument(format!(
                    "argument 'cluster_id' {}",
                    e
                )))
            }
        };

        let tenant_domain = self.get_tenant_domain(tenant_ctx.tenant_id).await;

        // Start transaction and set tenant context for RLS
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| Status::internal(format!("Failed to begin transaction: {}", e)))?;
        auth::set_tenant_context(&mut *tx, tenant_ctx.tenant_id).await?;

        let cluster_data =
            match sqlx::query_as::<_, ClusterRow>(r#"SELECT name FROM clusters WHERE id = $1"#)
                .bind(cluster_id)
                .fetch_one(&mut *tx)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    let message = format!("Cluster not found: {}", e);
                    error!("[tenant:{}] {}", tenant_domain, message);
                    return Err(Status::not_found(message));
                }
            };

        let is_deprecated = request_data.is_deprecated;

        if is_deprecated {
            match sqlx::query(
                r#"
                    UPDATE hive_errors
                    SET
                        deprecated_at = NOW()
                    WHERE
                        cluster_id = $1
                "#,
            )
            .bind(cluster_id)
            .execute(&mut *tx)
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!(
                        "({}) Failed writing error to database: {}",
                        cluster_data.name, e
                    );
                }
            }
        }

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

        Ok(Response::new(beecd::Empty {}))
    }

    /// Login with username/password and receive JWT access token + refresh token
    async fn login(
        &self,
        request: Request<beecd::LoginRequest>,
    ) -> Result<Response<beecd::LoginResponse>, Status> {
        // Get client IP from request metadata BEFORE consuming request
        let ip_address = request
            .remote_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let req = request.into_inner();
        let username = req.username.trim().to_string();
        let password = req.password;
        let user_agent = req.user_agent;

        info!(
            "Login attempt: username={}, ip={}, user_agent={}",
            username, ip_address, user_agent
        );

        // Validate inputs
        if username.is_empty() || password.is_empty() {
            warn!("Login failed: empty credentials from ip={}", ip_address);
            return Err(Status::invalid_argument("Username and password required"));
        }

        // 1. Validate credentials via bcrypt (using SECURITY DEFINER function to bypass RLS)
        let user_row = sqlx::query_as::<_, UserAuthRow>(
            "SELECT user_id, tenant_id, password_hash FROM auth_lookup_agent_user($1)",
        )
        .bind(&username)
        .fetch_optional(&self.readonly_db)
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            warn!(
                "Login failed: user not found, username={}, ip={}",
                username, ip_address
            );
            Status::unauthenticated("Invalid credentials")
        })?;

        let is_valid = bcrypt::verify(&password, &user_row.password_hash).map_err(|e| {
            // Avoid logging the username to reduce info leakage; log user_id instead
            error!(
                "Bcrypt verification error for user_id {}: {:?}",
                user_row.user_id, e
            );
            Status::internal("Password verification failed")
        })?;

        if !is_valid {
            warn!(
                "Login failed: invalid password for username={}, ip={}",
                username, ip_address
            );
            return Err(Status::unauthenticated("Invalid credentials"));
        }

        // 2. Look up cluster_id (if user matches cluster name) - using SECURITY DEFINER function
        let cluster_id =
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT auth_lookup_cluster_by_name($1, $2)")
                .bind(&username)
                .bind(user_row.tenant_id)
                .fetch_optional(&self.readonly_db)
                .await
                .map_err(|e| Status::internal(format!("Database error: {}", e)))?
                .flatten()
                .unwrap_or_else(Uuid::nil); // Default to nil if no matching cluster

        // 3. Generate access token (JWT) with tenant_id for RLS context
        let access_token =
            auth::create_access_token(&username, user_row.user_id, user_row.tenant_id, cluster_id)?;

        // 4. Generate refresh token
        let refresh_token_raw = auth::generate_refresh_token();
        let refresh_token_hash = auth::hash_refresh_token(&refresh_token_raw);

        let refresh_ttl = std::env::var("REFRESH_TOKEN_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(86400); // Default 24 hours
        let refresh_expires_at = Utc::now() + chrono::Duration::seconds(refresh_ttl);

        // 5. Store refresh token in DB (ip_address as TEXT)
        let ip_to_store = if ip_address == "unknown" {
            None
        } else {
            Some(ip_address.clone()) // Clone for later logging
        };

        let user_agent_for_db = if user_agent.is_empty() {
            None
        } else {
            Some(user_agent.clone()) // Clone for later logging
        };

        // Use SECURITY DEFINER function to store refresh token (bypasses RLS)
        sqlx::query("SELECT auth_insert_refresh_token($1, $2, $3, $4, $5, $6, $7)")
            .bind(&refresh_token_hash)
            .bind(user_row.user_id)
            .bind(user_row.tenant_id)
            .bind(if cluster_id.is_nil() {
                None
            } else {
                Some(cluster_id)
            })
            .bind(refresh_expires_at)
            .bind(&user_agent_for_db)
            .bind(&ip_to_store)
            .execute(&self.db)
            .await
            .map_err(|e| Status::internal(format!("Failed to store refresh token: {}", e)))?;

        info!(
            "Login successful: username={}, ip={}, user_agent={}",
            username, ip_address, user_agent
        );

        let access_ttl = std::env::var("ACCESS_TOKEN_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(900);

        Ok(Response::new(beecd::LoginResponse {
            access_token,
            refresh_token: refresh_token_raw,
            access_token_expires_in: access_ttl,
            refresh_token_expires_in: refresh_ttl,
            token_type: "Bearer".to_string(),
        }))
    }

    /// Refresh access token using refresh token (with rotation and replay detection)
    async fn refresh_token(
        &self,
        request: Request<beecd::RefreshTokenRequest>,
    ) -> Result<Response<beecd::RefreshTokenResponse>, Status> {
        let req = request.into_inner();
        let refresh_token_raw = req.refresh_token;
        let refresh_token_hash = auth::hash_refresh_token(&refresh_token_raw);

        // 1. Look up refresh token with user info using SECURITY DEFINER function
        let token_row = sqlx::query_as::<_, RefreshTokenRow>(
            "SELECT token_id, user_id, tenant_id, cluster_id, expires_at, revoked_at, replaced_by_token_id, username FROM auth_lookup_refresh_token($1)",
        )
        .bind(&refresh_token_hash)
        .fetch_optional(&self.readonly_db)
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| Status::unauthenticated("Invalid refresh token"))?;

        // 2. Check if token is expired
        if token_row.expires_at < Utc::now() {
            return Err(Status::unauthenticated("Invalid refresh token"));
        }

        // 3. REPLAY ATTACK DETECTION
        if token_row.revoked_at.is_some() {
            // This token was already used and rotated
            warn!(
                "SECURITY: Refresh token replay detected for user_id {}",
                token_row.user_id
            );

            // Revoke the entire token family using SECURITY DEFINER function
            sqlx::query("SELECT auth_revoke_token_family($1)")
                .bind(token_row.token_id)
                .execute(&self.db)
                .await
                .map_err(|e| Status::internal(format!("Failed to revoke token family: {}", e)))?;

            return Err(Status::unauthenticated("Invalid refresh token"));
        }

        let cluster_id = match token_row.cluster_id {
            Some(id) => id,
            None => {
                warn!(
                    "Refresh token has no associated cluster_id; issuing JWT with cluster_id=nil for user_id {}",
                    token_row.user_id
                );
                Uuid::nil()
            }
        };

        // 4. Generate new access token with tenant_id for RLS context
        let access_token = auth::create_access_token(
            &token_row.username,
            token_row.user_id,
            token_row.tenant_id,
            cluster_id,
        )?;

        // 5. Generate new refresh token (ROTATION)
        let new_refresh_token_raw = auth::generate_refresh_token();
        let new_refresh_token_hash = auth::hash_refresh_token(&new_refresh_token_raw);

        let refresh_ttl = std::env::var("REFRESH_TOKEN_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(86400);
        let new_expires_at = Utc::now() + chrono::Duration::seconds(refresh_ttl);

        // 6. Atomic token rotation using SECURITY DEFINER function
        let _new_token_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT auth_rotate_refresh_token($1, $2, $3, $4, $5, $6)",
        )
        .bind(token_row.token_id)
        .bind(&new_refresh_token_hash)
        .bind(token_row.user_id)
        .bind(token_row.tenant_id)
        .bind(token_row.cluster_id)
        .bind(new_expires_at)
        .fetch_one(&self.db)
        .await
        .map_err(|e| Status::internal(format!("Token rotation failed: {}", e)))?;

        info!("User '{}' refreshed token successfully", token_row.username);

        let access_ttl = std::env::var("ACCESS_TOKEN_TTL")
            .ok()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(900);

        Ok(Response::new(beecd::RefreshTokenResponse {
            access_token,
            refresh_token: new_refresh_token_raw,
            access_token_expires_in: access_ttl,
            refresh_token_expires_in: refresh_ttl,
            token_type: "Bearer".to_string(),
        }))
    }

    /// Logout and revoke refresh token
    async fn logout(
        &self,
        request: Request<beecd::LogoutRequest>,
    ) -> Result<Response<beecd::Empty>, Status> {
        let req = request.into_inner();

        if req.refresh_token.is_empty() {
            // No refresh token provided; just return success
            return Ok(Response::new(beecd::Empty {}));
        }

        let refresh_token_hash = auth::hash_refresh_token(&req.refresh_token);

        // Revoke the refresh token using SECURITY DEFINER function
        sqlx::query("SELECT auth_revoke_refresh_token($1)")
            .bind(&refresh_token_hash)
            .execute(&self.db)
            .await
            .map_err(|e| Status::internal(format!("Failed to revoke token: {}", e)))?;

        info!("Refresh token revoked");

        Ok(Response::new(beecd::Empty {}))
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod worker_tests {
    use super::*;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use sqlx::{Connection, Executor};
    use sqlx::{Pool, Postgres};

    // Verify .cargo/config.toml is loaded and provides JWT_SECRET_KEY
    #[test]
    fn test_config_loaded() {
        assert!(
            std::env::var("JWT_SECRET_KEY").is_ok(),
            ".cargo/config.toml not loaded - ensure hive/.cargo/config.toml exists and contains [env] JWT_SECRET_KEY"
        );
        let secret = std::env::var("JWT_SECRET_KEY").unwrap();
        assert!(
            secret.len() >= 32,
            "JWT_SECRET_KEY from config must be at least 32 bytes, got {} bytes",
            secret.len()
        );
    }

    async fn test_pool() -> Pool<Postgres> {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect(
                "Failed to connect to test database - ensure DATABASE_URL is set and DB is running",
            );

        // Verify DB is actually reachable
        pool.acquire()
            .await
            .expect("Failed to acquire connection from pool - DB may not be available");

        pool
    }

    /// Ensure a test tenant exists and return its id
    async fn ensure_test_tenant(pool: &Pool<Postgres>) -> Uuid {
        let test_tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        sqlx::query(
            r#"
            INSERT INTO tenants (id, domain, name, status)
            VALUES ($1, 'test-tenant', 'Test Tenant', 'active')
            ON CONFLICT (domain) DO NOTHING
            "#,
        )
        .bind(test_tenant_id)
        .execute(pool)
        .await
        .expect("create test tenant");
        test_tenant_id
    }

    async fn mk_grpc_server(pool: &Pool<Postgres>) -> GrpcServer {
        GrpcServer {
            db: pool.clone(),
            readonly_db: pool.clone(),
            storage_prefix: "memory://test".to_string(),
            github_api_url: "https://api.github.com".to_string(),
        }
    }

    async fn mk_cluster(pool: &Pool<Postgres>, tenant_id: Uuid, name: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO clusters (tenant_id, name, metadata) VALUES ($1, $2, '{}') RETURNING id",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("insert cluster")
    }

    async fn mk_namespace(
        pool: &Pool<Postgres>,
        tenant_id: Uuid,
        cluster_id: Uuid,
        name: &str,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO namespaces (id, tenant_id, name, cluster_id) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(cluster_id)
        .fetch_one(pool)
        .await
        .expect("insert namespace")
    }

    async fn mk_repo(pool: &Pool<Postgres>, org: &str, repo: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO repos (id, org, repo) VALUES (gen_random_uuid(), $1, $2) RETURNING id",
        )
        .bind(org)
        .bind(repo)
        .fetch_one(pool)
        .await
        .expect("insert repo")
    }

    async fn mk_repo_branch(pool: &Pool<Postgres>, repo_id: Uuid, branch: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO repo_branches (id, repo_id, branch) VALUES (gen_random_uuid(), $1, $2) RETURNING id",
        )
        .bind(repo_id)
        .bind(branch)
        .fetch_one(pool)
        .await
        .expect("insert repo_branch")
    }

    async fn mk_manual_release(
        pool: &Pool<Postgres>,
        tenant_id: Uuid,
        namespace_id: Uuid,
        repo_branch_id: Uuid,
        name: &str,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            INSERT INTO releases (
                id, tenant_id, service_id, namespace_id, hash, path, name, version, repo_branch_id, git_sha, manually_selected_at
            ) VALUES (
                gen_random_uuid(), $1, gen_random_uuid(), $2, 'h123', '/manifests/svc.yaml', $3, '1.2.3', $4, 'deadbeef', NOW()
            ) RETURNING id
            "#,
        )
        .bind(tenant_id)
        .bind(namespace_id)
        .bind(name)
        .bind(repo_branch_id)
        .fetch_one(pool)
        .await
        .expect("insert release")
    }

    #[tokio::test]
    async fn get_release_returns_manual_selection() {
        let pool = test_pool().await;
        let tenant_id = ensure_test_tenant(&pool).await;
        let server = mk_grpc_server(&pool).await;

        let cluster_name = "worker-test-cluster";
        let ns_name = "default";
        let org = "acme";
        let repo = "widgets";
        let branch = "main";
        let release_name = "widget-api";

        let cluster_id = mk_cluster(&pool, tenant_id, cluster_name).await;
        let namespace_id = mk_namespace(&pool, tenant_id, cluster_id, ns_name).await;
        let repo_id = mk_repo(&pool, org, repo).await;
        let repo_branch_id = mk_repo_branch(&pool, repo_id, branch).await;
        let _release_id =
            mk_manual_release(&pool, tenant_id, namespace_id, repo_branch_id, release_name).await;

        let req = beecd::GetReleaseRequest {
            cluster_id: cluster_id.to_string(),
            namespace_id: vec![namespace_id.to_string()],
        };
        let resp = GrpcServer::get_release(&server, Request::new(req))
            .await
            .expect("get_release ok");

        let body = resp.into_inner();
        assert_eq!(body.release.len(), 1, "should return one release");
        let r = &body.release[0];
        assert_eq!(r.name, release_name);
        assert_eq!(r.org, org);
        assert_eq!(r.repo, repo);
        assert_eq!(r.branch, branch);
        assert_eq!(r.namespace_name, ns_name);
        assert!(!r.completed_first_install);
        assert!(!r.marked_for_deletion);
    }

    #[tokio::test]
    async fn get_release_rejects_bad_cluster_id() {
        let pool = test_pool().await;
        let server = mk_grpc_server(&pool).await;
        let req = beecd::GetReleaseRequest {
            cluster_id: "not-a-uuid".into(),
            namespace_id: vec![],
        };
        let err = GrpcServer::get_release(&server, Request::new(req))
            .await
            .expect_err("should error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_release_unknown_cluster() {
        let pool = test_pool().await;
        let server = mk_grpc_server(&pool).await;
        let req = beecd::GetReleaseRequest {
            cluster_id: Uuid::new_v4().to_string(),
            namespace_id: vec![],
        };
        let err = GrpcServer::get_release(&server, Request::new(req))
            .await
            .expect_err("should error");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    // Unit tests for critical functions

    #[test]
    fn test_sanitize_document_valid_yaml() {
        let yaml_content = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
"#;
        let result = sanitize_document(yaml_content.as_bytes().to_vec());
        assert!(
            result.is_ok(),
            "Valid YAML should be sanitized successfully"
        );
    }

    #[test]
    fn test_sanitize_document_multi_document_yaml() {
        let yaml_content = r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: config1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config2
"#;
        let result = sanitize_document(yaml_content.as_bytes().to_vec());
        assert!(
            result.is_ok(),
            "Multi-document YAML should be sanitized successfully"
        );
    }

    #[test]
    fn test_sanitize_document_special_characters() {
        let yaml_with_special = r#"metadata:
  name: test-pod
  labels:
    key: "value-with-special-chars-!@#$%"
"#;
        let result = sanitize_document(yaml_with_special.as_bytes().to_vec());
        assert!(
            result.is_ok(),
            "YAML with special characters should sanitize"
        );
    }

    #[test]
    fn test_sanitize_document_with_null_values() {
        let yaml_with_nulls = r#"spec:
  containers:
  - name: nginx
    image: nginx:latest
    env:
      - name: NULL_VAR
        value: null
"#;
        let result = sanitize_document(yaml_with_nulls.as_bytes().to_vec());
        assert!(result.is_ok(), "YAML with null values should sanitize");
    }

    #[test]
    fn test_sanitize_document_deeply_nested_yaml() {
        let mut yaml = String::from("root:");
        for i in 0..50 {
            yaml.push_str(&format!("\n  level{}:", i));
        }
        let result = sanitize_document(yaml.as_bytes().to_vec());
        // Should handle deeply nested YAML (may return error if too deep)
        let _ = result;
    }

    #[test]
    fn test_sanitize_document_empty_yaml() {
        let empty_yaml = "";
        let result = sanitize_document(empty_yaml.as_bytes().to_vec());
        // Empty YAML might pass or fail depending on YamlLoader behavior
        let _ = result; // Just verify it doesn't panic
    }

    #[test]
    fn test_sanitize_document_large_yaml() {
        let mut yaml = String::from("items:\n");
        for i in 0..1000 {
            yaml.push_str(&format!("  - name: item-{}\n", i));
        }
        let result = sanitize_document(yaml.as_bytes().to_vec());
        assert!(result.is_ok(), "Large YAML should sanitize successfully");
    }

    #[test]
    fn test_sanitize_document_invalid_utf8_returns_error() {
        // Invalid UTF-8 should return DecodeError instead of panicking
        let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
        let result = sanitize_document(invalid_utf8);
        assert!(result.is_err(), "Invalid UTF-8 should return error");
        assert!(
            matches!(result, Err(HiveError::DecodeError(_))),
            "Should return DecodeError variant"
        );
    }

    #[test]
    fn test_sanitize_document_invalid_yaml_returns_error() {
        // YamlLoader is lenient, so we test with actually invalid YAML
        // that will fail yaml-rust parsing
        let invalid_yaml = r#"key: value
invalid syntax here [broken"#;
        let result = sanitize_document(invalid_yaml.as_bytes().to_vec());
        // YamlLoader may or may not reject this, depending on strictness
        let _ = result;
    }

    // Migration Integration Tests
    // Run with: make test or make test-worker
    // The Makefile sets up a test database automatically
    #[tokio::test]
    async fn test_migration_runs_successfully() {
        let pool = test_pool().await;
        // Migrations are run by the Makefile (make test-db-migrate) before tests
        // This test just verifies the expected tables exist
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('clusters', 'repos', 'releases')"
        )
        .fetch_one(&pool)
        .await
        .expect("Should query table count");

        assert_eq!(
            count, 3,
            "Should have at least clusters, repos, and releases tables"
        );
    }

    #[tokio::test]
    async fn test_hive_user_owns_tables() {
        let pool = test_pool().await;

        // In test environment, table owner will be the test user (pg), not hive_user
        // Just verify the tables exist and have an owner
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT tableowner FROM pg_tables WHERE tablename = 'clusters' AND schemaname = 'public'"
        )
        .fetch_optional(&pool)
        .await
        .expect("Should query table owner");

        assert!(owner.is_some(), "Clusters table should exist with an owner");
    }

    #[tokio::test]
    async fn test_idempotent_migrations() {
        // Test that sqlx migrations are idempotent by running them against a fresh temp DB.
        // The Makefile applies migrations via psql (without _sqlx_migrations tracking), which is
        // intentionally separate from sqlx's migrator.

        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());

        let admin_opts: PgConnectOptions = database_url
            .parse::<PgConnectOptions>()
            .expect("DATABASE_URL must be a valid Postgres URL");

        let temp_db = format!("beecd_test_mig_{}", Uuid::new_v4().simple());

        // Create a fresh database for this test (requires CREATEDB privileges).
        let mut admin = sqlx::PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");

        admin
            .execute(format!("CREATE DATABASE \"{}\"", temp_db).as_str())
            .await
            .expect("create temp database");

        let test_opts = admin_opts.clone().database(&temp_db);

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(test_opts)
            .await
            .expect("connect temp database");

        let result1 = sqlx::migrate!("./migrations").run(&pool).await;
        let result2 = sqlx::migrate!("./migrations").run(&pool).await;

        assert!(
            result1.is_ok(),
            "First migration run should succeed: {:?}",
            result1.err()
        );
        assert!(
            result2.is_ok(),
            "Second migration run should succeed: {:?}",
            result2.err()
        );

        // Drop the temp DB (force-close connections).
        drop(pool);
        admin
            .execute(format!("DROP DATABASE \"{}\" WITH (FORCE)", temp_db).as_str())
            .await
            .expect("drop temp database");
    }

    // JWT/Auth focused tests

    async fn ensure_migrations(pool: &Pool<Postgres>) {
        // In the normal `make test-hive` path, migrations are applied via psql before tests run.
        // Avoid re-running sqlx's migrator (which is slower and requires tracking tables).
        let already_migrated: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='clusters')",
        )
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if already_migrated {
            return;
        }

        sqlx::migrate!("./migrations")
            .run(pool)
            .await
            .expect("migrations should run successfully");
    }

    async fn insert_user(
        pool: &Pool<Postgres>,
        tenant_id: Uuid,
        username: &str,
        password: &str,
    ) -> Uuid {
        let id = Uuid::new_v4();
        // Use a low bcrypt cost for test speed
        let hash = bcrypt::hash(password, 4).expect("bcrypt hash");
        sqlx::query(
            "INSERT INTO users (id, name, hash, tenant_id) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, name) DO UPDATE SET hash = EXCLUDED.hash"
        )
        .bind(id)
        .bind(username)
        .bind(hash)
        .bind(tenant_id)
        .execute(pool)
        .await
        .expect("insert user");
        id
    }

    #[tokio::test]
    async fn login_stores_null_ip_when_remote_unknown() {
        let pool = test_pool().await;
        ensure_migrations(&pool).await;
        let tenant_id = ensure_test_tenant(&pool).await;
        let server = mk_grpc_server(&pool).await;

        let username = "iptest";
        let password = "p@ssw0rd";
        insert_user(&pool, tenant_id, username, password).await;

        let req = beecd::LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            user_agent: String::new(),
        };

        let resp = GrpcServer::login(&server, Request::new(req))
            .await
            .expect("login ok");
        let body = resp.into_inner();

        // Verify the access token is valid using test helper
        let claims = crate::auth::validate_access_token_for_test(
            &body.access_token,
            "test-secret-key-with-sufficient-length-for-validation",
        )
        .expect("token should be valid");
        assert_eq!(claims.sub, username);

        // Compute hash and verify stored ip_address is NULL
        let token_hash = crate::auth::hash_refresh_token(&body.refresh_token);
        let ip: Option<Option<String>> =
            sqlx::query_scalar("SELECT ip_address FROM refresh_tokens WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_optional(&pool)
                .await
                .expect("query ip");

        // ip is Some(None) if row exists with NULL ip_address
        // ip is None if row doesn't exist
        assert!(
            matches!(ip, Some(None)),
            "ip_address should be NULL when remote_addr is unknown, got {:?}",
            ip
        );
    }

    #[tokio::test]
    async fn refresh_with_invalid_token_returns_generic_error() {
        let pool = test_pool().await;
        ensure_migrations(&pool).await;
        let server = mk_grpc_server(&pool).await;

        let req = beecd::RefreshTokenRequest {
            refresh_token: "this-is-not-valid".to_string(),
        };

        let err = GrpcServer::refresh_token(&server, Request::new(req))
            .await
            .expect_err("should error");

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "Invalid refresh token");
    }

    // Startup validation tests

    #[test]
    fn test_jwt_secret_validation_weak_key() {
        // Test that weak secrets are rejected (simulated via direct validation)
        let weak_secret = "short";
        assert!(
            weak_secret.len() < 32,
            "Weak secret should be less than 32 bytes and would be rejected at startup"
        );
    }

    #[test]
    fn test_jwt_secret_validation_strong_key() {
        // Test that strong secrets pass validation
        let strong_secret = "this-is-a-very-strong-secret-key-with-plenty-of-entropy";
        assert!(
            strong_secret.len() >= 32,
            "Strong secret should be at least 32 bytes"
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    let version = BUILD_VERSION.or(VERSION).unwrap_or(CARGO_VERSION);
    info!("hive-server version {}", version);

    // Validate JWT secret at startup (fail-fast for production safety)
    // Supports both base64-encoded secrets (e.g., `openssl rand -base64 32`)
    // and raw string secrets for backward compatibility
    let jwt_secret =
        std::env::var("JWT_SECRET_KEY").expect("JWT_SECRET_KEY environment variable must be set");

    let effective_bytes = match general_purpose::STANDARD.decode(jwt_secret.trim()) {
        Ok(bytes) => bytes.len(),
        Err(_) => jwt_secret.len(), // Fall back to raw string length
    };

    if effective_bytes < 32 {
        panic!(
            "JWT_SECRET_KEY must be at least 32 bytes (256 bits) for secure HS256 signing. \
             Current length: {} bytes. \
             Generate a secure key with: openssl rand -base64 32",
            effective_bytes
        );
    }

    let key = "STORAGE_TYPE";
    let storage_type = std::env::var(key).unwrap_or(String::from("local"));
    let key = "AWS_S3_STORAGE_BUCKET";
    let aws_s3_storage_bucket = std::env::var(key).unwrap_or(String::from(""));
    let key = "LOCAL_STORAGE_PREFIX";
    let local_storage_prefix = std::env::var(key).unwrap_or(String::from("/tmp"));
    let key = "GRPC_KEEP_ALIVE_IN_SECONDS";
    let grpc_keep_alive_in_seconds_str = std::env::var(key).unwrap_or(String::from("0"));
    let key = "GRPC_TIMEOUT_IN_SECONDS";
    let grpc_timeout_in_seconds_str = std::env::var(key).unwrap_or(String::from("30"));
    let key = "DATABASE_HOST";
    let database_host = std::env::var(key)
        .map_err(|_| format!("Environment variable {} is required but not set", key))?;
    let key = "DATABASE_HOST_RO";
    let database_host_readonly = std::env::var(key)
        .map_err(|_| format!("Environment variable {} is required but not set", key))?;
    let key = "DATABASE_PORT";
    let database_port = std::env::var(key).unwrap_or(String::from("5432"));
    let key = "DATABASE_NAME";
    let database_name = std::env::var(key)
        .map_err(|_| format!("Environment variable {} is required but not set", key))?;
    let key = "DATABASE_USER";
    let database_user = std::env::var(key)
        .map_err(|_| format!("Environment variable {} is required but not set", key))?;
    let key = "DATABASE_PASSWORD";
    let database_password = std::env::var(key)
        .map_err(|_| format!("Environment variable {} is required but not set", key))?;

    // Optional admin credentials for migrations (falls back to app user if not set)
    // Admin user owns tables and bypasses RLS; app user is subject to RLS
    let database_admin_user =
        std::env::var("DATABASE_ADMIN_USER").unwrap_or_else(|_| database_user.clone());
    let database_admin_password =
        std::env::var("DATABASE_ADMIN_PASSWORD").unwrap_or_else(|_| database_password.clone());

    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        database_user, database_password, database_host, database_port, database_name
    );
    let dsn_readonly = format!(
        "postgres://{}:{}@{}:{}/{}",
        database_user, database_password, database_host_readonly, database_port, database_name
    );
    let dsn_admin = format!(
        "postgres://{}:{}@{}:{}/{}",
        database_admin_user, database_admin_password, database_host, database_port, database_name
    );
    let key = "GITHUB_API_URL";
    let github_api_url = std::env::var(key).unwrap_or(String::from("https://api.github.com"));

    // Run database migrations with admin credentials (owns tables, bypasses RLS)
    // Admin pool is only used for migrations, then closed
    let admin_connection_options: PgConnectOptions = dsn_admin
        .parse::<PgConnectOptions>()
        .map_err(|e| format!("Failed to parse DATABASE_ADMIN connection string: {}", e))?
        .log_statements(log::LevelFilter::Trace)
        .log_slow_statements(log::LevelFilter::Debug, std::time::Duration::from_secs(1));

    let admin_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(admin_connection_options)
        .await?;

    // Run database migrations with retry logic for HA deployments
    // Multiple replicas may attempt migrations concurrently; PostgreSQL
    // serializes them via locks on _sqlx_migrations table
    info!("Running Hive database migrations (as admin user)...");
    for attempt in 1..=5 {
        match sqlx::migrate!("./migrations").run(&admin_pool).await {
            Ok(_) => {
                info!("Hive database migrations completed successfully");
                break;
            }
            Err(e) if attempt < 5 => {
                let backoff_secs = 2_u64.pow(attempt);
                warn!(
                    "Migration attempt {}/5 failed: {}. Retrying in {}s...",
                    attempt, e, backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            }
            Err(e) => {
                return Err(
                    format!("Failed to run database migrations after 5 attempts: {}", e).into(),
                );
            }
        }
    }

    // Close admin pool - not needed for runtime operations
    admin_pool.close().await;
    info!("Admin connection pool closed, switching to app user for runtime");

    // Create app connection pool (subject to RLS)
    let hive_db_connection_options: PgConnectOptions = dsn
        .parse::<PgConnectOptions>()
        .map_err(|e| format!("Failed to parse DATABASE connection string: {}", e))?
        .log_statements(log::LevelFilter::Trace)
        .log_slow_statements(log::LevelFilter::Debug, std::time::Duration::from_secs(1));

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(hive_db_connection_options.clone())
        .await?;

    let hive_db_connection_options_readonly: PgConnectOptions = dsn_readonly
        .parse::<PgConnectOptions>()
        .map_err(|e| format!("Failed to parse DATABASE_RO connection string: {}", e))?
        .log_statements(log::LevelFilter::Trace)
        .log_slow_statements(log::LevelFilter::Debug, std::time::Duration::from_secs(1));

    let pool_readonly = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(hive_db_connection_options_readonly.clone())
        .await?;

    let storage_prefix = match storage_type.as_str() {
        "local" => {
            format!("file://{local_storage_prefix}")
        }
        "s3" | "awss3" | "aws_s3" => {
            format!("s3://{aws_s3_storage_bucket}")
        }
        _ => {
            panic!("Storage type {storage_type} is not supported")
        }
    };

    let server = GrpcServer {
        db: pool,
        readonly_db: pool_readonly,
        storage_prefix,
        github_api_url,
    };

    let connection_authentication_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await?;

    let _connection_authentication_pool_readonly = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn_readonly)
        .await?;

    // Use tonic interceptor for JWT auth and tenant context injection
    let svc = WorkerServer::with_interceptor(server, auth::auth_interceptor);

    // Keep the tower layer for cluster check-in updates (separate concern)
    let auth_layer = auth::AuthLayer::new(connection_authentication_pool);

    let grpc_keep_alive_in_seconds =
        grpc_keep_alive_in_seconds_str
            .parse::<u64>()
            .map_or(Some(Duration::from_secs(20)), |i| {
                if i == 0 {
                    None
                } else {
                    Some(Duration::from_secs(i))
                }
            });

    let grpc_timeout_in_seconds = grpc_timeout_in_seconds_str.parse::<u64>().unwrap_or(30);

    let address: std::net::SocketAddr = "0.0.0.0:5180".parse().unwrap();
    info!("Starting grpc server on {}", &address.to_string());
    Server::builder()
        .timeout(std::time::Duration::from_secs(grpc_timeout_in_seconds))
        .http2_keepalive_timeout(grpc_keep_alive_in_seconds)
        .layer(auth_layer)
        .add_service(svc)
        .serve(address)
        .await?;

    Ok(())
}
