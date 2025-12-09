use axum::{
    routing::{delete, get, post, put},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use sqlx::postgres::PgPoolOptions;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};
use tracing::{debug, info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use utoipa::OpenApi;
use utoipa::{openapi::security::SecurityScheme, Modify};
use utoipa_swagger_ui::SwaggerUi;

mod handler;
mod util;

// const VERSION: Option<&'static str> = std::option_env!("API_VERSION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_VERSION: Option<&str> = option_env!("BUILD_VERSION");
static AGENT_MANIFEST_TEMPLATE: &str = include_str!("static/agent.tpl.yaml");

#[derive(Clone)]
pub struct ServerState {
    pool: sqlx::Pool<sqlx::Postgres>,
    readonly_pool: sqlx::Pool<sqlx::Postgres>,
    agent_manifest_template: String,
    agent_default_image: Option<String>,
    hive_default_grpc_server: Option<String>,
    version: String,
    /// JWT secret bytes - either decoded from base64 or raw UTF-8 bytes
    jwt_secret_bytes: Vec<u8>,
    read_replica_wait_in_ms: u64,
    github_webhook_callback_url: Option<String>,
}

/// Decode JWT secret from string.
/// Supports both base64-encoded secrets (e.g., from `openssl rand -base64 32`)
/// and raw string secrets for backward compatibility.
fn decode_jwt_secret(secret: &str) -> Vec<u8> {
    // Try to decode as base64 first (preferred for cryptographically random secrets)
    match STANDARD.decode(secret.trim()) {
        Ok(bytes) if bytes.len() >= 32 => {
            debug!(
                "JWT_SECRET: Loaded as base64-encoded binary ({} bytes decoded from {} char string)",
                bytes.len(),
                secret.trim().len()
            );
            bytes
        }
        Ok(bytes) => {
            debug!(
                "JWT_SECRET: Base64 decoded to only {} bytes (too short), using as raw UTF-8 ({} bytes)",
                bytes.len(),
                secret.len()
            );
            secret.as_bytes().to_vec()
        }
        Err(_) => {
            debug!(
                "JWT_SECRET: Loaded as raw UTF-8 string ({} bytes)",
                secret.len()
            );
            secret.as_bytes().to_vec()
        }
    }
}

fn normalize_github_webhook_callback_url(raw: &str) -> Result<(String, bool), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("GITHUB_WEBHOOK_CALLBACK_URL is empty".to_string());
    }

    if trimmed.contains('#') {
        return Err("GITHUB_WEBHOOK_CALLBACK_URL must not include a fragment (#...)".to_string());
    }

    if trimmed.contains('?') {
        return Err(
            "GITHUB_WEBHOOK_CALLBACK_URL must not include query parameters; the server appends ?repo_id=...".to_string(),
        );
    }

    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err("GITHUB_WEBHOOK_CALLBACK_URL must start with http:// or https://".to_string());
    }

    let mut normalized = trimmed.trim_end_matches('/').to_string();
    let before = normalized.clone();

    // If it already points at the receiver route, leave it as-is.
    if normalized.ends_with("/api/webhooks/github") {
        return Ok((normalized, false));
    }

    // If it looks like just scheme+host (or scheme+host/), append the receiver route.
    let after_scheme = normalized
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| "Invalid GITHUB_WEBHOOK_CALLBACK_URL".to_string())?;

    // If there is no '/' after the hostname, there's no path.
    if after_scheme.find('/').is_none() {
        normalized.push_str("/api/webhooks/github");
    } else if !normalized.ends_with("/api/webhooks/github") {
        return Err(
            "GITHUB_WEBHOOK_CALLBACK_URL must be the full receiver URL ending with /api/webhooks/github"
                .to_string(),
        );
    }

    Ok((normalized.clone(), normalized != before))
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components: &mut utoipa::openapi::Components = openapi.components.as_mut().unwrap(); // we can unwrap safely since there already is components registered.
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(utoipa::openapi::security::Http::new(
                utoipa::openapi::security::HttpAuthScheme::Bearer,
            )),
        )
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handler::version,
        handler::get_cluster_defaults,
        handler::get_service,
        handler::get_service_definition,
        handler::put_service_definition,
        handler::get_unassociated_service_definitions_for_cluster_group,
        handler::get_cluster_namespaces,
        handler::delete_cluster,
        handler::get_cluster,
        handler::get_clusters,
        handler::post_cluster,
        handler::get_error_count,
        handler::get_namespace_releases,
        handler::get_cluster_groups,
        handler::get_cluster_cluster_groups,
        handler::delete_group_relationship,
        handler::add_cluster_groups,
        handler::delete_cluster_group,
        handler::get_cluster_group,
        handler::put_cluster_group,
        handler::get_resource_diffs_for_release,
        handler::get_release_status,
        handler::get_namespace_release_info,
        handler::put_restore_latest_release,
        handler::get_hive_agent_errors,
        handler::get_hive_agent_heartbeat,
        handler::get_pending_releases,
        handler::get_release_errors,
        handler::put_approvals,
        handler::put_unapprovals,
        handler::get_cluster_group_service_definitions,
        handler::delete_service_definition_relationship,
        handler::delete_service_from_namespace,
        handler::get_cluster_group_cluster_association,
        handler::post_create_cluster_namespaces,
        handler::post_subscribe_clusters,
        handler::post_subscribe_service_definitions,
        handler::put_subscribe_service_definitions,
        handler::get_service_definitions,
        handler::get_service_releases,
        handler::post_repo,
        handler::get_repos,
        handler::get_repo,
        handler::get_branches,
        handler::post_branch,
        handler::get_branch_service_definitions,
        handler::get_autosync_data,
        handler::put_branch_autosync,
        handler::post_branch_service,
        handler::get_repo_service_definitions,
        handler::get_namespaces_via_cluster_name,
        handler::post_global_repo_service,
        handler::post_init_release,
        handler::post_additional_installations,
        handler::post_user,
        handler::put_user,
        handler::delete_service_definitions,
        handler::delete_service,
        handler::put_release_selection,
        // Service versions API
        handler::get_namespace_service_versions,
        handler::get_service_definition_versions,
        handler::post_service_version,
        handler::post_deprecate_service_version,
        handler::post_pin_service_version,
        handler::post_unpin_service_version,
        handler::delete_service_version,
        handler::get_service_version,
        handler::put_select_service_version,
        handler::get_release_service_versions,
        // Manifest path template API
        handler::update_manifest_path_template,
        handler::get_manifest_path_template,
        handler::validate_path_template_endpoint,
        // GitHub webhooks API
        handler::get_repo_webhook,
        handler::register_repo_webhook,
        handler::delete_repo_webhook,
        handler::get_webhook_events,
    ),
    modifiers(&SecurityAddon),
    external_docs(url = "/", description = "HiveHQ")
)]
struct ApiDoc;

async fn docs_disabled() -> (axum::http::StatusCode, &'static str) {
    (axum::http::StatusCode::NOT_FOUND, "Docs are disabled")
}

fn init() {
    let log_level = std::env::var("LOG_LEVEL")
        .unwrap_or(String::from("warn"))
        .to_lowercase();

    if !["none"].contains(&log_level.as_str()) || !log_level.is_empty() {
        let level = if ["-1", "error"].contains(&log_level.as_str()) {
            Level::ERROR
        } else if ["0", "warn", "warning"].contains(&log_level.as_str()) {
            Level::WARN
        } else if ["1", "info", "default"].contains(&log_level.as_str()) {
            Level::INFO
        } else if ["2", "debug"].contains(&log_level.as_str()) {
            Level::DEBUG
        } else if ["3", "trace", "tracing"].contains(&log_level.as_str()) {
            Level::TRACE
        } else {
            Level::INFO // fallback in case our spelling sucks
        };

        // a builder for `FmtSubscriber`.
        let subscriber = FmtSubscriber::builder()
            // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
            // will be written to stdout.
            .with_max_level(level)
            // completes the builder.
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");
    }
}

fn effective_version() -> &'static str {
    BUILD_VERSION.unwrap_or(VERSION)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    info!("hive-hq-api version {}", effective_version());

    let host = std::env::var("AXUM_HOST").unwrap_or(String::from("127.0.0.1"));
    let port = std::env::var("AXUM_PORT").unwrap_or(String::from("3000"));
    let read_replica_wait_in_ms =
        std::env::var("READ_REPLICA_WAIT_IN_MS").unwrap_or(String::from("75"));
    let dist = std::env::var("DIST").unwrap_or_else(|_| {
        // Try a few likely locations so `cargo run` works from either workspace root
        // or from within `hive-hq/api`, while keeping the container default behavior.
        let candidates = [
            "hive-hq/ui/dist", // running from workspace root
            "../ui/dist",      // running from hive-hq/api
            "dist",            // container (WORKDIR=/) or explicit builds
            "../dist",         // legacy/default
        ];

        candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or(&"../dist")
            .to_string()
    });
    let database_host = std::env::var("DATABASE_HOST").unwrap_or(String::from("localhost"));
    let database_host_readonly =
        std::env::var("DATABASE_HOST_RO").unwrap_or(String::from("localhost"));
    let database_port = std::env::var("DATABASE_PORT").unwrap_or(String::from("5432"));
    let database_name = std::env::var("DATABASE_NAME").unwrap_or(String::from("crud"));
    let database_user = std::env::var("DATABASE_USER").unwrap_or(String::from("pg"));
    let database_password = std::env::var("DATABASE_PASSWORD").unwrap_or(String::from("pass"));
    let jwt_secret =
        std::env::var("JWT_SECRET").expect("JWT_SECRET environment variable must be set");
    let jwt_secret_bytes = decode_jwt_secret(&jwt_secret);

    if jwt_secret_bytes.len() < 32 {
        panic!(
            "JWT_SECRET must be at least 32 bytes (256 bits) for secure HS256 signing. \
             Current length: {} bytes. \
             Generate a secure key with: openssl rand -base64 32",
            jwt_secret_bytes.len()
        );
    }

    let agent_default_image = std::env::var("AGENT_DEFAULT_IMAGE").ok();
    let hive_default_grpc_server = std::env::var("HIVE_DEFAULT_GRPC_SERVER").ok();
    let github_webhook_callback_url = match std::env::var("GITHUB_WEBHOOK_CALLBACK_URL") {
        Ok(s) if !s.trim().is_empty() => match normalize_github_webhook_callback_url(&s) {
            Ok((normalized, changed)) => {
                if changed {
                    warn!(
                        "Normalized GITHUB_WEBHOOK_CALLBACK_URL from '{}' to '{}'",
                        s.trim(),
                        normalized
                    );
                }
                Some(normalized)
            }
            Err(e) => {
                warn!(
                    "Ignoring invalid GITHUB_WEBHOOK_CALLBACK_URL ('{}'): {}",
                    s.trim(),
                    e
                );
                None
            }
        },
        _ => None,
    };

    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        database_user, database_password, database_host, database_port, database_name
    );
    info!("Connecting to database... ");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await?;
    info!("CONNECTED!");

    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        database_user, database_password, database_host_readonly, database_port, database_name
    );
    info!("Connecting to readonly database... ");
    let readonly_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await?;
    info!("CONNECTED!");

    let server_state = ServerState {
        pool,
        readonly_pool,
        agent_manifest_template: String::from(AGENT_MANIFEST_TEMPLATE),
        agent_default_image,
        hive_default_grpc_server,
        version: crate::BUILD_VERSION.map_or(crate::VERSION.to_string(), String::from),
        jwt_secret_bytes,
        read_replica_wait_in_ms: read_replica_wait_in_ms.parse().unwrap_or(75),
        github_webhook_callback_url,
    };

    let cors = CorsLayer::new().allow_origin(Any);

    // `ServeDir` allows setting a fallback if an asset is not found
    // so with this `GET /assets/doesnt-exist.jpg` will return `index.html`
    // rather than a 404
    let serve_dir = Router::new().fallback_service(
        ServeDir::new(&dist).not_found_service(ServeFile::new(format!("{}/index.html", dist))),
    );

    // build our application with a route
    let public_routes = Router::new()
        .route("/api/version", get(handler::version))
        .route("/api/auth/bootstrap", post(handler::ui_auth_bootstrap))
        .route(
            "/api/auth/bootstrap/status",
            get(handler::ui_auth_bootstrap_status),
        )
        .route("/api/auth/login", post(handler::ui_auth_login));

    #[cfg(feature = "dev-mode")]
    let public_routes = public_routes.route("/api/free-token", get(handler::free_token));

    let public_routes = public_routes
        .with_state(server_state.clone())
        .route("/docs", get(docs_disabled))
        .route("/docs/", get(docs_disabled))
        .route("/docs/{*path}", get(docs_disabled))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .fallback_service(serve_dir);

    // Routes specifically for aversion service - requires aversion or admin role
    let aversion_routes = Router::new()
        .route(
            // This is used by aversion. Do not modify the outputs without coordinating changes
            "/api/aversion/clusters/{cluster_name}/namespaces",
            get(handler::get_namespaces_via_cluster_name),
        )
        .with_state(server_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            server_state.clone(),
            handler::validate_auth_aversion,
        ));

    let protected_routes = Router::new()
        .layer(cors)
        .route("/api/auth/me", get(handler::ui_auth_me))
        .route("/api/auth/logout", post(handler::ui_auth_logout))
        .route("/api/cluster-defaults", get(handler::get_cluster_defaults))
        .route(
            "/api/clusters",
            get(handler::get_clusters).post(handler::post_cluster),
        )
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
            "/api/clusters/{id}/service-definitions",
            get(handler::get_cluster_service_definitions),
        )
        .route(
            "/api/clusters/{id}/releases",
            get(handler::get_release_status),
        )
        .route(
            "/api/clusters/{id}/errors",
            get(handler::get_hive_agent_errors),
        )
        .route(
            "/api/clusters/{id}/heartbeat",
            get(handler::get_hive_agent_heartbeat),
        )
        .route(
            "/api/releases/{id}/diff/{diff_generation}",
            get(handler::get_resource_diffs_for_release),
        )
        .route(
            "/api/releases/{id}/errors",
            get(handler::get_release_errors),
        )
        .route("/api/releases/pending", get(handler::get_pending_releases))
        .route(
            "/api/service-definitions",
            get(handler::get_service_definitions),
        )
        .route(
            "/api/service/{name}",
            get(handler::get_service).delete(handler::delete_service),
        )
        .route(
            "/api/service-definitions/{id}",
            get(handler::get_service_definition)
                .put(handler::put_service_definition)
                .delete(handler::delete_service_definitions),
        )
        .route(
            "/api/service-definitions/{id}/releases",
            get(handler::get_service_releases),
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
            "/api/cluster-groups/{id}/service-definitions/{service_definition_id}",
            delete(handler::delete_service_definition_relationship),
        )
        .route(
            "/api/cluster-groups/{id}/unassociated-service-definitions",
            get(handler::get_unassociated_service_definitions_for_cluster_group),
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
            "/api/branches/{id}/service-definitions/autosync",
            get(handler::get_autosync_data).put(handler::put_branch_autosync),
        )
        .route(
            "/api/namespaces/{id}/release/{release_name}",
            get(handler::get_namespace_releases),
        )
        .route(
            "/api/namespaces/{id}/service-name/{name}",
            delete(handler::delete_service_from_namespace),
        )
        .route(
            "/api/namespaces/{id}/release/{release_name}/current",
            get(handler::get_namespace_release_info),
        )
        .route(
            "/api/namespaces/{id}/release/{release_name}/versions",
            get(handler::get_release_service_versions),
        )
        .route(
            "/api/namespaces/{id}/release/{release_name}/latest",
            put(handler::put_restore_latest_release),
        )
        .route(
            "/api/releases/{id}/select",
            put(handler::put_release_selection),
        )
        .route(
            "/api/releases/namespaces/{id}/init",
            post(handler::post_init_release),
        )
        .route(
            "/api/releases/init-many",
            post(handler::post_additional_installations),
        )
        .route("/api/approvals", put(handler::put_approvals))
        .route("/api/approvals/unapprove", put(handler::put_unapprovals))
        .route(
            "/api/users",
            post(handler::post_user).put(handler::put_user),
        )
        // Service Versions API - replaces aversion database dependency
        .route("/api/service-versions", post(handler::post_service_version))
        .route(
            "/api/service-versions/{id}",
            get(handler::get_service_version).delete(handler::delete_service_version),
        )
        .route(
            "/api/service-versions/{id}/deprecate",
            post(handler::post_deprecate_service_version),
        )
        .route(
            "/api/service-versions/{id}/pin",
            post(handler::post_pin_service_version),
        )
        .route(
            "/api/service-versions/{id}/unpin",
            post(handler::post_unpin_service_version),
        )
        .route(
            "/api/service-versions/{id}/select",
            put(handler::put_select_service_version),
        )
        .route(
            "/api/namespaces/{namespace_id}/service-versions",
            get(handler::get_namespace_service_versions),
        )
        .route(
            "/api/service-definitions/{service_definition_id}/versions",
            get(handler::get_service_definition_versions),
        )
        // Manifest path template API
        .route(
            "/api/service-definitions/{id}/manifest-path",
            get(handler::get_manifest_path_template).put(handler::update_manifest_path_template),
        )
        .route(
            "/api/validate-path-template",
            post(handler::validate_path_template_endpoint),
        )
        // GitHub Webhook API
        .route(
            "/api/repos/{id}/webhook",
            get(handler::get_repo_webhook)
                .post(handler::register_repo_webhook)
                .delete(handler::delete_repo_webhook),
        )
        .route(
            "/api/repos/{id}/webhook/events",
            get(handler::get_webhook_events),
        )
        .with_state(server_state.clone())
        .layer(axum::middleware::from_fn_with_state(
            server_state.clone(),
            handler::validate_auth,
        ));

    // GitHub webhook receiver - public endpoint (validates via HMAC signature)
    let webhook_routes = Router::new()
        .route(
            "/api/webhooks/github",
            post(handler::receive_github_webhook),
        )
        .with_state(server_state.clone());

    let app = public_routes
        .merge(aversion_routes)
        .merge(webhook_routes)
        .merge(protected_routes);
    // run our app with hyper, listening globally on port 3000
    let listenter_address = format!("{}:{}", host, port);
    info!("Server is running on {}", listenter_address);
    let listener = tokio::net::TcpListener::bind(listenter_address)
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
