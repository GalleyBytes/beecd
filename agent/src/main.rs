use kube::Client;
use std::env;
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

use agent::agent::{Agent, GrpcHeaderInjector};
use agent::beecd::worker_client::WorkerClient;

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
            (Level::DEBUG, EnvFilter::new("agent=debug")) // Debug only from this crate (default debug)
        } else if ["3", "trace", "tracing"].contains(&log_level.as_str()) {
            (Level::TRACE, EnvFilter::new("agent=trace")) // Trace only from this crate (default tracing)
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init();

    info!(
        "hive-agent version {}",
        agent::BUILD_VERSION.map_or(agent::VERSION, |v| v)
    );

    let cluster_name =
        env::var("CLUSTER_NAME").map_err(|_| "CLUSTER_NAME environment variable not set")?;
    let cluster_metadata = env::var("CLUSTER_METADATA").unwrap_or_default();
    let password =
        env::var("HIVE_PASSWORD").map_err(|_| "HIVE_PASSWORD environment variable not set")?;
    let owner = env::var("OWNER").unwrap_or(String::from("beecd"));
    let query_time_in_seconds_str = env::var("QUERY_TIME_IN_SECONDS").unwrap_or(String::from("60"));
    let grpc_timeout_in_seconds_str =
        env::var("GRPC_TIMEOUT_IN_SECONDS").unwrap_or(String::from("30"));
    let grpc_keep_alive_in_seconds_str =
        env::var("GRPC_KEEP_ALIVE_IN_SECONDS").unwrap_or(String::from("20"));
    let grpc_address =
        env::var("GRPC_ADDRESS").map_err(|_| "GRPC_ADDRESS environment variable not set")?;
    let grpc_tls = env::var("GRPC_TLS").ok().map(|v| {
        matches!(
            v.trim().to_lowercase().as_str(),
            "true" | "1" | "yes" | "y" | "on"
        )
    });
    let ignored_managed_fields = env::var("IGNORED_MANAGED_FIELDS").ok();
    let post_install_sleep_duration_in_seconds_string =
        env::var("POST_INSTALL_SLEEP_DURATION").unwrap_or(String::from("5"));

    let query_time_in_seconds: u64 = query_time_in_seconds_str.parse().map_err(|_| {
        format!(
            "QUERY_TIME_IN_SECONDS must be a valid integer: {}",
            query_time_in_seconds_str
        )
    })?;

    let grpc_address = grpc_address.trim().to_string();
    let grpc_uri_string = if grpc_address.contains("://") {
        grpc_address.clone()
    } else {
        // Backward-compatible: if no scheme is provided, default to TLS unless GRPC_TLS is explicitly false.
        let use_tls = grpc_tls.unwrap_or(true);
        let scheme = if use_tls { "https" } else { "http" };
        format!("{}://{}", scheme, grpc_address)
    };

    let uri = tonic::transport::Uri::from_maybe_shared(grpc_uri_string.clone())
        .map_err(|e| format!("Invalid GRPC_ADDRESS/GRPC_TLS combination: {}", e))?;
    let scheme = uri
        .scheme()
        .ok_or("GRPC_ADDRESS must include a scheme (http:// or https://)")?;
    let host = uri.host().ok_or("GRPC_ADDRESS must include a valid host")?;
    let ca_cert_file = if scheme.as_str() == "https" {
        env::var("CA_CERT_FILE")
            .map_err(|_| "CA_CERT_FILE environment variable required for https")?
    } else {
        String::new()
    };
    info!("Connecting to {}", uri.to_string());
    let endpoint = Channel::from_shared(uri.to_string())
        .map_err(|e| format!("Failed to create gRPC channel: {}", e))?;
    let mut endpoint = if ca_cert_file != String::new() {
        let pem = std::fs::read_to_string(&ca_cert_file)
            .map_err(|e| format!("Failed to read CA_CERT_FILE {}: {}", ca_cert_file, e))?;
        let ca = tonic::transport::Certificate::from_pem(pem);
        let tls = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name(host);
        endpoint
            .tls_config(tls)
            .map_err(|e| format!("Failed to configure TLS: {}", e))?
    } else {
        endpoint
    };

    let grpc_keep_alive_in_seconds = grpc_keep_alive_in_seconds_str
        .parse::<u64>()
        .map_or(Duration::from_secs(20), Duration::from_secs);

    let grpc_timeout_in_seconds =
        Duration::from_secs(grpc_timeout_in_seconds_str.parse::<u64>().unwrap_or(30));

    endpoint = endpoint
        .timeout(grpc_timeout_in_seconds)
        .http2_keep_alive_interval(grpc_keep_alive_in_seconds);

    let channel = endpoint
        .connect()
        .await
        .map_err(|e| format!("Failed to connect to gRPC server: {}", e))?;

    // Perform JWT login to get access and refresh tokens
    info!("Authenticating with server using JWT...");
    let mut grpc_client_for_login = WorkerClient::new(channel.clone());

    let login_response = grpc_client_for_login
        .login(agent::beecd::LoginRequest {
            username: cluster_name.clone(),
            password: password.clone(),
            user_agent: format!(
                "beecd-agent/{}",
                agent::BUILD_VERSION.map_or(agent::VERSION, |v| v)
            ),
        })
        .await
        .map_err(|e| format!("Failed to login with server: {}", e))?
        .into_inner();

    let now = agent::Utc::now();
    let token_state = std::sync::Arc::new(std::sync::RwLock::new(Some(agent::agent::TokenState {
        access_token: login_response.access_token,
        refresh_token: login_response.refresh_token,
        access_expires_at: now
            + agent::ChronoDuration::seconds(login_response.access_token_expires_in),
        refresh_expires_at: now
            + agent::ChronoDuration::seconds(login_response.refresh_token_expires_in),
    })));

    info!("Successfully authenticated with server");

    let header_injector = GrpcHeaderInjector::new(token_state.clone());
    let grpc_client = WorkerClient::with_interceptor(channel, header_injector);

    let k8s_client = Client::try_default()
        .await
        .map_err(|e| format!("Failed to load k8s client: {}", e))?;

    let kubernetes_version = k8s_client
        .apiserver_version()
        .await
        .map_err(|e| format!("Failed to get kubernetes version: {}", e))?
        .git_version;

    let agent = Agent::new(
        grpc_client,
        k8s_client,
        owner,
        cluster_name,
        cluster_metadata,
        ignored_managed_fields,
        kubernetes_version,
        query_time_in_seconds,
        post_install_sleep_duration_in_seconds_string,
        token_state,
        password,
    )
    .await?;

    agent.run().await
}
