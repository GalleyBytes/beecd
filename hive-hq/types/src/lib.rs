use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "api")]
use sqlx::{error::BoxDynError, Decode, Encode, Postgres, Type};

#[cfg(feature = "api")]
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};

#[cfg(feature = "api")]
use sqlx::encode::IsNull;

pub const GITHUB_UI_URL: &str = "https://github.com";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub enum RepoProvider {
    #[default]
    Github,
    Forgejo,
    Gitlab,
}

impl RepoProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            RepoProvider::Github => "github",
            RepoProvider::Forgejo => "forgejo",
            RepoProvider::Gitlab => "gitlab",
        }
    }
}

impl std::fmt::Display for RepoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RepoProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github" => Ok(RepoProvider::Github),
            "forgejo" => Ok(RepoProvider::Forgejo),
            "gitlab" => Ok(RepoProvider::Gitlab),
            other => Err(format!("Unknown repo provider: {}", other)),
        }
    }
}

// SQLx mappings (provider is stored as TEXT).
#[cfg(feature = "api")]
impl Type<Postgres> for RepoProvider {
    fn type_info() -> PgTypeInfo {
        <String as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <String as Type<Postgres>>::compatible(ty)
    }
}

#[cfg(feature = "api")]
impl<'r> Decode<'r, Postgres> for RepoProvider {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let raw = <String as Decode<Postgres>>::decode(value)?;
        raw.parse::<RepoProvider>()
            .map_err(|e| -> BoxDynError { e.into() })
    }
}

#[cfg(feature = "api")]
impl<'q> Encode<'q, Postgres> for RepoProvider {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&str as Encode<Postgres>>::encode_by_ref(&self.as_str(), buf)
    }

    fn size_hint(&self) -> usize {
        <&str as Encode<Postgres>>::size_hint(&self.as_str())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct Cluster {
    pub id: Uuid,
    pub name: String,
    pub metadata: Option<String>,
    pub version: Option<String>,
    pub kubernetes_version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceName {
    pub name: String,
    /// Path template for manifest files in the git repository.
    /// Supports placeholders: {cluster}, {namespace}, {service}
    /// If ends with .yaml/.yml, watches a single file.
    /// Otherwise, watches all *.yaml files in the directory.
    pub manifest_path_template: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterNamespaceServicesData {
    pub id: Uuid,
    pub name: String,
    pub namespace_id: Uuid,
    pub namespace_name: String,
    pub service_names: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct NamespaceServiceData {
    pub id: Uuid,
    pub repo_branch_id: Uuid,
    pub service_name: String,
    pub cluster_name: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct RepoBranches {
    pub id: Uuid,
    pub repo_id: Uuid,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub api_base_url: String,
    pub org: String,
    pub repo: String,
    pub branch: String,
    pub service_autosync: Option<Vec<Uuid>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct RepoData {
    pub id: Uuid,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub api_base_url: String,
    pub org: String,
    pub repo: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceDefinitionData {
    pub repo_branch_id: Uuid,
    pub service_definition_id: Uuid,
    pub service_deleted_at: Option<DateTime<Utc>>,
    pub repo_id: Uuid,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub name: String,
    pub org: String,
    pub repo: String,
    pub branch: String,
    pub source_branch_requirements: Option<String>,
    pub manifest_path_template: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterServiceDefinitions {
    pub id: Uuid,
    pub repo_branch_id: Uuid,
    pub repo_id: Uuid,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub name: String,
    pub org: String,
    pub repo: String,
    pub branch: String,
    pub priority: i32,
    pub cluster_group_ids: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterGroupData {
    pub id: Uuid,
    pub name: String,
    pub priority: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterClusterGroups {
    pub id: Uuid,
    pub name: String,
    pub cluster_group_id: Uuid,
    pub cluster_group_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct AutosyncData {
    pub id: Uuid,
    pub branch: String,
    pub synced: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct DiffData {
    pub release_id: Uuid,
    pub diff_generation: i32,
    pub key: String,
    pub storage_url: Option<String>,
    pub change_order: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct DiffDataWithBody {
    pub body: String,
    #[serde(flatten)]
    pub diff_data: DiffData,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ReleaseCandidate {
    pub release_id: Uuid,
    pub release_name: String,
    pub cluster_name: String,
    pub namespace_name: String,
    pub cluster_group_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterGroupServices {
    pub cluster_group_id: Uuid,
    pub repo_id: Uuid,
    pub cluster_group_name: String,
    pub service_name: String,
    pub service_definition_id: Uuid,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub org: String,
    pub repo: String,
    pub branch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ClusterGroupClusterAssociation {
    pub id: Uuid,
    pub name: String,
    pub associated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ReleaseData {
    pub id: Uuid,
    pub namespace: String,
    pub name: String,
    pub version: String,
    pub path: String,
    pub hash: String,
    pub branch: String,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub api_base_url: String,
    pub org: String,
    pub repo: String,
    pub repo_id: Uuid,
    pub repo_branch_id: Uuid,
    pub diff_generation: i32,
    pub is_diff: Option<bool>,
    pub cluster_groups: String,
    pub git_sha: String,
    pub approved_by: Option<String>,
    pub unapproved_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub started_first_install_at: Option<DateTime<Utc>>,
    pub failed_first_install_at: Option<DateTime<Utc>>,
    pub completed_first_install_at: Option<DateTime<Utc>>,
    pub started_update_install_at: Option<DateTime<Utc>>,
    pub failed_update_install_at: Option<DateTime<Utc>>,
    pub completed_update_install_at: Option<DateTime<Utc>>,
    pub started_delete_at: Option<DateTime<Utc>>,
    pub failed_delete_at: Option<DateTime<Utc>>,
    pub completed_delete_at: Option<DateTime<Utc>>,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub last_diff_at: Option<DateTime<Utc>>,
    pub unapproved_at: Option<DateTime<Utc>>,
    pub unapproved_reason: Option<String>,
    pub service_id: Option<Uuid>,
    pub diff_service_id: Option<Uuid>,
    pub diff_namespace_id: Option<Uuid>,
    pub approved_at: Option<DateTime<Utc>>,
    pub service_definition_id: Uuid,
    pub namespace_id: Uuid,
    pub cluster_name: String,
    pub cluster_id: Uuid,
    pub total_errors: i32,
    pub previous_installed_hash: Option<String>,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub manually_selected_at: Option<DateTime<Utc>>,
    pub manifest_path_template: Option<String>,
    // Service version pinning info (joined from service_versions)
    pub pinned_at: Option<DateTime<Utc>>,
    pub pinned_by: Option<String>,
}

impl ReleaseData {
    pub fn status(&self) -> String {
        if self.approved_at.is_none() {
            return String::from("PendingApproval");
        }
        match (
            self.started_delete_at,
            self.completed_delete_at,
            self.failed_delete_at,
            self.started_update_install_at,
            self.completed_update_install_at,
            self.failed_update_install_at,
            self.started_first_install_at,
            self.completed_first_install_at,
            self.failed_first_install_at,
            self.approved_at,
        ) {
            (None, None, None, None, None, None, None, None, None, None) => {
                if self.version == "-" {
                    String::from("Uninitiated")
                } else {
                    String::from("PendingApproval")
                }
            }
            (None, None, None, None, None, None, None, None, None, Some(_)) => {
                String::from("PendingAgentInstallation")
            }
            (Some(_), None, None, ..) => String::from("Deleting"),
            (Some(_), Some(_), ..) => String::from("Deleted"),
            (Some(_), _, Some(_), ..) => String::from("DeleteFailed"),
            (_, _, _, Some(_), None, None, ..) => String::from("DriftRepairsInstalling"),
            (_, _, _, Some(_), Some(_), ..) => String::from("InstalledUpToDate"),
            (_, _, _, Some(_), _, Some(_), ..) => String::from("DriftRepairsFailed"),
            (_, _, _, _, _, _, Some(_), None, None, ..) => String::from("Installing"),
            (_, _, _, _, _, _, Some(_), Some(_), ..) => String::from("Installed"),
            (_, _, _, _, _, _, Some(_), _, Some(_), ..) => String::from("InstallFailed"),
            _ => String::from("Unknown"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ReleaseStatus {
    pub data: ReleaseData,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct UserData {
    pub secret: String,
    pub manifest: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct HiveError {
    pub updated_at: DateTime<Utc>,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct Heartbeat {
    pub last_check_in_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PendingReleases {
    pub cluster_id: Uuid,
    pub release_names: String,
    pub count: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ErrorCount {
    pub cluster_name: String,
    pub cluster_id: Uuid,
    pub count: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct AdditionalInstallation {
    pub namespace_id: Uuid,
    pub namespace_name: String,
    pub cluster_name: String,
    pub service_definition_id: Uuid,
    pub service_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostInitReleases {
    pub service_definition_ids: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostNamespaceNames {
    pub namespace_names: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostBranch {
    pub branch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceAutosyncBranches {
    pub ids: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostSubscribeCluster {
    pub id: Uuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostSubscriptions {
    pub ids: Vec<Uuid>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostRepo {
    pub url: String,
    #[serde(default)]
    pub provider: Option<RepoProvider>,
    #[serde(default)]
    pub web_base_url: Option<String>,
    #[serde(default)]
    pub api_base_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PutApprovals {
    pub ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PutClusterGroup {
    pub name: Option<String>,
    pub priority: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostUser {
    pub name: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostTriggerGhaBuild {
    pub service_definition_id: Vec<String>,
    pub branch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostAdditionalInstallation {
    pub service_definition_id: Uuid,
    pub namespace_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct AddClusterGroupInput {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostCluster {
    pub name: String,
    /// Context for manifest generation (namespace, grpc_address host:port, grpc_tls, image)
    pub context: Option<serde_json::Value>,
    /// If true and user already exists, regenerate the secret
    pub regenerate_secret: Option<bool>,
}

/// Response when creating a cluster
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct PostClusterResponse {
    pub cluster: Cluster,
    /// The generated manifest.
    pub manifest: Option<String>,
    /// True if the manifest is rendered with a placeholder secret (server does not store the real secret).
    #[serde(default)]
    pub manifest_is_placeholder: bool,
    /// Whether a user with matching name already existed
    pub user_existed: bool,
    /// Whether the secret was regenerated
    pub secret_regenerated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct PostJWT {
    pub uid: String,
    pub name: String,
    pub email: String,
    pub role: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct DeleteId {
    pub id: Uuid,
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct Claim {
    pub email: String,
    pub tenant_id: String,
    pub exp: usize,
    pub roles: Vec<String>,
}

/// Service version data - represents a deployable version of a service
/// This replaces the external aversion database dependency
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceVersionData {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub service_definition_id: Uuid,
    pub namespace_id: Uuid,
    pub version: String,
    pub git_sha: String,
    pub git_sha_short: Option<String>,
    pub path: String,
    pub hash: String,
    pub source: String,
    pub source_metadata: Option<serde_json::Value>,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub deprecated_by: Option<String>,
    pub deprecated_reason: Option<String>,
}

/// Extended service version data with joined service and repo information
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceVersionWithDetails {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub service_definition_id: Uuid,
    pub service_name: String,
    pub namespace_id: Uuid,
    pub namespace_name: String,
    pub cluster_name: String,
    pub version: String,
    pub git_sha: String,
    pub git_sha_short: Option<String>,
    pub path: String,
    pub hash: String,
    pub provider: RepoProvider,
    pub host: String,
    pub web_base_url: String,
    pub org: String,
    pub repo: String,
    pub branch: String,
    pub source: String,
    pub deprecated_at: Option<DateTime<Utc>>,
}

/// Service version data for release version selection UI
/// Includes deployment history and pinning info
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct ServiceVersionForRelease {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub service_definition_id: Uuid,
    pub namespace_id: Uuid,
    pub version: String,
    pub git_sha: String,
    pub git_sha_short: Option<String>,
    pub path: String,
    pub hash: String,
    pub source: String,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub pinned_at: Option<DateTime<Utc>>,
    pub pinned_by: Option<String>,
    // Deployment info (from releases table)
    pub last_deployed_at: Option<DateTime<Utc>>,
    pub is_current: bool,
}

/// Request body for creating a new service version
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct CreateServiceVersion {
    /// The service definition ID this version belongs to
    pub service_definition_id: Uuid,
    /// The namespace where this version can be deployed
    pub namespace_id: Uuid,
    /// Semantic version or tag (e.g., "1.2.3", "v1.0.0")
    pub version: String,
    /// Full git commit SHA
    pub git_sha: String,
    /// Path to manifest in repo (e.g., "deploy/production")
    pub path: String,
    /// Content hash of the rendered manifest
    pub hash: String,
    /// How this version was registered: 'api', 'git_watcher', 'webhook'
    #[serde(default = "default_source")]
    pub source: String,
    /// Additional source-specific metadata
    pub source_metadata: Option<serde_json::Value>,
}

fn default_source() -> String {
    "api".to_string()
}

/// Request body for deprecating a service version
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct DeprecateServiceVersion {
    pub deprecated_by: Option<String>,
    pub deprecated_reason: Option<String>,
}

/// Request body for pinning a service version
/// Pinned versions are protected from automatic deprecation by webhooks
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct PinServiceVersion {
    pub pinned_by: Option<String>,
}

// ============================================================================
// Repo Webhook Types (provider-agnostic)
// ============================================================================

/// Webhook registration data for a repo.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct RepoWebhookData {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub repo_id: Uuid,
    pub org: String,
    pub repo: String,
    pub provider_webhook_id: Option<i64>,
    pub active: bool,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// Request to register a provider webhook for a repo.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RegisterRepoWebhookRequest {
    /// Provider access token used to create/manage the webhook.
    #[serde(alias = "token", alias = "githubToken")]
    pub github_token: String,
}

/// Request to delete a provider webhook for a repo.
///
/// If `github_token` is provided, the server will attempt to delete the webhook on GitHub.
/// If omitted, the webhook is only disabled/soft-deleted locally.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct DeleteRepoWebhookRequest {
    #[serde(alias = "token", alias = "githubToken")]
    pub github_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::RegisterRepoWebhookRequest;

    #[test]
    fn register_repo_webhook_request_accepts_github_token() {
        let body = r#"{"github_token":"ghp_redacted"}"#;
        let parsed: RegisterRepoWebhookRequest = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.github_token, "ghp_redacted");
    }

    #[test]
    fn register_repo_webhook_request_accepts_token_alias() {
        let body = r#"{"token":"ghp_redacted"}"#;
        let parsed: RegisterRepoWebhookRequest = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.github_token, "ghp_redacted");
    }
}

/// Response after registering a webhook
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct RegisterRepoWebhookResponse {
    pub webhook_id: Uuid,
    pub provider_webhook_id: i64,
    pub callback_url: String,
    pub message: String,
}

/// Webhook event record (for audit log)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(sqlx::FromRow, utoipa::ToSchema))]
pub struct RepoWebhookEvent {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub webhook_id: Uuid,
    pub delivery_id: String,
    pub event_type: String,
    pub ref_name: Option<String>,
    pub before_sha: Option<String>,
    pub after_sha: Option<String>,
    pub pusher: Option<String>,
    pub processed_at: Option<DateTime<Utc>>,
    pub processing_error: Option<String>,
    pub matched_paths: Option<Vec<String>>,
    pub updated_service_versions: Option<Vec<Uuid>>,
}

/// Request body for updating a service definition's manifest path template
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct UpdateManifestPathTemplate {
    /// Path template with {service}, {cluster}, {namespace} placeholders
    /// Example: "manifests/{cluster}/{namespace}/{service}"
    pub manifest_path_template: String,
}

/// Validation result for a path template
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct PathTemplateValidation {
    pub valid: bool,
    pub has_service: bool,
    pub has_cluster: bool,
    pub has_namespace: bool,
    pub error: Option<String>,
    pub example_path: Option<String>,
}

/// GitHub push event payload (subset of fields we care about)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubPushEvent {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub before: String,
    pub after: String,
    pub repository: GitHubRepository,
    pub pusher: GitHubPusher,
    pub commits: Vec<GitHubCommit>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubRepository {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub owner: GitHubOwner,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubOwner {
    pub login: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubPusher {
    pub name: String,
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubCommit {
    pub id: String,
    pub message: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
}

impl GitHubPushEvent {
    /// Get all file paths that were changed in this push
    pub fn all_changed_files(&self) -> Vec<String> {
        let mut files = Vec::new();
        for commit in &self.commits {
            files.extend(commit.added.iter().cloned());
            files.extend(commit.modified.iter().cloned());
            // We include removed files too - might need to deprecate versions
        }
        // Deduplicate
        files.sort();
        files.dedup();
        files
    }

    /// Extract the branch name from the ref (e.g., "refs/heads/main" -> "main")
    pub fn branch_name(&self) -> Option<&str> {
        self.ref_name.strip_prefix("refs/heads/")
    }
}

/// Generic paginated response wrapper for list endpoints
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct PaginatedResponse<T> {
    /// The list of items for this page
    pub data: Vec<T>,
    /// Total number of items across all pages
    pub total: i64,
    /// Number of items returned in this response
    pub limit: i64,
    /// Number of items skipped
    pub offset: i64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, total: i64, limit: i64, offset: i64) -> Self {
        Self {
            data,
            total,
            limit,
            offset,
        }
    }
}
