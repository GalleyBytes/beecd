// Pagination types matching the Rust PaginatedResponse<T>
export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    limit: number;
    offset: number;
}

export interface PaginationParams {
    limit?: number;
    offset?: number;
}

// Cluster type matching Rust types::Cluster
export interface Cluster {
    id: string;
    name: string;
    metadata: string | null;
    version: string | null;
    kubernetes_version: string | null;
}

// Cluster namespace with services
export interface ClusterNamespaceServicesData {
    id: string;
    name: string;
    namespace_id: string;
    namespace_name: string;
    service_names: string[] | null;
}

// Heartbeat info
export interface Heartbeat {
    last_check_in_at: string;
    deleted_at: string | null;
}

// Hive agent error
export interface HiveError {
    updated_at: string;
    message: string;
}

// RepoData type matching Rust types::RepoData
export interface RepoData {
    id: string;
    org: string;
    repo: string;
}

// Repo branches
export interface RepoBranch {
    id: string;
    repo_id: string;
    org: string;
    repo: string;
    branch: string;
    service_autosync: string[] | null;
}

// ServiceDefinitionData type matching Rust types::ServiceDefinitionData
export interface ServiceDefinitionData {
    repo_branch_id: string;
    service_definition_id: string;
    service_deleted_at: string | null;
    repo_id: string;
    name: string;
    org: string;
    repo: string;
    branch: string;
    source_branch_requirements: string | null;
    manifest_path_template: string | null;
}

// ClusterGroup types
export interface ClusterGroupData {
    id: string;
    name: string;
    priority: number;
}

// Cluster group services association
export interface ClusterGroupServices {
    cluster_group_id: string;
    repo_id: string;
    cluster_group_name: string;
    service_name: string;
    service_definition_id: string;
    org: string;
    repo: string;
    branch: string;
}

// Cluster group cluster association
export interface ClusterGroupClusterAssociation {
    id: string;
    name: string;
    associated: boolean;
}

// Release data
export interface ReleaseData {
    id: string;
    namespace: string;
    name: string;
    version: string;
    path: string;
    hash: string;
    branch: string;
    org: string;
    repo: string;
    repo_id: string;
    repo_branch_id: string;
    diff_generation: number;
    is_diff: boolean | null;
    cluster_groups: string;
    git_sha: string;
    approved_by: string | null;
    unapproved_by: string | null;
    created_at: string | null;
    updated_at: string | null;
    deleted_at: string | null;
    started_first_install_at: string | null;
    failed_first_install_at: string | null;
    completed_first_install_at: string | null;
    started_update_install_at: string | null;
    failed_update_install_at: string | null;
    completed_update_install_at: string | null;
    started_delete_at: string | null;
    failed_delete_at: string | null;
    completed_delete_at: string | null;
    deprecated_at: string | null;
    last_diff_at: string | null;
    unapproved_at: string | null;
    unapproved_reason: string | null;
    service_id: string | null;
    diff_service_id: string | null;
    diff_namespace_id: string | null;
    approved_at: string | null;
    service_definition_id: string;
    namespace_id: string;
    cluster_name: string;
    cluster_id: string;
    total_errors: number;
    previous_installed_hash: string | null;
    last_sync_at: string | null;
    manually_selected_at: string | null;
    // Service version pinning info (joined from service_versions)
    pinned_at: string | null;
    pinned_by: string | null;
}

// Release status wrapper
export interface ReleaseStatus {
    data: ReleaseData;
    status: string;
}

// Auth types
export interface AuthUser {
    email: string;
    roles: string[];
}

export interface LoginResponse {
    token: string;
}

// Cluster's cluster groups (from /clusters/{id}/groups)
export interface ClusterClusterGroups {
    id: string;  // cluster id
    name: string;  // cluster name
    cluster_group_id: string;
    cluster_group_name: string;
}

// Cluster's available service definitions (from /clusters/{id}/service-definitions)
export interface ClusterServiceDefinitions {
    id: string;  // service definition id
    repo_branch_id: string;
    repo_id: string;
    name: string;
    org: string;
    repo: string;
    branch: string;
    priority: number;
    cluster_group_ids: string[];
}

// Additional installation suggestion after adding service to namespace
export interface AdditionalInstallation {
    namespace_id: string;
    namespace_name: string;
    cluster_name: string;
    exists: boolean;
}

// Re-export from generated types - these match the Rust structs
export type {
    DiffData,
    DiffDataWithBody,
    // Service version types
    ServiceVersionData,
    ServiceVersionWithDetails,
    ServiceVersionForRelease,
    CreateServiceVersion,
    DeprecateServiceVersion,
    PinServiceVersion,
    // GitHub webhook types
    GitHubWebhookData,
    GitHubWebhookEvent,
    RegisterWebhookRequest,
    RegisterWebhookResponse,
    // Manifest path template types
    PathTemplateValidation,
    UpdateManifestPathTemplate,
} from '@/api';


