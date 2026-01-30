use base64::DecodeError;
use base64::{engine::general_purpose, Engine as _};
use beecdiff::{
    aggregate_k8s_resources_managed_fields, aggregate_managed_fields_to_ignore,
    multi_document_parser_for_k8s_resources, Diff,
};
use chrono::Duration as ChronoDuration;
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::chrono::{DateTime, NaiveDateTime, Utc};
use k8s_openapi::ByteString;

// Re-export chrono types publicly for use in tests and main
pub use chrono::Duration as PublicChronoDuration;
pub use k8s_openapi::chrono::Utc as PublicUtc;
use kube::api::{GroupVersionKind, ObjectList, PropagationPolicy};
use kube::{
    api::{DeleteParams, ListParams, PostParams},
    core::{dynamic::DynamicObject, ObjectMeta},
    discovery::{ApiResource, Discovery, Scope},
    Api, Client, ResourceExt,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
// removed unused Hash import
// removed unused Bytes import
use futures::FutureExt;
use std::string::FromUtf8Error;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::vec;
use thiserror::Error;
use tonic::{Code, Request, Status};
use tracing::{debug, error, info, span, trace, warn, Instrument};

use crate::{
    beecd,
    beecd::worker_client::WorkerClient,
    beecd::{ClientNamespaceRegistrationRequest, ClusterName, GetReleaseRequest},
    util::{
        bytes_to_bytestring, diff_data_as_k8s_secret_data, gunzip_data, gunzipped_bytesstring,
        gzip_data, safe_keyname, string_to_bytestring,
    },
};

pub fn order_map(reverse: bool) -> std::collections::HashMap<&'static str, usize> {
    let mut list = vec![
        "PriorityClass",
        "Namespace",
        "NetworkPolicy",
        "ResourceQuota",
        "LimitRange",
        "PodSecurityPolicy",
        "PodDisruptionBudget",
        "ServiceAccount",
        "Secret",
        "SecretList",
        "ConfigMap",
        "StorageClass",
        "PersistentVolume",
        "PersistentVolumeClaim",
        "CustomResourceDefinition",
        "ClusterRole",
        "ClusterRoleList",
        "ClusterRoleBinding",
        "ClusterRoleBindingList",
        "Role",
        "RoleList",
        "RoleBinding",
        "RoleBindingList",
        "Service",
        "DaemonSet",
        "Pod",
        "ReplicationController",
        "ReplicaSet",
        "Deployment",
        "HorizontalPodAutoscaler",
        "StatefulSet",
        "Job",
        "CronJob",
        "IngressClass",
        "Ingress",
        "APIService",
    ];

    if reverse {
        list.reverse();
    }

    list.iter()
        .enumerate()
        .map(|(index, kind)| (*kind, index))
        .collect()
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("k8s error: {0:?}")]
    KubeError(kube::Error),
    #[error("Resource url/api not found: {0:?}")]
    KubeUrlNotFound(kube::error::ErrorResponse),
    #[error("conflict updating resource: {0}")]
    KubeConflict(kube::Error),
    #[error("failed converting resource {0} to struct: {1:?}")]
    ConvertingResourceToStructError(String, Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("grpc error for {rpc_name}: {err:#?}")]
    GrpcError {
        rpc_name: String,
        err: Box<tonic::Status>,
    },
    #[error("parse error: {0:?}")]
    ParseUtf8Error(FromUtf8Error),
    #[error("decode error: {0:?}")]
    DecodeError(DecodeError),
    #[error("parse info error: {0:?}")]
    FromUtf8Error(FromUtf8Error),
    #[error("failed to find manifest file")]
    ManifestNotFound,
    #[error("failed setting up resource config: {0:?}")]
    ResourceConfigError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("failed to deserialize yaml document: {0:?}")]
    YamlDeserializeError(serde_yaml::Error),
    #[error("failed to deserialize resource {0} yaml: {1:?}")]
    ResourceYamlDeserializeError(String, serde_yaml::Error),
    #[error("failed to interpret yaml value into: {0:?}")]
    YamlParseError(serde_yaml::Error),
    #[error("failed to get document deserializer")]
    DeserializerDocMissing,
    #[error("resource is missing a version")]
    ResourceMissingVersion,
    #[error("error parsing kubernetes manifest: {0:?}")]
    DiffParseError(Box<dyn std::error::Error>),
    #[error("error in diff when comparing documents: {0:?}")]
    DiffError(Box<dyn std::error::Error>),
    #[error("failed to sanitize diff resource key")]
    DiffResourceKeyError,
    #[error("manifest document expected {0} document but found {1}")]
    DiffDocumentLengthMismatch(usize, usize),
    #[error("Failed installation: {1}")]
    InstallationFailure(
        InstallationStatus,
        Box<dyn std::error::Error + Send + Sync + 'static>,
    ),
    #[error("Failed to gunzip: {0}")]
    GunzipFailure(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("An unknown error occurred: {0}?")]
    Unknown(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("")]
    EmptyError,
}

unsafe impl Send for AgentError {}
unsafe impl Sync for AgentError {}

pub type AgentResult<T> = Result<T, AgentError>;

/// Token state for JWT authentication
#[derive(Clone, Debug)]
pub struct TokenState {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

/// gRPC interceptor that injects JWT Bearer token from shared state
#[derive(Clone)]
pub struct GrpcHeaderInjector {
    pub token_state: Arc<RwLock<Option<TokenState>>>,
}

impl tonic::service::interceptor::Interceptor for GrpcHeaderInjector {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        // Clone access token while holding read lock, then release immediately
        let access_token = {
            let state = self
                .token_state
                .read()
                .map_err(|e| Status::internal(format!("Failed to read token state: {}", e)))?;

            state
                .as_ref()
                .ok_or_else(|| Status::unauthenticated("No authentication token available"))?
                .access_token
                .clone() // Clone token, then drop lock
        }; // Lock released here

        // Format Bearer token outside of lock to minimize contention
        let bearer_value = format!("Bearer {}", access_token)
            .parse()
            .map_err(|e| Status::internal(format!("Failed to parse token as metadata: {}", e)))?;

        request.metadata_mut().insert("authorization", bearer_value);
        Ok(request)
    }
}

impl GrpcHeaderInjector {
    pub fn new(token_state: Arc<RwLock<Option<TokenState>>>) -> Self {
        Self { token_state }
    }
}

pub struct Agent {
    pub grpc_client: WorkerClient<
        tonic::service::interceptor::InterceptedService<
            tonic::transport::Channel,
            GrpcHeaderInjector,
        >,
    >,
    /// Unauthenticated gRPC client for auth operations (Login, RefreshToken, Logout)
    /// Using the regular grpc_client for these would inject expired tokens, causing auth loops
    pub grpc_auth_client: WorkerClient<tonic::transport::Channel>,
    pub k8s_client: Client,
    pub discovery: Discovery,
    pub owner: String,
    pub cluster_name: String,
    pub cluster_metadata: String,
    pub cluster_id: String,
    pub query_time_in_seconds: u64,
    pub post_install_sleep_duration_in_seconds: u64,
    pub ignored_managed_fields: Option<String>,
    pub has_errors: Arc<RwLock<bool>>,
    pub namespaces: Arc<RwLock<Vec<beecd::NamespaceMap>>>,
    pub all_releases: Arc<RwLock<Vec<beecd::Release>>>,
    pub approved_releases: Arc<RwLock<Vec<String>>>,
    pub token_state: Arc<RwLock<Option<TokenState>>>,
    pub cluster_password: String,
    pub last_successful_token_check: Arc<RwLock<Option<DateTime<Utc>>>>,
}

pub struct Release {
    pub release_data: beecd::Release,
    agent: Arc<Agent>,
    manifest: Option<String>,
    diff_data: Option<BTreeMap<String, ByteString>>,
    resources: HashMap<String, Resource>,
    secret: Secret,
    previous_release_data: Option<PreviousReleaseData>,
    is_applied: bool,
    post_success: Option<bool>,
    resources_marked_for_removal: Vec<Resource>,
}

pub struct PreviousReleaseData {
    secret: Option<Secret>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct KubeMeta {
    #[serde(flatten)]
    typemeta: kube::api::TypeMeta,
    metadata: kube::api::ObjectMeta,
}

#[derive(PartialEq, Debug, Clone)]
pub enum InstallationStatus {
    Started,
    Completed,
    Failed,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Resource {
    yaml: serde_yaml::Value,
    name: String,
    namespace: String,
    kind: String,
    api_version: String,
    version: String,
    group: String,
    is_namespaced: bool,
    in_cluster_resource: Option<DynamicObject>,
    diff: Option<Diff>,
}

impl KubeMeta {
    pub fn to_string(&self) -> AgentResult<String> {
        serde_yaml::to_string(self).map_err(AgentError::YamlParseError)
    }

    pub fn with_namespace(&mut self, release_namespace: &str) -> &Self {
        let namespace = match &self.metadata.namespace {
            Some(resource_namespace) => resource_namespace.clone(),
            None => release_namespace.to_string(),
        };
        self.metadata.namespace = Some(namespace);
        self
    }

    pub fn name(&self) -> String {
        self.metadata.name.clone().unwrap_or(String::from(""))
    }

    pub fn namespace(&self) -> String {
        match &self.metadata.namespace {
            Some(s) => s.clone(),
            None => String::from("default"),
        }
    }

    pub fn kind(&self) -> String {
        self.typemeta.kind.clone()
    }

    pub fn api_version(&self) -> String {
        self.typemeta.api_version.clone()
    }

    pub fn version(&self) -> AgentResult<String> {
        let mut gv_slice = self.typemeta.api_version.split('/').collect::<Vec<_>>();
        match gv_slice.pop() {
            Some(s) => Ok(s.to_string()),
            None => Err(AgentError::ResourceMissingVersion),
        }
    }

    pub fn group(&self) -> String {
        let mut gv_slice = self.typemeta.api_version.split('/').collect::<Vec<_>>();
        gv_slice.pop();
        gv_slice.join("/")
    }
}

impl Resource {
    pub fn new(document: serde_yaml::Deserializer) -> AgentResult<Self> {
        let yaml =
            serde_yaml::Value::deserialize(document).map_err(AgentError::YamlDeserializeError)?;
        Ok(Self {
            yaml,
            ..Default::default()
        })
    }

    // Getter methods for testing
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn is_namespaced(&self) -> bool {
        self.is_namespaced
    }

    pub fn api_resource(&self) -> ApiResource {
        let plural = if self.kind.ends_with("y") {
            if self.kind.ends_with("way") {
                format!("{}s", self.kind)
            } else {
                format!("{}ies", self.kind.strip_suffix("y").unwrap())
            }
        } else if self.kind.ends_with("ss") {
            format!("{}es", self.kind)
        } else {
            format!("{}s", self.kind)
        };

        ApiResource {
            group: self.group.clone(),
            version: self.version.clone(),
            api_version: self.api_version.clone(),
            kind: self.kind.to_lowercase(),
            plural: plural.to_lowercase(),
        }
    }

    pub fn key(&self) -> String {
        format!(
            "Name: {}, Namespace: {}, Group: {}, Version: {}, Kind: {}",
            self.name, self.namespace, self.group, self.version, self.kind
        )
    }

    pub fn diff_key(&self) -> String {
        format!("{}/{}/{}", self.kind, self.namespace, self.name)
    }

    pub fn get_kubemeta(&self) -> AgentResult<KubeMeta> {
        self.to_struct()
    }

    /// will use the final yaml which is derived from the server rendered manifest with
    /// the additional ignore fields taken into account.
    ///
    /// This will result in an Error if the resource does not have a diff value.
    pub fn dynamic_object(&self) -> AgentResult<DynamicObject> {
        self.to_struct()
    }

    pub fn dynamic_object_from_yaml(&self) -> AgentResult<DynamicObject> {
        self.to_struct_from_yaml()
    }

    pub fn set_name(&mut self, s: String) -> &mut Self {
        self.name = s;
        self
    }

    pub fn set_namespace(&mut self, s: String) -> &mut Self {
        self.namespace = s;
        self
    }

    pub fn set_kind(&mut self, s: String) -> &mut Self {
        self.kind = s;
        self
    }

    pub fn set_api_version(&mut self, s: String) -> &mut Self {
        self.api_version = s;
        self
    }

    pub fn set_version(&mut self, s: String) -> &mut Self {
        self.version = s;
        self
    }

    pub fn set_group(&mut self, s: String) -> &mut Self {
        self.group = s;
        self
    }

    pub fn set_is_namespaced(&mut self, b: bool) -> &mut Self {
        self.is_namespaced = b;
        self
    }

    pub fn set_in_cluster_resource(&mut self, obj: Option<DynamicObject>) -> &mut Self {
        self.in_cluster_resource = obj;
        self
    }

    pub fn set_diff(&mut self, d: Option<Diff>) -> &mut Self {
        self.diff = d;
        self
    }

    pub fn to_struct<T>(&self) -> AgentResult<T>
    where
        T: DeserializeOwned,
    {
        let diff_string = if let Some(diff) = &self.diff {
            diff.text(true)
        } else {
            String::new()
        };

        let value = if diff_string.is_empty() {
            self.yaml.clone()
        } else {
            deserialize_doc(&diff_string).map_err(|e| {
                error!(
                    "Could not deserialize document for resource {}. Document: {}, Error: {}",
                    self.diff_key(),
                    &diff_string,
                    e
                );
                AgentError::ConvertingResourceToStructError(self.diff_key(), e.into())
            })?
        };
        let s: T = serde_yaml::from_value(value).map_err(AgentError::YamlParseError)?;
        Ok(s)
    }

    pub fn to_struct_from_yaml<T>(&self) -> AgentResult<T>
    where
        T: DeserializeOwned,
    {
        let s: T = serde_yaml::from_value(self.yaml.clone()).map_err(AgentError::YamlParseError)?;
        Ok(s)
    }

    pub fn is_weighted(&self) -> bool {
        match self.get_kubemeta() {
            Ok(kubemeta) => match kubemeta.metadata.annotations {
                Some(annotations) => annotations.contains_key("beecd/weight"),
                None => false, // no annotations
            },
            Err(e) => {
                warn!(
                    "Could not get kubemeta for resource {}/{}/{} when checking do_diff: {}",
                    self.kind, self.namespace, self.name, e
                );
                false
            }
        }
    }

    pub fn is_post_weighted(&self) -> bool {
        match self.get_kubemeta() {
            Ok(kubemeta) => match kubemeta.metadata.annotations {
                Some(annotations) => annotations.contains_key("beecd/post-weight"),
                None => false, // no annotations
            },
            Err(e) => {
                warn!(
                    "Could not get kubemeta for resource {}/{}/{} when checking do_diff: {}",
                    self.kind, self.namespace, self.name, e
                );
                false
            }
        }
    }

    pub fn should_diff(&self) -> bool {
        match self.get_kubemeta() {
            Ok(kubemeta) => match kubemeta.metadata.annotations {
                Some(annotations) => match (
                    annotations.get("beecd/weight"),
                    annotations.get("beecd/post-weight"),
                ) {
                    (Some(_), _) | (_, Some(_)) => match annotations.get("beecd/show-diff") {
                        Some(_show) => true, // weighted/post-weighted annotations with a show-diff override annotation
                        None => false, // weighted/post-weighted annotation is used to skip diffs
                    },
                    (None, None) => true, // no weight annotations
                },
                None => true, // no annotations
            },
            Err(e) => {
                warn!("Could not get kubemeta when checking do_diff: {}", e);
                false
            }
        }
    }
}

impl Release {
    // Maximum number of retry attempts for API calls before giving up
    const MAX_RETRIES: u32 = 10;

    pub fn new(agent: Arc<Agent>, release_data: beecd::Release) -> Self {
        Self {
            release_data,
            agent,
            manifest: None,
            diff_data: None,
            resources: HashMap::new(),
            secret: Secret::default(), // Maybe use Option/None instead
            previous_release_data: None,
            is_applied: false,
            post_success: None,
            resources_marked_for_removal: vec![],
        }
    }

    pub async fn secret_list_api_retryer(
        &self,
        retry_count: u32,
        service_label: String,
    ) -> AgentResult<ObjectList<Secret>> {
        let namespace = self.namespace();
        let secrets_v1: Api<Secret> =
            Api::namespaced(self.agent.k8s_client.clone(), namespace.as_str());

        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!("Running secret list for retryer attempt #{}", attempt);

            match secrets_v1
                .list(&ListParams::default().labels(&format!(
                    "hash,{},{}",
                    &service_label,
                    self.agent.owner_label()
                )))
                .await
            {
                Ok(result) => return Ok(result),
                Err(kube::Error::Api(error_response)) => {
                    if (error_response.code == 429 || error_response.code == 500)
                        && attempt < Self::MAX_RETRIES
                    {
                        // backoff, max 30 seconds
                        let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                        continue;
                    } else {
                        return Err(AgentError::KubeError(kube::Error::Api(error_response)));
                    }
                }
                Err(_) => return Err(AgentError::EmptyError),
            }
        }

        warn!(
            "Max retries ({}) exhausted for secret list with label: {}",
            Self::MAX_RETRIES,
            service_label
        );
        Err(AgentError::EmptyError)
    }

    // validate secret keys are in expected format and contain the required keys
    pub fn is_valid_secret(
        &mut self,
        s: &Secret,
        mut required_keys: Vec<&str>,
    ) -> AgentResult<bool> {
        if let Some(data_map) = s.data.clone() {
            for (key, value) in data_map {
                required_keys.retain(|k| k != &key);
                if let Err(e) = gunzipped_bytesstring(value) {
                    warn!("keys in unexpected format: {}", e);
                    return Ok(false);
                }
            }
        }
        Ok(required_keys.is_empty())
    }

    pub async fn secret_update_api_retryer(
        &self,
        retry_count: u32,
        secret: Secret,
    ) -> AgentResult<Secret> {
        let namespace = self.namespace();
        let secrets_v1_namespaced_client: Api<Secret> =
            Api::namespaced(self.agent.k8s_client.clone(), namespace.as_str());

        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!("Running secret update api retryer attempt #{}", attempt);

            match secrets_v1_namespaced_client
                .replace(
                    &secret.metadata.name.clone().unwrap(),
                    &PostParams {
                        dry_run: false,
                        field_manager: Some(self.agent.owner.clone()),
                    },
                    &secret,
                )
                .await
            {
                Ok(result) => return Ok(result),
                Err(kube::Error::Api(error_response)) => {
                    if (error_response.code == 429 || error_response.code == 500)
                        && attempt < Self::MAX_RETRIES
                    {
                        // backoff, max 30 seconds
                        let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                        continue;
                    } else {
                        return Err(AgentError::KubeError(kube::Error::Api(error_response)));
                    }
                }
                Err(_) => return Err(AgentError::EmptyError),
            }
        }

        warn!(
            "Max retries ({}) exhausted for secret update in namespace: {}",
            Self::MAX_RETRIES,
            namespace
        );
        Err(AgentError::EmptyError)
    }

    pub fn get_secret_label(&self, key: &str) -> Option<String> {
        self.secret.labels().get(key).cloned()
    }

    pub fn insert_secret_labels(&mut self, key: &str, value: &str) {
        self.secret
            .labels_mut()
            .insert(String::from(key), String::from(value));
    }

    pub fn update_secret_data(
        &mut self,
        data: Option<BTreeMap<String, ByteString>>,
    ) -> AgentResult<()> {
        let (manifest_key, manifest_value) = match self.secret.data.clone() {
            Some(s) => match s.iter().find(|k| k.0 == "manifest.gz") {
                Some(m) => (m.0.clone(), m.1.clone()),
                None => return Err(AgentError::ManifestNotFound),
            },
            None => return Err(AgentError::ManifestNotFound),
        };

        let data = match data.clone().as_mut() {
            Some(data_map) => {
                data_map.insert(manifest_key, manifest_value);
                data_map.clone()
            }
            None => BTreeMap::from([(manifest_key, manifest_value)]),
        };

        self.secret.data = Some(data);
        Ok(())
    }

    pub async fn update_release_secret(
        &mut self,
    ) -> AgentResult<k8s_openapi::api::core::v1::Secret> {
        self.secret_update_api_retryer(0, self.secret.clone()).await
    }

    pub fn set_diff_data(&mut self, data: Option<BTreeMap<String, ByteString>>) {
        self.diff_data = data
    }

    pub async fn secret_delete_api_retryer(
        &self,
        retry_count: u32,
        name: &str,
        namespace: &str,
    ) -> AgentResult<()> {
        let secrets_v1: Api<Secret> = Api::namespaced(self.agent.k8s_client.clone(), namespace);

        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!("Running secret delete api retryer attempt #{}", attempt);

            match secrets_v1.delete(name, &DeleteParams::default()).await {
                Ok(_) => return Ok(()),
                Err(kube::Error::Api(error_response)) => {
                    if (error_response.code == 429 || error_response.code == 500)
                        && attempt < Self::MAX_RETRIES
                    {
                        // backoff, max 30 seconds
                        let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                        continue;
                    } else {
                        return Err(AgentError::KubeError(kube::Error::Api(error_response)));
                    }
                }
                Err(_) => return Err(AgentError::EmptyError),
            }
        }

        warn!(
            "Max retries ({}) exhausted for secret delete: {}/{}",
            Self::MAX_RETRIES,
            namespace,
            name
        );
        Err(AgentError::EmptyError)
    }

    async fn delete_k8s_secret(&self, secret: &Secret) {
        let name = &secret
            .metadata
            .name
            .clone()
            .unwrap_or(String::from("NOT_SET"));
        let namespace = &secret
            .metadata
            .namespace
            .clone()
            .unwrap_or(String::from("NOT_SET"));
        match self.secret_delete_api_retryer(0, name, namespace).await {
            Ok(_) => info!(
                "Secret {} in namespace {} deleted successfully.",
                name, namespace
            ),
            Err(e) => error!(
                "Failed to delete secret {} in namespace {}: {}",
                name, namespace, e
            ),
        }
    }

    pub async fn extract_manifest_from_secret(
        &self,
        secret: &k8s_openapi::api::core::v1::Secret,
    ) -> Option<String> {
        match &secret.data {
            Some(secret_data) => match secret_data.get("manifest.gz") {
                Some(manifest) => match gunzip_data(&manifest.0) {
                    Ok(s) => Some(String::from_utf8(s).unwrap()),
                    Err(e) => {
                        error!("Failed to parse manifest: {}", e);
                        None
                    }
                },
                None => match secret_data.get("manifest") {
                    Some(_) => {
                        self.delete_k8s_secret(secret).await;
                        None
                    }
                    None => {
                        error!("Failed to find manifest in secret");
                        None
                    }
                },
            },
            None => {
                error!("Failed to find secret");
                None
            }
        }
    }

    /// Get the hash of the last known install, first from the server, next the
    /// last recorded entry in the release secret.
    pub fn get_previous_installed_hash(&self) -> Option<String> {
        // database first
        let value = &self.release_data.previous_installed_hash;
        // release secret second
        if value.is_empty() {
            match self.secret.labels().get("previous-installed-hash") {
                Some(label_value) => {
                    if label_value.is_empty() {
                        None
                    } else {
                        Some(label_value.clone())
                    }
                }
                None => None,
            }
        } else {
            Some(value.clone())
        }
    }

    pub fn set_previous_release_secret(&mut self, previous_release_data: PreviousReleaseData) {
        self.previous_release_data = Some(previous_release_data);
    }

    pub async fn get_previous_release_secret(&mut self) -> AgentResult<Option<Secret>> {
        let secret_option = match self.get_previous_installed_hash() {
            Some(hash_value) => {
                let name = &self.release_data.name;

                let service_label = format!(
                    "agent={},service={},hash={},last-applied,applied-service-id",
                    self.agent.cluster_name, name, hash_value
                );
                let secrets = self.secret_list_api_retryer(0, service_label).await?;
                let secret = secrets.iter().next();
                secret.cloned()
            }
            None => {
                let name = &self.release_data.name;
                let hash = &self.release_data.hash;
                let service_label = format!(
                    "service={},hash!={},last-applied,applied-service-id",
                    name, hash
                );
                let secrets = self.secret_list_api_retryer(0, service_label).await?;

                secrets.into_iter().reduce(|a, b| {
                    let fallback = String::from("0000-00-00T00:00:00");
                    let timestamp1 = a.labels().get("last-applied").unwrap_or(&fallback);
                    let timestamp2 = b.labels().get("last-applied").unwrap_or(&fallback);

                    let datetime1 =
                        NaiveDateTime::parse_from_str(timestamp1, "%Y-%m-%dT%H-%M-%S").unwrap();
                    let datetime2 =
                        NaiveDateTime::parse_from_str(timestamp2, "%Y-%m-%dT%H-%M-%S").unwrap();

                    if datetime1 >= datetime2 {
                        a
                    } else {
                        b
                    }
                })
            }
        };

        Ok(secret_option)
    }

    /// Looks for the manifest of the current release in secrets. If a secret is not found, requests the
    /// manifest from the server and creates a new secret with manifest data.
    ///
    /// Returns the secret with data
    pub async fn get_release_secret(&mut self) -> AgentResult<k8s_openapi::api::core::v1::Secret> {
        let name = &self.release_data.name;
        let service_label = format!("agent={},service={}", self.agent.cluster_name, name);
        let secrets = self.secret_list_api_retryer(0, service_label).await?;

        // Find the service manifest that matches the current service_id (UUID)
        // Each service_version has a unique UUID, so this ensures we fetch fresh manifests
        // when a new version is created, rather than reusing cached manifests from old versions
        //
        // TODO: Once manifest hashes are properly computed (not "pending"), implement hash-based
        // change detection here. Should:
        // 1. First check if a secret exists with matching service_id AND hash
        // 2. If hash matches, reuse the secret (manifest content unchanged)
        // 3. If hash differs or no match, fetch new manifest and create new secret
        // This will avoid unnecessary secret creation when manifest content hasn't actually changed
        let service_id = &self.release_data.service_id;
        let secret_lookup = secrets.into_iter().find(|s| {
            s.clone()
                .metadata
                .labels
                .unwrap_or_default()
                .get("service-id")
                .unwrap_or(&String::new())
                == service_id
        });

        // When searching for secrets, we check if a "manifest" exists in the found secret.
        // If multiple secrets share the same identifier (e.g., hash), we return the first result.
        // However, this "first" item might be "bad" due to manual changes or missing data.
        //
        // If we encounter
        //
        //      k8s error: ApiError: secrets "..." already exists: AlreadyExists
        //
        // we should consider changing this behavior.

        let secret = match &secret_lookup {
            Some(s) => {
                if !self.is_valid_secret(s, vec!["manifest.gz"])? {
                    // The secret must be deleted since it was not compatible with the
                    // expected format or was missing data.
                    self.delete_k8s_secret(s).await;

                    // Check for existing diffs in database matching current release
                    // since this manifest was corrupted or in a bad state for any
                    // other reason. This should make the system fault tolerant case
                    // of manual tampering with the release secret by restoring all the
                    // last known data for the release.
                    let diff_data = diff_data_as_k8s_secret_data(&self.grpc_restore_diff().await?);
                    self.k8s_new_release_secret(diff_data).await?
                } else {
                    s.clone()
                }
            }
            None => {
                let diff_data = diff_data_as_k8s_secret_data(&self.grpc_restore_diff().await?);
                self.k8s_new_release_secret(diff_data).await?
            }
        };

        Ok(secret)
    }

    pub fn set_manifest(&mut self, manifest: Option<String>) {
        self.manifest = manifest;
    }

    pub fn set_secret(&mut self, secret: Secret) {
        self.secret = secret;
    }

    pub fn get_resource_from_raw_manifest(
        &self,
        raw_manifest: String,
    ) -> AgentResult<Vec<Resource>> {
        let mut resources = vec![];

        for document in serde_yaml::Deserializer::from_str(&raw_manifest) {
            // uses --- doc delimiter

            let mut doc = Resource::new(document).map_err(|e| {
                let message = format!("Failed setting up resource from yaml document: {}", e);
                AgentError::ResourceConfigError(message.into())
            })?;

            let dynamic_object = doc.dynamic_object()?;
            let gvk = if let Some(tm) = &dynamic_object.types {
                match GroupVersionKind::try_from(tm) {
                    Ok(group_version_kind) => group_version_kind,
                    Err(e) => {
                        error!("Failed getting GroupVersionKind: {}", e);
                        continue;
                    }
                }
            } else {
                error!(
                    "cannot apply object without valid TypeMeta {:?}",
                    dynamic_object
                ); // todo send more info
                continue;
            };

            let is_namespaced = match self.agent.discovery.resolve_gvk(&gvk) {
                Some((_, capabilities)) => capabilities.scope == Scope::Namespaced,
                None => false,
            };

            let mut kubemeta = doc.get_kubemeta()?;

            doc.set_name(kubemeta.name());
            doc.set_kind(kubemeta.kind());
            doc.set_api_version(kubemeta.api_version());
            doc.set_version(kubemeta.version()?);
            doc.set_group(kubemeta.group());
            let namespace = if is_namespaced {
                doc.set_is_namespaced(true);
                kubemeta.with_namespace(&self.namespace());
                kubemeta.namespace()
            } else {
                doc.set_is_namespaced(false);
                String::new()
            };
            doc.set_namespace(namespace.clone());

            resources.push(doc);
        }
        Ok(resources)
    }

    /// Extracts documents from the raw yaml manifest and updates self with a HashMap of k8s (unvalidated) resources.
    /// However, each resource is checked to have valid typemeta and kubemeta. Also checks if this resouce is
    /// nameapced by using kuberentes discovery api.
    pub fn get_resources(&self) -> AgentResult<Vec<Resource>> {
        self.get_resource_from_raw_manifest(self.get_manifest()?)
    }

    pub async fn get_resources_marked_for_removal(&mut self) -> AgentResult<Vec<Resource>> {
        let previous_data = match &self.previous_release_data {
            Some(data) => data,
            None => return Ok(vec![]),
        };

        let previous_secret = match &previous_data.secret {
            Some(secret) => secret,
            None => return Ok(vec![]),
        };

        let previous_secret_data = match &previous_secret.data {
            Some(secret_data) => secret_data,
            None => return Ok(vec![]),
        };

        let previous_manifest = match previous_secret_data.get("manifest.gz") {
            Some(compressed_data) => {
                let result_bytes =
                    gunzip_data(&compressed_data.0).map_err(AgentError::GunzipFailure)?;
                String::from_utf8_lossy(&result_bytes).to_string()
            }
            None => return Ok(vec![]),
        };

        let previous_resources = self.get_resource_from_raw_manifest(previous_manifest)?;

        let previous_keys = previous_secret_data.keys().cloned().collect::<Vec<_>>();
        debug!(?previous_keys);

        let current_keys = self
            .resources
            .values()
            .map(|resource| safe_keyname(resource.diff_key()).unwrap_or_default())
            .collect::<Vec<_>>();
        debug!(?current_keys);

        let missing_keys = previous_keys
            .iter()
            .filter(|key| *key != "manifest.gz")
            .filter(|key| !current_keys.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        debug!(?missing_keys);

        let potential_resources_to_delete = previous_resources
            .iter()
            .filter(|resource| {
                missing_keys.contains(&safe_keyname(resource.diff_key()).unwrap_or_default())
            })
            .cloned()
            .collect::<Vec<_>>();

        let mut resources_to_delete = vec![];
        for resource in potential_resources_to_delete {
            let (_, original) = self.resource_manifest(&resource).await?;
            if let Some(dynamic_object) = original {
                let mut deletable_resource = resource.clone();
                if let Ok(yaml) = serde_yaml::to_value(dynamic_object) {
                    deletable_resource.yaml = yaml;
                    resources_to_delete.push(deletable_resource);
                };
            }
        }

        Ok(resources_to_delete)
    }

    pub async fn grpc_log_release_error(
        &self,
        message: String,
        is_deprecated: bool,
    ) -> AgentResult<()> {
        debug!("Calling {} RPC", "LogReleaseError");
        let _ = self
            .agent
            .grpc_client
            .clone()
            .log_release_error(beecd::LogReleaseErrorRequest {
                release_id: self.release_data.id.clone(),
                message: message.as_bytes().to_vec(),
                is_deprecated,
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: String::from("LogReleaseError"),
                err: Box::new(e),
            })?;
        Ok(())
    }

    pub async fn grpc_get_service_manifest(&self) -> AgentResult<String> {
        debug!("Calling {} RPC", "GetServiceManifest");
        let data = self
            .agent
            .grpc_client
            .clone()
            .get_service_manifest(beecd::GetServiceManifestRequest {
                release_id: self.release_data.id.clone(),
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: String::from("GetServiceManifest"),
                err: Box::new(e),
            })?
            .into_inner()
            .data;

        let encoded = String::from_utf8(data).map_err(AgentError::ParseUtf8Error)?;

        String::from_utf8(
            general_purpose::STANDARD
                .decode(encoded.replace('\n', "").as_bytes())
                .map_err(AgentError::DecodeError)?,
        )
        .map_err(AgentError::FromUtf8Error)
    }

    pub async fn grpc_restore_diff(&self) -> AgentResult<Vec<beecd::Diff>> {
        debug!("Calling {} RPC", "RestoreDiff");

        Ok(self
            .agent
            .grpc_client
            .clone()
            .restore_diff(beecd::RestoreDiffRequest {
                release_id: self.release_data.id.clone(),
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: String::from("RestoreDiff"),
                err: Box::new(e),
            })?
            .into_inner()
            .diff)
    }

    pub fn namespace(&self) -> String {
        let namespaces = self
            .agent
            .namespaces
            .read()
            .expect("namespaces RwLock poisoned - agent namespace lookup failed");
        let namespace_id = &self.release_data.namespace_id;
        let namespace_map = namespaces.iter().find(|n| n.id == *namespace_id);

        match namespace_map {
            Some(namespace) => namespace.name.clone(),
            None => String::from("default"),
        }
    }

    pub fn is_approved(&self) -> bool {
        let agent_releases = self
            .agent
            .approved_releases
            .read()
            .expect("approved_releases RwLock poisoned - cannot check approval status");
        agent_releases
            .iter()
            .any(|release_id| release_id == &self.release_data.id)
    }

    pub fn is_new_release(&self) -> bool {
        let agent_releases = self
            .agent
            .approved_releases
            .read()
            .expect("approved_releases RwLock poisoned - cannot check new release status");
        agent_releases.iter().any(|release| {
            release == &self.release_data.id && !self.release_data.completed_first_install
        })
    }

    pub async fn secret_create_api_retryer(
        &self,
        retry_count: u32,
        secret: Secret,
    ) -> AgentResult<Secret> {
        let namespace = self.namespace();
        let secrets_v1_namespaced_client: Api<Secret> =
            Api::namespaced(self.agent.k8s_client.clone(), namespace.as_str());

        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!("Running secret create api retryer attempt #{}", attempt);

            match secrets_v1_namespaced_client
                .create(
                    &PostParams {
                        dry_run: false,
                        field_manager: Some(self.agent.owner.clone()),
                    },
                    &secret,
                )
                .await
            {
                Ok(result) => return Ok(result),
                Err(kube::Error::Api(error_response)) => {
                    if (error_response.code == 429 || error_response.code == 500)
                        && attempt < Self::MAX_RETRIES
                    {
                        // backoff, max 30 seconds
                        let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                        continue;
                    } else {
                        return Err(AgentError::KubeError(kube::Error::Api(error_response)));
                    }
                }
                Err(_) => return Err(AgentError::EmptyError),
            }
        }

        warn!(
            "Max retries ({}) exhausted for secret create in namespace: {}",
            Self::MAX_RETRIES,
            namespace
        );
        Err(AgentError::EmptyError)
    }

    pub async fn k8s_new_release_secret(
        &mut self,
        additional_data: Option<BTreeMap<String, k8s_openapi::ByteString>>,
    ) -> AgentResult<k8s_openapi::api::core::v1::Secret> {
        let mut data = BTreeMap::new();
        if let Some(d) = additional_data {
            data = d;
        }
        // gzdata will be the zipped contents of the manfiest (or diff) that gets saved to the k8s-secret
        let gzdata = gzip_data(self.grpc_get_service_manifest().await?.as_bytes()).unwrap();
        data.insert(String::from("manifest.gz"), bytes_to_bytestring(gzdata));

        let mut labels = BTreeMap::new();
        labels.insert(String::from("agent"), self.agent.cluster_name.clone());
        labels.insert(String::from("service"), self.release_data.name.clone());
        labels.insert(String::from("owner"), self.agent.owner.clone());
        labels.insert(String::from("hash"), self.release_data.hash.clone());
        labels.insert(
            String::from("service-id"),
            self.release_data.service_id.clone(),
        );
        labels.insert(
            String::from("diff-generation"),
            self.release_data.diff_generation.to_string(),
        );

        let namespace = self.namespace();

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(format!(
                    "{}-{}",
                    &self.release_data.name,
                    // Use first 8 chars of service_id (UUID) instead of hash for uniqueness
                    // This ensures each service_version gets its own secret
                    // TODO: Once hash is properly computed, consider using hash prefix here instead
                    // of service_id. This would allow multiple service_versions to share the same
                    // secret if their manifest content is identical (better deduplication)
                    &self.release_data.service_id[..8].to_lowercase()
                )),
                namespace: Some(namespace.clone()),
                labels: Some(labels),
                ..ObjectMeta::default()
            },
            data: Some(data),
            ..Secret::default()
        };

        self.secret_create_api_retryer(0, secret).await
    }

    // Sends current installation status to server
    pub async fn gprc_installation_status(
        &self,
        status: InstallationStatus,
        msg: String,
    ) -> AgentResult<()> {
        debug!("Calling {} RPC", "InstallationStatus");
        self.agent
            .grpc_client
            .clone()
            .installation_status(beecd::InstallationStatusRequest {
                release_id: self.release_data.id.clone(),
                msg,
                started: status == InstallationStatus::Started,
                failed: status == InstallationStatus::Failed,
                completed: status == InstallationStatus::Completed,
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: String::from("InstallationStatus"),
                err: Box::new(e),
            })?;

        Ok(())
    }

    pub fn get_manifest(&self) -> AgentResult<String> {
        match &self.manifest {
            Some(manifest) => Ok(manifest.clone()),
            None => Err(AgentError::ManifestNotFound),
        }
    }

    pub async fn wait_for_install(&self, resource: &Resource) -> bool {
        let mut counter = 0;
        const MAX_WAIT_ITERATIONS: u32 = 360; // 1 hour max (with exponential backoff)

        loop {
            counter += 1;
            if counter > MAX_WAIT_ITERATIONS {
                error!(
                    "Exceeded max wait time for {}/{}/{}",
                    resource.kind, resource.namespace, resource.name
                );
                return false;
            }

            let namespace = &resource.namespace;
            let client = self.agent.k8s_client.clone();
            let pod_waiter: Api<Pod> = Api::namespaced(client.clone(), namespace);
            let job_waiter: Api<Job> = Api::namespaced(client.clone(), namespace);

            info!("Count: {} checking {} state", counter, resource.name);

            if resource.kind == "Pod" {
                match pod_waiter.get_status(&resource.name).await {
                    Ok(pod_status) => {
                        if let Some(status) = pod_status.status {
                            if let Some(phase) = status.phase {
                                if phase == "Succeeded" {
                                    return true;
                                }
                                if phase == "Failed" {
                                    return false;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get pod status: {}", e);
                    }
                }
            } else if resource.kind == "Job" {
                match job_waiter.get_status(&resource.name).await {
                    Ok(job_status) => {
                        if let Some(status) = job_status.status {
                            if let Some(conditions) = status.conditions {
                                for condition in conditions {
                                    if condition.type_ == "Complete" && condition.status == "True" {
                                        return true;
                                    }
                                    if (condition.type_ == "Complete"
                                        && condition.status == "False")
                                        || (condition.type_ == "Failed"
                                            && condition.status == "True")
                                    {
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get job status: {}", e);
                    }
                }
            } else {
                return false;
            }

            // Exponential backoff: starts at ~10s, reaches 30s by iteration 14, caps at 60s
            // Reduces total API calls from 360 to ~100 over an hour
            let backoff_secs = 60_f32.min(10.0 + (counter as f32).powf(1.5) / 10.0);
            tokio::time::sleep(Duration::from_secs_f32(backoff_secs)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn install_resource_api_retryer(
        &self,
        retry_count: u32,
        dynamic_object: DynamicObject,
        dynamic_k8s_client: &Api<DynamicObject>,
        resource: &Resource,
        pause_for_status: bool,
        weighted: bool,
        post_weighted: bool,
        count: i32,
        _diff: Vec<beecd::Diff>,
        _diff_generation: i32,
    ) -> AgentResult<(InstallationStatus, Option<bool>)> {
        let mut current_count = count;

        for attempt in retry_count..=Self::MAX_RETRIES {
            let mut is_success = true;
            debug!(
                "Running install resource api retryer for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, attempt
            );

            match dynamic_k8s_client
                .create(
                    &PostParams {
                        dry_run: false,
                        field_manager: Some(self.agent.owner.clone()),
                    },
                    &dynamic_object,
                )
                .await
            {
                Ok(_) => {
                    if pause_for_status {
                        is_success = self.wait_for_install(resource).await;
                    };
                    if is_success {
                        let post_success = if post_weighted { Some(true) } else { None };
                        return Ok((InstallationStatus::Completed, post_success));
                    } else if post_weighted && !is_success {
                        return Ok((InstallationStatus::Completed, Some(false)));
                    } else {
                        return Err(AgentError::EmptyError);
                    }
                }
                Err(e) => match e {
                    kube::Error::Api(error_response) => {
                        if (error_response.code == 409)
                            && (weighted || post_weighted)
                            && current_count < 1
                        {
                            info!(
                                "Removing existing resource {}/{}/{}",
                                &resource.kind, &resource.namespace, &resource.name,
                            );
                            match self
                                .dynamic_object_delete_api_retryer(
                                    0,
                                    dynamic_k8s_client,
                                    resource,
                                    false,
                                )
                                .await
                            {
                                Ok(_) => {
                                    current_count += 1;
                                    // Retry the create after deletion
                                    continue;
                                }
                                Err(err) => {
                                    error!(
                                        "An error occurred removing resource {}/{}/{}: {:#?}",
                                        &resource.kind, &resource.namespace, &resource.name, err
                                    );

                                    return Err(AgentError::InstallationFailure(
                                        InstallationStatus::Failed,
                                        err.into(),
                                    ));
                                }
                            }
                        } else if (error_response.code == 429 || error_response.code == 500)
                            && attempt < Self::MAX_RETRIES
                        {
                            // backoff, max 30 seconds
                            let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                            tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                            continue;
                        } else if error_response.code == 404 {
                            error!("An error occurred {:#?}", error_response);
                            return Err(AgentError::KubeUrlNotFound(error_response));
                        } else {
                            error!("An error occurred {:#?}", error_response);

                            return Err(AgentError::InstallationFailure(
                                InstallationStatus::Failed,
                                error_response.into(),
                            ));
                        }
                    }
                    _ => {
                        error!("An error occurred {:}", e);
                        return Err(AgentError::InstallationFailure(
                            InstallationStatus::Failed,
                            e.into(),
                        ));
                    }
                },
            }
        }

        warn!(
            "Max retries ({}) exhausted for install resource: {}/{}/{}",
            Self::MAX_RETRIES,
            resource.kind,
            resource.namespace,
            resource.name
        );
        Err(AgentError::EmptyError)
    }

    pub async fn dynamic_object_delete_api_retryer(
        &self,
        retry_count: u32,
        dynamic_k8s_client: &Api<DynamicObject>,
        resource: &Resource,
        dry_run: bool,
    ) -> AgentResult<()> {
        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!(
                "Running dynamic object delete api retryer for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, attempt
            );

            match dynamic_k8s_client
                .delete(
                    &resource.name,
                    &DeleteParams {
                        dry_run,
                        propagation_policy: Some(PropagationPolicy::Background),
                        ..DeleteParams::default()
                    },
                )
                .await
            {
                Ok(_) => {
                    let mut delete_count = 0;
                    const MAX_DELETE_WAIT_ITERATIONS: u32 = 60; // ~1 hour max with exponential backoff
                    loop {
                        let deleted = match self
                            .dynamic_object_get_api_retryer(
                                delete_count,
                                dynamic_k8s_client,
                                resource,
                            )
                            .await
                        {
                            Ok(resource_option) => resource_option.is_none(),
                            Err(e) => return Err(e),
                        };
                        if deleted {
                            break;
                        }
                        delete_count += 1;
                        if delete_count >= MAX_DELETE_WAIT_ITERATIONS {
                            let message = format!(
                                "Resource deletion verification timed out after {} attempts for {}/{}/{}",
                                MAX_DELETE_WAIT_ITERATIONS,
                                resource.kind,
                                resource.namespace,
                                resource.name
                            );
                            error!("{}", message);
                            return Err(AgentError::ConfigError(message));
                        }
                        // Exponential backoff matching wait_for_install: starts at ~10s, caps at 60s
                        let backoff_secs =
                            60_f32.min(10.0 + (delete_count as f32).powf(1.5) / 10.0);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff_secs)).await;
                    }
                    return Ok(());
                }
                Err(kube::Error::Api(error_response)) => {
                    if (error_response.code == 429 || error_response.code == 500)
                        && attempt < Self::MAX_RETRIES
                    {
                        // backoff, max 30 seconds
                        let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                        tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                        continue;
                    } else if error_response.code == 404 {
                        return Err(AgentError::KubeUrlNotFound(error_response));
                    } else {
                        return Err(AgentError::InstallationFailure(
                            InstallationStatus::Failed,
                            error_response.into(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(AgentError::InstallationFailure(
                        InstallationStatus::Failed,
                        e.into(),
                    ));
                }
            }
        }

        warn!(
            "Max retries ({}) exhausted for dynamic object delete: {}/{}/{}",
            Self::MAX_RETRIES,
            resource.kind,
            resource.namespace,
            resource.name
        );
        Err(AgentError::EmptyError)
    }

    pub async fn dynamic_object_replace_api_retryer(
        &self,
        retry_count: u32,
        dynamic_k8s_client: &Api<DynamicObject>,
        resource: &Resource,
        dynamic_object: &DynamicObject,
        dry_run: bool,
    ) -> AgentResult<DynamicObject> {
        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!(
                "Running dynamic object replace api retryer for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, attempt
            );

            match dynamic_k8s_client
                .replace(
                    &resource.name,
                    &PostParams {
                        dry_run,
                        field_manager: Some(self.agent.owner.clone()),
                    },
                    dynamic_object,
                )
                .await
            {
                Ok(data) => {
                    info!(
                        "Validated {}/{}/{}",
                        &resource.kind, resource.namespace, resource.name
                    );
                    trace!(
                        "{}/{}/{} Patched manifest: {}",
                        &resource.kind,
                        &resource.namespace,
                        &resource.name,
                        serde_yaml::to_string(&data).unwrap_or_default()
                    );
                    return Ok(data);
                }
                Err(e) => match &e {
                    kube::Error::Api(error_response) => {
                        if error_response.code == 409 {
                            // In 409 cases when calling this replace api, the object has likely
                            // changed on the cluster between the original fetching of the
                            // service and the update. Returns a conflict error to let the caller
                            // decide how to handle this case.
                            return Err(AgentError::KubeConflict(e));
                        } else if (error_response.code == 429 || error_response.code == 500)
                            && attempt < Self::MAX_RETRIES
                        {
                            // backoff, max 30 seconds
                            let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                            tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                            continue;
                        } else {
                            return Err(AgentError::KubeError(e));
                        }
                    }
                    _ => {
                        return Err(AgentError::KubeError(e));
                    }
                },
            }
        }

        warn!(
            "Max retries ({}) exhausted for dynamic object replace: {}/{}/{}",
            Self::MAX_RETRIES,
            resource.kind,
            resource.namespace,
            resource.name
        );
        Err(AgentError::EmptyError)
    }

    pub async fn dynamic_object_create_api_retryer(
        &self,
        retry_count: u32,
        dynamic_k8s_client: &Api<DynamicObject>,
        resource: &Resource,
        dynamic_object: &DynamicObject,
        dry_run: bool,
    ) -> AgentResult<DynamicObject> {
        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!(
                "Running dynamic object create api retryer for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, attempt
            );

            match dynamic_k8s_client
                .create(
                    &PostParams {
                        dry_run,
                        field_manager: Some(self.agent.owner.clone()),
                    },
                    dynamic_object,
                )
                .await
            {
                Ok(data) => {
                    return Ok(data);
                }
                Err(e) => match &e {
                    kube::Error::Api(error_response) => {
                        if (error_response.code == 429 || error_response.code == 500)
                            && attempt < Self::MAX_RETRIES
                        {
                            // backoff, max 30 seconds
                            let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                            tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                            continue;
                        } else {
                            return Err(AgentError::KubeError(e));
                        }
                    }
                    _ => {
                        return Err(AgentError::KubeError(e));
                    }
                },
            }
        }

        warn!(
            "Max retries ({}) exhausted for dynamic object create: {}/{}/{}",
            Self::MAX_RETRIES,
            resource.kind,
            resource.namespace,
            resource.name
        );
        Err(AgentError::EmptyError)
    }

    pub async fn dynamic_object_get_api_retryer(
        &self,
        retry_count: u32,
        dynamic_k8s_client: &Api<DynamicObject>,
        resource: &Resource,
    ) -> AgentResult<Option<DynamicObject>> {
        for attempt in retry_count..=Self::MAX_RETRIES {
            debug!(
                "Running dynamic object get api retryer for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, attempt
            );

            match dynamic_k8s_client.get(&resource.name).await {
                Ok(found_dynamic_object) => return Ok(Some(found_dynamic_object)),
                Err(e) => match &e {
                    kube::Error::Api(error_response) => {
                        if error_response.code == 404 {
                            info!("no resource detected");
                            return Ok(None);
                        } else if (error_response.code == 429 || error_response.code == 500)
                            && attempt < Self::MAX_RETRIES
                        {
                            // backoff, max 30 seconds
                            let backoff = 30_f32.min(attempt.pow(2) as f32 / 10.);
                            tokio::time::sleep(std::time::Duration::from_secs_f32(backoff)).await;
                            continue;
                        } else {
                            return Err(AgentError::KubeError(e));
                        }
                    }
                    _ => return Err(AgentError::Unknown(e.into())),
                },
            }
        }

        warn!(
            "Max retries ({}) exhausted for dynamic object get: {}/{}/{}",
            Self::MAX_RETRIES,
            resource.kind,
            resource.namespace,
            resource.name
        );
        Err(AgentError::EmptyError)
    }

    pub async fn delete_resources(&self) -> AgentResult<bool> {
        let mut is_deleted = false;

        if self.release_data.marked_for_deletion {
            self.gprc_installation_status(InstallationStatus::Started, String::new())
                .await?;
        }

        let order = order_map(true);
        let mut resources = self.resources_marked_for_removal.clone();
        resources.sort_by_key(|resource| order.get(resource.kind.as_str()).unwrap_or(&usize::MAX));

        for resource in resources.iter() {
            let mut dynamic_object = resource.dynamic_object()?;
            let dynamic_k8s_client: Api<DynamicObject> = if resource.is_namespaced {
                trace!("kind: {} is namespaced", &resource.kind);
                dynamic_object.metadata.namespace = Some(resource.namespace.clone());
                Api::namespaced_with(
                    self.agent.k8s_client.clone(),
                    &resource.namespace,
                    &resource.api_resource(),
                )
            } else {
                trace!("kind: {} is not namespaced", &resource.kind);
                Api::all_with(self.agent.k8s_client.clone(), &resource.api_resource())
            };

            match self
                .dynamic_object_delete_api_retryer(0, &dynamic_k8s_client, resource, false)
                .await
            {
                Ok(_) => is_deleted = true,
                Err(e) => match &e {
                    AgentError::KubeUrlNotFound(_) => {
                        info!(
                            "Resource {}/{}/{} already deleted or did not exists",
                            &resource.kind, &resource.namespace, &resource.name
                        );
                        continue;
                    }
                    _ => {
                        let message = format!(
                            "An error occurred removing resource {}/{}/{}: {:#?}",
                            &resource.kind, &resource.namespace, &resource.name, e
                        );
                        error!("{}", message);
                        if self.release_data.marked_for_deletion {
                            self.gprc_installation_status(InstallationStatus::Failed, message)
                                .await?;
                        }
                        return Err(e);
                    }
                },
            };
        }

        if self.release_data.marked_for_deletion {
            self.gprc_installation_status(InstallationStatus::Completed, String::new())
                .await?;
        }
        Ok(is_deleted)
    }

    pub async fn install_loop(
        &self,
        releases: Vec<Resource>,
        weighted: bool,
        post_weighted: bool,
    ) -> AgentResult<(bool, Option<bool>)> {
        let mut is_applied = false;
        let mut post_success: Option<bool> = None;
        self.gprc_installation_status(InstallationStatus::Started, String::new())
            .await?;
        let mut install_status = InstallationStatus::Completed;
        let mut error_recorded_on_failure: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(AgentError::EmptyError);

        'releases_loop: for resource in releases.iter() {
            info!("Installing {}", resource.key());

            let kind = &resource.kind;
            let mut pause_for_status = false;
            let mut is_install_as_new_resource = false;
            if kind == "Job" || kind == "Pod" {
                is_install_as_new_resource = true;
                info!("kind: {:?}, name: {:?}", resource.kind, resource.name,);
                if weighted || post_weighted {
                    pause_for_status = true;
                }
            }

            if let Some(diff) = &resource.diff {
                if !diff.is_diff() && !is_install_as_new_resource {
                    info!("Skipping {} because is up-to-date", resource.key());
                    continue 'releases_loop;
                }
            }

            let mut dynamic_object = resource.dynamic_object()?;
            let dynamic_k8s_client: Api<DynamicObject> = if resource.is_namespaced {
                trace!("kind: {} is namespaced", &resource.kind);
                dynamic_object.metadata.namespace = Some(resource.namespace.clone());
                Api::namespaced_with(
                    self.agent.k8s_client.clone(),
                    &resource.namespace,
                    &resource.api_resource(),
                )
            } else {
                trace!("kind: {} is not namespaced", &resource.kind);
                Api::all_with(self.agent.k8s_client.clone(), &resource.api_resource())
            };

            if !is_install_as_new_resource {
                let mut retry_count = 0;
                'install_loop: loop {
                    let in_cluster_resource_retry = if retry_count == 0 {
                        None
                    } else {
                        match self.resource_manifest(resource).await {
                            Ok(data) => data.1,
                            Err(e) => {
                                let message = format!("Failed retry getter of resource: {}", e);
                                error!("{}", message);
                                install_status = InstallationStatus::Failed;
                                error_recorded_on_failure = message.into();
                                break 'releases_loop;
                            }
                        }
                    };

                    let in_cluster_resource = if retry_count == 0 {
                        resource.in_cluster_resource.as_ref()
                    } else {
                        in_cluster_resource_retry.as_ref()
                    };

                    match in_cluster_resource {
                        Some(original) => {
                            dynamic_object.metadata.resource_version = original.resource_version();
                            dynamic_object.metadata.uid = original.uid();

                            trace!(
                                "{}/{}/{} Patched manifest: {}",
                                &resource.kind,
                                &resource.namespace,
                                &resource.name,
                                serde_yaml::to_string(&dynamic_object).unwrap_or_default()
                            );

                            match self
                                .dynamic_object_replace_api_retryer(
                                    retry_count,
                                    &dynamic_k8s_client,
                                    resource,
                                    &dynamic_object,
                                    false,
                                )
                                .await
                            {
                                Ok(_) => {
                                    info!(
                                        "Applied {}/{}/{}",
                                        &resource.kind, &resource.namespace, &resource.name,
                                    );
                                    is_applied = true;
                                    break 'install_loop;
                                }
                                Err(e) => match e {
                                    AgentError::KubeConflict(error) => {
                                        retry_count += 1;
                                        warn! {"{}", error}
                                        continue 'install_loop;
                                    }
                                    _ => {
                                        let message = format!("Failed applying resource: {}", e);
                                        error!("{}", message); // todo send more info
                                        install_status = InstallationStatus::Failed;
                                        error_recorded_on_failure = message.into();
                                        break 'releases_loop;
                                    }
                                },
                            }
                        }
                        None => {
                            is_install_as_new_resource = true;
                            break 'install_loop;
                        }
                    }
                }
            }

            if is_install_as_new_resource {
                debug!(
                    "{}/{}/{} is a new resource.",
                    &resource.kind, &resource.namespace, &resource.name
                );
                info!(
                    "Creating {}/{}/{}",
                    &resource.kind, &resource.namespace, &resource.name
                );

                // On new installs, we shouldn't be modifying the original yaml
                let dynamic_object = resource.dynamic_object_from_yaml()?;

                install_status = match self
                    .install_resource_api_retryer(
                        0,
                        dynamic_object,
                        &dynamic_k8s_client,
                        resource,
                        pause_for_status,
                        weighted,
                        post_weighted,
                        0,
                        vec![],
                        self.release_data.diff_generation,
                    )
                    .await
                {
                    Ok(installation_result) => {
                        is_applied = true;
                        post_success = installation_result.1;
                        InstallationStatus::Completed
                    }
                    Err(e) => match &e {
                        AgentError::KubeUrlNotFound(error) => {
                            let url = dynamic_k8s_client.resource_url().to_string();
                            let message = format!(
                                "Error creating resource {}/{}/{}. Could not reach api {}: {} {} {} {}",
                                &resource.kind,
                                &resource.namespace,
                                &resource.name,
                                url,
                                &error.code,
                                &error.message,
                                &error.reason,
                                &error.status,
                            );
                            error_recorded_on_failure = message.into();
                            InstallationStatus::Failed
                        }

                        AgentError::InstallationFailure(installation_status, _) => {
                            let message = format!(
                                "Error creating resource {}/{}/{}: {:#?}",
                                &resource.kind, &resource.namespace, &resource.name, e,
                            );
                            error_recorded_on_failure = message.into();
                            installation_status.clone()
                        }

                        _ => {
                            let message = format!("Release Failed:: {:#?}", e,);
                            error_recorded_on_failure = message.into();
                            InstallationStatus::Failed
                        }
                    },
                };
                // TODO do we need to caputure install status at all if we `break` on the first failure?
                if install_status == InstallationStatus::Failed {
                    info!("is_install_as_new_resource: {:?}", install_status);
                    break 'releases_loop;
                }
            }
        }
        info!("install status:{:?}", install_status);
        self.gprc_installation_status(install_status.clone(), String::new())
            .await?;

        if install_status == InstallationStatus::Failed {
            Err(AgentError::InstallationFailure(
                install_status,
                error_recorded_on_failure,
            ))
        } else {
            Ok((is_applied, post_success))
        }
    }

    pub async fn order_and_install(&mut self) -> AgentResult<(bool, bool, Option<bool>)> {
        let order = order_map(false);
        let mut non_weighted_resources = self
            .resources
            .iter()
            .filter(|(_, resource)| !resource.is_weighted() && !resource.is_post_weighted())
            .map(|(_, resource)| resource.clone())
            .collect::<Vec<_>>();

        non_weighted_resources
            .sort_by_key(|resource| order.get(resource.kind.as_str()).unwrap_or(&usize::MAX));

        let mut weighted_resources = self
            .resources
            .iter()
            .filter(|(_, resource)| resource.is_weighted())
            .map(|(_, resource)| resource.clone())
            .collect::<Vec<_>>();

        weighted_resources.sort_by(|item_a, item_b| {
            let a: i32 = item_a
                .get_kubemeta()
                .unwrap()
                .metadata
                .annotations
                .unwrap()
                .get("beecd/weight")
                .unwrap()
                .parse::<i32>()
                .expect("couldn't convert weight to int");

            let b: i32 = item_b
                .get_kubemeta()
                .unwrap()
                .metadata
                .annotations
                .unwrap()
                .get("beecd/weight")
                .unwrap()
                .parse::<i32>()
                .expect("couldn't convert weight to int");

            a.cmp(&b)
        });

        let mut post_weighted_resources = self
            .resources
            .iter()
            .filter(|(_, resource)| resource.is_post_weighted())
            .map(|(_, resource)| resource.clone())
            .collect::<Vec<_>>();

        post_weighted_resources.sort_by(|item_a, item_b| {
            let a: i32 = item_a
                .get_kubemeta()
                .unwrap()
                .metadata
                .annotations
                .unwrap()
                .get("beecd/post-weight")
                .unwrap()
                .parse::<i32>()
                .expect("couldn't convert weight to int");

            let b: i32 = item_b
                .get_kubemeta()
                .unwrap()
                .metadata
                .annotations
                .unwrap()
                .get("beecd/post-weight")
                .unwrap()
                .parse::<i32>()
                .expect("couldn't convert weight to int");

            a.cmp(&b)
        });

        let is_weighted_applied = if self.is_new_release() && !self.release_data.marked_for_deletion
        {
            self.delete_resources().await?
                || self.install_loop(weighted_resources, true, false).await?.0
        } else {
            false
        };

        let is_non_weighted_applied = if !self.release_data.marked_for_deletion {
            self.install_loop(non_weighted_resources, false, false)
                .await?
                .0
        } else {
            false
        };

        let (is_post_weighted_applied, post_success) =
            if self.is_new_release() && !self.release_data.marked_for_deletion {
                let delete_resource_result = self.delete_resources().await?;
                let (is_applied, post_success) = self
                    .install_loop(post_weighted_resources, false, true)
                    .await?;
                ((delete_resource_result || is_applied), post_success)
            } else {
                (false, None)
            };

        let is_release_deleted = if self.release_data.marked_for_deletion {
            self.delete_resources().await?
        } else {
            false
        };

        if is_weighted_applied || is_release_deleted || is_post_weighted_applied {
            self.resources_marked_for_removal = vec![];
        }

        // Not sure if updating weighted resource installs should count as the last_applied release
        // if the non weighted resources are not modified. Until this is figured out, assume that
        // any resource that is modified, weighted or unweighted, will set itself as the last-applied release.
        Ok((
            (is_weighted_applied || is_non_weighted_applied || is_post_weighted_applied),
            is_release_deleted,
            post_success,
        ))
    }

    pub async fn resource_manifest(
        &self,
        resource: &Resource,
    ) -> AgentResult<(Option<Diff>, Option<DynamicObject>)> {
        if !resource.should_diff() {
            return Ok((None, None));
        }

        let ignored_managed_fields = self.agent.ignored_managed_fields.clone();
        let resource_name = &resource.name;
        let resource_type = &resource.kind;
        let namespace = &resource.namespace;
        let api_resource = &resource.api_resource();

        info!(
            "Running diff on: kind = {}, name = {}/{},  apiResource = {:?}",
            resource_type, namespace, resource_name, api_resource
        );

        let mut dynamic_object = resource.dynamic_object()?;

        let dynamic_k8s_client: Api<DynamicObject> = if resource.is_namespaced {
            dynamic_object.metadata.namespace = Some(resource.namespace.clone());
            Api::namespaced_with(
                self.agent.k8s_client.clone(),
                &resource.namespace,
                &resource.api_resource(),
            )
        } else {
            Api::all_with(self.agent.k8s_client.clone(), &resource.api_resource())
        };

        let mut loop_retry_count: u32 = 0;
        const MAX_DIFF_RETRY_ITERATIONS: u32 = 20; // Limit retries to prevent infinite loops
        let (sanitized_existing_resource, original, server_rendered_manifest) = 'get_rhs_loop: loop {
            if loop_retry_count >= MAX_DIFF_RETRY_ITERATIONS {
                let message = format!(
                    "Exceeded maximum retry attempts ({}) for resource diff {}/{}/{}",
                    MAX_DIFF_RETRY_ITERATIONS, &resource.kind, &resource.namespace, &resource.name
                );
                warn!("{}", message);
                return Err(AgentError::ConfigError(message));
            }
            debug!(
                "Diff get_rhs_loop for {}/{}/{} attempt #{}",
                &resource.kind, &resource.namespace, &resource.name, loop_retry_count
            );
            loop_retry_count += 1;

            let resource_option = match self
                .dynamic_object_get_api_retryer(0, &dynamic_k8s_client, resource)
                .await
            {
                Ok(resource_option) => resource_option,
                Err(e) => {
                    return Err(e);
                }
            };

            let (sanitized_existing_resource, original) = match resource_option {
                Some(mut found_dynamic_object) => {
                    // Keep an original copy of the resource to handle managed fields
                    let original = found_dynamic_object.clone();

                    // Setup dynamic object so it can pass thru a server-side apply
                    dynamic_object.metadata.resource_version =
                        found_dynamic_object.resource_version();
                    dynamic_object.metadata.uid = found_dynamic_object.uid();

                    // Remove the parts of the diff that change often so diffs can be "clean"
                    found_dynamic_object.metadata.creation_timestamp = None;
                    found_dynamic_object.metadata.generation = None;
                    found_dynamic_object.metadata.managed_fields = None;
                    found_dynamic_object.metadata.owner_references = None;
                    found_dynamic_object.metadata.resource_version = None;
                    found_dynamic_object.metadata.uid = None;

                    if found_dynamic_object.data.get("status").is_some() {
                        found_dynamic_object.data["status"] = serde_json::Value::Null;
                    }

                    let sanitized_resource = match serde_yaml::to_string(&found_dynamic_object) {
                        Ok(d) => d,
                        Err(e) => {
                            return Err(AgentError::ResourceYamlDeserializeError(
                                resource.diff_key(),
                                e,
                            ));
                        }
                    };

                    (sanitized_resource, Some(original))
                }
                None => match resource.get_kubemeta() {
                    Ok(mut kubemeta) => {
                        if resource.is_namespaced {
                            kubemeta.with_namespace(&self.namespace());
                        }
                        let empty_resource = match kubemeta.to_string() {
                            Ok(s) => s,
                            Err(e) => {
                                return Err(e);
                            }
                        };
                        (empty_resource, None)
                    }

                    Err(e) => {
                        return Err(e);
                    }
                },
            };

            let result = match &original {
                Some(_) => {
                    self.dynamic_object_replace_api_retryer(
                        0,
                        &dynamic_k8s_client,
                        resource,
                        &dynamic_object,
                        true,
                    )
                    .await
                }
                None => {
                    self.dynamic_object_create_api_retryer(
                        0,
                        &dynamic_k8s_client,
                        resource,
                        &dynamic_object,
                        true,
                    )
                    .await
                }
            };

            let server_rendered_manifest = match result {
                Ok(mut r) => {
                    // Also sanitize rhs for diff "clean"liness
                    r.metadata.creation_timestamp = None;
                    r.metadata.generation = None;
                    r.metadata.managed_fields = None;
                    r.metadata.owner_references = None;
                    r.metadata.resource_version = None;
                    r.metadata.uid = None;

                    if r.data.get("status").is_some() {
                        r.data["status"] = serde_json::Value::Null;
                    }

                    match serde_yaml::to_string(&r) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(AgentError::ResourceYamlDeserializeError(
                                resource.diff_key(),
                                e,
                            ));
                        }
                    }
                }
                Err(e) => match e {
                    AgentError::KubeConflict(error) => {
                        warn! {"The resource changed during diff: {}", error};
                        continue 'get_rhs_loop;
                    }
                    _ => {
                        warn!("Warning, could not execute dry_run of resource: {:#?}", e);
                        match serde_yaml::to_string(&dynamic_object) {
                            Ok(s) => s,
                            Err(e) => {
                                error!("Failed to parse original resource: {}", e);
                                String::new()
                            }
                        }
                    }
                },
            };
            break (
                sanitized_existing_resource,
                original,
                server_rendered_manifest,
            );
        };

        let original_resource = match &original {
            Some(original) => match serde_yaml::to_string(original) {
                Ok(d) => d,
                Err(e) => {
                    return Err(AgentError::ResourceYamlDeserializeError(
                        resource.diff_key(),
                        e,
                    ));
                }
            },
            None => String::new(),
        };

        trace!(
            "Will diff following 2 docs:\n1.\n---\n{}\n2.\n---\n{}",
            sanitized_existing_resource,
            server_rendered_manifest
        );
        let lhs_docs =
            multi_document_parser_for_k8s_resources(None, Some(&sanitized_existing_resource))
                .map_err(|e| AgentError::DiffParseError(e.into()))?;
        if lhs_docs.len() != 1 {
            return Err(AgentError::DiffDocumentLengthMismatch(1, lhs_docs.len()));
        }

        let rhs_docs =
            multi_document_parser_for_k8s_resources(None, Some(&server_rendered_manifest))
                .map_err(|e| AgentError::DiffParseError(e.into()))?;

        let field_sets = aggregate_k8s_resources_managed_fields(None, Some(&original_resource));

        let field_sets_map = field_sets.unwrap_or_default();

        let ignore_sets = aggregate_managed_fields_to_ignore(
            None,
            Some(&original_resource),
            ignored_managed_fields,
        );
        let ignore_sets_map = ignore_sets.unwrap_or_default();

        let (key, doc) = lhs_docs.iter().next().unwrap();
        let lhs = doc.clone();
        let rhs = rhs_docs.get(key).cloned();

        let field_set = match field_sets_map.get(key) {
            Some(v) => v.clone(),
            None => None,
        };

        let ignore_set = match ignore_sets_map.get(key) {
            Some(v) => v.clone(),
            None => None,
        };

        let mut diff = Diff::new(Some(lhs), rhs, field_set, ignore_set);

        diff.do_compare()
            .map_err(|e| AgentError::DiffError(e.into()))?;
        diff.remove_childrenless_parents();

        Ok((Some(diff), original))
    }

    pub async fn diff(&mut self) -> AgentResult<()> {
        let mut is_diff = false;
        let mut diff_data: Vec<beecd::Diff> = vec![];

        if self.post_success.unwrap_or(true) {
            if !self.release_data.marked_for_deletion {
                'resource_loop: for resource in self
                    .resources
                    .values()
                    .filter(|resource| resource.should_diff())
                {
                    let diff_key = resource.diff_key();

                    let diff = match self.resource_manifest(resource).await {
                        Ok(d) => d.0,
                        Err(e) => match e {
                            AgentError::DiffDocumentLengthMismatch(_, _) => {
                                return Err(e);
                            }
                            _ => {
                                continue 'resource_loop;
                            }
                        },
                    };
                    if let Some(diff) = diff {
                        if diff.is_diff() {
                            is_diff = true;
                        }

                        diff_data.push(beecd::Diff {
                            key: diff_key.clone(),
                            body: diff.text(false).as_bytes().to_vec(),
                            change_order: diff.ordered_changes(),
                        });
                    }
                }
            }
            for resource in &self.resources_marked_for_removal {
                // Is is_diff becuase resources marked for removal are still around and
                // should not be auto approved which is triggerd when is_diff is false.
                is_diff = true;
                diff_data.push(beecd::Diff {
                    key: format!("-{}", resource.diff_key()),
                    body: beecdiff::as_deletion(serde_yaml::to_string(&resource.yaml).unwrap())
                        .as_bytes()
                        .to_vec(),
                    change_order: vec![],
                })
            }
        }

        // gather all the in-cluster manifests
        let in_cluster_manifest = self
            .resources
            .iter()
            .filter_map(|(_, resource)| resource.in_cluster_resource.clone())
            .filter_map(|dynamic_object| serde_yaml::to_string(&dynamic_object).ok())
            .collect::<Vec<_>>()
            .join("\n\n---\n\n");

        debug!("Comparing real-time diffs with historical diffs to see if anything has changed");
        let diff_keys = diff_data
            .iter()
            .map(|diff| safe_keyname(diff.key.clone()).unwrap())
            .collect::<Vec<_>>();

        let is_first_diff_of_release = match self.secret.labels().get("current-service-id") {
            Some(value) => value != &self.release_data.service_id,
            None => true,
        } || self.release_data.diff_generation == 0;

        info!(
            "is_first_diff_of_release check: current-service-id={:?}, release_data.service_id={}, release_data.diff_generation={}, result={}",
            self.secret.labels().get("current-service-id"),
            self.release_data.service_id,
            self.release_data.diff_generation,
            is_first_diff_of_release
        );

        let is_next_generation_diff = match self.secret.data.clone() {
            Some(previous_diff_data) => {
                let previous_diff_data_keys = previous_diff_data
                    .iter()
                    .filter(|k| k.0 != "manifest.gz")
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>();

                let previous_diff_count = previous_diff_data_keys.len();
                if previous_diff_count != diff_keys.len() {
                    if previous_diff_count == 0 {
                        info!("Diff changed becuase no previous diffs found")
                    } else {
                        info!("Diff changed becuase total len of keys changed");
                    }
                    true
                } else if diff_keys
                    .iter()
                    .any(|key| !&previous_diff_data_keys.contains(&key))
                {
                    // New generation because the keys are not identical (ie new/different resources)
                    info!("Diff changed becuase the keys not identical");
                    true
                } else {
                    diff_data.iter().any(|diff| {
                       let diff_key = safe_keyname(diff.key.clone()).unwrap();
                       let current_diff =
                           &string_to_bytestring(String::from_utf8(diff.body.clone()).unwrap());
                       // Check the diffs of each resource to see if they have changed
                       match previous_diff_data.clone().get(&diff_key) {
                           Some(previous_diff) => {
                               let previous_diff_data = match gunzipped_bytesstring(previous_diff.clone()){
                                   Ok(s) => s,
                                   Err(e) => {
                                       error!("Failed to parse gzipped data: {}", e);
                                       return false;
                                   },
                               };

                               if previous_diff_data != *current_diff {
                                   info!("Diff changed because previous diff does not match current_diff");
                                   true
                               } else {
                                   false
                               }
                           },
                           None => {
                               if !diff.body.is_empty() {
                                   info!("Diff changed becuase previous diff value was empty, but current diff is not empty");
                                   true
                               } else {
                                   false
                               }
                           },
                       }
                   })
                }
            }
            None => {
                let is_new_diff = !diff_data.is_empty();
                if is_new_diff {
                    info!("Diff changed becuase previous diff not found")
                }
                is_new_diff
            }
        };

        info!(is_next_generation_diff, is_first_diff_of_release);
        let (diff, diff_generation) = if is_next_generation_diff || is_first_diff_of_release {
            self.update_secret_data(diff_data_as_k8s_secret_data(&diff_data))?;

            let diff_generation = self.release_data.diff_generation + 1;
            self.insert_secret_labels("diff-generation", &diff_generation.to_string());

            (diff_data, diff_generation)
        } else {
            // This is not the next generation diff which means it should
            // fallback to what the server knows as current
            let diff_generation = self.release_data.diff_generation;
            self.insert_secret_labels("diff-generation", &diff_generation.to_string());

            // Remove the diff data (e.g. vec![]) when not required to save bandwidth
            (vec![], diff_generation)
        };

        let response = {
            debug!("Calling {} RPC", "ServiceStatus");
            self.agent
                .grpc_client
                .clone()
                .service_status(beecd::ServiceStatusRequest {
                    release_id: self.release_data.id.clone(),
                    diff,
                    is_diff,
                    is_next_generation_diff: is_next_generation_diff || is_first_diff_of_release,
                    previous_installed_hash: self.get_previous_installed_hash().unwrap_or_default(),
                    diff_generation,
                    post_success: self.post_success.unwrap_or(true), // grpc doesn't support option
                    in_cluster_manifest,
                })
                .await
        };

        match response {
            Ok(_) => {
                info!("Success response for SerivceStatusRequest");

                // Always update the current version in secret
                let service_id = self.release_data.service_id.clone();
                self.insert_secret_labels("current-service-id", &service_id);

                info!("Updating diff secret");
                let secret = self.update_release_secret().await?;

                self.set_secret(secret);
            }
            Err(e) => {
                error!("Failed to save service status to server: {}", e);
            }
        }

        Ok(())
    }
}

impl Agent {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        grpc_client: WorkerClient<
            tonic::service::interceptor::InterceptedService<
                tonic::transport::Channel,
                GrpcHeaderInjector,
            >,
        >,
        grpc_auth_client: WorkerClient<tonic::transport::Channel>,
        k8s_client: Client,
        owner_name: String,
        cluster_name: String,
        cluster_metadata: String,
        ignored_managed_fields: Option<String>,
        kubernetes_version: String,
        query_time_in_seconds: u64,
        post_install_sleep_duration_in_seconds_string: String,
        token_state: Arc<RwLock<Option<TokenState>>>,
        cluster_password: String,
    ) -> AgentResult<Self> {
        let loop_span = span!(tracing::Level::ERROR, "Setup");
        let _enter = loop_span.enter();
        let cluster_id = {
            debug!("Calling {} RPC", "ClientRegistration");
            grpc_client
                .clone()
                .client_registration(ClusterName {
                    cluster_name: cluster_name.clone(),
                    metadata: cluster_metadata.clone(),
                    version: crate::BUILD_VERSION.map_or(crate::VERSION.to_string(), String::from),
                    kubernetes_version: kubernetes_version.clone(),
                })
                .await
                .map_err(|e| AgentError::GrpcError {
                    rpc_name: String::from("ClientRegistration"),
                    err: Box::new(e),
                })?
                .into_inner()
                .cluster_id
        };
        let discovery = Discovery::new(k8s_client.clone())
            .run()
            .await
            .map_err(|e| {
                AgentError::ConfigError(format!("Failed to load k8s discovery service: {}", e))
            })?;

        let post_install_sleep_duration_in_seconds: u64 =
            post_install_sleep_duration_in_seconds_string
                .parse()
                .unwrap_or(5);

        drop(_enter);
        Ok(Self {
            grpc_client,
            grpc_auth_client,
            k8s_client,
            discovery,
            owner: owner_name,
            cluster_name,
            cluster_metadata,
            cluster_id,
            ignored_managed_fields,
            namespaces: Arc::new(RwLock::new(vec![])),
            all_releases: Arc::new(RwLock::new(vec![])),
            approved_releases: Arc::new(RwLock::new(vec![])),
            has_errors: Arc::new(RwLock::new(false)),
            query_time_in_seconds,
            post_install_sleep_duration_in_seconds,
            token_state,
            cluster_password,
            last_successful_token_check: Arc::new(RwLock::new(Some(Utc::now()))),
        })
    }

    /// Refresh the access token using the current refresh token
    async fn refresh_token(&self) -> AgentResult<()> {
        let refresh_token_value = {
            let state = self.token_state.read().map_err(|e| {
                AgentError::ConfigError(format!("Failed to read token state for refresh: {}", e))
            })?;
            state
                .as_ref()
                .ok_or_else(|| {
                    AgentError::ConfigError("No token state available for refresh".to_string())
                })?
                .refresh_token
                .clone()
        };

        debug!("Refreshing access token");
        let response = self
            .grpc_auth_client
            .clone()
            .refresh_token(beecd::RefreshTokenRequest {
                refresh_token: refresh_token_value,
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: "RefreshToken".to_string(),
                err: Box::new(e),
            })?;

        let response_inner = response.into_inner();
        let now = Utc::now();

        let mut state = self.token_state.write().map_err(|e| {
            AgentError::ConfigError(format!("Failed to write token state after refresh: {}", e))
        })?;

        *state = Some(TokenState {
            access_token: response_inner.access_token,
            refresh_token: response_inner.refresh_token, // Token rotation!
            access_expires_at: now
                + ChronoDuration::seconds(response_inner.access_token_expires_in),
            refresh_expires_at: now
                + ChronoDuration::seconds(response_inner.refresh_token_expires_in),
        });

        info!("Successfully refreshed access token");
        Ok(())
    }

    /// Re-authenticate with the server using username and password
    async fn re_authenticate(&self) -> AgentResult<()> {
        info!("Re-authenticating with server");

        let response = self
            .grpc_auth_client
            .clone()
            .login(beecd::LoginRequest {
                username: self.cluster_name.clone(),
                password: self.cluster_password.clone(),
                user_agent: format!(
                    "beecd-agent/{}",
                    crate::BUILD_VERSION.map_or(crate::VERSION, |v| v)
                ),
            })
            .await
            .map_err(|e| AgentError::GrpcError {
                rpc_name: "Login".to_string(),
                err: Box::new(e),
            })?;

        let response_inner = response.into_inner();
        let now = Utc::now();

        let mut state = self.token_state.write().map_err(|e| {
            AgentError::ConfigError(format!("Failed to write token state after re-auth: {}", e))
        })?;

        *state = Some(TokenState {
            access_token: response_inner.access_token,
            refresh_token: response_inner.refresh_token,
            access_expires_at: now
                + ChronoDuration::seconds(response_inner.access_token_expires_in),
            refresh_expires_at: now
                + ChronoDuration::seconds(response_inner.refresh_token_expires_in),
        });

        info!("Successfully re-authenticated with server");
        Ok(())
    }

    /// Check and refresh token if needed (proactive refresh before expiry)
    async fn ensure_token_valid(&self) -> AgentResult<()> {
        let (should_reauth, should_refresh) = {
            let state = self.token_state.read().map_err(|e| {
                AgentError::ConfigError(format!("Failed to read token state: {}", e))
            })?;

            if let Some(ref ts) = *state {
                let now = Utc::now();
                // Re-authenticate if refresh token expires in less than 4 hours
                let refresh_expires_soon = ts.refresh_expires_at - now < ChronoDuration::hours(4);
                // Refresh if access token expires in less than 3 minutes
                let access_expires_soon = ts.access_expires_at - now < ChronoDuration::minutes(3);

                (
                    refresh_expires_soon,
                    access_expires_soon && !refresh_expires_soon,
                )
            } else {
                // No token state - need to re-authenticate
                (true, false)
            }
        };

        if should_reauth {
            self.re_authenticate().await?;
        } else if should_refresh {
            self.refresh_token().await?;
        }

        Ok(())
    }

    /// Wraps a gRPC call with automatic token refresh on 401 Unauthenticated responses
    async fn grpc_call_with_retry<F, T>(&self, call_name: &str, mut call: F) -> AgentResult<T>
    where
        F: FnMut() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<tonic::Response<T>, Status>> + Send>,
        >,
    {
        match call().await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) if status.code() == Code::Unauthenticated => {
                warn!(
                    "Received 401 Unauthenticated for {}, refreshing token and retrying once",
                    call_name
                );

                // Attempt to refresh or re-authenticate
                self.ensure_token_valid().await?;

                // Retry once after refresh
                call()
                    .await
                    .map(|r| r.into_inner())
                    .map_err(|e| AgentError::GrpcError {
                        rpc_name: format!("{} (retry)", call_name),
                        err: Box::new(e),
                    })
            }
            Err(e) => Err(AgentError::GrpcError {
                rpc_name: call_name.to_string(),
                err: Box::new(e),
            }),
        }
    }

    /// Returns health status of token refresh system
    pub fn token_health_status(&self) -> String {
        let last_check = self
            .last_successful_token_check
            .read()
            .expect("last_successful_token_check RwLock poisoned");
        let token_state = self
            .token_state
            .read()
            .expect("token_state RwLock poisoned");

        if let (Some(check_time), Some(state)) = (*last_check, token_state.as_ref()) {
            let now = Utc::now();
            let minutes_since_check = (now - check_time).num_minutes();
            let minutes_until_access_expiry = (state.access_expires_at - now).num_minutes();
            let hours_until_refresh_expiry = (state.refresh_expires_at - now).num_hours();

            if minutes_since_check > 20 {
                format!(
                    "WARN: Token refresh task may be stuck (last check: {} min ago)",
                    minutes_since_check
                )
            } else if minutes_until_access_expiry < 5 {
                format!(
                    "WARN: Access token expires soon ({} min)",
                    minutes_until_access_expiry
                )
            } else if hours_until_refresh_expiry < 6 {
                format!(
                    "WARN: Refresh token expires soon ({} hours)",
                    hours_until_refresh_expiry
                )
            } else {
                format!(
                    "OK: Last check {} min ago, access expires in {} min, refresh expires in {} hours",
                    minutes_since_check,
                    minutes_until_access_expiry,
                    hours_until_refresh_expiry
                )
            }
        } else {
            "WARN: Token state not initialized".to_string()
        }
    }

    pub async fn k8s_list_namespaces(&self) -> AgentResult<Vec<String>> {
        let namespace_v1_client: Api<Namespace> = Api::all(self.k8s_client.clone());

        let list = namespace_v1_client
            .list(&ListParams::default().labels("beecd/register"))
            .await
            .map_err(AgentError::KubeError)?;

        let namespaces = list
            .items
            .iter()
            .map(|s| s.clone().metadata.name.unwrap_or("".to_string()))
            .collect::<Vec<_>>();

        Ok(namespaces)
    }

    pub async fn grpc_client_namespace_registration(
        &self,
        namespaces: Vec<String>,
    ) -> AgentResult<Vec<beecd::NamespaceMap>> {
        debug!("Calling {} RPC", "ClientNamespaceRegistration");

        let cluster_id = self.cluster_id.to_string();
        let grpc_response = self
            .grpc_call_with_retry("ClientNamespaceRegistration", || {
                let mut client = self.grpc_client.clone();
                let request = ClientNamespaceRegistrationRequest {
                    cluster_id: cluster_id.clone(),
                    namespace: namespaces.clone(),
                };
                Box::pin(async move { client.client_namespace_registration(request).await })
            })
            .await?;

        Ok(grpc_response.namespace_data)
    }

    pub async fn register_namespaces(&self) -> AgentResult<&Self> {
        let namespaces = self.k8s_list_namespaces().await?;
        let namespace_data = self.grpc_client_namespace_registration(namespaces).await?;

        let mut agent_namespaces = self
            .namespaces
            .write()
            .expect("namespaces RwLock poisoned - cannot register namespaces");
        *agent_namespaces = namespace_data;

        Ok(self)
    }

    pub fn namespace_ids(&self) -> Vec<String> {
        let agent_namespaces = self
            .namespaces
            .read()
            .expect("namespaces RwLock poisoned - cannot get namespace IDs");
        agent_namespaces.iter().map(|n| n.id.clone()).collect()
    }

    pub fn namespace_lookup(&self, namespace_id: &String) -> String {
        let agent_namespaces = self
            .namespaces
            .read()
            .expect("namespaces RwLock poisoned - cannot lookup namespace");
        match agent_namespaces
            .iter()
            .find(|item| item.id == *namespace_id)
        {
            Some(namespace_map_item) => namespace_map_item.name.clone(),
            None => String::new(),
        }
    }

    pub fn namespace_map(&self) -> HashMap<String, String> {
        let agent_namespaces = self
            .namespaces
            .read()
            .expect("namespaces RwLock poisoned - cannot get namespace map");
        agent_namespaces
            .iter()
            .map(|n| (n.name.clone(), n.id.clone()))
            .collect()
    }

    pub async fn get_release_data(&self) -> AgentResult<&Self> {
        debug!("Calling {} RPC", "GetRelease");

        let cluster_id = self.cluster_id.to_string();
        let namespace_ids = self.namespace_ids();

        let grpc_response = self
            .grpc_call_with_retry("GetRelease", || {
                let mut client = self.grpc_client.clone();
                let request = GetReleaseRequest {
                    cluster_id: cluster_id.clone(),
                    namespace_id: namespace_ids.clone(),
                };
                Box::pin(async move { client.get_release(request).await })
            })
            .await
            .map_err(|e| {
                error!(
                    "GetRelease failed for cluster: {} namespaces: {}. Raw error: {:?}",
                    self.cluster_id,
                    self.namespace_ids().join(" "),
                    e
                );
                e
            })?;

        debug!("Completed call to {} RPC", "GetRelease");
        let releases = grpc_response.release;
        trace!(?releases);
        let mut all_releases = self
            .all_releases
            .write()
            .expect("all_releases RwLock poisoned - cannot update release data");
        *all_releases = releases;

        Ok(self)
    }

    pub async fn get_appoved_releases(&self) -> AgentResult<&Self> {
        debug!("Calling {} RPC", "GetApprovedReleases");

        let cluster_id = self.cluster_id.to_string();
        let response = self
            .grpc_call_with_retry("GetApprovedReleases", || {
                let mut client = self.grpc_client.clone();
                let request = beecd::ClusterId {
                    cluster_id: cluster_id.clone(),
                };
                Box::pin(async move { client.get_approved_releases(request).await })
            })
            .await?;

        debug!("Completed call to {} RPC", "GetApprovedReleases");
        let approved_releases = response.release_id;
        let mut agent_releases = self
            .approved_releases
            .write()
            .expect("approved_releases RwLock poisoned - cannot update approved releases");
        *agent_releases = approved_releases;
        Ok(self)
    }

    pub fn owner_label(&self) -> String {
        format!("owner={}", &self.owner)
    }

    pub async fn grpc_log_hive_error(
        &self,
        message: String,
        is_deprecated: bool,
    ) -> AgentResult<()> {
        debug!("Calling {} RPC", "LogHiveError");

        let cluster_id = self.cluster_id.to_string();
        let message_bytes = message.as_bytes().to_vec();

        self.grpc_call_with_retry("LogHiveError", || {
            let mut client = self.grpc_client.clone();
            let request = beecd::LogHiveErrorRequest {
                cluster_id: cluster_id.clone(),
                message: message_bytes.clone(),
                is_deprecated,
            };
            Box::pin(async move { client.log_hive_error(request).await })
        })
        .await
        .map_err(|e| {
            error!("Failed to report hive error to server: {}", e);
            e
        })?;

        Ok(())
    }

    /// Executes the main program loop
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let sleep_timer: u64 = self.query_time_in_seconds;
        let agent = Arc::new(self);
        let thread_lock = Arc::new(RwLock::new(HashMap::new()));

        // Spawn background task for proactive token refresh with exponential backoff
        let agent_for_refresh = Arc::clone(&agent);
        tokio::spawn(async move {
            let mut consecutive_failures: u32 = 0;
            let base_interval = 300; // 5 minutes

            loop {
                // Exponential backoff: 5min, 10min, 20min, 40min, 80min (max ~1.3 hours)
                let sleep_secs = base_interval * 2_u64.pow(consecutive_failures.min(4));
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

                match agent_for_refresh.ensure_token_valid().await {
                    Ok(_) => {
                        // Reset failure counter on success
                        if consecutive_failures > 0 {
                            info!(
                                "Token validation recovered after {} failures",
                                consecutive_failures
                            );
                            consecutive_failures = 0;
                        } else {
                            debug!("Token validation check passed");
                        }

                        // Track last successful check for health monitoring
                        let mut last_check = agent_for_refresh
                            .last_successful_token_check
                            .write()
                            .expect("last_successful_token_check RwLock poisoned");
                        *last_check = Some(Utc::now());
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let next_retry_secs =
                            base_interval * 2_u64.pow(consecutive_failures.min(4));

                        error!(
                            "Token validation failed (attempt {}, next retry in {}s): {}",
                            consecutive_failures, next_retry_secs, e
                        );

                        if consecutive_failures >= 8 {
                            error!(
                                "Token refresh failed {} times consecutively - likely credential or network issue. \
                                 Agent will continue but may fail requests. Check HIVE_PASSWORD and server connectivity.",
                                consecutive_failures
                            );
                        }
                    }
                }
            }
        });

        loop {
            // TODO
            {
                let mut has_errors = agent
                    .has_errors
                    .write()
                    .expect("has_errors RwLock poisoned - cannot reset error flag");
                *has_errors = false;
            }

            let loop_span = span!(tracing::Level::ERROR, "Agent");
            let _enter = loop_span.enter();

            match agent.register_namespaces().await {
                Ok(_) => {
                    debug!(namespaces=?agent.namespace_map());
                }
                Err(e) => {
                    let message = format!("Failed to register namespaces: {}", e);
                    error!("{}", message);
                    let _ = agent.grpc_log_hive_error(message, false).await;
                    tokio::time::sleep(Duration::from_secs(sleep_timer)).await;
                    continue;
                }
            }

            match agent.get_release_data().await {
                Ok(_) => {
                    let agent_filedata = agent
                        .all_releases
                        .read()
                        .expect("all_releases RwLock poisoned - cannot read release data");
                    info!(
                        "Discovered services: {}",
                        agent_filedata
                            .iter()
                            .map(|release| {
                                format!("{}/{}", release.namespace_name, release.name,)
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                Err(e) => {
                    let message = format!("Failed to get filedata: {}", e);
                    error!("{}", message);
                    let _ = agent.grpc_log_hive_error(message, false).await;
                    tokio::time::sleep(Duration::from_secs(sleep_timer)).await;
                    continue;
                }
            }

            match agent.get_appoved_releases().await {
                Ok(_) => {
                    let agent_filedata = agent.all_releases.read().expect(
                            "all_releases RwLock poisoned - cannot read release data for approved check",
                        );
                    let approved_release_ids = agent.approved_releases.read().expect(
                        "approved_releases RwLock poisoned - cannot read approved releases",
                    );
                    info!(
                        "Approved releases: {}",
                        agent_filedata
                            .iter()
                            .filter(|release| approved_release_ids.contains(&release.id))
                            .map(|release| {
                                format!("{}/{}", release.namespace_name, release.name,)
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                Err(e) => {
                    let message = format!("Failed to get releases: {}", e);
                    error!("{}", message);
                    let _ = agent.grpc_log_hive_error(message, false).await;
                    tokio::time::sleep(Duration::from_secs(sleep_timer)).await;
                    continue;
                }
            }

            let shared_agent = Arc::clone(&agent);
            let unlocked_releases = {
                let agent_filedata = shared_agent
                    .all_releases
                    .read()
                    .expect("all_releases RwLock poisoned - cannot read releases for filtering");
                agent_filedata
                    .clone()
                    .into_iter()
                    .filter(|filedata| {
                        let release_name = filedata.name.as_str();
                        let release_namespace =
                            shared_agent.namespace_lookup(&filedata.namespace_id);
                        let release_namespaced_name =
                            format!("{}/{}", release_namespace, release_name);
                        let lock = thread_lock.read().expect(
                            "thread_lock RwLock poisoned - cannot check release lock status",
                        );
                        let releasable = lock
                            .get(&release_namespaced_name)
                            .is_none_or(|is_locked| !is_locked);
                        debug!(release_namespaced_name, is_locked = !releasable);
                        releasable
                    })
                    .collect::<Vec<_>>()
            };
            drop(_enter);

            for filedata in unlocked_releases {
                let shared_agent_for_release = Arc::clone(&agent);
                let shared_thread_lock = Arc::clone(&thread_lock);
                let release = Release::new(Arc::clone(&agent), filedata.clone());

                let release_name = format!(
                    "{}/{}",
                    shared_agent_for_release.namespace_lookup(&filedata.namespace_id),
                    filedata.name,
                );
                let release_name_for_panic = release_name.clone();
                let shared_agent_for_panic = Arc::clone(&agent);
                let shared_thread_lock_for_panic = Arc::clone(&thread_lock);

                tokio::spawn(
                    async move {
                        // Wrap task in panic handler to prevent lock poisoning from crashing other releases
                        let panic_result = std::panic::AssertUnwindSafe(task_release(
                            shared_agent_for_release,
                            shared_thread_lock,
                            release,
                        ))
                        .catch_unwind()
                        .await;

                        if let Err(panic_err) = panic_result {
                            error!(
                                "Release task {} panicked: {:?}",
                                release_name_for_panic, panic_err
                            );
                            let mut has_errors = shared_agent_for_panic
                                .has_errors
                                .write()
                                .expect("has_errors RwLock poisoned after panic in release task");
                            *has_errors = true;
                            drop(has_errors);

                            // Unlock the release so it can be retried
                            let mut lock = shared_thread_lock_for_panic
                                .write()
                                .expect("thread_lock RwLock poisoned after panic in release task");
                            lock.remove(&release_name_for_panic);
                        }
                    }
                    .instrument(span!(
                        tracing::Level::ERROR,
                        "Release",
                        "{}",
                        release_name
                    )),
                );
            }
            tokio::time::sleep(Duration::from_secs(sleep_timer)).await;

            // TODO Separate hive (agent) errors generated in the release threads so that those agent errors
            // are managed on an independant lifecycle. The usage of has_errors cannot handle multi-threading
            // correctly.
            let has_errors = {
                let has_errors = agent
                    .has_errors
                    .read()
                    .expect("has_errors RwLock poisoned - cannot check error status");
                *has_errors
            };
            debug!(has_errors);
            if !has_errors {
                let _ = agent.grpc_log_hive_error(String::new(), true).await;
            }
        }
    }
}

async fn task_release(
    agent: Arc<Agent>,
    thread_lock: Arc<RwLock<HashMap<String, bool>>>,
    mut release: Release,
) {
    let filedata = release.release_data.clone();
    let release_name = filedata.name.as_str();
    let release_namespace = release.agent.namespace_lookup(&filedata.namespace_id);
    let release_namespaced_name = format!("{}/{}", release_namespace, release_name);

    {
        let k = release_namespaced_name.clone();
        let mut lock = thread_lock
            .write()
            .expect("thread_lock RwLock poisoned - cannot lock release");
        lock.insert(k, true);
    }
    {
        let lock_read = thread_lock
            .read()
            .expect("thread_lock RwLock poisoned - cannot read lock status");
        debug!(?lock_read);
    }

    match release.get_release_secret().await {
        Ok(s) => {
            release.set_manifest(release.extract_manifest_from_secret(&s).await);
            release.set_secret(s);
        }
        Err(e) => {
            error!("Failed to get release secret: {}", e);
            match e {
                AgentError::GrpcError { rpc_name: _, err } => {
                    if err.code() == Code::NotFound {
                        let mut agent_has_errors = agent.has_errors.write().expect(
                            "has_errors RwLock poisoned - cannot set error flag for NotFound",
                        );
                        *agent_has_errors = true;
                        drop(agent_has_errors);
                    } else {
                        let message = format!("Failed to get manifest: {}", err.message());
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                _ => {
                    let message = format!("Failed to get manifest: {}", e);
                    let _ = release.grpc_log_release_error(message, false).await;
                }
            }
            let k = release_namespaced_name.clone();
            let mut lock = thread_lock
                .write()
                .expect("thread_lock RwLock poisoned - cannot unlock release after secret error");
            lock.remove(&k);
            return;
        }
    }

    match release.get_previous_release_secret().await {
        Ok(secret) => {
            if let Some(value) = secret
                .as_ref()
                .and_then(|secret| secret.labels().get("hash").cloned())
            {
                release.insert_secret_labels("previous-installed-hash", &value)
            }
            release.set_previous_release_secret(PreviousReleaseData { secret });

            // TODO Download a new secret if one does not exist
        }
        Err(e) => {
            let message = format!("Failed to get previous release secret: {:?}", e);
            error!("{}", message);
            match e {
                AgentError::GrpcError { rpc_name: _, err } => {
                    if err.code() == Code::NotFound {
                        let mut agent_has_errors = agent.has_errors.write()
                            .expect("has_errors RwLock poisoned - cannot set error flag for previous secret NotFound");
                        *agent_has_errors = true;
                        drop(agent_has_errors);
                    } else {
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                _ => {
                    let _ = release.grpc_log_release_error(message, false).await;
                }
            }
            let k = release_namespaced_name.clone();
            let mut lock = thread_lock.write().expect(
                "thread_lock RwLock poisoned - cannot unlock release after previous secret error",
            );
            lock.remove(&k);
            return;
        }
    }

    match release.get_resources() {
        Ok(mut resources) => {
            for resource in resources.iter_mut() {
                let (diff, original) = match release.resource_manifest(resource).await {
                    Ok(data) => (data.0, data.1),
                    Err(e) => {
                        let message = format!("Failed to get final resource manifest: {}", e);
                        error!("{}", message);
                        let _ = release.grpc_log_release_error(message, false).await;
                        let k = release_namespaced_name.clone();
                        let mut lock = thread_lock.write().unwrap();
                        lock.remove(&k);
                        return;
                    }
                };
                resource.set_in_cluster_resource(original);
                resource.set_diff(diff);
                release.resources.insert(resource.key(), resource.clone());
            }
        }
        Err(e) => {
            error!("Failed to parse manifest: {}", e);
            match e {
                AgentError::GrpcError { rpc_name: _, err } => {
                    if err.code() == Code::NotFound {
                        let mut agent_has_errors = agent.has_errors.write()
                            .expect("has_errors RwLock poisoned - cannot set error flag for parse manifest NotFound");
                        *agent_has_errors = true;
                        drop(agent_has_errors);
                    } else {
                        let message = format!("Failed to parse manifest: {}", err.message());
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                _ => {
                    let message = format!("Failed to parse manifest: {}", e);
                    let _ = release.grpc_log_release_error(message, false).await;
                }
            }
            let k = release_namespaced_name.clone();
            let mut lock = thread_lock
                .write()
                .expect("thread_lock RwLock poisoned - cannot unlock release after parse error");
            lock.remove(&k);
            return;
        }
    }

    match release.get_resources_marked_for_removal().await {
        Ok(mut resources_marked_for_removal) => {
            if release.release_data.marked_for_deletion {
                resources_marked_for_removal.append(
                    &mut release
                        .resources
                        .iter()
                        .filter(|(_, resource)| resource.in_cluster_resource.is_some())
                        .map(|(_, resource)| resource.clone())
                        .collect::<Vec<_>>(),
                );
            }

            release.resources_marked_for_removal = resources_marked_for_removal
        }
        Err(e) => {
            error!("Failed to parse previous manifest: {}", e);
            match e {
                AgentError::GrpcError { rpc_name: _, err } => {
                    if err.code() == Code::NotFound {
                        let mut agent_has_errors = agent.has_errors.write()
                            .expect("has_errors RwLock poisoned - cannot set error flag for previous manifest NotFound");
                        *agent_has_errors = true;
                        drop(agent_has_errors);
                    } else {
                        let message =
                            format!("Failed to parse previous manifest: {}", err.message());
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                _ => {
                    let message = format!("Failed to parse previous manifest: {}", e);
                    let _ = release.grpc_log_release_error(message, false).await;
                }
            }
            let k = release_namespaced_name.clone();
            let mut lock = thread_lock.write().expect(
                "thread_lock RwLock poisoned - cannot unlock release after previous manifest error",
            );
            lock.remove(&k);
            return;
        }
    }

    if release.is_approved() {
        match release.order_and_install().await {
            Ok((is_applied, is_deleted, post_success)) => {
                // Update the installed version when applicable
                let service_id = release.release_data.clone().service_id;

                if is_deleted {
                    let now = Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
                    release.insert_secret_labels("deleted-on", &now);
                    release.insert_secret_labels("deleted-service-id", &service_id);
                }

                if is_applied {
                    release.is_applied = is_applied;
                    let now = Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
                    release.insert_secret_labels("last-applied", &now);
                    release.insert_secret_labels("applied-service-id", &service_id);
                }

                release.post_success = post_success;

                // After installation, allow time for the various controllers
                // to make their changes to the resource in the cluster.
                // The time varies per controller, but most complete shortly after install.
                tokio::time::sleep(std::time::Duration::from_secs(
                    release.agent.post_install_sleep_duration_in_seconds,
                ))
                .await;
            }
            Err(e) => {
                error!("Failed to perform installation: {}", e);
                match e {
                    AgentError::GrpcError { rpc_name: _, err } => {
                        if err.code() == Code::NotFound {
                            let mut agent_has_errors = agent.has_errors.write()
                                .expect("has_errors RwLock poisoned - cannot set error flag for installation NotFound");
                            *agent_has_errors = true;
                            drop(agent_has_errors);
                        } else {
                            let message =
                                format!("Failed to perform installation: {}", err.message());
                            let _ = release.grpc_log_release_error(message, false).await;
                        }
                    }
                    _ => {
                        let message = format!("Failed to perform installation: {}", e);
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                let k = release_namespaced_name.clone();
                let mut lock = thread_lock.write().expect(
                    "thread_lock RwLock poisoned - cannot unlock release after installation error",
                );
                lock.remove(&k);
                return;
            }
        };
    }

    match release.diff().await {
        Ok(_) => {
            debug!("Completed diffs successfully");
        }
        Err(e) => {
            error!("Failed to perform diff: {}", e);
            match e {
                AgentError::GrpcError { rpc_name: _, err } => {
                    if err.code() == Code::NotFound {
                        let mut agent_has_errors = agent.has_errors.write().expect(
                            "has_errors RwLock poisoned - cannot set error flag for diff NotFound",
                        );
                        *agent_has_errors = true;
                        drop(agent_has_errors);
                    } else {
                        let message = format!("Failed to perform diff: {}", err.message());
                        let _ = release.grpc_log_release_error(message, false).await;
                    }
                }
                _ => {
                    let message = format!("Failed to perform diff: {}", e);
                    let _ = release.grpc_log_release_error(message, false).await;
                }
            }
            let k = release_namespaced_name.clone();
            let mut lock = thread_lock
                .write()
                .expect("thread_lock RwLock poisoned - cannot unlock release after diff error");
            lock.remove(&k);
            return;
        }
    };
    debug!("Clearing out release errors from database");
    let _ = release.grpc_log_release_error(String::new(), true).await;
    debug!("Unlocking release");
    let k = release_namespaced_name.clone();
    let mut lock = thread_lock
        .write()
        .expect("thread_lock RwLock poisoned - cannot unlock release after completion");
    lock.remove(&k);
    debug!("Unlocked");
}

pub fn deserialize_doc(s: &str) -> AgentResult<serde_yaml::Value> {
    let d = match serde_yaml::Deserializer::from_str(s).next() {
        Some(d) => d,
        None => return Err(AgentError::DeserializerDocMissing),
    };

    serde_yaml::Value::deserialize(d).map_err(AgentError::YamlDeserializeError)
}

#[cfg(test)]
pub mod testing {
    use super::*;

    // Helper for creating test Resource
    pub fn create_test_resource(kind: &str, name: &str, namespace: &str) -> Resource {
        let yaml_str = format!(
            r#"
apiVersion: v1
kind: {}
metadata:
  name: {}
  namespace: {}
"#,
            kind, name, namespace
        );
        let doc = deserialize_doc(&yaml_str).unwrap();
        Resource {
            yaml: doc,
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            api_version: "v1".to_string(),
            version: "v1".to_string(),
            group: "".to_string(),
            is_namespaced: true,
            ..Resource::default()
        }
    }

    pub fn create_weighted_resource(weight: &str) -> Resource {
        let yaml_str = format!(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    beecd/weight: "{}"
"#,
            weight
        );
        let doc = deserialize_doc(&yaml_str).unwrap();
        Resource {
            yaml: doc,
            kind: "Pod".to_string(),
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            ..Resource::default()
        }
    }

    pub fn create_resource_from_yaml(yaml_str: &str) -> Resource {
        let doc = deserialize_doc(yaml_str).unwrap();
        Resource {
            yaml: doc,
            ..Resource::default()
        }
    }
}
