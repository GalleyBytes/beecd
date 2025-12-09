// Mock infrastructure for testing
// Provides mock implementations of Kubernetes API, gRPC server, and other dependencies

use k8s_openapi::api::core::v1::Secret;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, RwLock};

/// Mock gRPC WorkerClient for testing server communication
#[derive(Clone)]
pub struct MockWorkerClient {
    pub manifests: Arc<Mutex<HashMap<String, String>>>,
    pub approved_releases: Arc<Mutex<Vec<String>>>,
    pub diffs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    pub should_fail: Arc<Mutex<bool>>,
    pub request_count: Arc<Mutex<usize>>,
}

impl MockWorkerClient {
    pub fn new() -> Self {
        Self {
            manifests: Arc::new(Mutex::new(HashMap::new())),
            approved_releases: Arc::new(Mutex::new(Vec::new())),
            diffs: Arc::new(Mutex::new(HashMap::new())),
            should_fail: Arc::new(Mutex::new(false)),
            request_count: Arc::new(Mutex::new(0)),
        }
    }

    pub fn with_manifest(self, release_id: String, manifest: String) -> Self {
        self.manifests.lock().unwrap().insert(release_id, manifest);
        self
    }

    pub fn with_approved_release(self, release_id: String) -> Self {
        self.approved_releases.lock().unwrap().push(release_id);
        self
    }

    pub fn set_should_fail(&self, fail: bool) {
        *self.should_fail.lock().unwrap() = fail;
    }

    pub fn get_request_count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }
}

impl Default for MockWorkerClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock Kubernetes API client for testing cluster operations
pub struct MockK8sClient {
    pub secrets: Arc<RwLock<HashMap<String, Secret>>>,
    pub resources: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    pub api_errors: Arc<Mutex<Vec<(String, u16)>>>, // (resource_key, error_code)
}

impl MockK8sClient {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            api_errors: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_secret(self, name: String, secret: Secret) -> Self {
        self.secrets.write().unwrap().insert(name, secret);
        self
    }

    pub fn get_secret(&self, name: &str) -> Option<Secret> {
        self.secrets.read().unwrap().get(name).cloned()
    }

    pub fn add_api_error(&self, resource_key: String, error_code: u16) {
        self.api_errors
            .lock()
            .unwrap()
            .push((resource_key, error_code));
    }

    pub fn should_error(&self, resource_key: &str) -> Option<u16> {
        self.api_errors
            .lock()
            .unwrap()
            .iter()
            .find(|(key, _)| key == resource_key)
            .map(|(_, code)| *code)
    }
}

impl Default for MockK8sClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock discovery service for resolving Kubernetes API resources
pub struct MockDiscovery {
    pub resource_scopes: Arc<Mutex<HashMap<String, String>>>, // gvk -> "Namespaced" or "Cluster"
}

impl MockDiscovery {
    pub fn new() -> Self {
        Self {
            resource_scopes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_resource(self, gvk: String, scope: String) -> Self {
        self.resource_scopes.lock().unwrap().insert(gvk, scope);
        self
    }

    pub fn is_namespaced(&self, gvk: &str) -> bool {
        self.resource_scopes
            .lock()
            .unwrap()
            .get(gvk)
            .map(|s| s == "Namespaced")
            .unwrap_or(false)
    }
}

impl Default for MockDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Test-specific error simulation
#[derive(Clone)]
pub enum ErrorScenario {
    /// 409 Conflict error
    Conflict,
    /// 429 Throttle error (should retry)
    Throttle,
    /// 500 Server error (should retry)
    ServerError,
    /// 404 Not found error
    NotFound,
    /// No error
    None,
}

impl ErrorScenario {
    pub fn to_http_code(&self) -> Option<u16> {
        match self {
            ErrorScenario::Conflict => Some(409),
            ErrorScenario::Throttle => Some(429),
            ErrorScenario::ServerError => Some(500),
            ErrorScenario::NotFound => Some(404),
            ErrorScenario::None => None,
        }
    }
}
