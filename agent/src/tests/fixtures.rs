// Test fixtures providing sample YAML manifests and test data

/// Helper macro to load fixture YAML files at compile time
macro_rules! load_fixture {
    ($name:expr) => {
        include_str!(concat!("fixtures/", $name))
    };
}

/// Simple Deployment manifest for testing
pub const SIMPLE_DEPLOYMENT_YAML: &str = load_fixture!("simple_deployment.yaml");

/// StatefulSet manifest for testing
pub const SIMPLE_STATEFULSET_YAML: &str = load_fixture!("simple_statefulset.yaml");

/// ConfigMap manifest for testing
pub const SIMPLE_CONFIGMAP_YAML: &str = load_fixture!("simple_configmap.yaml");

/// Secret manifest for testing
pub const SIMPLE_SECRET_YAML: &str = load_fixture!("simple_secret.yaml");

/// Multi-document manifest with multiple resources
pub const MULTI_DOCUMENT_YAML: &str = load_fixture!("multi_document.yaml");

/// Weighted resource manifest with beecd annotations
pub const WEIGHTED_DEPLOYMENT_YAML: &str = load_fixture!("weighted_deployment.yaml");

/// Post-weighted resource (runs after main deployment)
pub const POST_WEIGHTED_JOB_YAML: &str = load_fixture!("post_weighted_job.yaml");

/// Pod manifest for testing
pub const SIMPLE_POD_YAML: &str = load_fixture!("simple_pod.yaml");

/// Job manifest for testing
pub const SIMPLE_JOB_YAML: &str = load_fixture!("simple_job.yaml");

/// Service manifest for testing
pub const SIMPLE_SERVICE_YAML: &str = load_fixture!("simple_service.yaml");

/// RBAC Role manifest for testing
pub const SIMPLE_ROLE_YAML: &str = load_fixture!("simple_role.yaml");

/// RBAC RoleBinding manifest for testing
pub const SIMPLE_ROLEBINDING_YAML: &str = load_fixture!("simple_rolebinding.yaml");

/// Custom Resource Definition for testing
pub const SIMPLE_CRD_YAML: &str = load_fixture!("simple_crd.yaml");

/// Manifest with image update (for diff testing)
pub const UPDATED_DEPLOYMENT_YAML: &str = load_fixture!("updated_deployment.yaml");

/// Test data for release IDs
pub const TEST_RELEASE_ID: &str = "release-12345";
pub const TEST_SERVICE_NAME: &str = "test-service";
pub const TEST_HASH: &str = "abc123def456";
pub const TEST_SERVICE_ID: &str = "abc12345-1234-5678-9abc-123456789012";
pub const TEST_CLUSTER_NAME: &str = "test-cluster";
pub const TEST_NAMESPACE_ID: &str = "ns-001";
pub const TEST_NAMESPACE_NAME: &str = "default";

/// Helper function to create a basic release data structure
pub fn create_test_release_data() -> crate::beecd::Release {
    crate::beecd::Release {
        id: TEST_RELEASE_ID.to_string(),
        service_id: TEST_SERVICE_ID.to_string(),
        repo_branch_id: "branch-001".to_string(),
        hash: TEST_HASH.to_string(),
        path: "/services/test-service".to_string(),
        name: TEST_SERVICE_NAME.to_string(),
        version: "1.0.0".to_string(),
        namespace_id: TEST_NAMESPACE_ID.to_string(),
        git_sha: "abcd1234".to_string(),
        diff_generation: 1,
        branch: "main".to_string(),
        org: "test-org".to_string(),
        repo: "test-repo".to_string(),
        completed_first_install: false,
        previous_installed_hash: String::new(),
        namespace_name: TEST_NAMESPACE_NAME.to_string(),
        marked_for_deletion: false,
    }
}

/// Helper to create a gzipped manifest
pub fn gzip_manifest(manifest: &str) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(manifest.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

/// Helper to create test Kubernetes Secret with manifest
pub fn create_secret_with_manifest(
    name: &str,
    namespace: &str,
    manifest: &str,
) -> k8s_openapi::api::core::v1::Secret {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::ByteString;
    use std::collections::BTreeMap;

    let mut data = BTreeMap::new();
    let gzipped = gzip_manifest(manifest);
    data.insert("manifest.gz".to_string(), ByteString(gzipped));

    let mut labels = BTreeMap::new();
    labels.insert("agent".to_string(), TEST_CLUSTER_NAME.to_string());
    labels.insert("service".to_string(), TEST_SERVICE_NAME.to_string());
    labels.insert("hash".to_string(), TEST_HASH.to_string());
    labels.insert("service-id".to_string(), TEST_SERVICE_ID.to_string());

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        data: Some(data),
        ..Secret::default()
    }
}

/// Helper to create test Secret with custom data (reduces duplication)
pub fn create_secret_with_data(
    name: &str,
    namespace: &str,
    data: std::collections::BTreeMap<String, k8s_openapi::ByteString>,
) -> k8s_openapi::api::core::v1::Secret {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..ObjectMeta::default()
        },
        data: Some(data),
        ..Secret::default()
    }
}

/// Helper to create test Secret with custom labels
pub fn create_secret_with_labels(
    name: &str,
    namespace: &str,
    labels: std::collections::BTreeMap<String, String>,
) -> k8s_openapi::api::core::v1::Secret {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        data: None,
        ..Secret::default()
    }
}
