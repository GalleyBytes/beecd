// Common test utilities and helpers

/// Setup common test environment with mocked dependencies
pub struct TestContext {
    pub mock_grpc_client: super::mocks::MockWorkerClient,
    pub mock_k8s_client: super::mocks::MockK8sClient,
    pub mock_discovery: super::mocks::MockDiscovery,
}

impl TestContext {
    pub fn new() -> Self {
        Self {
            mock_grpc_client: super::mocks::MockWorkerClient::new(),
            mock_k8s_client: super::mocks::MockK8sClient::new(),
            mock_discovery: super::mocks::MockDiscovery::new(),
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Assert that an error matches expected type
#[macro_export]
macro_rules! assert_error_type {
    ($result:expr, $error_type:path) => {
        match $result {
            Err($error_type(_)) => {}
            other => panic!("Expected error type, got: {:?}", other),
        }
    };
}

/// Helper to extract the number of retries from a backoff calculation
pub fn calculate_backoff_time(retry_count: u32) -> f32 {
    30_f32.min(retry_count.pow(2) as f32 / 10.)
}

/// Helper to verify resource ordering using production order_map from agent.rs
pub fn verify_resource_order(kinds: Vec<&str>) -> bool {
    // Get actual production ordering from agent.rs
    let order = crate::agent::order_map(false);

    for i in 0..kinds.len() - 1 {
        let current_priority = order.get(kinds[i]).unwrap_or(&usize::MAX);
        let next_priority = order.get(kinds[i + 1]).unwrap_or(&usize::MAX);

        if current_priority > next_priority {
            return false;
        }
    }

    true
}

/// Create a test namespace registration
pub fn create_test_namespace() -> crate::beecd::NamespaceMap {
    crate::beecd::NamespaceMap {
        id: super::fixtures::TEST_NAMESPACE_ID.to_string(),
        name: super::fixtures::TEST_NAMESPACE_NAME.to_string(),
    }
}

/// Verify gzip compression/decompression roundtrip
pub fn test_gzip_roundtrip(original: &str) -> bool {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let compressed = super::fixtures::gzip_manifest(original);
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();

    decompressed == original
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creates_successfully() {
        let ctx = TestContext::new();
        assert_eq!(ctx.mock_grpc_client.get_request_count(), 0);
    }

    #[test]
    fn test_backoff_calculation() {
        assert_eq!(calculate_backoff_time(0), 0.0);
        assert_eq!(calculate_backoff_time(1), 0.1);
        assert_eq!(calculate_backoff_time(5), 2.5);
        assert_eq!(calculate_backoff_time(100), 30.0); // capped at 30
    }

    #[test]
    fn test_gzip_roundtrip_simple() {
        let text = "Hello, World!";
        assert!(test_gzip_roundtrip(text));
    }

    #[test]
    fn test_gzip_roundtrip_yaml() {
        let yaml = super::super::fixtures::SIMPLE_DEPLOYMENT_YAML;
        assert!(test_gzip_roundtrip(yaml));
    }
}
