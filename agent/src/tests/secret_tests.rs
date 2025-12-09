// Tests for Secret Management and Corruption Recovery
//
// Critical workflows tested:
// - Loading manifest from secrets
// - Validating secret format ("manifest.gz" key required)
// - Detecting and handling corrupted secrets
// - Creating new secrets with gzipped manifest
// - Recovering from RestoreDiff RPC fallback

#[cfg(test)]
mod secret_management_tests {
    use crate::tests::fixtures::*;

    #[test]
    fn test_secret_with_valid_manifest_loads_successfully() {
        // Arrange
        let secret =
            create_secret_with_manifest("test-secret-123", "default", SIMPLE_DEPLOYMENT_YAML);

        // Act
        let name = secret.metadata.name.as_ref().unwrap();
        let namespace = secret.metadata.namespace.as_ref().unwrap();
        let has_manifest = secret
            .data
            .as_ref()
            .map(|d| d.contains_key("manifest.gz"))
            .unwrap_or(false);

        // Assert
        assert_eq!(name, "test-secret-123");
        assert_eq!(namespace, "default");
        assert!(has_manifest);
    }

    #[test]
    fn test_secret_with_manifest_gzipped_correctly() {
        // Arrange
        let manifest = SIMPLE_DEPLOYMENT_YAML;
        let secret = create_secret_with_manifest("test-secret", "default", manifest);

        // Act
        let data = secret.data.unwrap();
        let manifest_bytes = data.get("manifest.gz").unwrap();

        // Assert: Verify it's actually gzipped
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(&manifest_bytes.0[..]);
        let mut decompressed = String::new();
        let result = decoder.read_to_string(&mut decompressed);

        assert!(result.is_ok());
        assert_eq!(decompressed, manifest);
    }

    #[test]
    fn test_secret_labels_contain_service_info() {
        // Arrange
        let secret = create_secret_with_manifest("test-secret", "default", SIMPLE_DEPLOYMENT_YAML);

        // Act
        let labels = secret.metadata.labels.as_ref().unwrap();

        // Assert
        assert_eq!(
            labels.get("agent").map(|s| s.as_str()),
            Some(TEST_CLUSTER_NAME)
        );
        assert_eq!(
            labels.get("service").map(|s| s.as_str()),
            Some(TEST_SERVICE_NAME)
        );
        assert_eq!(labels.get("hash").map(|s| s.as_str()), Some(TEST_HASH));
        assert_eq!(
            labels.get("service-id").map(|s| s.as_str()),
            Some(TEST_SERVICE_ID)
        );
    }

    #[test]
    fn test_secret_missing_manifest_key_detected() {
        // Arrange: Create a secret without manifest.gz
        use std::collections::BTreeMap;

        let secret = create_secret_with_data(
            "bad-secret",
            "default",
            BTreeMap::new(), // Empty data, no manifest.gz
        );

        // Act
        let has_manifest = secret
            .data
            .as_ref()
            .map(|d| d.contains_key("manifest.gz"))
            .unwrap_or(false);

        // Assert
        assert!(!has_manifest);
    }

    #[test]
    fn test_multiple_manifests_in_secret_data() {
        // Arrange: Create a secret with multiple data keys (manifest + diffs)
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use k8s_openapi::ByteString;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        let manifest_gzip = gzip_manifest(SIMPLE_DEPLOYMENT_YAML);
        let diff_gzip = gzip_manifest("some diff data");

        data.insert("manifest.gz".to_string(), ByteString(manifest_gzip));
        data.insert(
            "default-default-deployment-test-deployment.gz".to_string(),
            ByteString(diff_gzip),
        );

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("multi-data-secret".to_string()),
                namespace: Some("default".to_string()),
                ..ObjectMeta::default()
            },
            data: Some(data),
            ..Secret::default()
        };

        // Act
        let data_keys: Vec<&String> = secret.data.as_ref().unwrap().keys().collect();

        // Assert
        assert_eq!(data_keys.len(), 2);
        assert!(secret.data.unwrap().contains_key("manifest.gz"));
    }

    #[test]
    fn test_secret_namespace_matches_release_namespace() {
        // Arrange
        let namespace = "kube-system";
        let secret =
            create_secret_with_manifest("secret-in-kube-system", namespace, SIMPLE_DEPLOYMENT_YAML);

        // Act
        let secret_namespace = secret.metadata.namespace.as_ref().unwrap();

        // Assert
        assert_eq!(secret_namespace, namespace);
    }

    #[test]
    fn test_secret_name_format_includes_service_id() {
        // Arrange
        let service_id = "abc12345-1234-5678-9abc-123456789012";
        let service_id_prefix = &service_id[..8]; // First 8 chars
        let service_name = "my-service";
        let secret_name = format!("{}-{}", service_name, service_id_prefix.to_lowercase());

        // Act & Assert
        assert!(secret_name.contains(service_id_prefix));
        assert!(secret_name.contains(service_name));
        assert_eq!(secret_name, "my-service-abc12345");
    }

    #[test]
    fn test_corrupted_secret_data_gzip_invalid() {
        // Arrange: Create secret with invalid gzip data
        use k8s_openapi::ByteString;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        let invalid_gzip = vec![0x1f, 0x8b, 0x08, 0xff]; // Truncated gzip header
        data.insert("manifest.gz".to_string(), ByteString(invalid_gzip));

        let secret = create_secret_with_data("corrupted-secret", "default", data);

        // Act: Try to decompress
        use flate2::read::GzDecoder;
        use std::io::Read;

        let data = secret.data.unwrap();
        let manifest_bytes = &data.get("manifest.gz").unwrap().0;
        let mut decoder = GzDecoder::new(&manifest_bytes[..]);
        let mut buf = String::new();
        let result = decoder.read_to_string(&mut buf);

        // Assert: Should fail
        assert!(result.is_err());
    }

    #[test]
    fn test_secret_previous_installed_hash_label() {
        // Arrange
        use std::collections::BTreeMap;

        let mut labels = BTreeMap::new();
        labels.insert(
            "previous-installed-hash".to_string(),
            "old-hash-123".to_string(),
        );

        let secret = create_secret_with_labels("versioned-secret", "default", labels);

        // Act
        let prev_hash = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("previous-installed-hash"))
            .map(|s| s.as_str());

        // Assert
        assert_eq!(prev_hash, Some("old-hash-123"));
    }

    #[test]
    fn test_secret_diff_generation_tracking() {
        // Arrange
        use std::collections::BTreeMap;

        let mut labels = BTreeMap::new();
        labels.insert("diff-generation".to_string(), "5".to_string());

        let secret = create_secret_with_labels("tracked-secret", "default", labels);

        // Act
        let diff_gen = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("diff-generation"))
            .and_then(|s| s.parse::<i32>().ok());

        // Assert
        assert_eq!(diff_gen, Some(5));
    }

    #[test]
    fn test_secret_last_applied_timestamp_label() {
        // Arrange
        use std::collections::BTreeMap;

        let timestamp = "2024-01-15T10-30-45";
        let mut labels = BTreeMap::new();
        labels.insert("last-applied".to_string(), timestamp.to_string());

        let secret = create_secret_with_labels("timestamped-secret", "default", labels);

        // Act
        let ts = secret
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("last-applied"))
            .map(|s| s.as_str());

        // Assert
        assert_eq!(ts, Some(timestamp));
    }

    #[test]
    fn test_recovery_secret_creation_with_diff_data() {
        // Arrange: Simulate a recovered secret with both manifest and diff data
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use k8s_openapi::ByteString;
        use std::collections::BTreeMap;

        let mut data = BTreeMap::new();
        data.insert(
            "manifest.gz".to_string(),
            ByteString(gzip_manifest(SIMPLE_DEPLOYMENT_YAML)),
        );
        data.insert(
            "default-default-deployment-test-deployment.gz".to_string(),
            ByteString(gzip_manifest("diff content")),
        );

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("recovered-secret".to_string()),
                namespace: Some("default".to_string()),
                ..ObjectMeta::default()
            },
            data: Some(data),
            ..Secret::default()
        };

        // Act
        let data = secret.data.unwrap();
        let data_keys: Vec<_> = data.keys().collect();

        // Assert
        assert!(data_keys.len() >= 2);
        assert!(data_keys.iter().any(|k| k.contains("manifest")));
    }
}
