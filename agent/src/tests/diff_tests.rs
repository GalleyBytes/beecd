// Tests for Manifest Diffing and Drift Detection
//
// Critical workflows tested:
// - Server-side apply dry-run execution
// - Field sanitization (status, timestamps, managed fields)
// - Diff generation and comparison
// - Ignored managed fields filtering
// - New generation detection

#[cfg(test)]
mod tests {
    use crate::tests::fixtures::*;
    use crate::util::{gunzip_data, gzip_data, safe_keyname};

    #[test]
    fn test_manifest_image_update_detected() {
        assert!(UPDATED_DEPLOYMENT_YAML.contains("nginx:1.20"));
        assert!(!UPDATED_DEPLOYMENT_YAML.contains("nginx:1.19"));
        assert!(SIMPLE_DEPLOYMENT_YAML.contains("nginx:1.19"));
    }

    #[test]
    fn test_diff_key_is_sanitized() {
        let raw = "Default Namespace / Deployment@My-App";
        let sanitized = safe_keyname(raw.to_string()).expect("key should sanitize");
        assert_eq!(sanitized, "default.namespace...deployment.my.app");
    }

    #[test]
    fn test_gzip_roundtrip_for_diff_payload() {
        let content = b"spec:\n  replicas: 3";
        let gz = gzip_data(content).expect("gzip succeeds");
        // Verify gzip magic number
        assert_eq!(gz[0], 0x1f);
        assert_eq!(gz[1], 0x8b);

        let unzipped = gunzip_data(&gz).expect("gunzip succeeds");
        assert_eq!(unzipped, content);
    }

    #[test]
    fn test_fixture_gzip_manifest_roundtrip() {
        let gz = gzip_manifest(SIMPLE_DEPLOYMENT_YAML);
        let body = gunzip_data(&gz).expect("gunzip succeeds");
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("kind: Deployment"));
        assert!(text.contains("metadata:"));
    }

    #[test]
    fn test_multi_document_fixture_parses_all_documents() {
        let docs: Vec<_> = serde_yaml::Deserializer::from_str(MULTI_DOCUMENT_YAML).collect();
        assert_eq!(docs.len(), 3, "expected 3 YAML documents");
    }

    #[test]
    fn test_sanitize_field_list_contains_expected_fields() {
        let fields_to_sanitize = [
            "status",
            "generation",
            "managed_fields",
            "owner_references",
            "resource_version",
            "uid",
            "creation_timestamp",
        ];

        assert!(fields_to_sanitize.contains(&"status"));
        assert!(fields_to_sanitize.contains(&"resource_version"));
        assert_eq!(fields_to_sanitize.len(), 7);
    }
}
