// Tests for actual Resource parsing and agent behavior
// These tests exercise agent code, not YAML fixtures

#[cfg(test)]
mod tests {
    use crate::agent::{deserialize_doc, order_map};

    #[test]
    fn test_deserialize_valid_yaml() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
"#;
        let result = deserialize_doc(yaml);
        assert!(result.is_ok());
        let doc = result.unwrap();
        assert_eq!(doc["kind"].as_str(), Some("Pod"));
        assert_eq!(doc["metadata"]["name"].as_str(), Some("test-pod"));
    }

    #[test]
    fn test_deserialize_invalid_yaml() {
        let yaml = "invalid: yaml: : :";
        let result = deserialize_doc(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_order_map_forward() {
        let order = order_map(false);
        assert!(order.get("Namespace").unwrap() < order.get("Secret").unwrap());
        assert!(order.get("Secret").unwrap() < order.get("Deployment").unwrap());
        assert!(order.get("Deployment").unwrap() < order.get("Ingress").unwrap());
    }

    #[test]
    fn test_order_map_reverse() {
        let order = order_map(true);
        assert!(order.get("Namespace").unwrap() > order.get("Secret").unwrap());
        assert!(order.get("Secret").unwrap() > order.get("Deployment").unwrap());
        assert!(order.get("Deployment").unwrap() > order.get("Ingress").unwrap());
    }

    #[test]
    fn test_order_map_contains_all_resources() {
        let order = order_map(false);
        let expected = vec![
            "Namespace",
            "Secret",
            "ConfigMap",
            "Service",
            "Deployment",
            "StatefulSet",
            "Job",
            "Ingress",
        ];
        for resource in expected {
            assert!(order.contains_key(resource), "Missing: {}", resource);
        }
    }
}
