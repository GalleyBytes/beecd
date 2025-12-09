// Tests for agent core functionality
// These tests exercise the actual Agent logic using testing helpers

#[cfg(test)]
mod tests {
    use crate::agent::order_map;
    use crate::agent::{deserialize_doc, testing::*, KubeMeta, Resource};

    #[test]
    fn test_resource_creation() {
        let res = create_test_resource("Pod", "test-pod", "default");
        assert_eq!(res.kind(), "Pod");
        assert_eq!(res.name(), "test-pod");
        assert_eq!(res.namespace(), "default");
    }

    #[test]
    fn test_resource_key() {
        let res = create_test_resource("Deployment", "my-app", "prod");
        let key = res.key();
        assert!(key.contains("my-app"));
        assert!(key.contains("prod"));
        assert!(key.contains("Deployment"));
    }

    #[test]
    fn test_resource_diff_key() {
        let res = create_test_resource("Service", "web", "default");
        let diff_key = res.diff_key();
        assert_eq!(diff_key, "Service/default/web");
    }

    #[test]
    fn test_resource_api_resource_simple() {
        let mut res = create_test_resource("Pod", "test", "default");
        res.set_group("".to_string());
        res.set_version("v1".to_string());
        let api_res = res.api_resource();
        assert_eq!(api_res.plural, "pods");
        assert_eq!(api_res.kind, "pod");
    }

    #[test]
    fn test_resource_api_resource_plural_y() {
        let res = create_test_resource("Policy", "test", "default");
        let api_res = res.api_resource();
        assert_eq!(api_res.plural, "policies");
    }

    #[test]
    fn test_resource_api_resource_plural_ss() {
        let res = create_test_resource("Ingress", "test", "default");
        let api_res = res.api_resource();
        assert_eq!(api_res.plural, "ingresses");
    }

    #[test]
    fn test_resource_set_methods() {
        let mut res = Resource::default();
        res.set_name("test-name".to_string())
            .set_namespace("test-ns".to_string())
            .set_kind("ConfigMap".to_string())
            .set_api_version("v1".to_string())
            .set_version("v1".to_string())
            .set_group("".to_string())
            .set_is_namespaced(true);

        assert_eq!(res.name(), "test-name");
        assert_eq!(res.namespace(), "test-ns");
        assert_eq!(res.kind(), "ConfigMap");
        assert!(res.is_namespaced());
    }

    #[test]
    fn test_resource_is_weighted_true() {
        let res = create_weighted_resource("10");
        assert!(res.is_weighted());
    }

    #[test]
    fn test_resource_is_weighted_false() {
        let res = create_test_resource("Pod", "test", "default");
        assert!(!res.is_weighted());
    }

    #[test]
    fn test_resource_is_post_weighted_true() {
        let yaml_str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    beecd/post-weight: "5"
"#;
        let res = create_resource_from_yaml(yaml_str);
        assert!(res.is_post_weighted());
    }

    #[test]
    fn test_resource_is_post_weighted_false() {
        let res = create_test_resource("Pod", "test", "default");
        assert!(!res.is_post_weighted());
    }

    #[test]
    fn test_resource_should_diff_no_annotations() {
        let res = create_test_resource("Pod", "test", "default");
        assert!(res.should_diff());
    }

    #[test]
    fn test_resource_should_diff_with_weight() {
        let yaml_str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    beecd/weight: "10"
"#;
        let res = create_resource_from_yaml(yaml_str);
        assert!(!res.should_diff());
    }

    #[test]
    fn test_resource_should_diff_with_weight_and_show_diff() {
        let yaml_str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    beecd/weight: "10"
    beecd/show-diff: "true"
"#;
        let res = create_resource_from_yaml(yaml_str);
        assert!(res.should_diff());
    }

    #[test]
    fn test_resource_should_diff_with_post_weight() {
        let yaml_str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    beecd/post-weight: "5"
"#;
        let res = create_resource_from_yaml(yaml_str);
        assert!(!res.should_diff());
    }

    #[test]
    fn test_resource_new_from_deserializer() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  namespace: default
"#;
        let deserializer = serde_yaml::Deserializer::from_str(yaml);
        let res = Resource::new(deserializer);
        assert!(res.is_ok());
    }

    #[test]
    fn test_resource_to_struct_from_yaml() {
        let yaml_str = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
"#;
        let res = create_resource_from_yaml(yaml_str);
        let kubemeta: Result<KubeMeta, _> = res.to_struct_from_yaml();
        assert!(kubemeta.is_ok());
        let km = kubemeta.unwrap();
        assert_eq!(km.name(), "test-pod");
    }

    #[test]
    fn test_kubemeta_name() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: default
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.name(), "my-pod");
    }

    #[test]
    fn test_kubemeta_namespace() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  namespace: test-namespace
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.namespace(), "test-namespace");
    }

    #[test]
    fn test_kubemeta_namespace_default() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.namespace(), "default");
    }

    #[test]
    fn test_kubemeta_kind() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.kind(), "Deployment");
    }

    #[test]
    fn test_kubemeta_api_version() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.api_version(), "apps/v1");
    }

    #[test]
    fn test_kubemeta_version() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.version().unwrap(), "v1");
    }

    #[test]
    fn test_kubemeta_group() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.group(), "apps");
    }

    #[test]
    fn test_kubemeta_group_empty_for_core() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.group(), "");
    }

    #[test]
    fn test_kubemeta_with_namespace() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let mut kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        kubemeta.with_namespace("custom-ns");
        assert_eq!(kubemeta.namespace(), "custom-ns");
    }

    #[test]
    fn test_kubemeta_preserves_existing_namespace() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test
  namespace: original-ns
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let mut kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        kubemeta.with_namespace("custom-ns");
        // Should keep original namespace, not override
        assert_eq!(kubemeta.namespace(), "original-ns");
    }

    #[test]
    fn test_order_map_namespace_before_deployment() {
        let order = order_map(false);
        let ns_order = order.get("Namespace").unwrap();
        let deploy_order = order.get("Deployment").unwrap();
        assert!(
            ns_order < deploy_order,
            "Namespace should come before Deployment"
        );
    }

    #[test]
    fn test_order_map_secret_before_deployment() {
        let order = order_map(false);
        let secret_order = order.get("Secret").unwrap();
        let deploy_order = order.get("Deployment").unwrap();
        assert!(
            secret_order < deploy_order,
            "Secret should come before Deployment"
        );
    }

    #[test]
    fn test_order_map_deployment_before_ingress() {
        let order = order_map(false);
        let deploy_order = order.get("Deployment").unwrap();
        let ingress_order = order.get("Ingress").unwrap();
        assert!(
            deploy_order < ingress_order,
            "Deployment should come before Ingress"
        );
    }

    #[test]
    fn test_order_map_reverse_flips_order() {
        let forward = order_map(false);
        let reverse = order_map(true);

        let ns_forward = forward.get("Namespace").unwrap();
        let deploy_forward = forward.get("Deployment").unwrap();
        let ns_reverse = reverse.get("Namespace").unwrap();
        let deploy_reverse = reverse.get("Deployment").unwrap();

        assert!(ns_forward < deploy_forward);
        assert!(ns_reverse > deploy_reverse);
    }

    #[test]
    fn test_deserialize_complex_yaml() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
"#;
        let result = deserialize_doc(yaml);
        assert!(result.is_ok());
        let doc = result.unwrap();
        assert_eq!(doc["kind"].as_str(), Some("Deployment"));
        assert_eq!(doc["metadata"]["name"].as_str(), Some("nginx-deployment"));
        assert_eq!(doc["spec"]["replicas"].as_i64(), Some(3));
    }

    #[test]
    fn test_deserialize_with_annotations() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    beecd/weight: "10"
    beecd/show-diff: "true"
"#;
        let result = deserialize_doc(yaml);
        assert!(result.is_ok());
        let doc = result.unwrap();
        assert_eq!(
            doc["metadata"]["annotations"]["beecd/weight"].as_str(),
            Some("10")
        );
    }

    #[test]
    fn test_resource_dynamic_object_from_yaml() {
        let yaml_str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: default
data:
  key: value
"#;
        let res = create_resource_from_yaml(yaml_str);
        let result = res.dynamic_object_from_yaml();
        assert!(result.is_ok());
    }

    #[test]
    fn test_kubemeta_to_string() {
        let yaml = r#"
apiVersion: v1
kind: Service
metadata:
  name: test-svc
  namespace: default
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        let result = kubemeta.to_string();
        assert!(result.is_ok());
        let yaml_str = result.unwrap();
        assert!(yaml_str.contains("test-svc"));
    }

    #[test]
    fn test_kubemeta_name_empty() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata: {}
"#;
        let doc = deserialize_doc(yaml).unwrap();
        let kubemeta: KubeMeta = serde_yaml::from_value(doc).unwrap();
        assert_eq!(kubemeta.name(), "");
    }

    #[test]
    fn test_order_map_all_resources_present() {
        let order = order_map(false);
        let expected_resources = vec![
            "Namespace",
            "Secret",
            "ConfigMap",
            "Service",
            "Deployment",
            "StatefulSet",
            "Job",
            "CronJob",
            "Ingress",
            "Role",
            "RoleBinding",
            "ClusterRole",
            "ClusterRoleBinding",
            "ServiceAccount",
            "PersistentVolume",
            "PersistentVolumeClaim",
            "Pod",
            "DaemonSet",
            "ReplicaSet",
        ];
        for resource in expected_resources {
            assert!(
                order.contains_key(resource),
                "Missing resource: {}",
                resource
            );
        }
    }

    #[test]
    fn test_order_map_priority_class_first() {
        let order = order_map(false);
        let pc_order = order.get("PriorityClass").unwrap();
        assert_eq!(*pc_order, 0, "PriorityClass should be first");
    }

    #[test]
    fn test_order_map_apiservice_last() {
        let order = order_map(false);
        let api_order = order.get("APIService").unwrap();
        let max_order = order.values().max().unwrap();
        assert_eq!(api_order, max_order, "APIService should be last");
    }
}
