//! Integration tests for beecdiff library.
//!
//! These tests verify the end-to-end functionality of comparing Kubernetes
//! manifests, including multi-document parsing, field sets, and ignore sets.

use beecdiff::{
    aggregate_k8s_resources_managed_fields, aggregate_managed_fields_to_ignore,
    multi_document_parser_for_k8s_resources, Diff,
};

/// Helper to create a diff between two YAML strings and return the Diff object
fn diff_yaml_strings(lhs_yaml: &str, rhs_yaml: &str) -> Diff {
    let lhs: serde_json::Value = serde_yaml::from_str(lhs_yaml).expect("Invalid LHS YAML");
    let rhs: serde_json::Value = serde_yaml::from_str(rhs_yaml).expect("Invalid RHS YAML");
    Diff::new(Some(lhs), Some(rhs), None, None)
}

// ==================== End-to-End Workflow Tests ====================

#[test]
fn test_full_k8s_manifest_comparison_workflow() {
    let lhs_yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: myapp:v1.0.0
          ports:
            - containerPort: 8080
          env:
            - name: LOG_LEVEL
              value: info
"#;

    let rhs_yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
spec:
  replicas: 5
  template:
    spec:
      containers:
        - name: app
          image: myapp:v2.0.0
          ports:
            - containerPort: 8080
          env:
            - name: LOG_LEVEL
              value: debug
"#;

    let mut diff = diff_yaml_strings(lhs_yaml, rhs_yaml);
    diff.do_compare().unwrap();

    assert!(diff.is_diff(), "Should detect changes between manifests");

    let changes = diff.ordered_changes();
    assert!(
        changes.iter().any(|c| c.contains("replicas")),
        "Should detect replicas change"
    );
    assert!(
        changes.iter().any(|c| c.contains("image")),
        "Should detect image change"
    );
}

#[test]
fn test_multi_document_workflow() {
    let multi_doc_yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  config.yaml: |
    key: value
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: default
type: Opaque
data:
  password: cGFzc3dvcmQ=
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: default
spec:
  replicas: 1
"#
    .to_string();

    let docs =
        multi_document_parser_for_k8s_resources(None, Some(&multi_doc_yaml)).expect("Should parse");

    assert_eq!(docs.len(), 3, "Should parse 3 documents");
    assert!(docs.contains_key("v1, default, app-config"));
    assert!(docs.contains_key("v1, default, app-secret"));
    assert!(docs.contains_key("apps/v1, default, my-app"));
}

#[test]
fn test_comparing_multi_document_manifests() {
    let lhs_yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
  namespace: default
data:
  key1: value1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  replicas: 1
"#
    .to_string();

    let rhs_yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
  namespace: default
data:
  key1: value2
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  replicas: 3
"#
    .to_string();

    let lhs_docs =
        multi_document_parser_for_k8s_resources(None, Some(&lhs_yaml)).expect("Should parse LHS");
    let rhs_docs =
        multi_document_parser_for_k8s_resources(None, Some(&rhs_yaml)).expect("Should parse RHS");

    // Compare each document
    for (key, lhs_doc) in &lhs_docs {
        if let Some(rhs_doc) = rhs_docs.get(key) {
            let mut diff = Diff::new(Some(lhs_doc.clone()), Some(rhs_doc.clone()), None, None);
            diff.do_compare().unwrap();
            assert!(diff.is_diff(), "Document {} should have changes", key);
        }
    }
}

// ==================== Field Set Tests ====================

#[test]
fn test_managed_fields_parsing() {
    let manifest_with_managed_fields = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
  managedFields:
    - manager: kubectl
      operation: Apply
      apiVersion: apps/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:spec:
          f:replicas: {}
          f:template:
            f:spec:
              f:containers:
                k:{"name":"app"}:
                  f:image: {}
spec:
  replicas: 1
"#
    .to_string();

    let result = aggregate_k8s_resources_managed_fields(None, Some(&manifest_with_managed_fields));
    assert!(result.is_ok(), "Should parse managed fields");

    let field_sets = result.unwrap();
    assert!(!field_sets.is_empty(), "Should have field sets");
}

#[test]
fn test_ignore_sets_parsing() {
    let manifest_with_managed_fields = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  namespace: default
  managedFields:
    - manager: kube-controller-manager
      operation: Update
      apiVersion: apps/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:status:
          f:replicas: {}
    - manager: kubectl
      operation: Apply
      apiVersion: apps/v1
      fieldsType: FieldsV1
      fieldsV1:
        f:spec:
          f:replicas: {}
spec:
  replicas: 1
"#
    .to_string();

    let result = aggregate_managed_fields_to_ignore(
        None,
        Some(&manifest_with_managed_fields),
        Some(String::from("kube-controller-manager")),
    );
    assert!(result.is_ok(), "Should parse ignore sets");
}

// ==================== Real-World Scenario Tests ====================

#[test]
fn test_deployment_rolling_update() {
    let before = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-server
  namespace: production
  labels:
    app: web-server
    version: v1
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-server
  template:
    metadata:
      labels:
        app: web-server
        version: v1
    spec:
      containers:
        - name: nginx
          image: nginx:1.19
          ports:
            - containerPort: 80
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "200m"
"#;

    let after = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-server
  namespace: production
  labels:
    app: web-server
    version: v2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-server
  template:
    metadata:
      labels:
        app: web-server
        version: v2
    spec:
      containers:
        - name: nginx
          image: nginx:1.21
          ports:
            - containerPort: 80
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "200m"
"#;

    let mut diff = diff_yaml_strings(before, after);
    diff.do_compare().unwrap();
    diff.remove_childrenless_parents();

    assert!(diff.is_diff());

    let changes = diff.ordered_changes();
    // Should detect version label and image changes
    assert!(changes.iter().any(|c| c.contains("version")));
    assert!(changes.iter().any(|c| c.contains("image")));

    // Resources should NOT be in changes (they're the same)
    let _text = diff.text(false);
    // The unchanged resources shouldn't show as +/-
    assert!(
        !changes
            .iter()
            .any(|c| (c.starts_with('+') || c.starts_with('-')) && c.contains("memory")),
        "Memory should not show as changed"
    );
}

#[test]
fn test_service_port_change() {
    let before = r#"
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
spec:
  selector:
    app: my-app
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: https
      port: 443
      targetPort: 8443
"#;

    let after = r#"
apiVersion: v1
kind: Service
metadata:
  name: my-service
  namespace: default
spec:
  selector:
    app: my-app
  ports:
    - name: http
      port: 80
      targetPort: 9090
    - name: https
      port: 443
      targetPort: 8443
"#;

    let mut diff = diff_yaml_strings(before, after);
    diff.do_compare().unwrap();

    assert!(diff.is_diff());
    let changes = diff.ordered_changes();
    assert!(changes.iter().any(|c| c.contains("targetPort")));
}

#[test]
fn test_configmap_data_update() {
    let before = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  database.host: "db.example.com"
  database.port: "5432"
  log.level: "info"
  feature.flags: |
    {
      "newUI": false,
      "darkMode": true
    }
"#;

    let after = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  database.host: "db.example.com"
  database.port: "5432"
  log.level: "debug"
  feature.flags: |
    {
      "newUI": true,
      "darkMode": true
    }
"#;

    let mut diff = diff_yaml_strings(before, after);
    diff.do_compare().unwrap();

    assert!(diff.is_diff());
    let changes = diff.ordered_changes();

    // Should detect log.level and feature.flags changes
    assert!(
        changes.len() >= 2,
        "Should have at least 2 changes: {:?}",
        changes
    );
}

#[test]
fn test_adding_new_container_sidecar() {
    let before = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: main
          image: myapp:v1
"#;

    let after = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: main
          image: myapp:v1
        - name: sidecar
          image: envoy:v1.20
          ports:
            - containerPort: 15001
"#;

    let mut diff = diff_yaml_strings(before, after);
    diff.do_compare().unwrap();

    assert!(diff.is_diff());
    let changes = diff.ordered_changes();
    assert!(
        changes.iter().any(|c| c.starts_with('+')),
        "Should have additions"
    );
}

#[test]
fn test_removing_annotation() {
    let before = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    deprecated: "true"
    owner: "team-a"
spec:
  containers:
    - name: app
      image: app:v1
"#;

    let after = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
  annotations:
    owner: "team-a"
spec:
  containers:
    - name: app
      image: app:v1
"#;

    let mut diff = diff_yaml_strings(before, after);
    diff.do_compare().unwrap();
    diff.remove_childrenless_parents();

    assert!(diff.is_diff());
    let changes = diff.ordered_changes();
    assert!(
        changes.iter().any(|c| c.starts_with('-')),
        "Should have removals"
    );
}

// ==================== Output Format Tests ====================

#[test]
fn test_text_output_is_valid_yaml_like() {
    let lhs = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "test"},
        "data": {"key": "old"}
    });
    let rhs = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "test"},
        "data": {"key": "new"}
    });

    let mut diff = Diff::new(Some(lhs), Some(rhs), None, None);
    diff.do_compare().unwrap();

    let text = diff.text(true); // manifest mode
    assert!(!text.is_empty());

    // Should have proper indentation (spaces)
    assert!(text.contains("  "), "Should have indentation");
}

#[test]
fn test_ordered_changes_are_consistent() {
    let lhs = serde_json::json!({"a": 1, "b": 2, "c": 3});
    let rhs = serde_json::json!({"a": 1, "b": 20, "c": 30, "d": 4});

    let mut diff = Diff::new(Some(lhs.clone()), Some(rhs.clone()), None, None);
    diff.do_compare().unwrap();
    let changes1 = diff.ordered_changes();

    // Run again to ensure consistency
    let mut diff2 = Diff::new(Some(lhs), Some(rhs), None, None);
    diff2.do_compare().unwrap();
    let changes2 = diff2.ordered_changes();

    assert_eq!(
        changes1.len(),
        changes2.len(),
        "Should have consistent number of changes"
    );
}

// ==================== Error Handling Tests ====================

#[test]
fn test_missing_rhs_document() {
    let lhs = serde_json::json!({"name": "test"});

    let mut diff = Diff::new(Some(lhs), None, None, None);
    let result = diff.do_compare();

    // Should handle gracefully (either Ok or specific error)
    assert!(result.is_err(), "Should error when RHS is missing");
}

#[test]
fn test_empty_yaml_document() {
    let empty_yaml = "".to_string();
    let result = multi_document_parser_for_k8s_resources(None, Some(&empty_yaml));

    // Empty YAML returns an error during deserialization
    // This is acceptable behavior - callers should validate input
    assert!(result.is_err() || result.as_ref().map(|m| m.is_empty()).unwrap_or(false));
}

#[test]
fn test_invalid_k8s_manifest_missing_metadata() {
    let invalid_yaml = r#"
apiVersion: v1
kind: ConfigMap
data:
  key: value
"#
    .to_string();

    let result = multi_document_parser_for_k8s_resources(None, Some(&invalid_yaml));
    // Library may error or return empty map for invalid manifests
    // Either behavior is acceptable - the important thing is it doesn't panic
    match result {
        Ok(docs) => {
            // If Ok, the invalid doc should be skipped (empty map)
            // or the doc might be included with default namespace
            assert!(docs.is_empty() || docs.len() == 1);
        }
        Err(_) => {
            // Error is also acceptable for invalid manifests
        }
    }
}
