#[test]
fn test_yaml_parsing() {
    let yaml_content = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: default
data:
  key1: value1
  key2: value2
"#;

    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml_content).expect("Failed to parse YAML");

    // Verify structure
    assert!(parsed.get("apiVersion").is_some());
    assert!(parsed.get("kind").is_some());
    assert!(parsed.get("metadata").is_some());
}

#[test]
fn test_yaml_to_json_conversion() {
    let yaml_content = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
"#;

    let yaml_value: serde_yaml::Value =
        serde_yaml::from_str(yaml_content).expect("Failed to parse YAML");
    let json_value: serde_json::Value =
        serde_json::to_value(&yaml_value).expect("Failed to convert to JSON");

    assert_eq!(json_value["kind"].as_str().unwrap(), "Deployment");
    assert_eq!(json_value["spec"]["replicas"].as_i64().unwrap(), 3);
}

#[test]
fn test_multi_document_yaml() {
    use serde::de::Deserialize;

    let yaml_content = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: config1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config2
"#;

    let docs: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(yaml_content)
        .map(|doc| serde_yaml::Value::deserialize(doc).expect("Failed to deserialize"))
        .collect();

    assert_eq!(docs.len(), 2, "Should parse 2 documents");
    assert_eq!(docs[0]["metadata"]["name"].as_str().unwrap(), "config1");
    assert_eq!(docs[1]["metadata"]["name"].as_str().unwrap(), "config2");
}

#[test]
fn test_yaml_lint_validation() {
    let valid_yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
"#;

    // Use yaml-rust to validate YAML structure
    let result = yaml_rust::YamlLoader::load_from_str(valid_yaml);
    assert!(result.is_ok(), "Valid YAML should parse without errors");

    let docs = result.unwrap();
    assert_eq!(docs.len(), 1, "Should have 1 document");
}

#[test]
fn test_yaml_lint_invalid() {
    let invalid_yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  invalid_indent
spec:
  containers:
"#;

    let result = yaml_rust::YamlLoader::load_from_str(invalid_yaml);
    assert!(result.is_err(), "Invalid YAML should fail to parse");
}

#[test]
fn test_empty_yaml_document() {
    use serde::de::Deserialize;

    let empty_yaml = "";

    let docs: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(empty_yaml)
        .filter_map(|doc| {
            let val = serde_yaml::Value::deserialize(doc).ok()?;
            // Filter out null values from empty documents
            if val.is_null() {
                None
            } else {
                Some(val)
            }
        })
        .collect();

    assert_eq!(
        docs.len(),
        0,
        "Empty YAML should have no non-null documents"
    );
}

#[test]
fn test_yaml_with_nulls() {
    let yaml_with_null = r#"
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    key1: value1
    key2: null
"#;

    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml_with_null).expect("Failed to parse YAML");

    let annotations = &parsed["metadata"]["annotations"];
    assert!(annotations["key1"].as_str().is_some());
    assert!(annotations["key2"].is_null());
}

#[test]
fn test_yaml_list_parsing() {
    let yaml_list = r#"
- item1
- item2
- item3
"#;

    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml_list).expect("Failed to parse YAML list");

    assert!(parsed.is_sequence());
    let seq = parsed.as_sequence().unwrap();
    assert_eq!(seq.len(), 3);
}

#[test]
fn test_serialize_to_yaml() {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct K8sResource {
        #[serde(rename = "apiVersion")]
        api_version: String,
        kind: String,
        metadata: Metadata,
    }

    #[derive(Serialize, Deserialize)]
    struct Metadata {
        name: String,
        namespace: String,
    }

    let resource = K8sResource {
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        metadata: Metadata {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
        },
    };

    let yaml_str = serde_yaml::to_string(&resource).expect("Failed to serialize to YAML");

    assert!(yaml_str.contains("apiVersion: v1"));
    assert!(yaml_str.contains("kind: Pod"));
    assert!(yaml_str.contains("name: test-pod"));
}

#[test]
fn test_yaml_with_special_characters() {
    let yaml_content = r#"
data:
  special: "value with \"quotes\""
  multiline: |
    line1
    line2
    line3
"#;

    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml_content).expect("Failed to parse YAML");

    assert!(parsed["data"]["special"].as_str().is_some());
    assert!(parsed["data"]["multiline"]
        .as_str()
        .unwrap()
        .contains("line1"));
}
