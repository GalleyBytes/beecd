use beecdstorage::manager::{AwsS3, StorageManager};

/// Integration tests for MinIO compatibility
///
/// These tests run automatically via `make test` which sets up MinIO infrastructure
/// Environment variables are set by the Makefile (AWS_ENDPOINT_URL_S3, AWS_ACCESS_KEY_ID, etc.)

const MINIO_BUCKET: &str = "test-bucket";

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_roundtrip() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-roundtrip.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    let data = b"MinIO roundtrip test data".to_vec();
    storage.push(&data).await.expect("Failed to push to MinIO");
    let fetched = storage.fetch().await.expect("Failed to fetch from MinIO");
    assert_eq!(fetched, data);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_empty_data() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-empty.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    let data = vec![];
    storage
        .push(&data)
        .await
        .expect("Failed to push empty data to MinIO");
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch empty data from MinIO");
    assert_eq!(fetched, data);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_large_object() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-large.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    // 10MB of data to test streaming
    let data = vec![b'X'; 10 * 1024 * 1024];
    storage
        .push(&data)
        .await
        .expect("Failed to push large object to MinIO");
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch large object from MinIO");

    assert_eq!(fetched.len(), data.len());
    assert_eq!(fetched, data);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_overwrite() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-overwrite.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    // Push first version
    let data1 = b"First version".to_vec();
    storage
        .push(&data1)
        .await
        .expect("Failed to push first version to MinIO");

    // Push second version (overwrite)
    let data2 = b"Second version - much longer data".to_vec();
    storage
        .push(&data2)
        .await
        .expect("Failed to push second version to MinIO");

    // Fetch and verify we get the second version
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch after overwrite from MinIO");
    assert_eq!(fetched, data2);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_concurrent_operations() {
    let mut handles = vec![];

    // Spawn 10 concurrent operations
    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let storage = AwsS3::new(
                MINIO_BUCKET.to_string(),
                format!("test-concurrent-{}.gz", i),
            )
            .await
            .expect("Failed to create storage manager");

            let data = format!("Data for object {}", i).into_bytes();
            storage
                .push(&data)
                .await
                .expect("Failed to push in concurrent test");
            storage
                .fetch()
                .await
                .expect("Failed to fetch in concurrent test")
        });

        handles.push((i, handle));
    }

    // Wait for all operations and verify
    for (i, handle) in handles {
        let fetched = handle.await.expect("Task panicked");
        let expected = format!("Data for object {}", i).into_bytes();
        assert_eq!(fetched, expected);
    }
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_binary_data() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-binary.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    // Create binary data with all possible byte values
    let data: Vec<u8> = (0..=255).cycle().take(10000).collect();
    storage
        .push(&data)
        .await
        .expect("Failed to push binary data to MinIO");
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch binary data from MinIO");
    assert_eq!(fetched, data);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_compression_effectiveness() {
    let storage = AwsS3::new(MINIO_BUCKET.to_string(), "test-compressed.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    // Highly compressible data (1MB of repeated characters)
    let data = vec![b'A'; 1024 * 1024];
    storage
        .push(&data)
        .await
        .expect("Failed to push compressible data to MinIO");
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch compressed data from MinIO");
    assert_eq!(fetched, data);
}

#[tokio::test]
#[ignore] // Requires MinIO - run manually with: make minio-start && cargo test --test minio_integration_tests -- --ignored
async fn test_minio_yaml_manifest() {
    let storage = AwsS3::new(
        MINIO_BUCKET.to_string(),
        "test-manifest.yaml.gz".to_string(),
    )
    .await
    .expect("Failed to create storage manager");

    // Typical Kubernetes manifest
    let manifest = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: default
data:
  key1: value1
  key2: value2
  config.yaml: |
    server:
      port: 8080
      host: 0.0.0.0
"#;

    storage
        .push(manifest.as_bytes())
        .await
        .expect("Failed to push manifest to MinIO");
    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch manifest from MinIO");
    let fetched_str = String::from_utf8(fetched).expect("Invalid UTF-8 in fetched manifest");
    assert_eq!(fetched_str, manifest);
}
