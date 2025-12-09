use beecdstorage::manager::{AwsS3, Local, StorageError, StorageManager, MAX_OBJECT_SIZE};
use temp_env::with_vars;
use tempfile::TempDir;

/// Tests for error handling in storage backends

// Common test constants
const MINIO_ENDPOINT: &str = "http://localhost:9000";
const MINIO_USER: &str = "minioadmin";
const MINIO_PASSWORD: &str = "minioadmin";
const TEST_REGION: &str = "us-east-1";
const TEST_BUCKET: &str = "test-bucket";

// Helper to run tests with MinIO environment variables
async fn run_with_minio<F, Fut>(test: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    with_vars(
        [
            ("AWS_ENDPOINT_URL", Some(MINIO_ENDPOINT)),
            ("AWS_REGION", Some(TEST_REGION)),
            ("AWS_ACCESS_KEY_ID", Some(MINIO_USER)),
            ("AWS_SECRET_ACCESS_KEY", Some(MINIO_PASSWORD)),
        ],
        test,
    )
    .await;
}

#[tokio::test]
#[ignore] // Requires AWS SDK configuration
async fn test_aws_invalid_endpoint_url() {
    with_vars(
        [
            ("AWS_ENDPOINT_URL_S3", Some("not-a-valid-url://invalid")),
            ("AWS_REGION", Some(TEST_REGION)),
            ("AWS_ACCESS_KEY_ID", Some("test")),
            ("AWS_SECRET_ACCESS_KEY", Some("test")),
        ],
        || async {
            let result = AwsS3::new(TEST_BUCKET.to_string(), "test.gz".to_string()).await;
            assert!(result.is_err(), "Expected error for invalid endpoint URL");
            if let Err(error) = result {
                let error_msg = error.to_string();
                assert!(
                    error_msg.contains("Invalid S3 endpoint URL"),
                    "Error message should mention invalid URL: {}",
                    error_msg
                );
            }
        },
    )
    .await;
}

#[tokio::test]
#[ignore] // Requires MinIO infrastructure - env var scoping issue in async context
async fn test_minio_nonexistent_bucket() {
    // Environment variables are set globally by make test
    let storage = AwsS3::new(
        "nonexistent-bucket-12345".to_string(),
        "test.gz".to_string(),
    )
    .await
    .expect("Failed to create storage manager");

    let result = storage.push(b"test").await;
    assert!(result.is_err(), "Expected error when bucket doesn't exist");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("NoSuchBucket") || error_msg.contains("bucket"),
        "Error should mention bucket issue: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_local_storage_nonexistent_fetch() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let storage_path = temp_dir.path().to_str().unwrap().to_string();

    let storage = Local::new(storage_path, "nonexistent.gz".to_string())
        .await
        .unwrap();

    let result = storage.fetch().await;
    assert!(
        result.is_err(),
        "Expected error when fetching nonexistent file"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("No such file") || error_msg.contains("not found"),
        "Error should mention file not found: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_local_storage_permission_denied() {
    // Try to write to a read-only location (this is system-dependent)
    let storage = Local::new("/dev/null".to_string(), "test.gz".to_string())
        .await
        .unwrap();

    let result = storage.push(b"test").await;
    // This might succeed or fail depending on OS, but shouldn't panic
    // The important thing is we get a Result, not a panic
    match result {
        Ok(_) => {
            // Some systems allow writing to /dev/null
        }
        Err(e) => {
            // Expected on most systems
            assert!(
                e.to_string().contains("permission")
                    || e.to_string().contains("denied")
                    || e.to_string().contains("directory"),
                "Error message should be descriptive: {}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_local_storage_empty_data_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let storage_path = temp_dir.path().to_str().unwrap().to_string();

    let storage = Local::new(storage_path, "empty.gz".to_string())
        .await
        .unwrap();

    // Empty data should work
    storage.push(&[]).await.expect("Failed to push empty data");

    let fetched = storage.fetch().await.expect("Failed to fetch empty data");
    assert_eq!(fetched, Vec::<u8>::new());
}

#[tokio::test]
#[ignore] // Requires MinIO infrastructure - env var scoping issue in async context
async fn test_minio_fetch_nonexistent_object() {
    // Environment variables are set globally by make test
    let storage = AwsS3::new(
        TEST_BUCKET.to_string(),
        "nonexistent-key-12345.gz".to_string(),
    )
    .await
    .expect("Failed to create storage manager");

    let result = storage.fetch().await;
    assert!(
        result.is_err(),
        "Expected error when fetching nonexistent object"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("NoSuchKey") || error_msg.contains("not found"),
        "Error should mention key not found: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_compression_with_corrupted_data() {
    use beecdstorage::manager::gunzip_data;

    // Try to decompress non-gzipped data
    let bad_data = b"This is not gzipped data";
    let result = gunzip_data(bad_data);

    assert!(
        result.is_err(),
        "Expected error when decompressing invalid data"
    );
    // The error should be descriptive
    let error_msg = result.unwrap_err().to_string();
    assert!(!error_msg.is_empty(), "Error message should not be empty");
}
#[tokio::test]
async fn test_local_push_object_too_large() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("huge.gz");
    let path_str = file_path.to_str().unwrap();

    let storage = Local::new(String::new(), path_str.to_string())
        .await
        .expect("Failed to create local storage");

    // Create data larger than MAX_OBJECT_SIZE (100MB)
    let large_data = vec![0u8; MAX_OBJECT_SIZE + 1];
    let result = storage.push(&large_data).await;

    assert!(result.is_err(), "Expected error for object too large");
    match result {
        Err(StorageError::ObjectTooLarge(size, limit)) => {
            assert_eq!(size, MAX_OBJECT_SIZE + 1);
            assert_eq!(limit, MAX_OBJECT_SIZE);
        }
        other => panic!("Expected ObjectTooLarge error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_local_fetch_object_too_large() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("huge.gz");

    // Write a file larger than MAX_OBJECT_SIZE directly (bypassing our push validation)
    let large_data = vec![0u8; MAX_OBJECT_SIZE + 1000];
    tokio::fs::write(&file_path, &large_data)
        .await
        .expect("Failed to write large file");

    let path_str = file_path.to_str().unwrap();
    let storage = Local::new(String::new(), path_str.to_string())
        .await
        .expect("Failed to create local storage");

    let result = storage.fetch().await;
    assert!(
        result.is_err(),
        "Expected error for fetching too large object"
    );
    match result {
        Err(StorageError::ObjectTooLarge(size, limit)) => {
            assert!(size > MAX_OBJECT_SIZE);
            assert_eq!(limit, MAX_OBJECT_SIZE);
        }
        other => panic!("Expected ObjectTooLarge error, got: {:?}", other),
    }
}

#[tokio::test]
#[ignore] // Requires MinIO infrastructure
async fn test_minio_push_object_too_large() {
    let storage = AwsS3::new(TEST_BUCKET.to_string(), "huge.gz".to_string())
        .await
        .expect("Failed to create storage manager");

    // Create data larger than MAX_OBJECT_SIZE (100MB)
    let large_data = vec![0u8; MAX_OBJECT_SIZE + 1];
    let result = storage.push(&large_data).await;

    assert!(result.is_err(), "Expected error for object too large");
    match result {
        Err(StorageError::ObjectTooLarge(size, limit)) => {
            assert_eq!(size, MAX_OBJECT_SIZE + 1);
            assert_eq!(limit, MAX_OBJECT_SIZE);
        }
        other => panic!("Expected ObjectTooLarge error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_local_push_at_size_limit() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join("at-limit.gz");
    let path_str = file_path.to_str().unwrap();

    let storage = Local::new(String::new(), path_str.to_string())
        .await
        .expect("Failed to create local storage");

    // Create data exactly at MAX_OBJECT_SIZE - should succeed
    let data = vec![0u8; MAX_OBJECT_SIZE];
    let result = storage.push(&data).await;

    assert!(result.is_ok(), "Should succeed at exactly MAX_OBJECT_SIZE");
}
