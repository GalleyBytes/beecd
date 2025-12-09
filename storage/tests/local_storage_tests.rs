use beecdstorage::manager::{Local, StorageManager};
use std::fs;
use tempfile::TempDir;

// Test file constants
const TEST_FILE: &str = "test.dat";
const EMPTY_FILE: &str = "empty.dat";
const LARGE_FILE: &str = "large.dat";
const NESTED_FILE: &str = "nested/deep/path/test.dat";
const OVERWRITE_FILE: &str = "overwrite.dat";
const NONEXISTENT_FILE: &str = "nonexistent.dat";
const BINARY_FILE: &str = "binary.dat";
const COMPRESSED_FILE: &str = "compressed.dat";

// Helper function to create a temp directory and storage instance
async fn setup_local_storage(filename: &str) -> (TempDir, Local) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let file_path = temp_dir.path().join(filename);
    let path_str = file_path.to_str().unwrap();
    let storage = Local::new(String::new(), path_str.to_string())
        .await
        .unwrap();
    (temp_dir, storage)
}

#[tokio::test]
async fn test_local_storage_roundtrip() {
    let (temp_dir, storage) = setup_local_storage(TEST_FILE).await;
    let file_path = temp_dir.path().join(TEST_FILE);

    let data = b"Hello, local storage!".to_vec();
    storage.push(&data).await.expect("Failed to push data");

    assert!(file_path.exists(), "File should exist after push");

    let fetched = storage.fetch().await.expect("Failed to fetch data");
    assert_eq!(fetched, data);
}

#[tokio::test]
async fn test_local_storage_empty_data() {
    let (_temp_dir, storage) = setup_local_storage(EMPTY_FILE).await;

    let data = vec![];
    storage
        .push(&data)
        .await
        .expect("Failed to push empty data");

    let fetched = storage.fetch().await.expect("Failed to fetch empty data");
    assert_eq!(fetched, data);
}

#[tokio::test]
async fn test_local_storage_large_data() {
    let (_temp_dir, storage) = setup_local_storage(LARGE_FILE).await;

    let data = vec![b'X'; 10 * 1024 * 1024];
    storage
        .push(&data)
        .await
        .expect("Failed to push large data");

    let fetched = storage.fetch().await.expect("Failed to fetch large data");
    assert_eq!(fetched.len(), data.len());
    assert_eq!(fetched, data);
}

#[tokio::test]
async fn test_local_storage_nested_directory() {
    let (temp_dir, storage) = setup_local_storage(NESTED_FILE).await;
    let file_path = temp_dir.path().join(NESTED_FILE);

    let data = b"Nested directory test".to_vec();
    storage
        .push(&data)
        .await
        .expect("Failed to push to nested directory");

    assert!(file_path.exists(), "File should exist in nested directory");

    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch from nested directory");
    assert_eq!(fetched, data);
}

#[tokio::test]
async fn test_local_storage_overwrite() {
    let (_temp_dir, storage) = setup_local_storage(OVERWRITE_FILE).await;

    let data1 = b"First version".to_vec();
    storage
        .push(&data1)
        .await
        .expect("Failed to push first data");

    let data2 = b"Second version - much longer data".to_vec();
    storage
        .push(&data2)
        .await
        .expect("Failed to push second data");

    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch after overwrite");
    assert_eq!(fetched, data2);
}

#[tokio::test]
async fn test_local_storage_fetch_nonexistent() {
    let (_temp_dir, storage) = setup_local_storage(NONEXISTENT_FILE).await;

    let result = storage.fetch().await;
    assert!(
        result.is_err(),
        "Should fail when fetching non-existent file"
    );
}

#[tokio::test]
async fn test_local_storage_concurrent_operations() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let mut handles = vec![];

    // Spawn 10 concurrent write operations to different files
    for i in 0..10 {
        let file_path = temp_dir.path().join(format!("concurrent_{}.dat", i));
        let path_str = file_path.to_str().unwrap().to_string();

        let handle = tokio::spawn(async move {
            let storage = Local::new(String::new(), path_str).await.unwrap();
            let data = format!("Data for file {}", i).into_bytes();
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

    // Wait for all operations to complete and verify data
    for (i, handle) in handles {
        let fetched = handle.await.expect("Task panicked");
        let expected = format!("Data for file {}", i).into_bytes();
        assert_eq!(fetched, expected);
    }
}

#[tokio::test]
async fn test_local_storage_binary_data() {
    let (_temp_dir, storage) = setup_local_storage(BINARY_FILE).await;

    let data: Vec<u8> = (0..=255).cycle().take(10000).collect();

    storage
        .push(&data)
        .await
        .expect("Failed to push binary data");
    let fetched = storage.fetch().await.expect("Failed to fetch binary data");

    assert_eq!(fetched, data);
}

#[tokio::test]
async fn test_local_storage_compression_effectiveness() {
    let (temp_dir, storage) = setup_local_storage(COMPRESSED_FILE).await;
    let file_path = temp_dir.path().join(COMPRESSED_FILE);

    let data = vec![b'A'; 1024 * 1024];
    storage
        .push(&data)
        .await
        .expect("Failed to push compressible data");

    let metadata = fs::metadata(&file_path).expect("Failed to read file metadata");
    let compressed_size = metadata.len();

    assert!(
        compressed_size < (data.len() as u64) / 100,
        "Compressed file should be much smaller than original (compressed: {}, original: {})",
        compressed_size,
        data.len()
    );

    let fetched = storage
        .fetch()
        .await
        .expect("Failed to fetch compressed data");
    assert_eq!(fetched, data);
}
