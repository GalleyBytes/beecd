use async_trait::async_trait;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};
use thiserror::Error;
use url::Url;

mod aws_s3;
mod local_storage;

// Re-export for testing
pub use aws_s3::AwsS3;
pub use local_storage::Local;

// Maximum object size: 100MB (compressed)
// Prevents OOM issues with unbounded memory allocation
pub const MAX_OBJECT_SIZE: usize = 100 * 1024 * 1024;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Failed to parse storage url: {0}")]
    UrlParseError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Value of `{0}` not an allowed storage proto")]
    UnexpectedProto(String),
    #[error("Missing Bucket in URL")]
    AwsS3MissingBucket,
    #[error("Invalid endpoint URL: {0}")]
    InvalidEndpointUrl(String),
    #[error("Object size {0} bytes exceeds maximum allowed size of {1} bytes")]
    ObjectTooLarge(usize, usize),
    #[error("AwsS3SdkError {0:?}")]
    AwsS3SdkError(Box<dyn std::error::Error + Send + Sync>),
    #[error("AwsS3StreamError {0:?}")]
    AwsS3StreamError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to create file {0:?}")]
    LocalFileCreateError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Failed to open file {0:?}")]
    LocalFileOpenError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Unable to write data {0:?}")]
    LocalFileWriteError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Unable to read data {0:?}")]
    LocalFileReadError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Gzip error: {0}")]
    GzipError(Box<dyn std::error::Error + Send + Sync>),
}

#[async_trait]
pub trait StorageManager {
    async fn new(host: String, path: String) -> Result<Self, StorageError>
    where
        Self: Sized;

    async fn push(&self, bytes: &[u8]) -> Result<(), StorageError>;
    async fn fetch(&self) -> Result<Vec<u8>, StorageError>;
}

pub async fn get_manager(
    storage_url: &str,
) -> Result<Box<dyn StorageManager + Send>, StorageError> {
    let parsed = Url::parse(storage_url).map_err(|e| StorageError::UrlParseError(e.into()))?;

    // Parse out the proto
    let proto = parsed.scheme();
    let host = parsed.host();
    let path = parsed.path().trim_start_matches('/');

    if proto == "s3" {
        // Setup s3 manager
        let bucket = match host {
            Some(s) => s.to_string(),
            None => return Err(StorageError::AwsS3MissingBucket),
        };

        Ok(Box::new(
            aws_s3::AwsS3::new(bucket, path.to_string()).await?,
        ))
    } else if proto == "file" {
        // Setup local storage
        Ok(Box::new(
            local_storage::Local::new(String::new(), path.to_string()).await?,
        ))
    } else {
        Err(StorageError::UnexpectedProto(proto.to_string()))
    }
}

pub fn gzip_data(data: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| StorageError::GzipError(e.into()))?;
    encoder
        .finish()
        .map_err(|e| StorageError::GzipError(e.into()))
}

pub fn gunzip_data(compressed_data: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut decoder = GzDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder
        .read_to_end(&mut decompressed_data)
        .map_err(|e| StorageError::GzipError(e.into()))?;

    Ok(decompressed_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_empty_data() {
        let data = vec![];
        let compressed = gzip_data(&data).expect("Failed to compress empty data");
        assert!(!compressed.is_empty(), "Gzip header should be present");

        let decompressed = gunzip_data(&compressed).expect("Failed to decompress empty data");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzip_single_byte() {
        let data = vec![42];
        let compressed = gzip_data(&data).expect("Failed to compress single byte");
        assert!(!compressed.is_empty());

        let decompressed = gunzip_data(&compressed).expect("Failed to decompress single byte");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzip_small_data() {
        let data = b"Hello, World!".to_vec();
        let compressed = gzip_data(&data).expect("Failed to compress small data");

        let decompressed = gunzip_data(&compressed).expect("Failed to decompress small data");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzip_large_data() {
        // Create 1MB of data
        let data = vec![b'A'; 1024 * 1024];
        let compressed = gzip_data(&data).expect("Failed to compress large data");

        // Compression should reduce size significantly for repeated data
        assert!(compressed.len() < data.len() / 10);

        let decompressed = gunzip_data(&compressed).expect("Failed to decompress large data");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gzip_random_data() {
        // Create 100KB of pseudo-random data (less compressible)
        let data: Vec<u8> = (0..102400).map(|i| (i % 256) as u8).collect();
        let compressed = gzip_data(&data).expect("Failed to compress random data");

        let decompressed = gunzip_data(&compressed).expect("Failed to decompress random data");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gunzip_invalid_data() {
        let invalid_data = b"This is not gzipped data".to_vec();
        let result = gunzip_data(&invalid_data);
        assert!(result.is_err(), "Should fail on invalid gzip data");
    }

    #[test]
    fn test_gunzip_partial_data() {
        let data = b"Test data".to_vec();
        let compressed = gzip_data(&data).expect("Failed to compress");

        // Try to decompress only part of the compressed data
        let partial = &compressed[..compressed.len() / 2];
        let result = gunzip_data(partial);
        assert!(result.is_err(), "Should fail on partial gzip data");
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_get_manager_s3_url() {
        let result = get_manager("s3://my-bucket/path/to/object").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_manager_file_url() {
        let result = get_manager("file:///tmp/test.dat").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_manager_s3_missing_bucket() {
        let result = get_manager("s3:///path/without/bucket").await;
        assert!(result.is_err());
        if let Err(StorageError::AwsS3MissingBucket) = result {
            // Expected error
        } else {
            panic!("Expected AwsS3MissingBucket error");
        }
    }

    #[tokio::test]
    async fn test_get_manager_unsupported_protocol() {
        let result = get_manager("http://example.com/file").await;
        assert!(result.is_err());
        if let Err(StorageError::UnexpectedProto(proto)) = result {
            assert_eq!(proto, "http");
        } else {
            panic!("Expected UnexpectedProto error");
        }
    }

    #[tokio::test]
    async fn test_get_manager_invalid_url() {
        let result = get_manager("not a valid url").await;
        assert!(result.is_err());
        if let Err(StorageError::UrlParseError(_)) = result {
            // Expected error
        } else {
            panic!("Expected UrlParseError");
        }
    }

    #[tokio::test]
    async fn test_get_manager_file_url_quadruple_slash() {
        // file://// should work - path parsing should handle it
        let result = get_manager("file:////tmp/test.dat").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_get_manager_s3_double_slash_in_path() {
        // s3://bucket//nested//path should work - double slashes in path are valid
        let result = get_manager("s3://my-bucket//nested//path/object").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_manager_file_url_no_triple_slash() {
        // file://path (without triple slash) should still work
        let result = get_manager("file://tmp/test.dat").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_manager_file_url_relative_path() {
        // file:relative/path - should parse correctly
        let result = get_manager("file:relative/path.dat").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore] // Requires AWS credentials
    async fn test_get_manager_s3_nested_path() {
        // Complex nested path
        let result = get_manager("s3://my-bucket/very/deeply/nested/path/to/object.gz").await;
        assert!(result.is_ok());
    }
}
