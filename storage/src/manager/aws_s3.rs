use super::*;
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::Client;
use std::env;
use std::time::Duration;
use url;

pub struct AwsS3 {
    bucket: String,
    key: String,
    client: Client,
}

#[async_trait]
impl StorageManager for AwsS3 {
    async fn new(bucket: String, key: String) -> Result<Self, StorageError> {
        let endpoint_s3 = env::var("AWS_ENDPOINT_URL_S3").ok();
        let endpoint_generic = env::var("AWS_ENDPOINT_URL").ok();
        let region = env::var("AWS_REGION").ok();

        let (endpoint_url, is_valid_url) =
            get_endpoint_config_from_env(endpoint_s3, endpoint_generic);

        // Get configurable timeouts from environment or use defaults
        let operation_timeout_secs = env::var("AWS_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30);
        let total_timeout_secs = env::var("AWS_TOTAL_TIMEOUT_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(300);

        let client = if let Some(endpoint) = endpoint_url {
            if !is_valid_url {
                // Invalid URL - return error instead of panic
                return Err(StorageError::InvalidEndpointUrl(format!(
                    "Invalid S3 endpoint URL: '{}'. Please check AWS_ENDPOINT_URL_S3 or AWS_ENDPOINT_URL environment variable.",
                    endpoint
                )));
            }

            // Custom endpoint mode (MinIO, LocalStack, etc.)
            let region_name = region.unwrap_or_else(|| "us-east-1".to_string());

            let timeout_config = aws_config::timeout::TimeoutConfig::builder()
                .operation_attempt_timeout(Duration::from_secs(operation_timeout_secs))
                .operation_timeout(Duration::from_secs(total_timeout_secs))
                .build();

            // Read credentials from environment variables
            let access_key_id = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
            let secret_access_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();

            // Build S3 client directly without using aws_config::defaults
            // to avoid region resolution issues with custom endpoints
            let mut s3_config_builder = aws_sdk_s3::config::Builder::new()
                .endpoint_url(&endpoint)
                .region(aws_sdk_s3::config::Region::new(region_name))
                .force_path_style(true) // Required for MinIO compatibility
                .timeout_config(timeout_config);

            // Add credentials if provided
            if !access_key_id.is_empty() && !secret_access_key.is_empty() {
                let credentials = Credentials::new(
                    access_key_id,
                    secret_access_key,
                    None, // session token
                    None, // expiration
                    "environment",
                );
                s3_config_builder = s3_config_builder.credentials_provider(credentials);
            }

            Client::from_conf(s3_config_builder.build())
        } else {
            // Standard AWS S3 mode
            let timeout_config = aws_config::timeout::TimeoutConfig::builder()
                .operation_attempt_timeout(Duration::from_secs(operation_timeout_secs))
                .operation_timeout(Duration::from_secs(total_timeout_secs))
                .build();

            let config = aws_config::defaults(BehaviorVersion::latest())
                .timeout_config(timeout_config)
                .load()
                .await;
            Client::new(&config)
        };

        Ok(Self {
            bucket,
            key,
            client,
        })
    }

    async fn push(&self, bytes: &[u8]) -> Result<(), StorageError> {
        // Check size limit before processing
        if bytes.len() > MAX_OBJECT_SIZE {
            return Err(StorageError::ObjectTooLarge(bytes.len(), MAX_OBJECT_SIZE));
        }

        // Compress in a blocking task to avoid blocking the async runtime
        // Note: to_vec() copies the input to satisfy spawn_blocking's 'static bound.
        // This temporarily doubles memory usage. For zero-copy, API would need to
        // accept Vec<u8> or Arc<[u8]>, or use streaming compression.
        let bytes_owned = bytes.to_vec();
        let data = tokio::task::spawn_blocking(move || gzip_data(&bytes_owned))
            .await
            .map_err(|e| StorageError::GzipError(e.into()))??;

        let body = aws_sdk_s3::primitives::ByteStream::from(data);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::AwsS3SdkError(e.into()))?;

        Ok(())
    }

    async fn fetch(&self) -> Result<Vec<u8>, StorageError> {
        let mut byte_stream = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .send()
            .await
            .map_err(|e| StorageError::AwsS3SdkError(e.into()))?
            .body;

        // Collect all chunks from the stream with size limit enforcement
        // Pre-allocate 8MB to reduce reallocation overhead
        let mut bytes = Vec::with_capacity(8 * 1024 * 1024);
        while let Some(chunk) = byte_stream
            .try_next()
            .await
            .map_err(|e| StorageError::AwsS3StreamError(e.into()))?
        {
            // Check size limit BEFORE extending to prevent overshooting
            if bytes.len() + chunk.len() > MAX_OBJECT_SIZE {
                return Err(StorageError::ObjectTooLarge(
                    bytes.len() + chunk.len(),
                    MAX_OBJECT_SIZE,
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        // Decompress in a blocking task to avoid blocking the async runtime
        let decompressed = tokio::task::spawn_blocking(move || gunzip_data(&bytes))
            .await
            .map_err(|e| StorageError::GzipError(e.into()))??;

        Ok(decompressed)
    }
}

/// Helper function to get endpoint configuration from explicit parameters
/// Returns (endpoint_url, is_valid) tuple
/// This function is pure and testable without environment mutation
fn get_endpoint_config(
    endpoint_s3: Option<String>,
    endpoint_generic: Option<String>,
) -> (Option<String>, bool) {
    // AWS_ENDPOINT_URL_S3 takes precedence over AWS_ENDPOINT_URL
    let endpoint_url = endpoint_s3.or(endpoint_generic);

    if let Some(ref endpoint) = endpoint_url {
        // Validate URL format
        let is_valid = url::Url::parse(endpoint).is_ok();
        (endpoint_url, is_valid)
    } else {
        (None, true) // No endpoint is valid (use AWS defaults)
    }
}

/// Wrapper for production use that reads from environment variables
fn get_endpoint_config_from_env(
    endpoint_s3: Option<String>,
    endpoint_generic: Option<String>,
) -> (Option<String>, bool) {
    get_endpoint_config(endpoint_s3, endpoint_generic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_endpoint_config_no_env() {
        let (endpoint, is_valid) = get_endpoint_config(None, None);
        assert_eq!(endpoint, None);
        assert!(is_valid);
    }

    #[test]
    fn test_get_endpoint_config_s3_specific() {
        let (endpoint, is_valid) =
            get_endpoint_config(Some("http://localhost:9000".to_string()), None);
        assert_eq!(endpoint, Some("http://localhost:9000".to_string()));
        assert!(is_valid);
    }

    #[test]
    fn test_get_endpoint_config_generic() {
        let (endpoint, is_valid) = get_endpoint_config(None, Some("http://minio:9000".to_string()));
        assert_eq!(endpoint, Some("http://minio:9000".to_string()));
        assert!(is_valid);
    }

    #[test]
    fn test_get_endpoint_config_precedence() {
        // AWS_ENDPOINT_URL_S3 should take precedence
        let (endpoint, is_valid) = get_endpoint_config(
            Some("http://specific:9000".to_string()),
            Some("http://generic:9000".to_string()),
        );
        assert_eq!(endpoint, Some("http://specific:9000".to_string()));
        assert!(is_valid);
    }

    #[test]
    fn test_get_endpoint_config_invalid_url() {
        let (endpoint, is_valid) = get_endpoint_config(Some("not-a-valid-url".to_string()), None);
        assert_eq!(endpoint, Some("not-a-valid-url".to_string()));
        assert!(!is_valid);
    }

    #[test]
    fn test_get_endpoint_config_https() {
        let (endpoint, is_valid) =
            get_endpoint_config(None, Some("https://s3.amazonaws.com".to_string()));
        assert_eq!(endpoint, Some("https://s3.amazonaws.com".to_string()));
        assert!(is_valid);
    }
}
