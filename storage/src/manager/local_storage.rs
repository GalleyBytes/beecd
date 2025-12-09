use super::*;
use std::path::Path;

pub struct Local {
    path: String,
}

#[async_trait]
impl StorageManager for Local {
    async fn new(_: String, path: String) -> Result<Self, StorageError> {
        Ok(Self { path })
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

        let path = Path::new(&self.path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::LocalFileCreateError(e.into()))?;
        }

        tokio::fs::write(&self.path, &data)
            .await
            .map_err(|e| StorageError::LocalFileWriteError(e.into()))?;

        Ok(())
    }

    async fn fetch(&self) -> Result<Vec<u8>, StorageError> {
        let buffer = tokio::fs::read(&self.path)
            .await
            .map_err(|e| StorageError::LocalFileOpenError(e.into()))?;

        // Check size limit to prevent OOM
        if buffer.len() > MAX_OBJECT_SIZE {
            return Err(StorageError::ObjectTooLarge(buffer.len(), MAX_OBJECT_SIZE));
        }

        // Decompress in a blocking task to avoid blocking the async runtime
        let decompressed = tokio::task::spawn_blocking(move || gunzip_data(&buffer))
            .await
            .map_err(|e| StorageError::GzipError(e.into()))??;

        Ok(decompressed)
    }
}
