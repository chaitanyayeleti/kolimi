//! Content-addressed blob storage.
//!
//! Blobs are addressed by the BLAKE3 hash of their plaintext bytes and
//! scoped per user (no cross-user dedup or existence oracle). Writes are
//! atomic (temp file + fsync + rename) and reads are verified.
//!
//! M1 stores one blob per file. RFC 0001 replaces this with chunk
//! manifests in M2; the addressing scheme stays the same.

use std::{
    fmt::Display,
    io,
    path::{Path, PathBuf},
};

use futures_util::{Stream, StreamExt};
use kolimi_chunk::Hash;
use tokio::io::AsyncWriteExt;

/// Errors returned by the blob store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A stored blob does not hash to its address.
    #[error("blob {0} is corrupt")]
    Corrupt(Hash),
    /// The requested blob does not exist.
    #[error("blob {0} not found")]
    NotFound(Hash),
    /// The upload exceeded the configured size limit.
    #[error("upload exceeds the {limit} byte limit")]
    TooLarge {
        /// Configured maximum size in bytes.
        limit: u64,
    },
    /// The upload stream failed.
    #[error("upload stream failed: {0}")]
    Stream(String),
    /// Randomness generation failed.
    #[error("randomness error: {0}")]
    Random(String),
}

/// A per-user, content-addressed blob store rooted at a directory.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Opens (creating if needed) a blob store at `root`.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        tokio::fs::create_dir_all(root.join("tmp")).await?;
        Ok(Self { root })
    }

    fn blob_path(&self, user_id: i64, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        self.root
            .join("users")
            .join(user_id.to_string())
            .join(&hex[..2])
            .join(&hex[2..4])
            .join(&hex)
    }

    fn tmp_path(&self) -> Result<PathBuf, StoreError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|e| StoreError::Random(e.to_string()))?;
        Ok(self
            .root
            .join("tmp")
            .join(format!("{}.part", hex::encode(random))))
    }

    /// Stores `data`, returning its hash. No-op if already present.
    pub async fn put_bytes(&self, user_id: i64, data: &[u8]) -> Result<Hash, StoreError> {
        let hash = Hash::of(data);
        let path = self.blob_path(user_id, &hash);
        if tokio::fs::try_exists(&path).await? {
            return Ok(hash);
        }
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);
        self.commit(&tmp, &path).await?;
        Ok(hash)
    }

    /// Streams `stream` to the store, returning its hash and length.
    pub async fn put_stream<B, E>(
        &self,
        user_id: i64,
        mut stream: impl Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<(Hash, u64), StoreError>
    where
        B: AsRef<[u8]>,
        E: Display,
    {
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
        let mut hasher = blake3::Hasher::new();
        let mut size: u64 = 0;

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(StoreError::Stream(e.to_string()));
                }
            };
            let chunk = chunk.as_ref();
            size += chunk.len() as u64;
            if size > max_bytes {
                drop(file);
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(StoreError::TooLarge { limit: max_bytes });
            }
            hasher.update(chunk);
            file.write_all(chunk).await?;
        }

        file.sync_all().await?;
        drop(file);

        let hash = Hash::from_bytes(*hasher.finalize().as_bytes());
        let path = self.blob_path(user_id, &hash);
        if tokio::fs::try_exists(&path).await? {
            tokio::fs::remove_file(&tmp).await?;
        } else {
            self.commit(&tmp, &path).await?;
        }
        Ok((hash, size))
    }

    /// Reads and verifies a blob.
    pub async fn get(&self, user_id: i64, hash: &Hash) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(user_id, hash);
        let data = match tokio::fs::read(&path).await {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(*hash));
            }
            Err(e) => return Err(StoreError::Io(e)),
        };
        if Hash::of(&data) != *hash {
            return Err(StoreError::Corrupt(*hash));
        }
        Ok(data)
    }

    /// Returns whether a blob exists and is intact.
    pub async fn verify(&self, user_id: i64, hash: &Hash) -> Result<bool, StoreError> {
        match self.get(user_id, hash).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Deletes a blob. Missing blobs are reported as [`StoreError::NotFound`].
    pub async fn delete(&self, user_id: i64, hash: &Hash) -> Result<(), StoreError> {
        let path = self.blob_path(user_id, hash);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::NotFound(*hash)),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    async fn commit(&self, tmp: &Path, path: &Path) -> Result<(), StoreError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        match tokio::fs::rename(tmp, path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = tokio::fs::remove_file(tmp).await;
                Err(StoreError::Io(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).await.unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn put_and_get_roundtrip() {
        let (_dir, store) = store().await;
        let hash = store.put_bytes(1, b"kolimi").await.unwrap();
        assert_eq!(store.get(1, &hash).await.unwrap(), b"kolimi");
    }

    #[tokio::test]
    async fn identical_content_is_deduped() {
        let (_dir, store) = store().await;
        let a = store.put_bytes(1, b"same").await.unwrap();
        let b = store.put_bytes(1, b"same").await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn blobs_are_scoped_per_user() {
        let (_dir, store) = store().await;
        let hash = store.put_bytes(1, b"private").await.unwrap();
        assert!(matches!(
            store.get(2, &hash).await,
            Err(StoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn corrupt_blob_is_detected_on_read() {
        let (_dir, store) = store().await;
        let hash = store.put_bytes(1, b"original").await.unwrap();
        let path = store.blob_path(1, &hash);
        tokio::fs::write(&path, b"tampered").await.unwrap();
        assert!(matches!(
            store.get(1, &hash).await,
            Err(StoreError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn missing_blob_reports_not_found() {
        let (_dir, store) = store().await;
        let hash = Hash::of(b"never stored");
        assert!(matches!(
            store.get(1, &hash).await,
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.delete(1, &hash).await,
            Err(StoreError::NotFound(_))
        ));
        assert!(!store.verify(1, &hash).await.unwrap());
    }

    #[tokio::test]
    async fn streamed_upload_roundtrips() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
            Ok(b"hello ".to_vec()),
            Ok(b"streamed ".to_vec()),
            Ok(b"world".to_vec()),
        ];
        let stream = futures_util::stream::iter(chunks);
        let (hash, size) = store.put_stream(1, stream, 1024).await.unwrap();
        assert_eq!(size, 20);
        assert_eq!(hash, Hash::of(b"hello streamed world"));
        assert_eq!(store.get(1, &hash).await.unwrap(), b"hello streamed world");
    }

    #[tokio::test]
    async fn streamed_upload_enforces_size_limit() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![Ok(vec![0u8; 2048])];
        let stream = futures_util::stream::iter(chunks);
        assert!(matches!(
            store.put_stream(1, stream, 1024).await,
            Err(StoreError::TooLarge { limit: 1024 })
        ));
    }

    #[tokio::test]
    async fn streamed_upload_propagates_stream_errors() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            vec![Ok(b"partial".to_vec()), Err(std::io::Error::other("boom"))];
        let stream = futures_util::stream::iter(chunks);
        assert!(matches!(
            store.put_stream(1, stream, 1024).await,
            Err(StoreError::Stream(_))
        ));
    }
}
