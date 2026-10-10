//! Content-addressed, chunked blob storage (RFC 0001).
//!
//! Files are stored as manifests of FastCDC chunks, each addressed by its
//! BLAKE3 hash. Everything is scoped per user (no cross-user dedup or
//! existence oracle). Writes are atomic (temp file + fsync + rename) and
//! reads are verified chunk by chunk.
//!
//! Layout:
//! ```text
//! users/<id>/chunks/aa/bb/<hash>     chunk blobs
//! users/<id>/manifests/<content-id>  manifest JSON
//! tmp/                               in-flight uploads
//! ```

use std::{
    collections::HashSet,
    fmt::Display,
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use futures_util::{Stream, StreamExt};
use kolimi_chunk::{AVG_CHUNK_SIZE, ChunkRef, Hash, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, Manifest};
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
    /// Chunking failed.
    #[error("chunking failed: {0}")]
    Chunking(String),
    /// A chunk was submitted under the wrong hash.
    #[error("chunk hash mismatch: expected {expected}, got {actual}")]
    Mismatch {
        /// Hash the chunk was stored under.
        expected: Hash,
        /// Actual hash of the received bytes.
        actual: Hash,
    },
    /// Randomness generation failed.
    #[error("randomness error: {0}")]
    Random(String),
    /// An internal worker failed.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Result of a garbage collection sweep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    /// Chunk blobs deleted.
    pub chunks_deleted: u64,
    /// Manifest blobs deleted.
    pub manifests_deleted: u64,
}

/// Result of verifying a manifest's chunks.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VerifyStats {
    /// Chunks checked.
    pub chunks_checked: u64,
    /// Total bytes read.
    pub bytes: u64,
}

/// A per-user, content-addressed, chunked blob store.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Opens (creating if needed) a blob store at `root`.
    ///
    /// Stale in-flight upload temp files (older than a day) are removed:
    /// a crash mid-upload may leave those behind, but never a partially
    /// visible blob.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        let tmp = root.join("tmp");
        tokio::fs::create_dir_all(&tmp).await?;
        cleanup_stale_temp(&tmp, Duration::from_secs(24 * 60 * 60)).await?;
        Ok(Self { root })
    }

    fn chunk_path(&self, user_id: i64, hash: &Hash) -> PathBuf {
        let hex = hash.to_hex();
        self.root
            .join("users")
            .join(user_id.to_string())
            .join("chunks")
            .join(&hex[..2])
            .join(&hex[2..4])
            .join(&hex)
    }

    fn manifest_path(&self, user_id: i64, content_id: &Hash) -> PathBuf {
        self.root
            .join("users")
            .join(user_id.to_string())
            .join("manifests")
            .join(content_id.to_hex())
    }

    fn chunks_dir(&self, user_id: i64) -> PathBuf {
        self.root
            .join("users")
            .join(user_id.to_string())
            .join("chunks")
    }

    fn manifests_dir(&self, user_id: i64) -> PathBuf {
        self.root
            .join("users")
            .join(user_id.to_string())
            .join("manifests")
    }

    fn tmp_path(&self) -> Result<PathBuf, StoreError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|e| StoreError::Random(e.to_string()))?;
        Ok(self
            .root
            .join("tmp")
            .join(format!("{}.part", hex::encode(random))))
    }

    /// Stores a single chunk under `hash`, verifying the bytes match.
    pub async fn put_chunk(
        &self,
        user_id: i64,
        hash: &Hash,
        data: &[u8],
    ) -> Result<(), StoreError> {
        let actual = Hash::of(data);
        if actual != *hash {
            return Err(StoreError::Mismatch {
                expected: *hash,
                actual,
            });
        }
        let path = self.chunk_path(user_id, hash);
        if tokio::fs::try_exists(&path).await? {
            return Ok(());
        }
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);
        commit(&tmp, &path).await
    }

    /// Reads and verifies a chunk.
    pub async fn get_chunk(&self, user_id: i64, hash: &Hash) -> Result<Vec<u8>, StoreError> {
        let path = self.chunk_path(user_id, hash);
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

    /// Returns whether a chunk exists (and is intact).
    pub async fn has_chunk(&self, user_id: i64, hash: &Hash) -> Result<bool, StoreError> {
        match self.get_chunk(user_id, hash).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Stores a manifest under its content id, verifying identity.
    pub async fn put_manifest(
        &self,
        user_id: i64,
        manifest: &Manifest,
    ) -> Result<Hash, StoreError> {
        let content_id = manifest.content_id();
        let path = self.manifest_path(user_id, &content_id);
        if tokio::fs::try_exists(&path).await? {
            return Ok(content_id);
        }
        let json = serde_json::to_vec(manifest)
            .map_err(|e| StoreError::Internal(format!("manifest serialization: {e}")))?;
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(&json).await?;
        file.sync_all().await?;
        drop(file);
        commit(&tmp, &path).await?;
        Ok(content_id)
    }

    /// Reads a manifest by content id and verifies its identity.
    pub async fn get_manifest(
        &self,
        user_id: i64,
        content_id: &Hash,
    ) -> Result<Manifest, StoreError> {
        let path = self.manifest_path(user_id, content_id);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(*content_id));
            }
            Err(e) => return Err(StoreError::Io(e)),
        };
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt(*content_id))?;
        if manifest.content_id() != *content_id {
            return Err(StoreError::Corrupt(*content_id));
        }
        Ok(manifest)
    }

    /// Returns whether a manifest exists (and is intact).
    pub async fn has_manifest(&self, user_id: i64, content_id: &Hash) -> Result<bool, StoreError> {
        match self.get_manifest(user_id, content_id).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Chunks and stores a byte buffer; returns the manifest.
    pub async fn ingest_bytes(&self, user_id: i64, data: &[u8]) -> Result<Manifest, StoreError> {
        let chunks: Vec<(Hash, Vec<u8>)> = kolimi_chunk::split(data)
            .into_iter()
            .map(|chunk| (chunk.hash, chunk.data.to_vec()))
            .collect();
        let mut refs = Vec::with_capacity(chunks.len());
        for (hash, bytes) in &chunks {
            self.put_chunk(user_id, hash, bytes).await?;
            refs.push(ChunkRef {
                hash: *hash,
                len: bytes.len() as u32,
            });
        }
        let manifest = Manifest {
            version: Manifest::VERSION,
            size: data.len() as u64,
            chunks: refs,
        };
        self.put_manifest(user_id, &manifest).await?;
        Ok(manifest)
    }

    /// Streams a body to a temp file, chunks it, and stores chunks + manifest.
    pub async fn ingest_stream<B, E>(
        &self,
        user_id: i64,
        mut stream: impl Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<(Manifest, u64), StoreError>
    where
        B: AsRef<[u8]>,
        E: Display,
    {
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
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
            file.write_all(chunk).await?;
        }
        file.sync_all().await?;
        drop(file);

        let chunks_dir = self.chunks_dir(user_id);
        let ingest_path = tmp.clone();
        let manifest = tokio::task::spawn_blocking(move || chunk_file(&chunks_dir, &ingest_path))
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))??;
        let _ = tokio::fs::remove_file(&tmp).await;

        self.put_manifest(user_id, &manifest).await?;
        Ok((manifest, size))
    }

    /// Reassembles a manifest's content in memory, verifying every chunk.
    pub async fn read_content(
        &self,
        user_id: i64,
        manifest: &Manifest,
    ) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::with_capacity(manifest.size as usize);
        for chunk in &manifest.chunks {
            let bytes = self.get_chunk(user_id, &chunk.hash).await?;
            out.extend_from_slice(&bytes);
        }
        if out.len() as u64 != manifest.size {
            return Err(StoreError::Corrupt(manifest.content_id()));
        }
        Ok(out)
    }

    /// Verifies every chunk of a manifest without keeping the content.
    pub async fn verify_manifest(
        &self,
        user_id: i64,
        content_id: &Hash,
    ) -> Result<VerifyStats, StoreError> {
        let manifest = self.get_manifest(user_id, content_id).await?;
        let mut stats = VerifyStats::default();
        for chunk in &manifest.chunks {
            let bytes = self.get_chunk(user_id, &chunk.hash).await?;
            stats.bytes += bytes.len() as u64;
            stats.chunks_checked += 1;
        }
        if stats.bytes != manifest.size {
            return Err(StoreError::Corrupt(*content_id));
        }
        Ok(stats)
    }

    /// Deletes a manifest blob.
    pub async fn delete_manifest(&self, user_id: i64, content_id: &Hash) -> Result<(), StoreError> {
        let path = self.manifest_path(user_id, content_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::NotFound(*content_id)),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    /// Deletes every chunk and manifest not in the keep sets and older than
    /// `grace` (protecting in-flight uploads).
    pub async fn sweep(
        &self,
        user_id: i64,
        keep_manifests: &HashSet<Hash>,
        keep_chunks: &HashSet<Hash>,
        grace: Duration,
    ) -> Result<SweepStats, StoreError> {
        let mut stats = SweepStats::default();
        let cutoff = SystemTime::now()
            .checked_sub(grace)
            .unwrap_or(SystemTime::UNIX_EPOCH);

        let chunks = collect_files(&self.chunks_dir(user_id)).await?;
        for path in chunks {
            let Some(hash) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<Hash>().ok())
            else {
                continue;
            };
            if keep_chunks.contains(&hash) {
                continue;
            }
            if older_than(&path, cutoff).await? {
                tokio::fs::remove_file(&path).await?;
                stats.chunks_deleted += 1;
            }
        }

        let manifests = collect_files(&self.manifests_dir(user_id)).await?;
        for path in manifests {
            let Some(content_id) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<Hash>().ok())
            else {
                continue;
            };
            if keep_manifests.contains(&content_id) {
                continue;
            }
            if older_than(&path, cutoff).await? {
                tokio::fs::remove_file(&path).await?;
                stats.manifests_deleted += 1;
            }
        }

        Ok(stats)
    }

    /// Copies the whole store tree to `dest` (used by backup).
    pub async fn copy_tree_to(&self, dest: &Path) -> Result<u64, StoreError> {
        copy_tree(&self.root.join("users"), &dest.join("users")).await
    }
}

fn chunk_file(chunks_dir: &Path, path: &Path) -> Result<Manifest, StoreError> {
    let file = std::fs::File::open(path)?;
    let chunker =
        fastcdc::v2020::StreamCDC::new(file, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let mut refs = Vec::new();
    let mut total: u64 = 0;
    for result in chunker {
        let chunk = result.map_err(|e| StoreError::Chunking(e.to_string()))?;
        let hash = Hash::of(&chunk.data);
        let hex = hash.to_hex();
        let dir = chunks_dir.join(&hex[..2]).join(&hex[2..4]);
        std::fs::create_dir_all(&dir)?;
        let target = dir.join(&hex);
        if !target.exists() {
            let tmp = dir.join(format!("{hex}.part"));
            std::fs::write(&tmp, &chunk.data)?;
            std::fs::rename(&tmp, &target)?;
        }
        refs.push(ChunkRef {
            hash,
            len: chunk.data.len() as u32,
        });
        total += chunk.data.len() as u64;
    }
    Ok(Manifest {
        version: Manifest::VERSION,
        size: total,
        chunks: refs,
    })
}

async fn commit(tmp: &Path, path: &Path) -> Result<(), StoreError> {
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

async fn collect_files(root: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(StoreError::Io(e)),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if entry.file_type().await?.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

async fn older_than(path: &Path, cutoff: SystemTime) -> Result<bool, StoreError> {
    let metadata = tokio::fs::metadata(path).await?;
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    Ok(modified < cutoff)
}

async fn cleanup_stale_temp(tmp: &Path, max_age: Duration) -> Result<(), StoreError> {
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    for path in collect_files(tmp).await? {
        if older_than(&path, cutoff).await.unwrap_or(false) {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
    Ok(())
}

async fn copy_tree(src: &Path, dest: &Path) -> Result<u64, StoreError> {
    let mut count = 0;
    let mut stack = vec![(src.to_path_buf(), dest.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&from).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(StoreError::Io(e)),
        };
        tokio::fs::create_dir_all(&to).await?;
        while let Some(entry) = entries.next_entry().await? {
            let from_path = entry.path();
            let to_path = to.join(entry.file_name());
            if entry.file_type().await?.is_dir() {
                stack.push((from_path, to_path));
            } else {
                tokio::fs::copy(&from_path, &to_path).await?;
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    async fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path()).await.unwrap();
        (dir, store)
    }

    fn pseudorandom(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[tokio::test]
    async fn chunk_roundtrip_and_verification() {
        let (_dir, store) = store().await;
        let data = pseudorandom(5 * 1024 * 1024);
        let manifest = store.ingest_bytes(1, &data).await.unwrap();
        assert!(manifest.chunks.len() > 1);

        let content = store.read_content(1, &manifest).await.unwrap();
        assert_eq!(content, data);

        let stats = store
            .verify_manifest(1, &manifest.content_id())
            .await
            .unwrap();
        assert_eq!(stats.bytes, data.len() as u64);
        assert_eq!(stats.chunks_checked, manifest.chunks.len() as u64);
    }

    #[tokio::test]
    async fn identical_content_dedupes_chunks_and_manifest() {
        let (_dir, store) = store().await;
        let data = pseudorandom(3 * 1024 * 1024);
        let first = store.ingest_bytes(1, &data).await.unwrap();
        let second = store.ingest_bytes(1, &data).await.unwrap();
        assert_eq!(first.content_id(), second.content_id());

        // Uploading the same content twice must not duplicate chunk files.
        let chunk_files = collect_files(&store.chunks_dir(1)).await.unwrap();
        let unique: std::collections::HashSet<_> = chunk_files.iter().collect();
        assert_eq!(chunk_files.len(), unique.len());
        assert_eq!(chunk_files.len(), first.chunks.len());
    }

    #[tokio::test]
    async fn blobs_are_scoped_per_user() {
        let (_dir, store) = store().await;
        let manifest = store.ingest_bytes(1, b"private").await.unwrap();
        assert!(matches!(
            store.get_manifest(2, &manifest.content_id()).await,
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.get_chunk(2, &manifest.chunks[0].hash).await,
            Err(StoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn tampered_chunk_is_detected() {
        let (_dir, store) = store().await;
        let manifest = store.ingest_bytes(1, b"hello chunk world").await.unwrap();
        let hash = manifest.chunks[0].hash;
        let path = store.chunk_path(1, &hash);
        tokio::fs::write(&path, b"tampered").await.unwrap();
        assert!(matches!(
            store.get_chunk(1, &hash).await,
            Err(StoreError::Corrupt(_))
        ));
    }

    #[tokio::test]
    async fn put_chunk_rejects_hash_mismatch() {
        let (_dir, store) = store().await;
        let wrong = Hash::of(b"other");
        assert!(matches!(
            store.put_chunk(1, &wrong, b"bytes").await,
            Err(StoreError::Mismatch { .. })
        ));
    }

    #[tokio::test]
    async fn streamed_ingest_roundtrips() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
            Ok(b"hello ".to_vec()),
            Ok(b"streamed ".to_vec()),
            Ok(b"world".to_vec()),
        ];
        let (manifest, size) = store
            .ingest_stream(1, futures_util::stream::iter(chunks), 1024)
            .await
            .unwrap();
        assert_eq!(size, 20);
        assert_eq!(manifest.size, 20);
        assert_eq!(
            store.read_content(1, &manifest).await.unwrap(),
            b"hello streamed world"
        );
    }

    #[tokio::test]
    async fn streamed_ingest_enforces_limit_and_cleans_temp() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![Ok(vec![0u8; 2048])];
        assert!(matches!(
            store
                .ingest_stream(1, futures_util::stream::iter(chunks), 1024)
                .await,
            Err(StoreError::TooLarge { limit: 1024 })
        ));
        let leftovers = std::fs::read_dir(store.root.join("tmp")).unwrap().count();
        assert_eq!(leftovers, 0, "failed uploads must not leave temp files");
    }

    #[tokio::test]
    async fn interrupted_ingest_is_crash_safe() {
        let (_dir, store) = store().await;
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = vec![
            Ok(b"partial".to_vec()),
            Err(std::io::Error::other("connection reset")),
        ];
        assert!(matches!(
            store
                .ingest_stream(1, futures_util::stream::iter(chunks), 1024)
                .await,
            Err(StoreError::Stream(_))
        ));
        // No manifest exists, so no reader can observe the partial upload.
        let manifests = collect_files(&store.manifests_dir(1)).await.unwrap();
        assert!(manifests.is_empty());
        let leftovers = std::fs::read_dir(store.root.join("tmp")).unwrap().count();
        assert_eq!(leftovers, 0);
    }

    #[tokio::test]
    async fn sweep_removes_unreferenced_but_respects_grace() {
        let (_dir, store) = store().await;
        let keep = store.ingest_bytes(1, b"keep me around").await.unwrap();
        let stale = store.ingest_bytes(1, b"delete me later").await.unwrap();
        let keep_manifests: HashSet<Hash> = [keep.content_id()].into_iter().collect();
        let keep_chunks: HashSet<Hash> = keep.chunks.iter().map(|c| c.hash).collect();

        // Everything is within the grace window: nothing is deleted.
        let stats = store
            .sweep(1, &keep_manifests, &keep_chunks, Duration::from_secs(3600))
            .await
            .unwrap();
        assert_eq!(stats, SweepStats::default());
        assert!(store.has_manifest(1, &stale.content_id()).await.unwrap());

        // With no grace, unreferenced blobs are swept.
        let stats = store
            .sweep(1, &keep_manifests, &keep_chunks, Duration::ZERO)
            .await
            .unwrap();
        assert!(stats.manifests_deleted >= 1);
        assert!(!store.has_manifest(1, &stale.content_id()).await.unwrap());
        assert!(store.has_manifest(1, &keep.content_id()).await.unwrap());
        assert!(store.get_chunk(1, &keep.chunks[0].hash).await.is_ok());
    }

    #[tokio::test]
    async fn copy_tree_backs_up_blobs() {
        let (_dir, store) = store().await;
        let manifest = store.ingest_bytes(1, b"backup me").await.unwrap();

        let dest = tempfile::tempdir().unwrap();
        let count = store.copy_tree_to(dest.path()).await.unwrap();
        assert!(count >= 2);

        let restored = BlobStore::open(dest.path()).await.unwrap();
        let bytes = restored.read_content(1, &manifest).await.unwrap();
        assert_eq!(bytes, b"backup me");
    }
}
