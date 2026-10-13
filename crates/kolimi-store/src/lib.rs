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
    sync::Arc,
    time::{Duration, SystemTime},
};

use futures_util::{Stream, StreamExt, stream};
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
    /// Total bytes reclaimed.
    pub bytes_freed: u64,
}

/// Result of one scrub batch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScrubBatch {
    /// Blobs verified in this batch.
    pub checked: u64,
    /// Relative paths whose bytes do not match their hash.
    pub corrupt: Vec<String>,
    /// Cursor for the next call; `None` means the cycle finished.
    pub next: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobKind {
    Chunk,
    Manifest,
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
    /// Server-wide default quota in bytes (`0` = unlimited), used when a
    /// user has no per-user override. Enforcement lives in the VFS, which
    /// can see the per-user quota and usage counter.
    default_quota: u64,
}

impl BlobStore {
    /// Opens (creating if needed) a blob store at `root` with no quota.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Self::open_with_quota(root, 0).await
    }

    /// Opens a blob store with a server-wide default quota (`0` = unlimited).
    ///
    /// Stale in-flight upload temp files (older than a day) are removed:
    /// a crash mid-upload may leave those behind, but never a partially
    /// visible blob.
    pub async fn open_with_quota(
        root: impl Into<PathBuf>,
        default_quota: u64,
    ) -> Result<Self, StoreError> {
        let root = root.into();
        let tmp = root.join("tmp");
        tokio::fs::create_dir_all(&tmp).await?;
        cleanup_stale_temp(&tmp, Duration::from_secs(24 * 60 * 60)).await?;
        Ok(Self {
            root,
            default_quota,
        })
    }

    /// The server-wide default quota in bytes (`0` = unlimited).
    pub fn default_quota(&self) -> u64 {
        self.default_quota
    }

    /// Returns the user's stored bytes by walking the blob tree. Chunks
    /// dominate, so this is an upper bound on live data. Used by the
    /// janitor's reconciliation, never on the request path.
    pub async fn usage_bytes(&self, user_id: i64) -> Result<u64, StoreError> {
        let mut total = 0u64;
        for dir in [self.chunks_dir(user_id), self.manifests_dir(user_id)] {
            total = total.saturating_add(dir_size(&dir).await?);
        }
        Ok(total)
    }

    /// Removes every blob owned by a user.
    ///
    /// Storage is per-user (manifests and chunks live under
    /// `users/<id>/`), so nothing else can reference these files. Used
    /// when an account is deleted; a missing directory is not an error.
    pub async fn remove_user(&self, user_id: i64) -> Result<(), StoreError> {
        let dir = self.root.join("users").join(user_id.to_string());
        match tokio::fs::remove_dir_all(&dir).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
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

    /// Verifies up to `limit` blobs strictly after the cursor `after`,
    /// in lexicographic order (the scrub cycle order).
    ///
    /// Chunks are re-hashed against their address; manifests are parsed
    /// and their structural content id recomputed. Returns the corrupt
    /// paths and the cursor for the next batch (`None` = cycle finished,
    /// start over next time).
    pub async fn scrub_batch(
        &self,
        user_id: i64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ScrubBatch, StoreError> {
        let mut blobs: Vec<(String, BlobKind)> = Vec::new();
        collect_blobs(
            &self.chunks_dir(user_id),
            "chunks",
            BlobKind::Chunk,
            &mut blobs,
        )
        .await?;
        collect_blobs(
            &self.manifests_dir(user_id),
            "manifests",
            BlobKind::Manifest,
            &mut blobs,
        )
        .await?;
        blobs.sort_by(|a, b| a.0.cmp(&b.0));

        let mut batch = ScrubBatch::default();
        let mut last: Option<String> = None;
        let mut has_more = false;
        for (rel, kind) in &blobs {
            if after.is_some_and(|after| rel.as_str() <= after) {
                continue;
            }
            if batch.checked as usize >= limit {
                // A blob remains beyond this batch: resume from `last`.
                has_more = true;
                break;
            }
            batch.checked += 1;
            last = Some(rel.clone());
            let path = self.root.join("users").join(user_id.to_string()).join(rel);
            if !verify_blob(&path, rel, *kind).await {
                batch.corrupt.push(rel.clone());
            }
        }
        batch.next = if has_more { last } else { None };
        Ok(batch)
    }

    /// Stores a single chunk under `hash`, verifying the bytes match.
    ///
    /// Returns `true` when the chunk was newly written (so callers can
    /// adjust the usage counter), `false` when it already existed.
    pub async fn put_chunk(
        &self,
        user_id: i64,
        hash: &Hash,
        data: &[u8],
    ) -> Result<bool, StoreError> {
        let actual = Hash::of(data);
        if actual != *hash {
            return Err(StoreError::Mismatch {
                expected: *hash,
                actual,
            });
        }
        let path = self.chunk_path(user_id, hash);
        if tokio::fs::try_exists(&path).await? {
            return Ok(false);
        }
        let tmp = self.tmp_path()?;
        let mut file = tokio::fs::File::create(&tmp).await?;
        file.write_all(data).await?;
        file.sync_all().await?;
        drop(file);
        commit(&tmp, &path).await?;
        Ok(true)
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
        if !manifest.is_consistent() {
            return Err(StoreError::Internal(
                "manifest size does not match its chunk lengths".to_string(),
            ));
        }
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
        // Guard against a manifest whose `size` lies about its chunks, which
        // would otherwise drive an oversized allocation on read.
        if !manifest.is_consistent() {
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
    pub async fn ingest_bytes(
        &self,
        user_id: i64,
        data: &[u8],
    ) -> Result<(Manifest, u64), StoreError> {
        let chunks: Vec<(Hash, Vec<u8>)> = kolimi_chunk::split(data)
            .into_iter()
            .map(|chunk| (chunk.hash, chunk.data.to_vec()))
            .collect();
        let mut refs = Vec::with_capacity(chunks.len());
        let mut new_bytes = 0u64;
        for (hash, bytes) in &chunks {
            if self.put_chunk(user_id, hash, bytes).await? {
                new_bytes += bytes.len() as u64;
            }
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
        Ok((manifest, new_bytes))
    }

    /// Streams a body to a temp file, chunks it, and stores chunks + manifest.
    /// Returns the manifest, the total content size, and the number of
    /// **newly written** chunk bytes (deduplicated against existing blobs).
    pub async fn ingest_stream<B, E>(
        &self,
        user_id: i64,
        mut stream: impl Stream<Item = Result<B, E>> + Unpin,
        max_bytes: u64,
    ) -> Result<(Manifest, u64, u64), StoreError>
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
            if let Err(e) = file.write_all(chunk).await {
                drop(file);
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(StoreError::Io(e));
            }
        }
        if let Err(e) = file.sync_all().await {
            drop(file);
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(StoreError::Io(e));
        }
        drop(file);

        let chunks_dir = self.chunks_dir(user_id);
        let ingest_path = tmp.clone();
        let (manifest, new_bytes) =
            tokio::task::spawn_blocking(move || chunk_file(&chunks_dir, &ingest_path))
                .await
                .map_err(|e| StoreError::Internal(e.to_string()))??;
        let _ = tokio::fs::remove_file(&tmp).await;

        self.put_manifest(user_id, &manifest).await?;
        Ok((manifest, size, new_bytes))
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

    /// Streams a manifest's content, verifying each chunk as it is read.
    ///
    /// Only one chunk is held in memory at a time, so large files stream
    /// without buffering the whole body. Chunks are emitted in order.
    pub fn content_stream(
        &self,
        user_id: i64,
        manifest: Arc<Manifest>,
    ) -> impl Stream<Item = Result<Vec<u8>, StoreError>> + Send + 'static {
        self.content_window_stream(user_id, manifest, 0, u64::MAX)
    }

    /// Streams the byte window `[start, end_exclusive)` of a manifest.
    ///
    /// Only the chunks overlapping the window are read; the first and last
    /// are trimmed to the window boundaries. Chunk verification still runs
    /// in full for every chunk touched.
    pub fn content_window_stream(
        &self,
        user_id: i64,
        manifest: Arc<Manifest>,
        start: u64,
        end_exclusive: u64,
    ) -> impl Stream<Item = Result<Vec<u8>, StoreError>> + Send + 'static {
        let store = self.clone();
        let segments = range_segments(&manifest, start, end_exclusive);
        stream::iter(segments).then(move |(hash, skip, take)| {
            let store = store.clone();
            async move {
                let data = store.get_chunk(user_id, &hash).await?;
                if skip == 0 && take == data.len() {
                    return Ok(data);
                }
                let end = (skip + take).min(data.len());
                Ok(data[skip.min(end)..end].to_vec())
            }
        })
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
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    stats.bytes_freed = stats.bytes_freed.saturating_add(meta.len());
                }
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
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    stats.bytes_freed = stats.bytes_freed.saturating_add(meta.len());
                }
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

/// Byte segments of the window `[start, end_exclusive)` of a manifest, as
/// `(chunk hash, skip, take)` triples. Chunks outside the window are
/// omitted; the first and last are trimmed to the window boundaries.
fn range_segments(
    manifest: &Manifest,
    start: u64,
    end_exclusive: u64,
) -> Vec<(Hash, usize, usize)> {
    let mut segments = Vec::new();
    if start >= end_exclusive {
        return segments;
    }
    let mut offset = 0u64;
    for chunk in &manifest.chunks {
        let chunk_start = offset;
        let chunk_end = offset + u64::from(chunk.len);
        offset = chunk_end;
        if chunk_end <= start || chunk_start >= end_exclusive {
            continue;
        }
        let from = start.max(chunk_start);
        let to = end_exclusive.min(chunk_end);
        segments.push((
            chunk.hash,
            (from - chunk_start) as usize,
            (to - from) as usize,
        ));
    }
    segments
}

/// Splits `path` into chunks under `chunks_dir`. Returns the manifest and
/// the number of bytes that were newly written (chunks that already existed
/// are deduplicated and not counted).
fn chunk_file(chunks_dir: &Path, path: &Path) -> Result<(Manifest, u64), StoreError> {
    let file = std::fs::File::open(path)?;
    let chunker =
        fastcdc::v2020::StreamCDC::new(file, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let mut refs = Vec::new();
    let mut total: u64 = 0;
    let mut new_bytes: u64 = 0;
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
            new_bytes += chunk.data.len() as u64;
        }
        refs.push(ChunkRef {
            hash,
            len: chunk.data.len() as u32,
        });
        total += chunk.data.len() as u64;
    }
    Ok((
        Manifest {
            version: Manifest::VERSION,
            size: total,
            chunks: refs,
        },
        new_bytes,
    ))
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

/// Sums the sizes of all files under `dir` (recursively); a missing
/// directory counts as zero.
async fn dir_size(dir: &Path) -> Result<u64, StoreError> {
    let mut total = 0u64;
    for path in collect_files(dir).await? {
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            total = total.saturating_add(meta.len());
        }
    }
    Ok(total)
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

async fn collect_blobs(
    dir: &Path,
    prefix: &str,
    kind: BlobKind,
    out: &mut Vec<(String, BlobKind)>,
) -> Result<(), StoreError> {
    let mut stack = vec![(dir.to_path_buf(), prefix.to_string())];
    while let Some((dir, prefix)) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(StoreError::Io(e)),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                stack.push((path, format!("{prefix}/{name}")));
            } else {
                out.push((format!("{prefix}/{name}"), kind));
            }
        }
    }
    Ok(())
}

async fn verify_blob(path: &Path, rel: &str, kind: BlobKind) -> bool {
    let Some(name) = rel.rsplit('/').next() else {
        return false;
    };
    let Ok(expected) = name.parse::<Hash>() else {
        return false;
    };
    let Ok(bytes) = tokio::fs::read(path).await else {
        return false;
    };
    match kind {
        BlobKind::Chunk => Hash::of(&bytes) == expected,
        BlobKind::Manifest => serde_json::from_slice::<Manifest>(&bytes)
            .map(|manifest| manifest.content_id() == expected)
            .unwrap_or(false),
    }
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
        let manifest = store.ingest_bytes(1, &data).await.unwrap().0;
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
        let first = store.ingest_bytes(1, &data).await.unwrap().0;
        let second = store.ingest_bytes(1, &data).await.unwrap().0;
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
        let manifest = store.ingest_bytes(1, b"private").await.unwrap().0;
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
    async fn remove_user_erases_its_blobs_and_leaves_others() {
        let (dir, store) = store().await;
        store.ingest_bytes(1, b"user one data").await.unwrap();
        store.ingest_bytes(2, b"user two data").await.unwrap();
        assert!(dir.path().join("users/1").exists());
        assert!(dir.path().join("users/2").exists());

        store.remove_user(1).await.unwrap();
        assert!(!dir.path().join("users/1").exists());
        assert!(dir.path().join("users/2").exists());

        // Idempotent, and a never-existing user is fine too.
        store.remove_user(1).await.unwrap();
        store.remove_user(99).await.unwrap();
    }

    #[tokio::test]
    async fn ingest_stream_reports_newly_written_bytes() {
        let (_dir, store) = store().await;
        let chunks = || vec![Ok::<Vec<u8>, std::io::Error>(b"hello world".to_vec())];
        let (_manifest, size, new_bytes) = store
            .ingest_stream(1, futures_util::stream::iter(chunks()), 1024)
            .await
            .unwrap();
        assert_eq!(size, 11);
        assert_eq!(new_bytes, 11);

        // Re-ingesting identical content writes nothing new.
        let (_manifest, _size, again) = store
            .ingest_stream(1, futures_util::stream::iter(chunks()), 1024)
            .await
            .unwrap();
        assert_eq!(again, 0, "deduplicated chunks are not counted as new");

        // usage_bytes reflects what is on disk (chunks + manifest).
        assert!(store.usage_bytes(1).await.unwrap() >= 11);
    }

    #[tokio::test]
    async fn put_chunk_reports_whether_it_wrote() {
        let (_dir, store) = store().await;
        let data = b"chunk bytes";
        let hash = Hash::of(data);
        assert!(
            store.put_chunk(1, &hash, data).await.unwrap(),
            "first write"
        );
        assert!(!store.put_chunk(1, &hash, data).await.unwrap(), "dedup");
    }

    #[tokio::test]
    async fn tampered_chunk_is_detected() {
        let (_dir, store) = store().await;
        let manifest = store.ingest_bytes(1, b"hello chunk world").await.unwrap().0;
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
        let (manifest, size, new_bytes) = store
            .ingest_stream(1, futures_util::stream::iter(chunks), 1024)
            .await
            .unwrap();
        assert_eq!(size, 20);
        assert_eq!(new_bytes, 20);
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
        let keep = store.ingest_bytes(1, b"keep me around").await.unwrap().0;
        let stale = store.ingest_bytes(1, b"delete me later").await.unwrap().0;
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
        let manifest = store.ingest_bytes(1, b"backup me").await.unwrap().0;

        let dest = tempfile::tempdir().unwrap();
        let count = store.copy_tree_to(dest.path()).await.unwrap();
        assert!(count >= 2);

        let restored = BlobStore::open(dest.path()).await.unwrap();
        let bytes = restored.read_content(1, &manifest).await.unwrap();
        assert_eq!(bytes, b"backup me");
    }

    #[tokio::test]
    async fn scrub_verifies_blobs_and_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).await.unwrap();
        let data = b"scrub me please, thoroughly".to_vec();
        store.ingest_bytes(1, &data).await.unwrap();

        // A clean cycle checks the chunks and the manifest, then finishes.
        let batch = store.scrub_batch(1, None, 1000).await.unwrap();
        assert!(batch.checked >= 2, "{batch:?}");
        assert!(batch.corrupt.is_empty(), "{batch:?}");
        assert_eq!(batch.next, None);

        // Corrupt one chunk on disk: the scrubber names it.
        let mut corrupt_path = None;
        let mut stack = vec![dir.path().join("blobs/users/1/chunks")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    corrupt_path = Some(path);
                }
            }
        }
        let corrupt_path = corrupt_path.expect("a chunk file");
        let mut bytes = std::fs::read(&corrupt_path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&corrupt_path, &bytes).unwrap();
        let name = corrupt_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let batch = store.scrub_batch(1, None, 1000).await.unwrap();
        assert_eq!(batch.corrupt.len(), 1, "{batch:?}");
        assert!(batch.corrupt[0].ends_with(&name));

        // Cursor batches advance deterministically.
        let first = store.scrub_batch(1, None, 1).await.unwrap();
        assert_eq!(first.checked, 1);
        let cursor = first.next.clone().expect("more blobs remain");
        let second = store.scrub_batch(1, Some(&cursor), 1).await.unwrap();
        assert_eq!(second.checked, 1);
        assert_ne!(second.next, Some(cursor));
    }
}
