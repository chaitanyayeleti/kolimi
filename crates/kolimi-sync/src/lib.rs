//! Kolimi desktop sync core (alpha).
//!
//! Mirrors a local directory against a Kolimi server using the native
//! delta protocol (RFC 0002):
//!
//! - **pull**: server tree snapshot → manifests → only the chunks missing
//!   from the local cache are downloaded, then files are written
//!   atomically; remotely deleted files are removed locally
//! - **push**: changed local files are chunked client-side (FastCDC +
//!   BLAKE3, identical to the server), missing chunks are uploaded, and
//!   the manifest is committed with `if_content_id` conflict detection;
//!   conflicts keep the server version and preserve local edits as a
//!   `.conflict-<timestamp>` copy
//!
//! State lives in `<local>/.kolimi/state.json`; the chunk cache in
//! `<local>/.kolimi/chunks/` doubles as the delta base in both
//! directions. This is the core the Tauri/mobile shells will wrap; it is
//! intentionally one-shot (call it from a timer or file watcher).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use kolimi_chunk::{Manifest, chunker};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Configuration for one sync root.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Base URL, e.g. `https://cloud.example.com`.
    pub server: String,
    /// Username for HTTP Basic authentication.
    pub username: String,
    /// Password for HTTP Basic authentication.
    pub password: String,
    /// Local directory to mirror.
    pub local_dir: PathBuf,
}

/// What one sync pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncReport {
    /// Files written locally from the server.
    pub pulled: u64,
    /// Files uploaded to the server.
    pub pushed: u64,
    /// Locally deleted files (deleted remotely).
    pub removed_local: u64,
    /// Push conflicts (server version kept, local copy preserved).
    pub conflicts: u64,
    /// Remote files deleted because they were deleted locally.
    pub removed_remote: u64,
}

/// Errors from the sync core.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Local filesystem failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// HTTP transport failure.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    /// The server rejected a request.
    #[error("server error: {status} for {path}")]
    Server {
        /// HTTP status.
        status: u16,
        /// Request path.
        path: String,
    },
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    files: BTreeMap<String, StateFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateFile {
    content_id: String,
    size: u64,
    /// Local modification time in nanoseconds since the epoch.
    mtime_ns: i64,
    /// Set when the local file disappeared after having been synced; the
    /// pull pass must not resurrect it, and push propagates the deletion.
    #[serde(default)]
    deleted: bool,
}

impl State {
    fn state_path(local: &Path) -> PathBuf {
        local.join(".kolimi").join("state.json")
    }

    fn load(local: &Path) -> Result<Self, SyncError> {
        let path = Self::state_path(local);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, local: &Path) -> Result<(), SyncError> {
        let path = Self::state_path(local);
        let tmp = local.join(".kolimi").join("state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Runs one full sync pass: pull, then push.
pub async fn sync_once(config: &SyncConfig) -> Result<SyncReport, SyncError> {
    let http = Http::new(config)?;
    std::fs::create_dir_all(config.local_dir.join(".kolimi"))?;
    let mut state = State::load(&config.local_dir)?;
    let mut report = SyncReport::default();
    pull(&http, config, &mut state, &mut report).await?;
    push(&http, config, &mut state, &mut report).await?;
    if report.conflicts > 0 {
        // Fetch the winning server versions for the conflicted paths.
        pull(&http, config, &mut state, &mut report).await?;
    }
    state.save(&config.local_dir)?;
    Ok(report)
}

struct Http {
    client: reqwest::Client,
    base: String,
    username: String,
    password: String,
}

impl Http {
    fn new(config: &SyncConfig) -> Result<Self, SyncError> {
        let client = reqwest::Client::builder().build()?;
        Ok(Self {
            client,
            base: config.server.trim_end_matches('/').to_string(),
            username: config.username.clone(),
            password: config.password.clone(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn get(&self, path: &str) -> Result<(u16, Vec<u8>), SyncError> {
        let response = self
            .client
            .get(self.url(path))
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.bytes().await?.to_vec()))
    }

    async fn get_json(&self, path: &str) -> Result<(u16, Value), SyncError> {
        let (status, bytes) = self.get(path).await?;
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        Ok((status, value))
    }

    async fn delete(&self, path: &str) -> Result<u16, SyncError> {
        let response = self
            .client
            .delete(self.url(path))
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        Ok(response.status().as_u16())
    }

    async fn put_bytes(&self, path: &str, body: &[u8]) -> Result<u16, SyncError> {
        let response = self
            .client
            .put(self.url(path))
            .basic_auth(&self.username, Some(&self.password))
            .body(body.to_vec())
            .send()
            .await?;
        Ok(response.status().as_u16())
    }

    async fn put_json(&self, path: &str, value: &Value) -> Result<(u16, Value), SyncError> {
        let response = self
            .client
            .put(self.url(path))
            .basic_auth(&self.username, Some(&self.password))
            .json(value)
            .send()
            .await?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await?.to_vec();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        Ok((status, value))
    }
}

fn encode(value: &str) -> String {
    percent_encode(value)
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

struct RemoteFile {
    /// Absolute server path (`/docs/a.txt`).
    path: String,
    /// BLAKE3 manifest identity.
    content_id: String,
}

async fn remote_files(http: &Http) -> Result<BTreeMap<String, RemoteFile>, SyncError> {
    let mut remote = BTreeMap::new();
    let mut after = 0i64;
    loop {
        let path = format!("/api/sync/tree?after_id={after}&limit=1000");
        let (status, body) = http.get_json(&path).await?;
        if status != 200 {
            return Err(SyncError::Server { status, path });
        }
        let mut advanced = false;
        if let Some(entries) = body["entries"].as_array() {
            for entry in entries {
                if let Some(id) = entry["id"].as_i64()
                    && id > after
                {
                    after = id;
                    advanced = true;
                }
                if entry["kind"].as_str() != Some("file") {
                    continue;
                }
                let Some(server_path) = entry["path"].as_str() else {
                    continue;
                };
                let Some(content_id) = entry["content_id"].as_str() else {
                    continue;
                };
                let rel = server_path.trim_start_matches('/').to_string();
                remote.insert(
                    rel,
                    RemoteFile {
                        path: server_path.to_string(),
                        content_id: content_id.to_string(),
                    },
                );
            }
        }
        if !body["has_more"].as_bool().unwrap_or(false) || !advanced {
            break;
        }
    }
    Ok(remote)
}

async fn pull(
    http: &Http,
    config: &SyncConfig,
    state: &mut State,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let remote = remote_files(http).await?;

    for (rel, file) in &remote {
        let local = config.local_dir.join(rel);
        if let Some(known) = state.files.get(rel).cloned() {
            if known.content_id == file.content_id {
                if local.exists() {
                    continue;
                }
                // Synced before and gone locally: the user deleted it.
                // Mark a tombstone and let push propagate the deletion.
                if let Some(entry) = state.files.get_mut(rel) {
                    entry.deleted = true;
                }
                continue;
            }
            // The remote changed. If the local copy was modified since the
            // last sync, leave it alone: push will detect the conflict.
            let locally_modified = !known.deleted
                && match std::fs::metadata(&local) {
                    Ok(metadata) => {
                        metadata.len() != known.size || mtime_ns(&local)? != known.mtime_ns
                    }
                    Err(_) => false,
                };
            if locally_modified {
                continue;
            }
        }
        let manifest_path = format!("/api/files/manifest?path={}", encode(&file.path));
        let (status, manifest_value) = http.get_json(&manifest_path).await?;
        if status != 200 {
            // Raced with a delete; the next pass will clean up.
            continue;
        }
        let manifest: Manifest = serde_json::from_value(manifest_value)?;
        let mut data = Vec::with_capacity(manifest.size as usize);
        for chunk in &manifest.chunks {
            data.extend_from_slice(&chunk_bytes(http, config, &chunk.hash.to_hex()).await?);
        }
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = config
            .local_dir
            .join(".kolimi")
            .join(format!("pull-{}.tmp", std::process::id()));
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &local)?;
        state.files.insert(
            rel.clone(),
            StateFile {
                content_id: file.content_id.clone(),
                size: data.len() as u64,
                mtime_ns: mtime_ns(&local)?,
                deleted: false,
            },
        );
        report.pulled += 1;
    }

    // Remote deletions.
    let stale: Vec<String> = state
        .files
        .keys()
        .filter(|rel| !remote.contains_key(*rel))
        .cloned()
        .collect();
    for rel in stale {
        let local = config.local_dir.join(&rel);
        if local.exists() {
            std::fs::remove_file(&local)?;
        }
        state.files.remove(&rel);
        report.removed_local += 1;
    }
    Ok(())
}

async fn chunk_bytes(http: &Http, config: &SyncConfig, hash: &str) -> Result<Vec<u8>, SyncError> {
    let cached = config
        .local_dir
        .join(".kolimi")
        .join("chunks")
        .join(&hash[..2])
        .join(hash);
    if let Ok(bytes) = std::fs::read(&cached) {
        return Ok(bytes);
    }
    let path = format!("/api/chunks/{hash}");
    let (status, bytes) = http.get(&path).await?;
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    if let Some(parent) = cached.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cached, &bytes)?;
    Ok(bytes)
}

async fn push(
    http: &Http,
    config: &SyncConfig,
    state: &mut State,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let mut locals: Vec<String> = Vec::new();
    collect_files(&config.local_dir, &config.local_dir, &mut locals)?;
    locals.sort();

    // Create remote directories for every parent path first.
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for rel in &locals {
        let mut parts: Vec<&str> = rel.split('/').collect();
        parts.pop();
        let mut current = String::new();
        for part in parts {
            current.push('/');
            current.push_str(part);
            dirs.insert(current.clone());
        }
    }
    for dir in &dirs {
        mkcol(http, dir).await?;
    }

    for rel in locals {
        let local_path = config.local_dir.join(&rel);
        let metadata = std::fs::metadata(&local_path)?;
        let mtime = mtime_ns(&local_path)?;
        if let Some(known) = state.files.get(&rel)
            && known.size == metadata.len()
            && known.mtime_ns == mtime
        {
            continue;
        }
        let data = std::fs::read(&local_path)?;
        let manifest = Manifest::for_data(&data);
        let content_id = manifest.content_id().to_hex();
        for chunk in chunker::split(&data) {
            let path = format!("/api/chunks/{}", chunk.hash.to_hex());
            let status = http.put_bytes(&path, chunk.data).await?;
            if status != 201 && status != 204 {
                return Err(SyncError::Server { status, path });
            }
        }
        let remote_path = format!("/{rel}");
        let mut path = format!("/api/files?path={}", encode(&remote_path));
        if let Some(known) = state.files.get(&rel) {
            path.push_str(&format!("&if_content_id={}", known.content_id));
        }
        let (status, _) = http
            .put_json(&path, &serde_json::to_value(&manifest)?)
            .await?;
        match status {
            200 => {
                state.files.insert(
                    rel,
                    StateFile {
                        content_id,
                        size: metadata.len(),
                        mtime_ns: mtime,
                        deleted: false,
                    },
                );
                report.pushed += 1;
            }
            409 => {
                // Keep the server version; preserve local edits alongside.
                let conflict = conflict_path(&local_path);
                std::fs::rename(&local_path, &conflict)?;
                state.files.remove(&rel);
                report.conflicts += 1;
            }
            status => return Err(SyncError::Server { status, path }),
        }
    }

    // Local deletions propagate: any known file that is gone locally (and
    // was not already removed by pull) is deleted remotely.
    let deleted: Vec<String> = state
        .files
        .keys()
        .filter(|rel| !config.local_dir.join(rel.as_str()).exists())
        .cloned()
        .collect();
    for rel in deleted {
        let path = format!("/dav{}", encode_path(&format!("/{rel}")));
        let status = http.delete(&path).await?;
        if status != 204 && status != 404 {
            return Err(SyncError::Server { status, path });
        }
        state.files.remove(&rel);
        report.removed_remote += 1;
    }
    Ok(())
}

async fn mkcol(http: &Http, dir: &str) -> Result<(), SyncError> {
    let path = format!("/dav{}", encode_path(dir));
    let method = reqwest::Method::from_bytes(b"MKCOL").map_err(|error| SyncError::Server {
        status: 0,
        path: format!("{path} ({error})"),
    })?;
    let response = http
        .client
        .request(method, http.url(&path))
        .basic_auth(&http.username, Some(&http.password))
        .send()
        .await?;
    let status = response.status().as_u16();
    // 201 created, 405 already exists.
    if status != 201 && status != 405 {
        return Err(SyncError::Server { status, path });
    }
    Ok(())
}

fn conflict_path(local: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = local
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    local.with_file_name(format!("{name}.conflict-{stamp}"))
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), SyncError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".kolimi" {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, out)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| std::io::Error::other("path outside root"))?
                .to_string_lossy()
                .to_string();
            out.push(rel);
        }
    }
    Ok(())
}

fn mtime_ns(path: &Path) -> Result<i64, SyncError> {
    let modified = std::fs::metadata(path)?.modified()?;
    Ok(modified
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as i64)
        .unwrap_or(0))
}
