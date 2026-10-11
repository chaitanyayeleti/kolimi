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

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_chunk::{ChunkRef, Manifest, chunker};
use kolimi_crypto::{
    Argon2Params, FileKey, Keyring, MasterKey, generate_recovery_code, recovery_code_parse,
};
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
    /// End-to-end encryption settings (RFC 0007); `None` syncs plaintext.
    pub e2ee: Option<E2eeOptions>,
}

/// E2EE settings for a sync root.
#[derive(Debug, Clone)]
pub struct E2eeOptions {
    /// Passphrase used to unlock the master key.
    pub passphrase: Option<String>,
    /// Recovery code (alternative unlock path).
    pub recovery_code: Option<String>,
    /// WebAuthn PRF output (32 bytes) for passkey unlock; platform shells
    /// obtain it from the authenticator and pass it here (RFC 0007).
    pub prf_secret: Option<Vec<u8>>,
    /// Relative paths whose files are encrypted end-to-end.
    pub encrypted_roots: Vec<String>,
}

impl E2eeOptions {
    /// Whether `rel` (a relative path) is covered by an encrypted root.
    pub fn covers(&self, rel: &str) -> bool {
        self.encrypted_roots.iter().any(|root| {
            let root = root.trim_matches('/');
            rel == root || rel.starts_with(&format!("{root}/"))
        })
    }
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
    /// E2EE failure (missing keyring, wrong secret, mixed plaintext state).
    #[error("e2ee error: {0}")]
    E2ee(String),
    /// Crypto primitive failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] kolimi_crypto::CryptoError),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    files: BTreeMap<String, StateFile>,
    /// Wrapped file keys by relative path (base64), cached from the server.
    #[serde(default)]
    keys: BTreeMap<String, String>,
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
    let e2ee = unlock_e2ee(&http, config).await?;
    let mut report = SyncReport::default();
    pull(&http, config, e2ee.as_ref(), &mut state, &mut report).await?;
    push(&http, config, e2ee.as_ref(), &mut state, &mut report).await?;
    if report.conflicts > 0 {
        // Fetch the winning server versions for the conflicted paths.
        pull(&http, config, e2ee.as_ref(), &mut state, &mut report).await?;
    }
    state.save(&config.local_dir)?;
    Ok(report)
}

/// Unlocked E2EE session state.
struct E2ee {
    master: MasterKey,
    options: E2eeOptions,
}

async fn unlock_e2ee(http: &Http, config: &SyncConfig) -> Result<Option<E2ee>, SyncError> {
    let Some(options) = &config.e2ee else {
        return Ok(None);
    };
    let (status, body) = http.get_json("/api/e2ee/keyring").await?;
    match status {
        200 => {}
        404 => {
            return Err(SyncError::E2ee(
                "no keyring on the server; run `kolimi-sync --e2ee-setup` first".to_string(),
            ));
        }
        status => {
            return Err(SyncError::Server {
                status,
                path: "/api/e2ee/keyring".to_string(),
            });
        }
    }
    let keyring_json = body["keyring"]
        .as_str()
        .ok_or_else(|| SyncError::E2ee("malformed keyring response".to_string()))?;
    let keyring = Keyring::from_json(keyring_json)?;
    let master = if let Some(passphrase) = &options.passphrase {
        keyring
            .unlock_with_passphrase(passphrase)
            .map_err(|_| SyncError::E2ee("wrong passphrase".to_string()))?
    } else if let Some(code) = &options.recovery_code {
        let code = recovery_code_parse(code)?;
        keyring
            .unlock_with_recovery(&code)
            .map_err(|_| SyncError::E2ee("wrong recovery code".to_string()))?
    } else if let Some(prf) = &options.prf_secret {
        let prf: [u8; 32] = prf
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::E2ee("PRF secret must be exactly 32 bytes".to_string()))?;
        keyring
            .unlock_with_prf(&prf)
            .map_err(|_| SyncError::E2ee("PRF secret does not unlock the keyring".to_string()))?
    } else {
        return Err(SyncError::E2ee(
            "e2ee roots are configured but neither a passphrase nor a recovery code was given"
                .to_string(),
        ));
    };
    Ok(Some(E2ee {
        master,
        options: options.clone(),
    }))
}

/// Creates a keyring (setup side); returns it plus the recovery code.
pub fn create_keyring(passphrase: &str) -> Result<(Keyring, [u8; 32]), SyncError> {
    create_keyring_with_params(passphrase, &Argon2Params::default())
}

/// Creates a keyring with explicit Argon2id parameters (tests).
pub fn create_keyring_with_params(
    passphrase: &str,
    params: &Argon2Params,
) -> Result<(Keyring, [u8; 32]), SyncError> {
    let master = MasterKey::generate()?;
    let recovery = generate_recovery_code()?;
    let keyring = Keyring::create(&master, passphrase, params, &recovery)?;
    Ok((keyring, recovery))
}

/// Uploads a keyring to the server (setup side).
pub async fn upload_keyring(config: &SyncConfig, keyring: &Keyring) -> Result<(), SyncError> {
    let http = Http::new(config)?;
    let path = "/api/e2ee/keyring";
    let status = http.put_bytes(path, keyring.to_json()?.as_bytes()).await?;
    if status != 204 {
        return Err(SyncError::Server {
            status,
            path: path.to_string(),
        });
    }
    Ok(())
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
    /// Whether the server holds this file encrypted (RFC 0007).
    encrypted: bool,
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
                        encrypted: entry["encrypted"].as_bool().unwrap_or(false),
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
    e2ee: Option<&E2ee>,
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
        let file_key = if file.encrypted {
            let Some(e2ee) = e2ee else {
                return Err(SyncError::E2ee(format!(
                    "remote file /{rel} is encrypted but no e2ee roots are configured"
                )));
            };
            if !e2ee.options.covers(rel) {
                return Err(SyncError::E2ee(format!(
                    "remote file /{rel} is encrypted but not under a configured e2ee root"
                )));
            }
            Some(load_file_key(http, state, e2ee, rel).await?)
        } else {
            None
        };
        let mut data = Vec::with_capacity(manifest.size as usize);
        for chunk in &manifest.chunks {
            let bytes = chunk_bytes(http, config, &chunk.hash.to_hex()).await?;
            match &file_key {
                Some(key) => data.extend_from_slice(&key.decrypt_chunk(&bytes)?),
                None => data.extend_from_slice(&bytes),
            }
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
        state.keys.remove(&rel);
        report.removed_local += 1;
    }
    Ok(())
}

async fn load_file_key(
    http: &Http,
    state: &mut State,
    e2ee: &E2ee,
    rel: &str,
) -> Result<FileKey, SyncError> {
    if let Some(cached) = state.keys.get(rel) {
        let wrapped = STANDARD
            .decode(cached)
            .map_err(|error| SyncError::E2ee(format!("cached key: {error}")))?;
        return Ok(e2ee.master.unwrap_file_key(&wrapped)?);
    }
    let path = format!("/api/files/key?path={}", encode(&format!("/{rel}")));
    let (status, body) = http.get_json(&path).await?;
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    let encoded = body["wrapped_key"]
        .as_str()
        .ok_or_else(|| SyncError::E2ee("malformed file key response".to_string()))?;
    let wrapped = STANDARD
        .decode(encoded)
        .map_err(|error| SyncError::E2ee(format!("file key: {error}")))?;
    let file_key = e2ee.master.unwrap_file_key(&wrapped)?;
    state.keys.insert(rel.to_string(), encoded.to_string());
    Ok(file_key)
}

/// Loads an existing file key or generates one for a new encrypted file.
///
/// Returns the key plus, for new files, the wrapped blob to upload after
/// the manifest commit has created the node (the server stores keys per
/// node, so the node must exist first).
async fn fetch_or_create_file_key(
    http: &Http,
    state: &mut State,
    e2ee: &E2ee,
    rel: &str,
) -> Result<(FileKey, Option<Vec<u8>>), SyncError> {
    if let Some(cached) = state.keys.get(rel) {
        let wrapped = STANDARD
            .decode(cached)
            .map_err(|error| SyncError::E2ee(format!("cached key: {error}")))?;
        return Ok((e2ee.master.unwrap_file_key(&wrapped)?, None));
    }
    let path = format!("/api/files/key?path={}", encode(&format!("/{rel}")));
    let (status, body) = http.get_json(&path).await?;
    match status {
        200 => {
            let encoded = body["wrapped_key"]
                .as_str()
                .ok_or_else(|| SyncError::E2ee("malformed file key response".to_string()))?;
            let wrapped = STANDARD
                .decode(encoded)
                .map_err(|error| SyncError::E2ee(format!("file key: {error}")))?;
            let file_key = e2ee.master.unwrap_file_key(&wrapped)?;
            state.keys.insert(rel.to_string(), encoded.to_string());
            Ok((file_key, None))
        }
        404 => {
            let file_key = FileKey::generate()?;
            let wrapped = e2ee.master.wrap_file_key(&file_key)?;
            Ok((file_key, Some(wrapped)))
        }
        status => Err(SyncError::Server { status, path }),
    }
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
    e2ee: Option<&E2ee>,
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
        let mut pending_key: Option<Vec<u8>> = None;
        let manifest = if let Some(e2ee) = e2ee.filter(|e2ee| e2ee.options.covers(&rel)) {
            // Encrypt-then-chunk (RFC 0007): chunk boundaries follow the
            // plaintext so edits stay delta-friendly; the manifest hashes
            // ciphertext chunks.
            let (file_key, pending) = fetch_or_create_file_key(http, state, e2ee, &rel).await?;
            pending_key = pending;
            let mut chunks = Vec::new();
            let mut total = 0u64;
            for chunk in chunker::split(&data) {
                let ciphertext = file_key.encrypt_chunk(chunk.data)?;
                let hash = kolimi_chunk::Hash::of(&ciphertext);
                let path = format!("/api/chunks/{}", hash.to_hex());
                let status = http.put_bytes(&path, &ciphertext).await?;
                if status != 201 && status != 204 {
                    return Err(SyncError::Server { status, path });
                }
                total += ciphertext.len() as u64;
                chunks.push(ChunkRef {
                    hash,
                    len: ciphertext.len() as u32,
                });
            }
            Manifest {
                version: Manifest::VERSION,
                size: total,
                chunks,
            }
        } else {
            let manifest = Manifest::for_data(&data);
            for chunk in chunker::split(&data) {
                let path = format!("/api/chunks/{}", chunk.hash.to_hex());
                let status = http.put_bytes(&path, chunk.data).await?;
                if status != 201 && status != 204 {
                    return Err(SyncError::Server { status, path });
                }
            }
            manifest
        };
        let content_id = manifest.content_id().to_hex();
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
                if let Some(wrapped) = pending_key {
                    // The node now exists: store the wrapped file key so
                    // the server can flag the file as encrypted.
                    let key_path = format!("/api/files/key?path={}", encode(&remote_path));
                    let status = http.put_bytes(&key_path, &wrapped).await?;
                    if status != 204 {
                        return Err(SyncError::Server {
                            status,
                            path: key_path,
                        });
                    }
                    state.keys.insert(rel.clone(), STANDARD.encode(&wrapped));
                }
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
                state.keys.remove(&rel);
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
        state.keys.remove(&rel);
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
