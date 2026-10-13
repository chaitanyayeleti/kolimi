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
    Argon2Params, FileKey, Identity, Keyring, MasterKey, generate_recovery_code,
    recovery_code_parse,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Local directory mirroring files shared with this user.
pub const SHARED_MOUNT: &str = "Shared with me";

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
    /// The server returned an unexpected or malformed response.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// E2EE failure (missing keyring, wrong secret, mixed plaintext state).
    #[error("e2ee error: {0}")]
    E2ee(String),
    /// E2EE is configured but **locked**: no keyring exists yet, no usable
    /// unlock material is held locally, or the stored secret did not unlock
    /// it. This is a *state the user resolves* (enter the passphrase, use the
    /// recovery code, enroll the device), not a sync failure — clients should
    /// surface it as "locked", not as an error.
    #[error("e2ee locked: {0}")]
    Locked(String),
    /// Crypto primitive failure.
    #[error("crypto error: {0}")]
    Crypto(#[from] kolimi_crypto::CryptoError),
}

impl SyncError {
    /// Whether this is an E2EE **locked** state (user action needed) rather
    /// than a genuine failure.
    pub fn is_locked(&self) -> bool {
        matches!(self, SyncError::Locked(_))
    }
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
    /// True for files that live under `Shared with me/` (read-only here;
    /// push never uploads or deletes them).
    #[serde(default)]
    shared: bool,
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
    sync_once_rooted(config, "/").await
}

/// Like [`sync_once`], but scoped to a remote subfolder: `remote` is an
/// absolute server path (e.g. `/Documents`) that this local directory mirrors.
/// `"/"` mirrors the whole account (identical to [`sync_once`]).
pub async fn sync_once_rooted(config: &SyncConfig, remote: &str) -> Result<SyncReport, SyncError> {
    let root = remote_prefix(remote);
    let http = Http::new(config)?;
    std::fs::create_dir_all(config.local_dir.join(".kolimi"))?;
    let mut state = State::load(&config.local_dir)?;
    let e2ee = unlock_e2ee(&http, config).await?;
    let mut report = SyncReport::default();
    pull(&http, config, &root, e2ee.as_ref(), &mut state, &mut report).await?;
    push(&http, config, &root, e2ee.as_ref(), &mut state, &mut report).await?;
    if report.conflicts > 0 {
        // Fetch the winning server versions for the conflicted paths.
        pull(&http, config, &root, e2ee.as_ref(), &mut state, &mut report).await?;
    }
    state.save(&config.local_dir)?;
    Ok(report)
}

/// Normalize a remote root: `"/"` or empty -> `""` (account root); otherwise
/// `"/prefix"` without a trailing slash.
fn remote_prefix(remote: &str) -> String {
    let trimmed = remote.trim().trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("/{trimmed}")
    }
}

/// The path of `server_path` relative to `root`, or `None` when it is not
/// under `root` (or is the root itself).
fn relative_to_root(server_path: &str, root: &str) -> Option<String> {
    if root.is_empty() {
        return Some(server_path.trim_start_matches('/').to_string());
    }
    let rest = server_path.strip_prefix(root)?;
    let rel = rest.strip_prefix('/')?;
    Some(rel.to_string())
}

/// Unlocked E2EE session state.
struct E2ee {
    master: MasterKey,
    identity: Identity,
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
            return Err(SyncError::Locked(
                "no keyring on the server yet; set up encryption first".to_string(),
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
            .map_err(|_| SyncError::Locked("wrong encryption passphrase".to_string()))?
    } else if let Some(code) = &options.recovery_code {
        let code = recovery_code_parse(code)?;
        keyring
            .unlock_with_recovery(&code)
            .map_err(|_| SyncError::Locked("wrong recovery code".to_string()))?
    } else if let Some(prf) = &options.prf_secret {
        let prf: [u8; 32] = prf
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::E2ee("PRF secret must be exactly 32 bytes".to_string()))?;
        keyring
            .unlock_with_prf(&prf)
            .map_err(|_| SyncError::Locked("passkey does not unlock the keyring".to_string()))?
    } else if let Some(device) = load_device_file(&config.local_dir)? {
        // Enrolled device: unlock the master key from the local device file.
        let secret = hex_decode(&device.device_secret)?;
        let secret: [u8; 32] = secret
            .try_into()
            .map_err(|_| SyncError::E2ee("device key must be 32 bytes".to_string()))?;
        let wrapped = STANDARD
            .decode(&device.wrapped_master_key)
            .map_err(|error| SyncError::E2ee(format!("device key: {error}")))?;
        MasterKey::from_bytes(kolimi_crypto::unwrap_secret(&secret, &wrapped)?)
    } else {
        return Err(SyncError::Locked(
            "enter your encryption passphrase to unlock these folders".to_string(),
        ));
    };
    let identity = ensure_identity(http, &master).await?;
    Ok(Some(E2ee {
        master,
        identity,
        options: options.clone(),
    }))
}

/// Loads the user's X25519 identity, creating and publishing one on first
/// use (the private key is wrapped under the master key).
async fn ensure_identity(http: &Http, master: &MasterKey) -> Result<Identity, SyncError> {
    let (status, body) = http.get_json("/api/e2ee/identity").await?;
    match status {
        200 => {
            let wrapped = STANDARD
                .decode(body["wrapped_private"].as_str().unwrap_or_default())
                .map_err(|error| SyncError::E2ee(format!("identity: {error}")))?;
            Ok(master.unwrap_identity(&wrapped)?)
        }
        404 => {
            let identity = Identity::generate()?;
            let wrapped = master.wrap_identity(&identity)?;
            let payload = serde_json::json!({
                "public_key": STANDARD.encode(identity.public_key()),
                "wrapped_private": STANDARD.encode(&wrapped),
            });
            let (status, _) = http.put_json("/api/e2ee/identity", &payload).await?;
            if status != 204 {
                return Err(SyncError::Server {
                    status,
                    path: "/api/e2ee/identity".to_string(),
                });
            }
            Ok(identity)
        }
        status => Err(SyncError::Server {
            status,
            path: "/api/e2ee/identity".to_string(),
        }),
    }
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

/// Who a share targets.
#[derive(Debug, Clone)]
pub enum ShareTarget {
    /// A single user.
    User(String),
    /// Every member of a group (keys wrapped per member).
    Group(String),
}

impl ShareTarget {
    /// `"user"` or `"group"`.
    pub fn kind(&self) -> &'static str {
        match self {
            ShareTarget::User(_) => "user",
            ShareTarget::Group(_) => "group",
        }
    }

    /// The recipient name.
    pub fn name(&self) -> &str {
        match self {
            ShareTarget::User(name) | ShareTarget::Group(name) => name,
        }
    }
}

/// Shares a path with one user, wrapping encrypted file keys for them.
pub async fn share_file(
    config: &SyncConfig,
    rel_path: &str,
    recipient: &str,
) -> Result<u64, SyncError> {
    share_path(config, rel_path, ShareTarget::User(recipient.to_string())).await
}

/// Shares a path with a group, wrapping encrypted file keys for every
/// member (per-member X25519 wrapping; not MLS — see RFC 0007).
pub async fn share_file_to_group(
    config: &SyncConfig,
    rel_path: &str,
    group: &str,
) -> Result<u64, SyncError> {
    share_path(config, rel_path, ShareTarget::Group(group.to_string())).await
}

/// Shares a path with a user or group. Returns how many key wraps were
/// uploaded. Plaintext files are shared through the normal ACL path and
/// need no keys.
pub async fn share_path(
    config: &SyncConfig,
    rel_path: &str,
    target: ShareTarget,
) -> Result<u64, SyncError> {
    let http = Http::new(config)?;
    let Some(e2ee) = unlock_e2ee(&http, config).await? else {
        return Err(SyncError::E2ee(
            "sharing encrypted files requires e2ee options".to_string(),
        ));
    };
    let rel_path = rel_path.trim_start_matches('/');
    let server_path = format!("/{rel_path}");

    // Resolve the recipients (group members, minus ourselves).
    let members: Vec<String> = match &target {
        ShareTarget::User(name) => vec![name.clone()],
        ShareTarget::Group(name) => {
            let path = format!("/api/groups/{}/members", encode(name));
            let (status, body) = http.get_json(&path).await?;
            if status == 403 {
                return Err(SyncError::E2ee(format!(
                    "you must be a member of group {name} to share encrypted files with it"
                )));
            }
            if status != 200 {
                return Err(SyncError::E2ee(format!("no such group: {name}")));
            }
            body["members"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .filter_map(|value| value.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        }
    };
    let mut recipients: Vec<(String, [u8; 32])> = Vec::new();
    for member in members {
        if member == config.username {
            continue;
        }
        let path = format!("/api/e2ee/identity/{}", encode(&member));
        let (status, body) = http.get_json(&path).await?;
        if status != 200 {
            return Err(SyncError::E2ee(format!(
                "{member} has no E2EE identity (they must unlock E2EE once first)"
            )));
        }
        let public_key: [u8; 32] = STANDARD
            .decode(body["public_key"].as_str().unwrap_or_default())
            .map_err(|error| SyncError::E2ee(format!("{member} key: {error}")))?
            .try_into()
            .map_err(|_| SyncError::E2ee(format!("{member} key must be 32 bytes")))?;
        recipients.push((member, public_key));
    }
    if recipients.is_empty() {
        return Err(SyncError::E2ee(
            "no recipients with an E2EE identity".to_string(),
        ));
    }

    let (status, _) = http
        .post_json(
            "/api/shares",
            &serde_json::json!({
                "path": server_path,
                "kind": target.kind(),
                "recipient": target.name(),
                "permission": "read",
            }),
        )
        .await?;
    if status != 201 && status != 409 {
        return Err(SyncError::Server {
            status,
            path: "/api/shares".to_string(),
        });
    }

    let local_root = config.local_dir.join(rel_path);
    let mut files = Vec::new();
    if local_root.is_file() {
        files.push(rel_path.to_string());
    } else if local_root.is_dir() {
        collect_files(&config.local_dir, &local_root, &mut files)?;
    } else {
        return Err(SyncError::E2ee(format!(
            "{rel_path} does not exist locally"
        )));
    }

    let mut wrapped_count = 0u64;
    for rel in files {
        let key_path = format!("/api/files/key?path={}", encode(&format!("/{rel}")));
        let (status, body) = http.get_json(&key_path).await?;
        if status == 404 {
            continue; // plaintext file
        }
        if status != 200 {
            return Err(SyncError::Server {
                status,
                path: key_path,
            });
        }
        let wrapped = STANDARD
            .decode(body["wrapped_key"].as_str().unwrap_or_default())
            .map_err(|error| SyncError::E2ee(format!("file key: {error}")))?;
        let file_key = e2ee.master.unwrap_file_key(&wrapped)?;
        for (member, public_key) in &recipients {
            let share_key = e2ee.identity.wrap_file_key_for(public_key, &file_key)?;
            let path = format!(
                "/api/e2ee/share-key?path={}&recipient={}",
                encode(&format!("/{rel}")),
                encode(member)
            );
            let status = http.put_bytes(&path, &share_key).await?;
            if status != 204 {
                return Err(SyncError::Server { status, path });
            }
            wrapped_count += 1;
        }
    }
    Ok(wrapped_count)
}

/// Revokes a user share of `rel_path` (the server also drops the
/// recipient's wrapped keys).
pub async fn unshare_file(
    config: &SyncConfig,
    rel_path: &str,
    recipient: &str,
) -> Result<(), SyncError> {
    unshare_path(config, rel_path, ShareTarget::User(recipient.to_string())).await
}

/// Revokes a share of `rel_path` from a user or group.
pub async fn unshare_path(
    config: &SyncConfig,
    rel_path: &str,
    target: ShareTarget,
) -> Result<(), SyncError> {
    let http = Http::new(config)?;
    let server_path = format!("/{}", rel_path.trim_start_matches('/'));
    let list_path = format!("/api/shares?path={}", encode(&server_path));
    let (status, body) = http.get_json(&list_path).await?;
    if status != 200 {
        return Err(SyncError::Server {
            status,
            path: list_path,
        });
    }
    let share_id = body["shares"]
        .as_array()
        .and_then(|shares| {
            shares.iter().find(|share| {
                share["kind"] == target.kind() && share["recipient"].as_str() == Some(target.name())
            })
        })
        .and_then(|share| share["id"].as_i64());
    let Some(share_id) = share_id else {
        return Err(SyncError::E2ee(format!(
            "no share of {server_path} with {} {}",
            target.kind(),
            target.name()
        )));
    };
    let path = format!("/api/shares/{share_id}");
    let status = http.delete(&path).await?;
    if status != 204 {
        return Err(SyncError::Server { status, path });
    }
    Ok(())
}

/// Publishes this user's X25519 identity, creating it on first use.
///
/// Part of E2EE setup: after this, other users can wrap file keys for
/// this account. Requires unlocked E2EE options (passphrase/recovery).
pub async fn publish_identity(config: &SyncConfig) -> Result<(), SyncError> {
    let http = Http::new(config)?;
    if unlock_e2ee(&http, config).await?.is_none() {
        return Err(SyncError::E2ee(
            "identity setup requires e2ee options".to_string(),
        ));
    }
    Ok(())
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

/// Device-enrollment file stored under `.kolimi/device.json` (RFC 0008).
///
/// Note: this holds the device key **and** the wrapped master key, so the
/// file is equivalent to the master key at rest; it is written `0600` and
/// is intended to be replaced by an OS keystore / passkey-PRF wrap in the
/// desktop shell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFile {
    /// Label of this device.
    pub name: String,
    /// X25519 private key (hex).
    pub device_secret: String,
    /// Master key wrapped for this device (base64).
    pub wrapped_master_key: String,
    /// This device's X25519 public key (base64).
    pub device_public_key: String,
}

fn device_file_path(local: &Path) -> PathBuf {
    local.join(".kolimi").join("device.json")
}

fn load_device_file(local: &Path) -> Result<Option<DeviceFile>, SyncError> {
    match std::fs::read(device_file_path(local)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_device_file(local: &Path, file: &DeviceFile) -> Result<(), SyncError> {
    let dir = local.join(".kolimi");
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join("device.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(file)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, device_file_path(local))?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(text: &str) -> Result<Vec<u8>, SyncError> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(SyncError::E2ee("hex length must be even".to_string()));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| SyncError::E2ee("invalid hex digits".to_string()))
        })
        .collect()
}

/// Enrolls this device (RFC 0008): creates an enrollment, waits for an
/// unlocked device to approve it, unwraps the master key, and writes
/// `.kolimi/device.json`. Returns the enrollment id.
pub async fn enroll_device(config: &SyncConfig, device_name: &str) -> Result<i64, SyncError> {
    let http = Http::new(config)?;
    let device = Identity::generate()?;
    let (status, body) = http
        .post_json(
            "/api/e2ee/enrollments",
            &serde_json::json!({
                "device_name": device_name,
                "device_public_key": STANDARD.encode(device.public_key()),
            }),
        )
        .await?;
    if status != 200 {
        return Err(SyncError::Server {
            status,
            path: "/api/e2ee/enrollments".to_string(),
        });
    }
    let id = body["id"]
        .as_i64()
        .ok_or_else(|| SyncError::E2ee("malformed enrollment response".to_string()))?;

    // Wait for an unlocked device to approve (up to five minutes).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let wrapped = loop {
        let path = format!("/api/e2ee/enrollments/{id}");
        let (status, body) = http.get_json(&path).await?;
        if status != 200 {
            return Err(SyncError::Server { status, path });
        }
        if body["approved"].as_bool() == Some(true) {
            let wrapped = body["wrapped_master_key"].as_str().unwrap_or_default();
            break STANDARD
                .decode(wrapped)
                .map_err(|error| SyncError::E2ee(format!("wrapped key: {error}")))?;
        }
        if std::time::Instant::now() > deadline {
            return Err(SyncError::E2ee(
                "enrollment was not approved in time".to_string(),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };

    // Verify the wrap opens with our key before persisting anything; keep
    // the unwrapped master key zeroized on drop.
    let _master: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
        kolimi_crypto::unwrap_secret(&device.private_bytes(), &wrapped)?,
    );

    write_device_file(
        &config.local_dir,
        &DeviceFile {
            name: device_name.to_string(),
            device_secret: hex_encode(&device.private_bytes()),
            wrapped_master_key: STANDARD.encode(&wrapped),
            device_public_key: STANDARD.encode(device.public_key()),
        },
    )?;
    Ok(id)
}

/// Approves a pending enrollment by wrapping this (unlocked) device's master
/// key for the new device. Returns the new device's name.
pub async fn approve_device(config: &SyncConfig, id: i64) -> Result<String, SyncError> {
    let http = Http::new(config)?;
    let e2ee = unlock_e2ee(&http, config).await?.ok_or_else(|| {
        SyncError::E2ee(
            "approving needs an unlock secret (passphrase, recovery code or PRF)".into(),
        )
    })?;

    let path = format!("/api/e2ee/enrollments/{id}");
    let (status, body) = http.get_json(&path).await?;
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    let name = body["device_name"].as_str().unwrap_or_default().to_string();
    let public = STANDARD
        .decode(body["device_public_key"].as_str().unwrap_or_default())
        .map_err(|error| SyncError::E2ee(format!("device public key: {error}")))?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| SyncError::E2ee("device public key must be 32 bytes".to_string()))?;
    let wrapped = kolimi_crypto::wrap_secret_for(&public, e2ee.master.as_bytes())?;

    let approve = format!("/api/e2ee/enrollments/{id}/approve");
    let (status, _) = http
        .post_json(
            &approve,
            &serde_json::json!({ "wrapped_master_key": STANDARD.encode(&wrapped) }),
        )
        .await?;
    if status != 204 {
        return Err(SyncError::Server {
            status,
            path: approve,
        });
    }
    Ok(name)
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

    async fn post_json(&self, path: &str, value: &Value) -> Result<(u16, Value), SyncError> {
        let response = self
            .client
            .post(self.url(path))
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
    /// True for entries under `Shared with me/`.
    shared: bool,
}

async fn remote_files(http: &Http, root: &str) -> Result<BTreeMap<String, RemoteFile>, SyncError> {
    let mut remote = BTreeMap::new();
    let mut after = 0i64;
    loop {
        let path = format!("/api/sync/tree?after_id={after}&limit=1000");
        let (status, body) = http.get_json(&path).await?;
        if status != 200 {
            return Err(SyncError::Server { status, path });
        }
        // A malformed/absent `entries` array must never be read as "the
        // server has no files" — that would make the caller delete every
        // locally tracked file.
        let Some(entries) = body["entries"].as_array() else {
            return Err(SyncError::Protocol(format!(
                "sync tree response for {path} has no 'entries' array"
            )));
        };
        let mut advanced = false;
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
            let Some(rel) = relative_to_root(server_path, root) else {
                continue;
            };
            remote.insert(
                rel,
                RemoteFile {
                    path: server_path.to_string(),
                    content_id: content_id.to_string(),
                    encrypted: entry["encrypted"].as_bool().unwrap_or(true),
                    shared: false,
                },
            );
        }
        if !body["has_more"].as_bool().unwrap_or(false) || !advanced {
            break;
        }
    }

    // Files shared with the user (read-only mirror under `Shared with me/`).
    let (status, body) = http.get_json("/api/sync/shared-tree").await?;
    if status != 200 {
        return Err(SyncError::Server {
            status,
            path: "/api/sync/shared-tree".to_string(),
        });
    }
    let Some(entries) = body["entries"].as_array() else {
        return Err(SyncError::Protocol(
            "shared-tree response has no 'entries' array".to_string(),
        ));
    };
    for entry in entries {
        let Some(server_path) = entry["path"].as_str() else {
            continue;
        };
        let Some(content_id) = entry["content_id"].as_str() else {
            continue;
        };
        let Some(rel) = relative_to_root(server_path, root) else {
            continue;
        };
        remote.insert(
            rel,
            RemoteFile {
                path: server_path.to_string(),
                content_id: content_id.to_string(),
                encrypted: entry["encrypted"].as_bool().unwrap_or(true),
                shared: true,
            },
        );
    }
    Ok(remote)
}

async fn pull(
    http: &Http,
    config: &SyncConfig,
    root: &str,
    e2ee: Option<&E2ee>,
    state: &mut State,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let remote = remote_files(http, root).await?;

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
            // Shared files are encrypted by their owner; local roots only
            // govern which of *our* files we encrypt.
            if !file.shared && !e2ee.options.covers(rel) {
                return Err(SyncError::E2ee(format!(
                    "remote file /{rel} is encrypted but not under a configured e2ee root"
                )));
            }
            if file.shared {
                Some(load_shared_file_key(http, e2ee, &file.path).await?)
            } else {
                Some(load_file_key(http, state, e2ee, rel).await?)
            }
        } else {
            None
        };
        let mut data = Vec::with_capacity(manifest.size as usize);
        let chunk_context = file.shared.then_some(file.path.as_str());
        for chunk in &manifest.chunks {
            let bytes = chunk_bytes(http, config, &chunk.hash.to_hex(), chunk_context).await?;
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
                shared: file.shared,
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
/// Fetches and unwraps the share key for a file shared with this user.
async fn load_shared_file_key(
    http: &Http,
    e2ee: &E2ee,
    server_path: &str,
) -> Result<FileKey, SyncError> {
    let path = format!("/api/e2ee/share-key?path={}", encode(server_path));
    let (status, body) = http.get_json(&path).await?;
    if status != 200 {
        return Err(SyncError::E2ee(format!(
            "no share key for {server_path}; ask the owner to re-share it"
        )));
    }
    let wrapped = STANDARD
        .decode(body["wrapped_key"].as_str().unwrap_or_default())
        .map_err(|error| SyncError::E2ee(format!("share key: {error}")))?;
    Ok(e2ee.identity.unwrap_file_key(&wrapped)?)
}

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

async fn chunk_bytes(
    http: &Http,
    config: &SyncConfig,
    hash: &str,
    context: Option<&str>,
) -> Result<Vec<u8>, SyncError> {
    let cached = config
        .local_dir
        .join(".kolimi")
        .join("chunks")
        .join(&hash[..2])
        .join(hash);
    if let Ok(bytes) = std::fs::read(&cached) {
        return Ok(bytes);
    }
    let path = match context {
        Some(context) => format!("/api/chunks/{hash}?path={}", encode(context)),
        None => format!("/api/chunks/{hash}"),
    };
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
    root: &str,
    e2ee: Option<&E2ee>,
    state: &mut State,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let mut locals: Vec<String> = Vec::new();
    collect_files(&config.local_dir, &config.local_dir, &mut locals)?;
    locals.sort();

    // Create remote directories for every parent path first.
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    if !root.is_empty() {
        dirs.insert(root.to_string());
    }
    for rel in &locals {
        let mut parts: Vec<&str> = rel.split('/').collect();
        parts.pop();
        let mut current = String::new();
        for part in parts {
            current.push('/');
            current.push_str(part);
            dirs.insert(format!("{root}{current}"));
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
        let remote_path = format!("{root}/{rel}");
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
                        shared: false,
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
        .iter()
        .filter(|(rel, known)| !known.shared && !config.local_dir.join(rel.as_str()).exists())
        .map(|(rel, _)| rel.clone())
        .collect();
    for rel in deleted {
        let path = format!("/dav{}", encode_path(&format!("{root}/{rel}")));
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

/// Whether `name` looks like a preserved conflict copy (`*.conflict-<unix>`).
fn is_conflict_name(name: &str) -> bool {
    match name.rsplit_once(".conflict-") {
        Some((_, stamp)) => !stamp.is_empty() && stamp.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
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
        // Preserved conflict copies are local-only; never push them back.
        if is_conflict_name(&name) {
            continue;
        }
        // Shared files are read-only mirrors of someone else's tree.
        if name == SHARED_MOUNT && dir == root {
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

#[cfg(test)]
mod root_tests {
    use super::{SyncError, relative_to_root, remote_prefix};

    #[test]
    fn locked_is_distinct_from_e2ee_error() {
        assert!(SyncError::Locked("enter passphrase".into()).is_locked());
        assert!(!SyncError::E2ee("mixed plaintext".into()).is_locked());
        assert!(!SyncError::Protocol("bad response".into()).is_locked());
    }

    #[test]
    fn prefix_normalization() {
        assert_eq!(remote_prefix("/"), "");
        assert_eq!(remote_prefix(""), "");
        assert_eq!(remote_prefix("Documents"), "/Documents");
        assert_eq!(remote_prefix("/Documents/"), "/Documents");
        assert_eq!(remote_prefix("/a/b/"), "/a/b");
    }

    #[test]
    fn relative_paths() {
        // Account root: strip the leading slash only.
        assert_eq!(
            relative_to_root("/docs/a.txt", "").as_deref(),
            Some("docs/a.txt")
        );
        // Scoped root: strip the prefix and its separator.
        assert_eq!(
            relative_to_root("/Docs/a.txt", "/Docs").as_deref(),
            Some("a.txt")
        );
        assert_eq!(
            relative_to_root("/Docs/sub/a.txt", "/Docs").as_deref(),
            Some("sub/a.txt")
        );
        // The root itself is not a file.
        assert_eq!(relative_to_root("/Docs", "/Docs"), None);
        // Sibling with a shared prefix must not match.
        assert_eq!(relative_to_root("/Docsx/a.txt", "/Docs"), None);
        // Unrelated path is excluded.
        assert_eq!(relative_to_root("/Other/a.txt", "/Docs"), None);
    }
}
