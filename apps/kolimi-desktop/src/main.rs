//! Kolimi desktop client (phase 1, Option A: remote webview).
//!
//! A native window loads the server's `/app/` UI (the same Leptos app the
//! browser uses), with a tray icon and background sync alongside. Settings
//! live in `~/.config/kolimi/desktop.json` (or `$KOLIMI_DESKTOP_CONFIG`) and
//! support **multiple accounts**, each with **multiple sync directories**:
//!
//! ```json
//! {
//!   "version": 2,
//!   "autostart": false,
//!   "accounts": [
//!     {
//!       "server": "https://cloud.example.com",
//!       "username": "alice",
//!       "pairs": [{ "local_dir": "/home/alice/Kolimi", "remote": "/", "encrypted_roots": [] }]
//!     }
//!   ]
//! }
//! ```
//!
//! Accounts and directories are managed from the in-app **Accounts & Sync**
//! window (tray → Accounts & Sync): sign in/out, add/remove accounts, and
//! add/remove synced directories. Passwords live in the **OS keychain**
//! (Secret Service via zbus on Linux); if none is running they fall back to
//! the Linux **kernel session keyring** (`keyctl`, session-only, never on
//! disk), and only as a last resort to the `0600` file (warned).
//!
//! It syncs every five minutes and on demand, with a tray icon that reflects
//! idle/syncing/error and a desktop notification on failures and conflicts.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager, WebviewUrl, WebviewWindowBuilder,
    image::Image,
    menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
    webview::DownloadEvent,
};
use url::Url;

/// Background sync cadence. Kept short so remote changes land promptly;
/// opening the window also triggers a sync (see `open_main`).
const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the "close to tray" tip has been shown this session.
static CLOSE_TIP_SHOWN: AtomicBool = AtomicBool::new(false);

/// Whether the "encryption is locked" tip has been shown this session.
static LOCKED_TIP_SHOWN: AtomicBool = AtomicBool::new(false);

/// Script injected into the server webview. Adds a **Sync** status item to
/// the sidebar and an offline banner. The Rust sync loop publishes state via
/// `window.__kolimiDesktopSync`; this script never calls Tauri IPC, so the
/// remote server origin gets no extra capabilities. Clicking the item
/// navigates to a sentinel path that `on_navigation` intercepts.
const DESKTOP_INIT_JS: &str = r#"
(function () {
  if (window.__kolimiDesktop) return;
  window.__kolimiDesktop = true;

  var SENTINEL = '/__kolimi/open-settings';

  function statusData() {
    return window.__kolimiDesktopSync || null;
  }

  function badgeClass(state) {
    if (state === 'error') return 'badge danger';
    if (state === 'conflict' || state === 'locked' || state === 'paused' || state === 'syncing') {
      return 'badge warn';
    }
    if (state === 'no_account') return 'badge muted';
    return 'badge ok';
  }

  function relativeTime(ms) {
    if (!ms) return '';
    var seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (seconds < 45) return 'just now';
    if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
    return Math.round(seconds / 86400) + 'd ago';
  }

  function statusLabel(data) {
    if (!data) return 'idle';
    if (data.state === 'syncing') return 'syncing';
    if (data.state === 'paused') return 'paused';
    if (data.state === 'locked') return 'locked';
    if (data.state === 'error') return 'error';
    if (data.state === 'conflict') return 'conflicts';
    if (data.state === 'no_account') return 'set up';
    if (data.synced_at) return relativeTime(data.synced_at);
    return 'idle';
  }

  function makeStatus() {
    var button = document.createElement('button');
    button.id = 'kolimi-sync-status';
    button.type = 'button';
    button.className = 'nav-item kolimi-sync-status';
    button.title = 'Open Accounts & Sync';
    button.innerHTML =
      '<span class="icon" aria-hidden="true">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" ' +
      'stroke-linecap="round" stroke-linejoin="round">' +
      '<path d="M20 11a8 8 0 1 0-2.3 6.3"/><path d="M20 5v6h-6"/></svg></span>' +
      '<span>Sync</span><span class="kolimi-sync-state badge ok">idle</span>';
    button.addEventListener('click', function () {
      window.location.href = SENTINEL;
    });
    return button;
  }

  function ensureOfflineBanner() {
    var banner = document.getElementById('kolimi-offline-banner');
    if (banner) return banner;
    banner = document.createElement('div');
    banner.id = 'kolimi-offline-banner';
    banner.className = 'toast error';
    banner.setAttribute('role', 'alert');
    banner.style.position = 'fixed';
    banner.style.left = '1rem';
    banner.style.bottom = '1rem';
    banner.style.zIndex = '9999';
    banner.style.maxWidth = 'min(92vw, 28rem)';
    banner.innerHTML =
      '<span class="toast-msg">Server unreachable — changes will sync when it returns.</span>' +
      '<button type="button" class="icon-btn" aria-label="Retry">\u21BB</button>';
    banner.querySelector('button').addEventListener('click', function () {
      window.location.reload();
    });
    document.body.appendChild(banner);
    return banner;
  }

  function update() {
    if (!document.body) return;
    var data = statusData();
    var state = data && data.state ? data.state : 'idle';
    var button = document.getElementById('kolimi-sync-status');
    if (button) {
      var label = statusLabel(data);
      var badge = button.querySelector('.kolimi-sync-state');
      badge.textContent = label;
      badge.className = 'kolimi-sync-state ' + badgeClass(state);
      button.setAttribute(
        'aria-label',
        'Sync status: ' + label + '. Open Accounts & Sync.'
      );
      button.title = data && data.detail ? data.detail : 'Open Accounts & Sync';
    }
    var offline = (data && data.offline) || !navigator.onLine;
    if (offline) {
      ensureOfflineBanner();
    } else {
      var banner = document.getElementById('kolimi-offline-banner');
      if (banner) banner.remove();
    }
  }

  function place() {
    if (!document.body) return;
    var host = document.querySelector('.sidebar .nav');
    if (host && !document.getElementById('kolimi-sync-status')) {
      host.appendChild(makeStatus());
    }
    update();
  }

  window.addEventListener('offline', update);
  window.addEventListener('online', update);
  window.addEventListener('hashchange', place);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', place);
  } else {
    place();
  }
  setInterval(place, 1000);
})();
"#;

/// Sentinel path (blocked by `on_navigation`) that opens the settings window.
const SETTINGS_SENTINEL: &str = "/__kolimi/open-settings";

// ---------------------------------------------------------------------------
// Settings model (on disk)
// ---------------------------------------------------------------------------

/// Top-level settings. Secrets are *not* stored here (see the keychain).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    accounts: Vec<Account>,
    /// Launch in the background on login (XDG autostart entry).
    #[serde(default)]
    autostart: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: 2,
            accounts: Vec::new(),
            autostart: false,
        }
    }
}

fn default_version() -> u32 {
    2
}

/// A signed-in server account.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    server: String,
    username: String,
    #[serde(default)]
    pairs: Vec<SyncPair>,
    /// Automatically approve pending device enrollments when this machine
    /// is unlocked (default on). Turn off if you don't fully trust the
    /// server, and approve each device by comparing codes instead.
    #[serde(default = "default_true")]
    auto_approve_devices: bool,
}

fn default_true() -> bool {
    true
}

/// One local directory mirrored to a remote subpath.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncPair {
    local_dir: String,
    #[serde(default = "default_remote")]
    remote: String,
    #[serde(default)]
    encrypted_roots: Vec<String>,
    /// Opt in to MLS group shares (write-enabled encrypted shares).
    #[serde(default)]
    mls: bool,
    /// Last successful sync for this folder (Unix milliseconds).
    #[serde(default)]
    last_synced_at: Option<i64>,
}

fn default_remote() -> String {
    "/".to_string()
}

fn pair_sync_config(
    account: &Account,
    pair: &SyncPair,
    secrets: &Secrets,
) -> kolimi_sync::SyncConfig {
    kolimi_sync::SyncConfig {
        server: account.server.clone(),
        username: account.username.clone(),
        password: secrets.sync_password().to_string(),
        token: None,
        local_dir: PathBuf::from(&pair.local_dir),
        e2ee: (!pair.encrypted_roots.is_empty()).then(|| kolimi_sync::E2eeOptions {
            passphrase: secrets.e2ee_passphrase.clone(),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: pair.encrypted_roots.clone(),
            mls: pair.mls || std::env::var_os("KOLIMI_MLS_SHARES").is_some(),
        }),
    }
}

/// v1 on-disk shape: a single account + directory (migrated on load).
#[derive(Debug, Deserialize)]
struct V1Config {
    server: String,
    username: String,
    #[serde(default)]
    password: String,
    local_dir: String,
    #[serde(default)]
    encrypted_roots: Vec<String>,
    #[serde(default)]
    e2ee_passphrase: Option<String>,
    #[serde(default)]
    autostart: bool,
}

// ---------------------------------------------------------------------------
// Secrets (OS keychain, keyed by user@server)
// ---------------------------------------------------------------------------

/// Secrets kept in the OS keychain.
#[derive(Serialize, Deserialize)]
struct Secrets {
    /// Empty when the account is signed out but the E2EE passphrase is kept.
    #[serde(default)]
    password: String,
    #[serde(default)]
    e2ee_passphrase: Option<String>,
    /// Long-lived per-device app password used for background sync.
    #[serde(default)]
    app_password: Option<String>,
}

impl Secrets {
    fn signed_in(&self) -> bool {
        !self.password.is_empty() || self.app_password.is_some()
    }

    fn sync_password(&self) -> &str {
        self.app_password.as_deref().unwrap_or(&self.password)
    }
}

/// Keychain service name for secret entries.
const KEYRING_SERVICE: &str = "kolimi-desktop";

/// Keychain account key for an account.
fn account_key(server: &str, username: &str) -> String {
    format!("{username}@{server}")
}

/// Read stored secrets: OS keychain first, then the session keyring.
fn keyring_get(key: &str) -> Option<Secrets> {
    let raw = secret_service_get(key).or_else(|| session_get(key))?;
    serde_json::from_str(&raw).ok()
}

/// Store secrets: OS keychain, else session keyring, else the file.
fn store_secrets(key: &str, secrets: &Secrets) -> SecretStorage {
    let Ok(raw) = serde_json::to_string(secrets) else {
        return SecretStorage::File;
    };
    if secret_service_set(key, &raw) {
        return SecretStorage::Keychain;
    }
    if session_set(key, &raw) {
        return SecretStorage::Session;
    }
    SecretStorage::File
}

fn delete_secrets(key: &str) {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, key)
        && let Err(error) = entry.delete_credential()
    {
        eprintln!("kolimi-desktop: failed to delete keychain entry for {key}: {error}");
    }
    keyctl::session_delete(&session_description(key));
}

/// Forgets an account's password while **preserving its E2EE passphrase**, so
/// signing out never destroys the key needed to decrypt encrypted folders.
/// If there is no passphrase to keep, the entry is removed entirely.
fn forget_password(key: &str) {
    let Some(mut secrets) = keyring_get(key) else {
        return;
    };
    if secrets.e2ee_passphrase.is_none() {
        delete_secrets(key);
        return;
    }
    secrets.password.clear();
    secrets.app_password = None;
    store_secrets(key, &secrets);
}

fn secret_service_get(key: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, key).ok()?;
    entry.get_password().ok()
}

fn secret_service_set(key: &str, raw: &str) -> bool {
    let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, key) else {
        return false;
    };
    entry.set_password(raw).is_ok()
}

fn session_description(key: &str) -> String {
    format!("{KEYRING_SERVICE}:{key}")
}

fn session_set(key: &str, raw: &str) -> bool {
    keyctl::session_set(&session_description(key), raw.as_bytes())
}

fn session_get(key: &str) -> Option<String> {
    let bytes = keyctl::session_get(&session_description(key))?;
    String::from_utf8(bytes).ok()
}

/// Where the account secrets ended up.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretStorage {
    /// OS keychain (encrypted at rest, out of the config file).
    Keychain,
    /// Linux kernel session keyring (session-only, never written to disk).
    Session,
    /// Fallback: written into the `0600` config file (nothing else available).
    File,
}

/// Linux kernel session keyring (`keyctl`): a session-only fallback that never
/// touches disk. Non-Linux platforms are no-ops.
#[cfg(target_os = "linux")]
mod keyctl {
    use std::ffi::CString;

    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;
    const KEYCTL_UNLINK: libc::c_long = 9;

    /// Add or update a "user" key in the session keyring.
    pub fn session_set(description: &str, payload: &[u8]) -> bool {
        let Ok(key_type) = CString::new("user") else {
            return false;
        };
        let Ok(description) = CString::new(description) else {
            return false;
        };
        let id = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                key_type.as_ptr(),
                description.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                KEY_SPEC_SESSION_KEYRING,
            )
        };
        id >= 0
    }

    /// Find a "user" key in the session keyring, returning its serial.
    fn find(description: &str) -> Option<libc::c_long> {
        let key_type = CString::new("user").ok()?;
        let description = CString::new(description).ok()?;
        let id = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_SEARCH,
                KEY_SPEC_SESSION_KEYRING,
                key_type.as_ptr(),
                description.as_ptr(),
                0,
            )
        };
        (id >= 0).then_some(id)
    }

    /// Read the payload of a "user" key in the session keyring.
    pub fn session_get(description: &str) -> Option<Vec<u8>> {
        let id = find(description)?;
        let len = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                std::ptr::null_mut::<u8>(),
                0,
            )
        };
        if len < 0 {
            return None;
        }
        let mut buffer = vec![0u8; len as usize];
        let read = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                id,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if read < 0 {
            return None;
        }
        buffer.truncate(read as usize);
        Some(buffer)
    }

    /// Remove a "user" key from the session keyring.
    pub fn session_delete(description: &str) {
        if let Some(id) = find(description) {
            unsafe {
                libc::syscall(
                    libc::SYS_keyctl,
                    KEYCTL_UNLINK,
                    id,
                    KEY_SPEC_SESSION_KEYRING,
                );
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod keyctl {
    pub fn session_set(_description: &str, _payload: &[u8]) -> bool {
        false
    }
    pub fn session_get(_description: &str) -> Option<Vec<u8>> {
        None
    }
    pub fn session_delete(_description: &str) {}
}

// ---------------------------------------------------------------------------
// State + paths
// ---------------------------------------------------------------------------

/// Per-folder sync state shown in Accounts & Sync and the injected web chip.
#[derive(Debug, Clone, Serialize)]
struct PairSyncInfo {
    server: String,
    username: String,
    local_dir: String,
    remote: String,
    last_synced_at: Option<i64>,
}

/// Current sync state, shared by the tray, the Accounts & Sync window and the
/// status chip injected into the remote web UI.
#[derive(Debug, Clone, Serialize)]
struct SyncStatus {
    state: String,
    detail: String,
    synced_at: Option<i64>,
    conflicts: u64,
    errors: Vec<String>,
    offline: bool,
    paused: bool,
    pairs: Vec<PairSyncInfo>,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: "idle".to_string(),
            detail: "No sync has run yet.".to_string(),
            synced_at: None,
            conflicts: 0,
            errors: Vec::new(),
            offline: false,
            paused: false,
            pairs: Vec::new(),
        }
    }
}

impl SyncStatus {
    fn tray_text(&self) -> String {
        match self.state.as_str() {
            "syncing" => {
                if self.detail.is_empty() {
                    "Syncing…".to_string()
                } else {
                    self.detail.clone()
                }
            }
            "paused" => "Paused".to_string(),
            "locked" => "Encryption locked — open Accounts & Sync to unlock".to_string(),
            "error" => format!("Sync failed: {}", self.detail),
            "conflict" => self.detail.clone(),
            "no_account" => "No account configured".to_string(),
            _ => {
                if self.detail.is_empty() {
                    "Idle".to_string()
                } else {
                    self.detail.clone()
                }
            }
        }
    }

    fn icon_state(&self) -> &'static str {
        match self.state.as_str() {
            "syncing" => "syncing",
            "error" | "conflict" => "error",
            "locked" => "locked",
            "paused" => "paused",
            _ => "idle",
        }
    }
}

struct DesktopState {
    settings: Mutex<Settings>,
    status_item: MenuItem<tauri::Wry>,
    pause_item: MenuItem<tauri::Wry>,
    status: Mutex<SyncStatus>,
    syncing: AtomicBool,
    paused: AtomicBool,
}

fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("KOLIMI_DESKTOP_CONFIG") {
        return PathBuf::from(path);
    }
    config_base().join("kolimi").join("desktop.json")
}

#[cfg(target_os = "windows")]
fn config_base() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .or_else(|_| {
            std::env::var("USERPROFILE")
                .map(|home| PathBuf::from(home).join("AppData").join("Roaming"))
        })
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(target_os = "macos")]
fn config_base() -> PathBuf {
    std::env::var("HOME")
        .map(|home| {
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
        })
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn config_base() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        })
}

fn home_dir() -> String {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into())
}

fn expand_home(path: &str) -> String {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        return format!("{}/{rest}", home_dir());
    }
    trimmed.to_string()
}

fn normalize_server(server: &str) -> String {
    server.trim().trim_end_matches('/').to_string()
}

fn normalize_remote(remote: &str) -> String {
    let trimmed = remote.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Normalizes a list of encrypted-root paths (relative, no leading/trailing
/// slashes, no empties).
fn normalize_roots(roots: Vec<String>) -> Vec<String> {
    roots
        .into_iter()
        .map(|root| root.trim().trim_matches('/').to_string())
        .filter(|root| !root.is_empty())
        .collect()
}

fn short_dir(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

// ---------------------------------------------------------------------------
// Settings persistence + migration
// ---------------------------------------------------------------------------

fn load_settings_file() -> Result<Settings, String> {
    let path = config_path();
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| format!("{}: {error}", path.display()))?;
    if value.get("accounts").is_some() {
        let mut settings: Settings = serde_json::from_value(value)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        settings.version = 2;
        return Ok(settings);
    }
    // v1: single account + directory.
    let v1: V1Config =
        serde_json::from_value(value).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(migrate_v1(v1))
}

fn migrate_v1(v1: V1Config) -> Settings {
    let settings = migrated_settings(&v1);
    // Move secrets from the v1 key (server URL) to the new key (user@server),
    // or adopt inline secrets if the v1 file held them.
    let secrets = keyring_get(&v1.server).or_else(|| {
        (!v1.password.is_empty()).then(|| Secrets {
            password: v1.password.clone(),
            e2ee_passphrase: v1.e2ee_passphrase.clone(),
            app_password: None,
        })
    });
    if let Some(secrets) = secrets {
        let new_key = account_key(&v1.server, &v1.username);
        let stored = store_secrets(&new_key, &secrets);
        // Drop the v1 entry (keyed by bare server URL) once the secret lives
        // under the new key, so no stale copy is left in the keychain.
        if new_key != v1.server && stored != SecretStorage::File {
            delete_secrets(&v1.server);
        }
        // If storage failed entirely, clean up any partial writes to avoid
        // secrets existing in both old and new keys.
        if stored == SecretStorage::File {
            delete_secrets(&new_key);
        }
    }
    settings
}

/// Pure v1 → v2 shape conversion (no keychain access).
fn migrated_settings(v1: &V1Config) -> Settings {
    Settings {
        version: 2,
        autostart: v1.autostart,
        accounts: vec![Account {
            server: v1.server.clone(),
            username: v1.username.clone(),
            auto_approve_devices: true,
            pairs: vec![SyncPair {
                local_dir: v1.local_dir.clone(),
                remote: "/".to_string(),
                encrypted_roots: v1.encrypted_roots.clone(),
                mls: false,
                last_synced_at: None,
            }],
        }],
    }
}

fn save_settings_file(settings: &Settings) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(settings).map_err(|error| error.to_string())?;
    // Atomic replace: write a sibling temp file, lock it down, then rename.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)
        .map_err(|error| format!("cannot write {}: {error}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)
        .map_err(|error| format!("cannot replace {}: {error}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Autostart
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn autostart_path() -> PathBuf {
    config_base()
        .join("autostart")
        .join("kolimi-desktop.desktop")
}

#[cfg(target_os = "linux")]
fn set_autostart(enabled: bool) -> Result<(), String> {
    let path = autostart_path();
    if enabled {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let contents = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Kolimi\n\
             Comment=Kolimi desktop client (background sync)\n\
             Exec={} --hidden\n\
             X-GNOME-Autostart-enabled=true\n\
             Terminal=false\n",
            exe.display()
        );
        let tmp = path.with_extension("desktop.tmp");
        std::fs::write(&tmp, contents)
            .map_err(|error| format!("cannot write {}: {error}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .map_err(|error| format!("cannot replace {}: {error}", path.display()))
    } else if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))
    } else {
        Ok(())
    }
}

/// Autostart integration is currently Linux-only (XDG autostart).
#[cfg(not(target_os = "linux"))]
fn set_autostart(enabled: bool) -> Result<(), String> {
    if enabled {
        eprintln!(
            "kolimi-desktop: autostart is not wired on this platform yet; launch Kolimi at login manually"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn open_folder(path: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(error) = std::process::Command::new(opener).arg(path).spawn() {
        eprintln!("kolimi-desktop: failed to open folder {path}: {error}");
    }
}

fn notify_user(summary: &str, body: &str) {
    if let Err(error) = notify_rust::Notification::new()
        .appname("Kolimi")
        .summary(summary)
        .body(body)
        .show()
    {
        eprintln!("kolimi-desktop: failed to show notification: {error}");
    }
}

fn set_tray_icon(app: &AppHandle, state: &str) {
    let (bytes, tooltip): (&[u8], &str) = match state {
        "syncing" => (include_bytes!("../tray-syncing.png"), "Kolimi — syncing…"),
        "error" => (include_bytes!("../tray-error.png"), "Kolimi — sync problem"),
        "paused" => (include_bytes!("../tray-idle.png"), "Kolimi — paused"),
        "locked" => (
            include_bytes!("../tray-idle.png"),
            "Kolimi — locked (unlock encryption)",
        ),
        _ => (include_bytes!("../tray-idle.png"), "Kolimi"),
    };
    if let Ok(icon) = Image::from_bytes(bytes)
        && let Some(tray) = app.tray_by_id("main")
    {
        if let Err(error) = tray.set_icon(Some(icon)) {
            eprintln!("kolimi-desktop: failed to set tray icon: {error}");
        }
        if let Err(error) = tray.set_tooltip(Some(tooltip)) {
            eprintln!("kolimi-desktop: failed to set tray tooltip: {error}");
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn current_status(app: &AppHandle) -> SyncStatus {
    let state = app.state::<DesktopState>();
    let mut status = state
        .status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    status.paused = state.paused.load(Ordering::SeqCst);
    status.pairs = state
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .accounts
        .iter()
        .flat_map(|account| {
            account.pairs.iter().map(|pair| PairSyncInfo {
                server: account.server.clone(),
                username: account.username.clone(),
                local_dir: pair.local_dir.clone(),
                remote: pair.remote.clone(),
                last_synced_at: pair.last_synced_at,
            })
        })
        .collect();
    status
}

fn push_status_to_main(app: &AppHandle, status: &SyncStatus) {
    if let Some(window) = app.get_webview_window("main") {
        // The remote server origin must not learn local folder paths.
        let mut web = status.clone();
        web.pairs.clear();
        if let Ok(json) = serde_json::to_string(&web) {
            let _ = window.eval(format!("window.__kolimiDesktopSync = {json};"));
        }
    }
}

fn set_sync_status(app: &AppHandle, status: SyncStatus) {
    let status_item = {
        let state = app.state::<DesktopState>();
        *state
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = status;
        state.status_item.clone()
    };
    let status = current_status(app);
    let _ = status_item.set_text(status.tray_text());
    set_tray_icon(app, status.icon_state());
    push_status_to_main(app, &status);
}

/// Shared by the tray item and the Accounts & Sync window.
fn apply_pause(app: &AppHandle, paused: bool) {
    {
        let state = app.state::<DesktopState>();
        state.paused.store(paused, Ordering::SeqCst);
        let _ = state.pause_item.set_text(if paused {
            "Resume syncing"
        } else {
            "Pause syncing"
        });
    }
    if paused {
        set_sync_status(
            app,
            SyncStatus {
                state: "paused".to_string(),
                detail: "Syncing paused".to_string(),
                paused: true,
                ..Default::default()
            },
        );
    } else {
        run_sync(app.clone());
    }
}

fn looks_offline(errors: &[String]) -> bool {
    errors.iter().any(|error| {
        let error = error.to_ascii_lowercase();
        [
            "cannot reach server",
            "error sending request",
            "connection refused",
            "dns error",
            "network is unreachable",
            "timed out",
            "connection reset",
        ]
        .iter()
        .any(|needle| error.contains(needle))
    })
}

fn looks_unauthorized(errors: &[String]) -> bool {
    errors.iter().any(|error| {
        error.contains("server error: 401")
            || error.contains("HTTP 401")
            || error.contains("401 for")
    })
}

#[derive(Debug, Serialize)]
struct SignInResult {
    totp_required: bool,
}

enum SessionLogin {
    Success(String),
    TotpRequired,
    MfaSetupRequired,
}

/// Extract the session token from the login response's `Set-Cookie` headers.
fn session_token(headers: &reqwest::header::HeaderMap) -> Option<String> {
    for value in headers.get_all(reqwest::header::SET_COOKIE) {
        let Ok(cookie) = value.to_str() else {
            continue;
        };
        let Some((name, rest)) = cookie.split_once('=') else {
            continue;
        };
        if name.trim() != "kolimi_session" {
            continue;
        }
        let token = rest.split(';').next().unwrap_or("").trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

/// Authenticate with the same endpoint as the web UI, so TOTP and recovery
/// codes are supported. The returned session token is used as a bearer
/// credential by the background sync client.
async fn session_login(
    server: &str,
    username: &str,
    password: &str,
    code: &str,
) -> Result<SessionLogin, String> {
    let url = format!("{}/api/session", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let mut payload = serde_json::json!({
        "username": username,
        "password": password,
    });
    if !code.is_empty() {
        payload["code"] = serde_json::Value::String(code.to_string());
    }
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|error| format!("cannot reach server: {error}"))?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    match status {
        200..=299 => {
            if body["must_setup_mfa"].as_bool() == Some(true) {
                return Ok(SessionLogin::MfaSetupRequired);
            }
            let token = session_token(&headers)
                .ok_or_else(|| "server did not return a session token".to_string())?;
            Ok(SessionLogin::Success(token))
        }
        401 if body["totp_required"].as_bool() == Some(true) => Ok(SessionLogin::TotpRequired),
        401 | 403 => Err("invalid username, password, or two-factor code".to_string()),
        429 => Err("too many attempts — wait a minute, then try again.".to_string()),
        code => Err(format!("server returned HTTP {code}")),
    }
}

async fn revoke_session(server: &str, token: &str) {
    let url = format!("{}/api/session", server.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            eprintln!("kolimi-desktop: could not build session client: {error}");
            return;
        }
    };
    if let Err(error) = client.delete(&url).bearer_auth(token).send().await {
        eprintln!("kolimi-desktop: could not revoke sync session: {error}");
    }
}

/// Check whether a password is a valid Basic credential. Used as a fallback
/// for manually supplied app passwords (including passkey-only accounts).
async fn validate_basic_login(
    server: &str,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    let url = format!("{}/api/me/usage", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .map_err(|error| format!("cannot reach server: {error}"))?;
    match response.status().as_u16() {
        200..=299 => Ok(true),
        401 | 403 => Ok(false),
        code => Err(format!("server returned HTTP {code}")),
    }
}

fn device_label() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "this device".to_string())
}

/// Exchange a fresh login session for a long-lived, revocable app password.
async fn create_app_password(
    server: &str,
    session_token: &str,
    name: &str,
) -> Result<String, String> {
    let url = format!("{}/api/me/app-passwords", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(&url)
        .bearer_auth(session_token)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .map_err(|error| format!("cannot reach server: {error}"))?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    if status != 201 {
        return Err(body["error"]
            .as_str()
            .unwrap_or("could not create a sync app password")
            .to_string());
    }
    let token = body["token"]
        .as_str()
        .ok_or_else(|| "server returned no app password".to_string())?;
    Ok(token.to_string())
}

/// Revoke the app password this device authenticated with.
async fn revoke_app_password(server: &str, username: &str, password: &str) {
    let url = format!(
        "{}/api/me/app-passwords/current",
        server.trim_end_matches('/')
    );
    let client = match reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            eprintln!("kolimi-desktop: could not build app-password client: {error}");
            return;
        }
    };
    if let Err(error) = client
        .delete(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
    {
        eprintln!("kolimi-desktop: could not revoke app password: {error}");
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

fn open_main(app: &AppHandle, server: &str) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        // Navigate the existing window to the requested server instead of
        // just focusing the stale URL.
        let base = server.trim_end_matches('/');
        let target = format!("{base}/app/");
        let escaped = target.replace('\\', "\\\\").replace('\'', "\\'");
        let _ = window.eval(format!("window.location.href = '{escaped}'"));
        let _ = window.show();
        let _ = window.set_focus();
        push_status_to_main(app, &current_status(app));
        // Opening the app should reflect the server right away.
        run_sync(app.clone());
        return Ok(());
    }
    let base = server.trim_end_matches('/');
    let url = Url::parse(&format!("{base}/app/"))
        .map_err(|error| format!("invalid server URL: {error}"))?;
    // The injected "Sync folders" button navigates to a sentinel path that we
    // intercept here (blocking the navigation) to open the Accounts & Sync
    // window. This avoids granting IPC to the remote server origin.
    let nav_handle = app.clone();
    let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("Kolimi")
        .inner_size(1100.0, 720.0)
        .initialization_script(DESKTOP_INIT_JS)
        .on_page_load(|window, _| {
            let app = window.app_handle();
            push_status_to_main(app, &current_status(app));
        })
        .on_navigation(move |url| {
            if url.path() == SETTINGS_SENTINEL {
                open_settings(&nav_handle);
                return false;
            }
            true
        })
        .disable_drag_drop_handler()
        .on_download(|webview, event| {
            match event {
                DownloadEvent::Requested { destination, .. } => {
                    if let Some(dir) = std::env::var("HOME")
                        .ok()
                        .map(|home| PathBuf::from(home).join("Downloads"))
                    {
                        let _ = std::fs::create_dir_all(&dir);
                        if let Some(name) = destination.file_name() {
                            *destination = dir.join(name);
                        }
                    }
                }
                DownloadEvent::Finished { success, path, .. } => {
                    let text = if success {
                        path.and_then(|path| {
                            path.file_name()
                                .map(|name| name.to_string_lossy().into_owned())
                        })
                        .map(|name| format!("Downloaded {name}"))
                        .unwrap_or_else(|| "Download complete".to_string())
                    } else {
                        "Download failed".to_string()
                    };
                    if let Some(state) = webview.app_handle().try_state::<DesktopState>() {
                        let _ = state.status_item.set_text(text);
                    }
                }
                _ => {}
            }
            true
        })
        .build()
        .map_err(|error| error.to_string())?;

    push_status_to_main(app, &current_status(app));

    // Closing the window hides it to the tray so background sync keeps
    // running. The tray's "Quit" is the way to actually exit.
    let handle = window.clone();
    window.on_window_event(move |event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            let _ = handle.hide();
            if !CLOSE_TIP_SHOWN.swap(true, Ordering::SeqCst) {
                notify_user(
                    "Kolimi",
                    "Still running in the tray — sync continues in the background.",
                );
            }
        }
    });
    run_sync(app.clone());
    Ok(())
}

fn open_settings(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("settings") {
        let _ = window.set_focus();
        return;
    }
    if let Err(error) =
        WebviewWindowBuilder::new(app, "settings", WebviewUrl::App("index.html".into()))
            .title("Kolimi — Accounts & Sync")
            .inner_size(680.0, 720.0)
            .min_inner_size(520.0, 560.0)
            .build()
    {
        eprintln!("kolimi-desktop: failed to open settings window: {error}");
    }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

fn run_sync(app: AppHandle) {
    let settings = {
        let state = app.state::<DesktopState>();
        if state.paused.load(Ordering::SeqCst) {
            set_sync_status(
                &app,
                SyncStatus {
                    state: "paused".to_string(),
                    detail: "Syncing paused".to_string(),
                    ..Default::default()
                },
            );
            return;
        }
        if state.syncing.swap(true, Ordering::SeqCst) {
            return;
        }
        state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    if settings.accounts.is_empty() {
        app.state::<DesktopState>()
            .syncing
            .store(false, Ordering::SeqCst);
        set_sync_status(
            &app,
            SyncStatus {
                state: "no_account".to_string(),
                detail: "Add an account in Accounts & Sync".to_string(),
                ..Default::default()
            },
        );
        return;
    }

    // Build the sync jobs up front (keychain reads are blocking).
    let mut jobs: Vec<(
        String,
        String,
        String,
        String,
        String,
        kolimi_sync::SyncConfig,
    )> = Vec::new();
    let mut startup_errors: Vec<String> = Vec::new();
    for account in &settings.accounts {
        // An entry with an empty password means "signed out, passphrase kept".
        let secrets = keyring_get(&account_key(&account.server, &account.username));
        let Some(secrets) = secrets.as_ref().filter(|secrets| secrets.signed_in()) else {
            startup_errors.push(format!(
                "{}@{}: not signed in",
                account.username,
                Url::parse(&account.server)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_string))
                    .unwrap_or_else(|| account.server.clone())
            ));
            continue;
        };
        for pair in &account.pairs {
            jobs.push((
                account.server.clone(),
                account.username.clone(),
                pair.local_dir.clone(),
                pair.remote.clone(),
                short_dir(&pair.local_dir),
                pair_sync_config(account, pair, secrets),
            ));
        }
    }

    set_sync_status(
        &app,
        SyncStatus {
            state: "syncing".to_string(),
            detail: format!("Syncing {} folder(s)…", jobs.len()),
            ..Default::default()
        },
    );
    let app_handle = app.clone();
    let accounts = settings.accounts.clone();
    tauri::async_runtime::spawn(async move {
        let total = jobs.len();
        let (mut pushed, mut pulled, mut conflicts, mut failed) = (0u64, 0u64, 0u64, 0u64);
        let mut errors = startup_errors;
        let mut locked: Vec<String> = Vec::new();
        let mut synced_pairs: Vec<(String, String, String, String, i64)> = Vec::new();
        for (server, username, local_dir, remote, label, config) in jobs {
            match kolimi_sync::sync_once_rooted(&config, &remote).await {
                Ok(report) => {
                    pushed += report.pushed;
                    pulled += report.pulled;
                    conflicts += report.conflicts;
                    failed += report.failed;
                    synced_pairs.push((server, username, local_dir, remote, now_ms()));
                }
                // Encryption locked: a state to resolve, not a failure.
                Err(error) if error.is_locked() => locked.push(label),
                Err(error) => errors.push(format!("{label}: {error}")),
            }
        }
        if !synced_pairs.is_empty() {
            let state = app_handle.state::<DesktopState>();
            let mut settings = state
                .settings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (server, username, local_dir, remote, synced_at) in synced_pairs {
                if let Some(pair) = settings
                    .accounts
                    .iter_mut()
                    .find(|account| account.server == server && account.username == username)
                    .and_then(|account| {
                        account
                            .pairs
                            .iter_mut()
                            .find(|pair| pair.local_dir == local_dir && pair.remote == remote)
                    })
                {
                    pair.last_synced_at = Some(synced_at);
                }
            }
            let _ = save_settings_file(&settings);
        }
        // Keep multi-pair accounts consistent: epoch and device files updated
        // in one pair's `.kolimi` are shared with the others.
        for account in &accounts {
            if account.pairs.len() > 1 {
                propagate_account_files(account);
            }
        }
        // Auto-approve pending device enrollments for accounts that opt in
        // (on by default): a new device becomes usable without comparing
        // codes. Only runs while this machine is unlocked; failures are
        // silent (the manual flow in Accounts & Sync still works).
        let mut approved: Vec<String> = Vec::new();
        for account in &accounts {
            if !account.auto_approve_devices {
                continue;
            }
            let Some(secrets) = keyring_get(&account_key(&account.server, &account.username))
                .filter(Secrets::signed_in)
            else {
                continue;
            };
            let local = account
                .pairs
                .first()
                .map(|pair| PathBuf::from(&pair.local_dir))
                .unwrap_or_else(|| account_state_dir(&account.server, &account.username));
            let config = account_config(account, &secrets, local);
            let Ok(pending) = kolimi_sync::list_enrollments(&config).await else {
                continue;
            };
            for enrollment in pending {
                match kolimi_sync::approve_device_unverified(&config, enrollment.id).await {
                    Ok(name) => approved.push(format!("{} ({})", name, account.username)),
                    Err(kolimi_sync::SyncError::Locked(_)) => break,
                    Err(_) => {}
                }
            }
            if !approved.is_empty() {
                propagate_account_files(account);
            }
        }
        let previous = current_status(&app_handle);
        app_handle
            .state::<DesktopState>()
            .syncing
            .store(false, Ordering::SeqCst);
        if app_handle
            .state::<DesktopState>()
            .paused
            .load(Ordering::SeqCst)
        {
            let offline = looks_offline(&errors);
            let detail = if errors.is_empty() {
                "Syncing paused".to_string()
            } else {
                format!("Syncing paused · {} folder error(s)", errors.len())
            };
            set_sync_status(
                &app_handle,
                SyncStatus {
                    state: "paused".to_string(),
                    detail,
                    conflicts,
                    errors,
                    offline,
                    paused: true,
                    ..Default::default()
                },
            );
            return;
        }
        if !errors.is_empty() {
            let first = errors.first().cloned().unwrap_or_default();
            let offline = looks_offline(&errors);
            let detail = if looks_unauthorized(&errors) {
                "Sync sign-in expired or was revoked — open Accounts & Sync and sign in again."
                    .to_string()
            } else {
                first.clone()
            };
            let errors_text = errors.join("\n");
            set_sync_status(
                &app_handle,
                SyncStatus {
                    state: "error".to_string(),
                    detail: detail.clone(),
                    conflicts,
                    errors,
                    offline,
                    ..Default::default()
                },
            );
            if previous.state != "error" || previous.detail != detail {
                notify_user("Kolimi sync problem", &errors_text);
            }
        } else if !locked.is_empty() {
            set_sync_status(
                &app_handle,
                SyncStatus {
                    state: "locked".to_string(),
                    detail: format!("Encrypted folders locked: {}", locked.join(", ")),
                    ..Default::default()
                },
            );
            if !LOCKED_TIP_SHOWN.swap(true, Ordering::SeqCst) {
                notify_user(
                    "Kolimi",
                    "Encrypted folders are locked. Open Accounts & Sync to enter your passphrase.",
                );
            }
        } else {
            let failed_note = if failed > 0 {
                format!(" · {failed} skipped")
            } else {
                String::new()
            };
            let synced_detail = format!(
                "Synced {total} folder{}: ↑{pushed} ↓{pulled}{failed_note}",
                if total == 1 { "" } else { "s" }
            );
            let (state, detail) = if conflicts > 0 {
                (
                    "conflict".to_string(),
                    format!("{conflicts} conflict(s) — local edits kept as .conflict-* files"),
                )
            } else {
                ("idle".to_string(), synced_detail)
            };
            set_sync_status(
                &app_handle,
                SyncStatus {
                    state,
                    detail,
                    synced_at: Some(now_ms()),
                    conflicts,
                    errors: Vec::new(),
                    offline: false,
                    ..Default::default()
                },
            );
            if !approved.is_empty() {
                // The "wasn't you?" notice for automatic approvals.
                notify_user(
                    "Kolimi",
                    &format!(
                        "Approved new device(s): {}. If that wasn't you, remove them under Accounts & Sync → Encryption.",
                        approved.join(", ")
                    ),
                );
            }
            if conflicts > 0 && (previous.state != "conflict" || previous.conflicts != conflicts) {
                notify_user(
                    "Kolimi sync",
                    &format!("{conflicts} conflict(s) — local edits kept as .conflict-* files"),
                );
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tauri commands (Settings window)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct PairView {
    local_dir: String,
    remote: String,
    encrypted_roots: Vec<String>,
    last_synced_at: Option<i64>,
}

#[derive(Serialize)]
struct AccountView {
    server: String,
    username: String,
    signed_in: bool,
    /// Whether any synced folder is end-to-end encrypted.
    has_e2ee: bool,
    /// Whether an E2EE passphrase is stored for this account.
    e2ee_unlocked: bool,
    /// Whether new devices are approved automatically while unlocked.
    auto_approve_devices: bool,
    pairs: Vec<PairView>,
}

#[derive(Serialize)]
struct SettingsView {
    accounts: Vec<AccountView>,
    autostart: bool,
}

/// The current sync state for the Accounts & Sync window.
#[tauri::command]
fn get_sync_status(app: AppHandle) -> SyncStatus {
    current_status(&app)
}

/// Pause or resume background sync from Accounts & Sync (same state as the
/// tray item).
#[tauri::command]
fn set_sync_paused(app: AppHandle, paused: bool) -> SyncStatus {
    apply_pause(&app, paused);
    current_status(&app)
}

/// The current settings, with a `signed_in` flag per account (no secrets).
#[tauri::command]
fn get_settings(app: AppHandle) -> SettingsView {
    let settings = app
        .state::<DesktopState>()
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let accounts = settings
        .accounts
        .iter()
        .map(|account| {
            let secrets = keyring_get(&account_key(&account.server, &account.username));
            AccountView {
                signed_in: secrets.as_ref().is_some_and(Secrets::signed_in),
                has_e2ee: account
                    .pairs
                    .iter()
                    .any(|pair| !pair.encrypted_roots.is_empty()),
                e2ee_unlocked: secrets
                    .as_ref()
                    .is_some_and(|secrets| secrets.e2ee_passphrase.is_some()),
                auto_approve_devices: account.auto_approve_devices,
                server: account.server.clone(),
                username: account.username.clone(),
                pairs: account
                    .pairs
                    .iter()
                    .map(|pair| PairView {
                        local_dir: pair.local_dir.clone(),
                        remote: pair.remote.clone(),
                        encrypted_roots: pair.encrypted_roots.clone(),
                        last_synced_at: pair.last_synced_at,
                    })
                    .collect(),
            }
        })
        .collect();
    SettingsView {
        accounts,
        autostart: settings.autostart,
    }
}

/// Sign in (or re-authenticate) an account. TOTP accounts return
/// `totp_required` on the first attempt, then exchange a code for a session
/// and create a long-lived app password for background sync.
#[tauri::command]
async fn sign_in(
    app: AppHandle,
    server: String,
    username: String,
    password: String,
    code: Option<String>,
) -> Result<SignInResult, String> {
    let server = normalize_server(&server);
    if server.is_empty() || username.is_empty() {
        return Err("server and username are required".to_string());
    }
    let code = code.unwrap_or_default();
    let code = code.trim();
    let (account_password, app_password) = match session_login(&server, &username, &password, code)
        .await
    {
        Ok(SessionLogin::TotpRequired) => {
            return Ok(SignInResult {
                totp_required: true,
            });
        }
        Ok(SessionLogin::MfaSetupRequired) => {
            return Err("finish two-factor or passkey setup in the web app first".to_string());
        }
        Ok(SessionLogin::Success(token)) => {
            let app_name = format!("Kolimi Desktop on {}", device_label());
            let app_password = match create_app_password(&server, &token, &app_name).await {
                Ok(password) => Some(password),
                Err(error) if code.is_empty() => {
                    // Non-TOTP accounts can still sync with the account password.
                    eprintln!("kolimi-desktop: app-password creation failed: {error}");
                    None
                }
                Err(error) => {
                    revoke_session(&server, &token).await;
                    return Err(format!("could not create a sync app password: {error}"));
                }
            };
            revoke_session(&server, &token).await;
            (password, app_password)
        }
        Err(_)
            if code.is_empty() && validate_basic_login(&server, &username, &password).await? =>
        {
            // A passkey-only account can paste an app password created in
            // the web UI; it authenticates with Basic, not /api/session.
            (String::new(), Some(password))
        }
        Err(error) => return Err(error),
    };
    // Re-authenticating must not drop the E2EE passphrase the user already
    // stored for this account.
    let key = account_key(&server, &username);
    let previous = keyring_get(&key);
    if let Some(old) = previous
        .as_ref()
        .and_then(|secrets| secrets.app_password.as_deref())
        && Some(old) != app_password.as_deref()
    {
        revoke_app_password(&server, &username, old).await;
    }
    let e2ee_passphrase = previous.and_then(|secrets| secrets.e2ee_passphrase);
    store_secrets(
        &key,
        &Secrets {
            password: account_password,
            e2ee_passphrase,
            app_password,
        },
    );
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !settings
            .accounts
            .iter()
            .any(|account| account.server == server && account.username == username)
        {
            settings.accounts.push(Account {
                server: server.clone(),
                username: username.clone(),
                pairs: Vec::new(),
                auto_approve_devices: true,
            });
        }
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(SignInResult {
        totp_required: false,
    })
}

/// Forget an account's password (keeps its configuration and E2EE passphrase).
#[tauri::command]
async fn sign_out(app: AppHandle, server: String, username: String) {
    let key = account_key(&server, &username);
    if let Some(secrets) = keyring_get(&key)
        && let Some(password) = secrets.app_password.as_deref()
    {
        revoke_app_password(&server, &username, password).await;
    }
    forget_password(&key);
    run_sync(app);
}

#[derive(Debug, Serialize)]
struct LinkResult {
    server: String,
    username: String,
}

/// Link the signed-in server webview to the native sync client. Works for
/// passkey-only accounts, where the local Accounts & Sync window cannot run a
/// WebAuthn ceremony. The webview session is exchanged for an app password;
/// the session cookie is never stored.
#[tauri::command]
async fn link_web_session(app: AppHandle) -> Result<LinkResult, String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "open the Kolimi window and sign in first".to_string())?;
    let url = window
        .url()
        .map_err(|error| format!("cannot read the Kolimi window URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("the Kolimi window is not on a server URL".to_string());
    }
    let cookies = window
        .cookies_for_url(url.clone())
        .map_err(|error| format!("cannot read the web session: {error}"))?;
    let session = cookies
        .iter()
        .find(|cookie| cookie.name() == "kolimi_session")
        .map(|cookie| cookie.value().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "sign in to the Kolimi window first, then try again".to_string())?;
    let server = url.origin().ascii_serialization();
    let me_url = format!("{}/api/me", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .user_agent(format!("Kolimi Desktop/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(&me_url)
        .bearer_auth(&session)
        .send()
        .await
        .map_err(|error| format!("cannot reach server: {error}"))?;
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
    if status != 200 {
        return Err(body["error"]
            .as_str()
            .unwrap_or("the web session is not valid")
            .to_string());
    }
    let username = body["username"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "server returned no username".to_string())?
        .to_string();
    if body["must_setup_mfa"].as_bool() == Some(true) {
        return Err("finish two-factor or passkey setup in the web app first".to_string());
    }
    let app_name = format!("Kolimi Desktop on {}", device_label());
    let app_password = create_app_password(&server, &session, &app_name).await?;
    let key = account_key(&server, &username);
    let previous = keyring_get(&key);
    if let Some(old) = previous
        .as_ref()
        .and_then(|secrets| secrets.app_password.as_deref())
    {
        revoke_app_password(&server, &username, old).await;
    }
    let e2ee_passphrase = previous
        .as_ref()
        .and_then(|secrets| secrets.e2ee_passphrase.clone());
    let password = previous.map(|secrets| secrets.password).unwrap_or_default();
    store_secrets(
        &key,
        &Secrets {
            password,
            e2ee_passphrase,
            app_password: Some(app_password),
        },
    );
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !settings
            .accounts
            .iter()
            .any(|account| account.server == server && account.username == username)
        {
            settings.accounts.push(Account {
                server: server.clone(),
                username: username.clone(),
                pairs: Vec::new(),
                auto_approve_devices: true,
            });
        }
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(LinkResult { server, username })
}

/// Remove an account entirely (configuration + password).
#[tauri::command]
async fn remove_account(app: AppHandle, server: String, username: String) -> Result<(), String> {
    let key = account_key(&server, &username);
    if let Some(secrets) = keyring_get(&key)
        && let Some(password) = secrets.app_password.as_deref()
    {
        revoke_app_password(&server, &username, password).await;
    }
    delete_secrets(&key);
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        settings
            .accounts
            .retain(|account| !(account.server == server && account.username == username));
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Add a directory to sync for an account.
#[tauri::command]
fn add_pair(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
    remote: String,
    encrypted_roots: Vec<String>,
) -> Result<(), String> {
    let local = expand_home(&dir);
    if local.is_empty() {
        return Err("directory is required".to_string());
    }
    std::fs::create_dir_all(&local).map_err(|error| format!("cannot create {local}: {error}"))?;
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.server == server && account.username == username)
            .ok_or_else(|| "account not found".to_string())?;
        if account.pairs.iter().any(|pair| pair.local_dir == local) {
            return Err("directory is already synced".to_string());
        }
        account.pairs.push(SyncPair {
            local_dir: local,
            remote: normalize_remote(&remote),
            encrypted_roots: normalize_roots(encrypted_roots),
            mls: false,
            last_synced_at: None,
        });
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Remove a synced directory (local files are left untouched).
#[tauri::command]
fn remove_pair(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
) -> Result<(), String> {
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.server == server && account.username == username)
            .ok_or_else(|| "account not found".to_string())?;
        account.pairs.retain(|pair| pair.local_dir != dir);
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Change a synced directory's local path and/or remote subfolder in place
/// (no remove + re-add).
#[tauri::command]
fn update_pair(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
    new_dir: String,
    remote: String,
    encrypted_roots: Vec<String>,
) -> Result<(), String> {
    let local = expand_home(&new_dir);
    if local.is_empty() {
        return Err("directory is required".to_string());
    }
    std::fs::create_dir_all(&local).map_err(|error| format!("cannot create {local}: {error}"))?;
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.server == server && account.username == username)
            .ok_or_else(|| "account not found".to_string())?;
        if account
            .pairs
            .iter()
            .any(|pair| pair.local_dir == local && pair.local_dir != dir)
        {
            return Err("that directory is already synced".to_string());
        }
        let pair = account
            .pairs
            .iter_mut()
            .find(|pair| pair.local_dir == dir)
            .ok_or_else(|| "directory not found".to_string())?;
        let old_remote = pair.remote.clone();
        let old_local = pair.local_dir.clone();
        pair.local_dir = local.clone();
        pair.remote = normalize_remote(&remote);
        pair.encrypted_roots = normalize_roots(encrypted_roots);
        // Changing the remote root or local folder invalidates the sync
        // state: the tracked paths belong to the old root. Drop state.json
        // so the next pass re-baselines instead of deleting local files as
        // "remote deletions".
        if old_remote != pair.remote || old_local != pair.local_dir {
            pair.last_synced_at = None;
            let _ = std::fs::remove_file(
                std::path::Path::new(&pair.local_dir).join(".kolimi/state.json"),
            );
            if old_local != pair.local_dir {
                let _ = std::fs::remove_file(
                    std::path::Path::new(&old_local).join(".kolimi/state.json"),
                );
            }
        }
        settings.clone()
    };
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Set (or clear, when empty) the E2EE passphrase stored for an account, then
/// sync so encrypted folders unlock immediately. A non-empty passphrase is
/// verified against the keyring first, so "unlocked" is never a lie.
#[tauri::command]
async fn set_e2ee_passphrase(
    app: AppHandle,
    server: String,
    username: String,
    passphrase: String,
) -> Result<(), String> {
    let key = account_key(&server, &username);
    let mut secrets =
        keyring_get(&key).ok_or_else(|| "sign in to this account first".to_string())?;
    if !passphrase.trim().is_empty() {
        let (account, _) = find_account(&app, &server, &username)?;
        let local = account
            .pairs
            .first()
            .map(|pair| PathBuf::from(&pair.local_dir))
            .unwrap_or_else(|| account_state_dir(&account.server, &account.username));
        let mut config = account_config(&account, &secrets, local);
        config.e2ee = Some(kolimi_sync::E2eeOptions {
            passphrase: Some(passphrase.clone()),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: Vec::new(),
            mls: false,
        });
        kolimi_sync::verify_unlock(&config)
            .await
            .map_err(|error| error.to_string())?;
    }
    secrets.e2ee_passphrase = if passphrase.is_empty() {
        None
    } else {
        Some(passphrase)
    };
    store_secrets(&key, &secrets);
    run_sync(app);
    Ok(())
}

/// Whether E2EE is set up for the account: `none`, `locked`, `unlocked`, or
/// `signed_out` (no password to reach the server).
#[tauri::command]
async fn e2ee_status(app: AppHandle, server: String, username: String) -> Result<String, String> {
    let settings = app
        .state::<DesktopState>()
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(account) = settings
        .accounts
        .into_iter()
        .find(|account| account.server == server && account.username == username)
    else {
        return Ok("signed_out".to_string());
    };
    let Some(secrets) = keyring_get(&account_key(&server, &username)) else {
        return Ok("signed_out".to_string());
    };
    if !secrets.signed_in() {
        return Ok("signed_out".to_string());
    }
    let local = account
        .pairs
        .first()
        .map(|pair| PathBuf::from(&pair.local_dir))
        .unwrap_or_else(|| account_state_dir(&account.server, &account.username));
    let config = account_config(&account, &secrets, local);
    match kolimi_sync::keyring_exists(&config).await {
        Ok(true) => {
            // Unlocked = passphrase on hand, or an enrolled device key in any
            // pair (passwordless devices must not report "locked").
            let enrolled = account.pairs.iter().any(|pair| {
                PathBuf::from(&pair.local_dir)
                    .join(".kolimi/device.json")
                    .exists()
            });
            Ok(if secrets.e2ee_passphrase.is_some() || enrolled {
                "unlocked"
            } else {
                "locked"
            }
            .to_string())
        }
        Ok(false) => Ok("none".to_string()),
        Err(error) => Err(error.to_string()),
    }
}

/// First-time E2EE setup: creates and uploads a keyring, publishes the
/// identity, and stores the passphrase. Returns the recovery code to show once.
#[tauri::command]
async fn setup_e2ee(
    app: AppHandle,
    server: String,
    username: String,
    passphrase: String,
) -> Result<String, String> {
    if passphrase.trim().is_empty() {
        return Err("Enter a passphrase".to_string());
    }
    let (account, mut secrets) = find_account(&app, &server, &username)?;
    let local = first_pair_dir(&account)?;
    let config = account_config(&account, &secrets, local);
    if kolimi_sync::keyring_exists(&config)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err("Encryption is already set up for this account".to_string());
    }
    let recovery = kolimi_sync::setup_keyring(&config, &passphrase)
        .await
        .map_err(|error| error.to_string())?;
    secrets.e2ee_passphrase = Some(passphrase);
    store_secrets(&account_key(&server, &username), &secrets);
    run_sync(app);
    Ok(recovery)
}

/// Toggle automatic approval of new device enrollments for an account.
#[tauri::command]
fn set_auto_approve(
    app: AppHandle,
    server: String,
    username: String,
    enabled: bool,
) -> Result<(), String> {
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.server == server && account.username == username)
            .ok_or_else(|| "account not found".to_string())?;
        account.auto_approve_devices = enabled;
        settings.clone()
    };
    save_settings_file(&settings)?;
    Ok(())
}

/// Toggle the "start on login" autostart entry.
#[tauri::command]
fn set_autostart_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    set_autostart(enabled)?;
    let settings = {
        let state = app.state::<DesktopState>();
        let mut settings = state
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        settings.autostart = enabled;
        settings.clone()
    };
    save_settings_file(&settings)?;
    Ok(())
}

/// Trigger a sync now.
#[tauri::command]
fn sync_now(app: AppHandle) {
    run_sync(app);
}

/// Open an account's server in the main window.
#[tauri::command]
fn open_account(app: AppHandle, server: String) -> Result<(), String> {
    open_main(&app, &server)
}

// ---------------------------------------------------------------------------
// E2EE device enrollment (RFC 0008) and pinned recipient keys
// ---------------------------------------------------------------------------

/// A device enrollment shown in the UI (id, name, approval code, fingerprint).
#[derive(Serialize)]
struct EnrollmentView {
    id: i64,
    name: String,
    code: String,
    fingerprint: String,
}

impl From<kolimi_sync::Enrollment> for EnrollmentView {
    fn from(enrollment: kolimi_sync::Enrollment) -> Self {
        Self {
            id: enrollment.id,
            name: enrollment.name,
            code: enrollment.code,
            fingerprint: enrollment.fingerprint,
        }
    }
}

/// A pinned recipient key (trust on first use).
#[derive(Serialize)]
struct RecipientView {
    member: String,
    fingerprint: String,
}

/// An enrollment started by `enroll_device`, awaiting approval and `finish`.
static PENDING_ENROLLMENT: LazyLock<Mutex<Option<kolimi_sync::PendingDevice>>> =
    LazyLock::new(|| Mutex::new(None));

/// Looks up an account and its stored secrets.
fn find_account(
    app: &AppHandle,
    server: &str,
    username: &str,
) -> Result<(Account, Secrets), String> {
    let settings = app
        .state::<DesktopState>()
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let account = settings
        .accounts
        .into_iter()
        .find(|account| account.server == server && account.username == username)
        .ok_or_else(|| "unknown account".to_string())?;
    let secrets =
        keyring_get(&account_key(server, username)).ok_or_else(|| "sign in first".to_string())?;
    Ok((account, secrets))
}

/// The first sync folder of an account (the local dir used for enrollment).
fn first_pair_dir(account: &Account) -> Result<PathBuf, String> {
    account
        .pairs
        .first()
        .map(|pair| PathBuf::from(&pair.local_dir))
        .ok_or_else(|| "Add a sync folder for this account first".to_string())
}

/// Private per-account dir for account-level operations when the account has
/// no sync folder yet. Never the shared `/tmp`: epoch and state files live
/// under the user's config dir.
fn account_state_dir(server: &str, username: &str) -> PathBuf {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    server.hash(&mut hasher);
    username.hash(&mut hasher);
    let dir = config_base()
        .join("kolimi")
        .join("accounts")
        .join(format!("{:016x}", hasher.finish()));
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir
}

/// Copies account-level sync state (`device.json`, `keyring.epoch`,
/// `known_keys.json`) from whichever pair has it to every pair, so a second
/// sync folder does not stay locked after enrollment on the first.
fn propagate_account_files(account: &Account) {
    const FILES: [&str; 3] = ["device.json", "keyring.epoch", "known_keys.json"];
    let dirs: Vec<PathBuf> = account
        .pairs
        .iter()
        .map(|pair| PathBuf::from(&pair.local_dir).join(".kolimi"))
        .collect();
    for name in FILES {
        // Newest copy wins.
        let mut source: Option<(std::time::SystemTime, PathBuf)> = None;
        for dir in &dirs {
            let path = dir.join(name);
            if let Ok(meta) = std::fs::metadata(&path)
                && let Ok(modified) = meta.modified()
                && source.as_ref().is_none_or(|(time, _)| modified > *time)
            {
                source = Some((modified, path));
            }
        }
        let Some((_, source)) = source else {
            continue;
        };
        if let Ok(bytes) = std::fs::read(&source) {
            for dir in &dirs {
                let dest = dir.join(name);
                if dest == source {
                    continue;
                }
                if std::fs::read(&dest).ok().as_deref() == Some(bytes.as_slice()) {
                    continue;
                }
                let _ = std::fs::create_dir_all(dir);
                let tmp = dir.join(format!("{name}.tmp"));
                if std::fs::write(&tmp, &bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, &dest);
                }
            }
        }
    }
}

/// Ensures a pair config has E2EE options and MLS enabled.
fn with_mls(
    mut config: kolimi_sync::SyncConfig,
    pair: &SyncPair,
    secrets: &Secrets,
) -> kolimi_sync::SyncConfig {
    if config.e2ee.is_none() {
        config.e2ee = Some(kolimi_sync::E2eeOptions {
            passphrase: secrets.e2ee_passphrase.clone(),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: pair.encrypted_roots.clone(),
            mls: true,
        });
    } else if let Some(e2ee) = config.e2ee.as_mut() {
        e2ee.mls = true;
    }
    config
}

/// A config for account-level E2EE operations (no encrypted roots).
fn account_config(
    account: &Account,
    secrets: &Secrets,
    local_dir: PathBuf,
) -> kolimi_sync::SyncConfig {
    kolimi_sync::SyncConfig {
        server: account.server.clone(),
        username: account.username.clone(),
        password: secrets.sync_password().to_string(),
        token: None,
        local_dir,
        e2ee: Some(kolimi_sync::E2eeOptions {
            passphrase: secrets.e2ee_passphrase.clone(),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: Vec::new(),
            mls: false,
        }),
    }
}

/// Starts enrolling this machine as a device; returns the code to compare.
#[tauri::command]
async fn enroll_device(
    app: AppHandle,
    server: String,
    username: String,
    name: String,
) -> Result<EnrollmentView, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let config = account_config(&account, &secrets, first_pair_dir(&account)?);
    let pending = kolimi_sync::start_enrollment(&config, &name)
        .await
        .map_err(|error| error.to_string())?;
    let view = EnrollmentView {
        id: pending.details.id,
        name: pending.details.name.clone(),
        code: pending.details.code.clone(),
        fingerprint: pending.details.fingerprint.clone(),
    };
    *PENDING_ENROLLMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pending);
    Ok(view)
}

/// Waits for the in-progress enrollment to be approved and saves the device key.
#[tauri::command]
async fn finish_enrollment(
    app: AppHandle,
    server: String,
    username: String,
) -> Result<i64, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let config = account_config(&account, &secrets, first_pair_dir(&account)?);
    let pending = PENDING_ENROLLMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .ok_or_else(|| "no enrollment in progress".to_string())?;
    let id = kolimi_sync::finish_enrollment(&config, &pending)
        .await
        .map_err(|error| error.to_string())?;
    // The device key landed in the first pair's `.kolimi`; share it with
    // every other pair so they unlock too.
    propagate_account_files(&account);
    Ok(id)
}

/// Pending device enrollments awaiting approval.
#[tauri::command]
async fn list_enrollments(
    app: AppHandle,
    server: String,
    username: String,
) -> Result<Vec<EnrollmentView>, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let local = account
        .pairs
        .first()
        .map(|pair| PathBuf::from(&pair.local_dir))
        .unwrap_or_else(|| account_state_dir(&account.server, &account.username));
    let config = account_config(&account, &secrets, local);
    kolimi_sync::list_enrollments(&config)
        .await
        .map(|list| list.into_iter().map(EnrollmentView::from).collect())
        .map_err(|error| error.to_string())
}

/// Approves a pending enrollment; `code` must match the new device's code.
#[tauri::command]
async fn approve_device(
    app: AppHandle,
    server: String,
    username: String,
    id: i64,
    code: String,
) -> Result<String, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let config = account_config(&account, &secrets, first_pair_dir(&account)?);
    // Empty code = one-click trust-on-first-use; a typed code is verified
    // against the device key (refuses on mismatch).
    let result = if code.trim().is_empty() {
        kolimi_sync::approve_device_unverified(&config, id).await
    } else {
        kolimi_sync::approve_device(&config, id, &code).await
    }
    .map_err(|error| error.to_string());
    // Approvals pin recipient keys (TOFU) in the first pair's `.kolimi`;
    // share them with every other pair.
    if result.is_ok() {
        propagate_account_files(&account);
    }
    result
}

/// The recipient keys pinned on this machine (member -> fingerprint).
#[tauri::command]
fn recipient_fingerprints(
    app: AppHandle,
    server: String,
    username: String,
) -> Result<Vec<RecipientView>, String> {
    let (account, _secrets) = find_account(&app, &server, &username)?;
    let mut out: Vec<RecipientView> = Vec::new();
    for pair in &account.pairs {
        if let Ok(keys) = kolimi_sync::known_recipient_keys(Path::new(&pair.local_dir)) {
            for (member, fingerprint) in keys {
                if !out.iter().any(|entry| entry.member == member) {
                    out.push(RecipientView {
                        member,
                        fingerprint,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[derive(Serialize)]
struct MlsStatusView {
    epoch: u64,
    members: Vec<String>,
}

fn pair_for<'a>(account: &'a Account, dir: &str) -> Result<&'a SyncPair, String> {
    account
        .pairs
        .iter()
        .find(|pair| pair.local_dir == dir)
        .ok_or_else(|| "sync folder not found".to_string())
}

/// Adds an MLS recipient (folder shares) for one sync pair.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn share_mls(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
    path: String,
    kind: String,
    recipient: String,
    write: bool,
) -> Result<u64, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let pair = pair_for(&account, &dir)?;
    let config = with_mls(pair_sync_config(&account, pair, &secrets), pair, &secrets);
    let target = if kind == "group" {
        kolimi_sync::ShareTarget::Group(recipient)
    } else {
        kolimi_sync::ShareTarget::User(recipient)
    };
    let permission = if write {
        kolimi_sync::SharePermission::Write
    } else {
        kolimi_sync::SharePermission::Read
    };
    kolimi_sync::share_path_with_permission(&config, &pair.remote, &path, target, permission)
        .await
        .map_err(|error| error.to_string())
}

/// Revokes an MLS recipient share.
#[tauri::command]
async fn unshare_mls(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
    path: String,
    kind: String,
    recipient: String,
) -> Result<(), String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let pair = pair_for(&account, &dir)?;
    let config = with_mls(pair_sync_config(&account, pair, &secrets), pair, &secrets);
    let target = if kind == "group" {
        kolimi_sync::ShareTarget::Group(recipient)
    } else {
        kolimi_sync::ShareTarget::User(recipient)
    };
    kolimi_sync::unshare_path(&config, &pair.remote, &path, target)
        .await
        .map_err(|error| error.to_string())
}

/// Promotes existing encrypted folder shares to MLS groups/keyrings.
#[tauri::command]
async fn migrate_mls(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
) -> Result<Vec<String>, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let pair = pair_for(&account, &dir)?;
    let config = with_mls(pair_sync_config(&account, pair, &secrets), pair, &secrets);
    kolimi_sync::migrate_mls_shares(&config)
        .await
        .map_err(|error| error.to_string())
}

/// Shows the MLS epoch and members for a folder.
#[tauri::command]
async fn mls_status(
    app: AppHandle,
    server: String,
    username: String,
    dir: String,
    path: String,
) -> Result<Option<MlsStatusView>, String> {
    let (account, secrets) = find_account(&app, &server, &username)?;
    let pair = pair_for(&account, &dir)?;
    let config = with_mls(pair_sync_config(&account, pair, &secrets), pair, &secrets);
    let status = kolimi_sync::mls_status(&config, &pair.remote, &path)
        .await
        .map_err(|error| error.to_string())?;
    Ok(status.map(|(epoch, members)| MlsStatusView {
        epoch,
        members: members.into_iter().map(|(name, _)| name).collect(),
    }))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        // Single instance: a second launch (e.g. re-launching after an update)
        // focuses the running one instead of starting a second tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            let window = app
                .get_webview_window("main")
                .or_else(|| app.get_webview_window("settings"));
            match window {
                Some(window) => {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
                None => open_settings(app),
            }
            run_sync(app.clone());
        }))
        .invoke_handler(tauri::generate_handler![
            get_settings,
            get_sync_status,
            set_sync_paused,
            sign_in,
            link_web_session,
            sign_out,
            remove_account,
            add_pair,
            remove_pair,
            update_pair,
            set_e2ee_passphrase,
            e2ee_status,
            setup_e2ee,
            set_autostart_enabled,
            set_auto_approve,
            sync_now,
            open_account,
            enroll_device,
            finish_enrollment,
            list_enrollments,
            approve_device,
            recipient_fingerprints,
            share_mls,
            unshare_mls,
            migrate_mls,
            mls_status
        ])
        .setup(|app| {
            let mut settings = match load_settings_file() {
                Ok(settings) => {
                    // Persist the migrated/v2 shape once.
                    let _ = save_settings_file(&settings);
                    settings
                }
                Err(_) => Settings::default(),
            };
            settings.version = 2;
            let autostart_on = settings.autostart;

            let status = MenuItem::with_id(app, "status", "Idle", false, None::<&str>)?;
            let open = MenuItem::with_id(app, "open", "Open Kolimi", true, None::<&str>)?;
            let folder = MenuItem::with_id(app, "folder", "Open folder", true, None::<&str>)?;
            let sync_now_item = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause syncing", true, None::<&str>)?;
            let autostart = CheckMenuItem::with_id(
                app,
                "autostart",
                "Start on login",
                true,
                autostart_on,
                None::<&str>,
            )?;
            let settings_item =
                MenuItem::with_id(app, "settings", "Accounts & Sync…", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let sep_a = PredefinedMenuItem::separator(app)?;
            let sep_b = PredefinedMenuItem::separator(app)?;
            let sep_c = PredefinedMenuItem::separator(app)?;
            let menu = Menu::with_items(
                app,
                &[
                    &status,
                    &sep_a,
                    &open,
                    &folder,
                    &sync_now_item,
                    &pause,
                    &autostart,
                    &sep_b,
                    &settings_item,
                    &sep_c,
                    &quit,
                ],
            )?;

            let pause_item = pause.clone();
            let autostart_item = autostart.clone();
            let icon = Image::from_bytes(include_bytes!("../tray-idle.png"))?;
            TrayIconBuilder::with_id("main")
                .icon(icon)
                .tooltip("Kolimi")
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => {
                        let settings = app
                            .state::<DesktopState>()
                            .settings
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        match settings.accounts.first() {
                            Some(account) => {
                                let _ = open_main(app, &account.server);
                            }
                            None => open_settings(app),
                        }
                    }
                    "folder" => {
                        let settings = app
                            .state::<DesktopState>()
                            .settings
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        if let Some(dir) = settings
                            .accounts
                            .iter()
                            .flat_map(|account| account.pairs.iter())
                            .map(|pair| pair.local_dir.clone())
                            .next()
                        {
                            open_folder(&dir);
                        }
                    }
                    "sync" => run_sync(app.clone()),
                    "pause" => {
                        let paused = !app.state::<DesktopState>().paused.load(Ordering::SeqCst);
                        apply_pause(app, paused);
                    }
                    "autostart" => {
                        let enabled = autostart_item.is_checked().unwrap_or(false);
                        if let Err(error) = set_autostart(enabled) {
                            notify_user("Kolimi", &format!("autostart: {error}"));
                            let _ = autostart_item.set_checked(!enabled);
                        } else {
                            let saved = {
                                let state = app.state::<DesktopState>();
                                let mut settings = state
                                    .settings
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                settings.autostart = enabled;
                                settings.clone()
                            };
                            let _ = save_settings_file(&saved);
                        }
                    }
                    "settings" => open_settings(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            let has_account = !settings.accounts.is_empty();
            app.manage(DesktopState {
                settings: Mutex::new(settings),
                status_item: status,
                pause_item,
                status: Mutex::new(SyncStatus::default()),
                syncing: AtomicBool::new(false),
                paused: AtomicBool::new(false),
            });

            // Launched by autostart? Start in the tray without a window.
            let start_hidden = std::env::args().any(|arg| arg == "--hidden")
                || std::env::var_os("KOLIMI_START_HIDDEN").is_some();

            if has_account {
                if !start_hidden {
                    let server = app
                        .state::<DesktopState>()
                        .settings
                        .lock()
                        .unwrap()
                        .accounts
                        .first()
                        .map(|account| account.server.clone());
                    if let Some(server) = server
                        && let Err(error) = open_main(app.handle(), &server)
                    {
                        eprintln!("kolimi-desktop: {error}");
                        open_settings(app.handle());
                    }
                }
            } else {
                open_settings(app.handle());
            }

            // First sync shortly after startup, then on the interval.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                loop {
                    run_sync(handle.clone());
                    tokio::time::sleep(SYNC_INTERVAL).await;
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Kolimi desktop");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_status_maps_to_tray_and_chip_states() {
        let idle = SyncStatus {
            state: "idle".to_string(),
            detail: "Synced 2 folders: ↑3 ↓1".to_string(),
            synced_at: Some(1),
            ..Default::default()
        };
        assert_eq!(idle.tray_text(), "Synced 2 folders: ↑3 ↓1");
        assert_eq!(idle.icon_state(), "idle");

        let failed = SyncStatus {
            state: "error".to_string(),
            detail: "cannot reach server".to_string(),
            offline: true,
            ..Default::default()
        };
        assert!(failed.tray_text().contains("Sync failed"));
        assert_eq!(failed.icon_state(), "error");
        assert!(looks_offline(&[
            "alice@example: cannot reach server".to_string()
        ]));
        assert!(!looks_offline(&[
            "alice@example: invalid password".to_string()
        ]));
        assert!(looks_unauthorized(&[
            "alice@example: server error: 401 for /api/sync/manifest".to_string()
        ]));
        assert!(!looks_unauthorized(&[
            "alice@example: server error: 500 for /api/sync/manifest".to_string()
        ]));
    }

    #[test]
    fn desktop_init_script_has_status_and_offline_hooks() {
        assert!(DESKTOP_INIT_JS.contains("kolimi-sync-status"));
        assert!(DESKTOP_INIT_JS.contains("kolimi-offline-banner"));
        assert!(DESKTOP_INIT_JS.contains("__kolimiDesktopSync"));
        assert!(!DESKTOP_INIT_JS.contains("Sync folders"));
    }

    #[test]
    fn session_token_reads_the_login_cookie() {
        use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};

        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("kolimi_csrf=csrf-value; Path=/; HttpOnly"),
        );
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("kolimi_session=deadbeef; Path=/; HttpOnly"),
        );
        assert_eq!(session_token(&headers).as_deref(), Some("deadbeef"));

        let empty = HeaderMap::new();
        assert_eq!(session_token(&empty), None);
    }

    fn login_server(
        status: &'static str,
        body: &'static str,
        cookie: Option<&'static str>,
    ) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let mut response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some(cookie) = cookie {
                response.push_str(&format!("Set-Cookie: {cookie}\r\n"));
            }
            response.push_str("\r\n");
            response.push_str(body);
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{address}")
    }

    #[test]
    fn session_login_supports_totp_and_returns_the_cookie_token() {
        let server = login_server(
            "200 OK",
            r#"{"expires_at": 4102444800000}"#,
            Some("kolimi_session=feedface; Path=/; HttpOnly"),
        );
        match tauri::async_runtime::block_on(session_login(&server, "alice", "pw", "123456"))
            .unwrap()
        {
            SessionLogin::Success(token) => assert_eq!(token, "feedface"),
            SessionLogin::TotpRequired => panic!("expected a session"),
            SessionLogin::MfaSetupRequired => panic!("expected a session"),
        }

        let server = login_server(
            "401 Unauthorized",
            r#"{"error":"two-factor code required","totp_required":true}"#,
            None,
        );
        assert!(matches!(
            tauri::async_runtime::block_on(session_login(&server, "alice", "pw", "")).unwrap(),
            SessionLogin::TotpRequired
        ));
    }

    #[test]
    fn app_password_creation_reads_the_one_time_token() {
        let server = login_server(
            "201 Created",
            r#"{"id":7,"name":"Kolimi Desktop","token":"one-time-token"}"#,
            None,
        );
        let token = tauri::async_runtime::block_on(create_app_password(
            &server,
            "session-token",
            "Kolimi Desktop",
        ))
        .unwrap();
        assert_eq!(token, "one-time-token");
    }

    #[test]
    fn secrets_accept_an_app_password_without_a_password() {
        let app_only = Secrets {
            password: String::new(),
            e2ee_passphrase: None,
            app_password: Some("app-password".to_string()),
        };
        assert!(app_only.signed_in());
        assert_eq!(app_only.sync_password(), "app-password");

        let password_only = Secrets {
            password: "account-password".to_string(),
            e2ee_passphrase: None,
            app_password: None,
        };
        assert!(password_only.signed_in());
        assert_eq!(password_only.sync_password(), "account-password");

        let signed_out = Secrets {
            password: String::new(),
            e2ee_passphrase: Some("pp".to_string()),
            app_password: None,
        };
        assert!(!signed_out.signed_in());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn session_keyring_round_trip() {
        let description = "kolimi-desktop:selftest";
        if !keyctl::session_set(description, b"secret-value") {
            return;
        }
        assert_eq!(
            keyctl::session_get(description),
            Some(b"secret-value".to_vec())
        );
        assert!(keyctl::session_set(description, b"other"));
        assert_eq!(keyctl::session_get(description), Some(b"other".to_vec()));
        keyctl::session_delete(description);
        assert_eq!(keyctl::session_get(description), None);
    }

    #[test]
    fn migrate_v1_to_v2() {
        let v1 = V1Config {
            server: "https://cloud.example.com/".to_string(),
            username: "alice".to_string(),
            password: "pw".to_string(),
            local_dir: "/home/alice/Kolimi".to_string(),
            encrypted_roots: vec!["Private".to_string()],
            e2ee_passphrase: Some("pp".to_string()),
            autostart: true,
        };
        let settings = migrated_settings(&v1);
        assert_eq!(settings.version, 2);
        assert!(settings.autostart);
        assert_eq!(settings.accounts.len(), 1);
        let account = &settings.accounts[0];
        assert_eq!(account.username, "alice");
        let pair = &account.pairs[0];
        assert_eq!(pair.local_dir, "/home/alice/Kolimi");
        assert_eq!(pair.remote, "/");
        assert_eq!(pair.encrypted_roots, vec!["Private".to_string()]);
    }

    #[test]
    fn normalize_helpers() {
        assert_eq!(normalize_server("https://x.y/"), "https://x.y");
        assert_eq!(normalize_remote(""), "/");
        assert_eq!(normalize_remote("Private/"), "/Private");
        assert_eq!(normalize_remote("/a/b"), "/a/b");
    }

    #[test]
    fn desktop_ui_assets_are_linked() {
        let html = include_str!("../ui/index.html");
        assert!(html.contains("href=\"style.css\""));
        assert!(html.contains("src=\"app.js\""));
        assert!(include_str!("../ui/style.css").contains("--accent"));
        assert!(include_str!("../ui/app.js").contains("get_settings"));
    }
}
