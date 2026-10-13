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

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager, WebviewUrl, WebviewWindowBuilder,
    image::Image,
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    webview::DownloadEvent,
};
use url::Url;

/// Background sync cadence. Kept short so remote changes land promptly;
/// opening the window also triggers a sync (see `open_main`).
const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the "close to tray" tip has been shown this session.
static CLOSE_TIP_SHOWN: AtomicBool = AtomicBool::new(false);

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
}

/// One local directory mirrored to a remote subpath.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncPair {
    local_dir: String,
    #[serde(default = "default_remote")]
    remote: String,
    #[serde(default)]
    encrypted_roots: Vec<String>,
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
        password: secrets.password.clone(),
        local_dir: PathBuf::from(&pair.local_dir),
        e2ee: (!pair.encrypted_roots.is_empty()).then(|| kolimi_sync::E2eeOptions {
            passphrase: secrets.e2ee_passphrase.clone(),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: pair.encrypted_roots.clone(),
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
    password: String,
    #[serde(default)]
    e2ee_passphrase: Option<String>,
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
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, key) {
        let _ = entry.delete_credential();
    }
    keyctl::session_delete(&session_description(key));
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

struct DesktopState {
    settings: Mutex<Settings>,
    status_item: MenuItem<tauri::Wry>,
    syncing: AtomicBool,
    paused: AtomicBool,
}

fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("KOLIMI_DESKTOP_CONFIG") {
        return PathBuf::from(path);
    }
    config_base().join("kolimi").join("desktop.json")
}

fn config_base() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        })
}

fn expand_home(path: &str) -> String {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        return format!("{home}/{rest}");
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

fn host(server: &str) -> String {
    Url::parse(server)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .unwrap_or_else(|| server.to_string())
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
            pairs: vec![SyncPair {
                local_dir: v1.local_dir.clone(),
                remote: "/".to_string(),
                encrypted_roots: v1.encrypted_roots.clone(),
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
    std::fs::write(&path, json)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Autostart
// ---------------------------------------------------------------------------

fn autostart_path() -> PathBuf {
    config_base()
        .join("autostart")
        .join("kolimi-desktop.desktop")
}

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
        std::fs::write(&path, contents)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    } else if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|error| format!("cannot remove {}: {error}", path.display()))
    } else {
        Ok(())
    }
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
    let _ = std::process::Command::new(opener).arg(path).spawn();
}

fn downloads_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join("Downloads"))
}

fn notify_user(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname("Kolimi")
        .summary(summary)
        .body(body)
        .show();
}

fn set_tray_icon(app: &AppHandle, state: &str) {
    let (bytes, tooltip): (&[u8], &str) = match state {
        "syncing" => (include_bytes!("../tray-syncing.png"), "Kolimi — syncing…"),
        "error" => (include_bytes!("../tray-error.png"), "Kolimi — sync problem"),
        "paused" => (include_bytes!("../tray-idle.png"), "Kolimi — paused"),
        _ => (include_bytes!("../tray-idle.png"), "Kolimi"),
    };
    if let Ok(icon) = Image::from_bytes(bytes)
        && let Some(tray) = app.tray_by_id("main")
    {
        let _ = tray.set_icon(Some(icon));
        let _ = tray.set_tooltip(Some(tooltip));
    }
}

/// Validate credentials against the server (any authenticated endpoint).
async fn validate_login(server: &str, username: &str, password: &str) -> Result<(), String> {
    let url = format!("{}/api/me/usage", server.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(&url)
        .basic_auth(username, Some(password))
        .send()
        .await
        .map_err(|error| format!("cannot reach server: {error}"))?;
    match response.status().as_u16() {
        200..=299 => Ok(()),
        401 | 403 => Err("invalid username or password".to_string()),
        code => Err(format!("server returned HTTP {code}")),
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

fn open_main(app: &AppHandle, server: &str) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        // Opening the app should reflect the server right away.
        run_sync(app.clone());
        return Ok(());
    }
    let base = server.trim_end_matches('/');
    let url = Url::parse(&format!("{base}/app/"))
        .map_err(|error| format!("invalid server URL: {error}"))?;
    let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("Kolimi")
        .inner_size(1100.0, 720.0)
        .disable_drag_drop_handler()
        .on_download(|webview, event| {
            match event {
                DownloadEvent::Requested { destination, .. } => {
                    if let Some(dir) = downloads_dir() {
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
    let _ = WebviewWindowBuilder::new(app, "settings", WebviewUrl::App("index.html".into()))
        .title("Kolimi — Accounts & Sync")
        .inner_size(680.0, 720.0)
        .build();
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

fn run_sync(app: AppHandle) {
    let (settings, status_item) = {
        let state = app.state::<DesktopState>();
        if state.paused.load(Ordering::SeqCst) || state.syncing.swap(true, Ordering::SeqCst) {
            return;
        }
        (
            state.settings.lock().unwrap().clone(),
            state.status_item.clone(),
        )
    };
    if settings.accounts.is_empty() {
        let _ = status_item.set_text("No account configured");
        app.state::<DesktopState>()
            .syncing
            .store(false, Ordering::SeqCst);
        return;
    }

    // Build the sync jobs up front (keychain reads are blocking).
    let mut jobs: Vec<(String, String, kolimi_sync::SyncConfig)> = Vec::new();
    let mut startup_errors: Vec<String> = Vec::new();
    for account in &settings.accounts {
        let Some(secrets) = keyring_get(&account_key(&account.server, &account.username)) else {
            startup_errors.push(format!(
                "{}@{}: not signed in",
                account.username,
                host(&account.server)
            ));
            continue;
        };
        for pair in &account.pairs {
            jobs.push((
                short_dir(&pair.local_dir),
                pair.remote.clone(),
                pair_sync_config(account, pair, &secrets),
            ));
        }
    }

    let _ = status_item.set_text("Syncing…");
    set_tray_icon(&app, "syncing");
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let total = jobs.len();
        let (mut pushed, mut pulled, mut conflicts) = (0u64, 0u64, 0u64);
        let mut errors = startup_errors;
        for (label, remote, config) in jobs {
            match kolimi_sync::sync_once_rooted(&config, &remote).await {
                Ok(report) => {
                    pushed += report.pushed;
                    pulled += report.pulled;
                    conflicts += report.conflicts;
                }
                Err(error) => errors.push(format!("{label}: {error}")),
            }
        }
        let state = app_handle.state::<DesktopState>();
        state.syncing.store(false, Ordering::SeqCst);
        if errors.is_empty() {
            let _ = state.status_item.set_text(format!(
                "Synced {total} dir(s): ↑{pushed} ↓{pulled} ⚠{conflicts}"
            ));
            if conflicts > 0 {
                set_tray_icon(&app_handle, "error");
                notify_user(
                    "Kolimi sync",
                    &format!("{conflicts} conflict(s) — local edits kept as .conflict-* files"),
                );
            } else {
                set_tray_icon(&app_handle, "idle");
            }
        } else {
            let first = errors.first().cloned().unwrap_or_default();
            let _ = state.status_item.set_text(format!("Sync failed: {first}"));
            set_tray_icon(&app_handle, "error");
            notify_user("Kolimi sync problem", &errors.join("\n"));
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
}

#[derive(Serialize)]
struct AccountView {
    server: String,
    username: String,
    signed_in: bool,
    pairs: Vec<PairView>,
}

#[derive(Serialize)]
struct SettingsView {
    accounts: Vec<AccountView>,
    autostart: bool,
}

/// The current settings, with a `signed_in` flag per account (no secrets).
#[tauri::command]
fn get_settings(app: AppHandle) -> SettingsView {
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
    let accounts = settings
        .accounts
        .iter()
        .map(|account| AccountView {
            signed_in: keyring_get(&account_key(&account.server, &account.username)).is_some(),
            server: account.server.clone(),
            username: account.username.clone(),
            pairs: account
                .pairs
                .iter()
                .map(|pair| PairView {
                    local_dir: pair.local_dir.clone(),
                    remote: pair.remote.clone(),
                    encrypted_roots: pair.encrypted_roots.clone(),
                })
                .collect(),
        })
        .collect();
    SettingsView {
        accounts,
        autostart: settings.autostart,
    }
}

/// Sign in (or re-authenticate) an account; stores the password and kicks off
/// a sync.
#[tauri::command]
async fn sign_in(
    app: AppHandle,
    server: String,
    username: String,
    password: String,
) -> Result<(), String> {
    let server = normalize_server(&server);
    if server.is_empty() || username.is_empty() {
        return Err("server and username are required".to_string());
    }
    validate_login(&server, &username, &password).await?;
    store_secrets(
        &account_key(&server, &username),
        &Secrets {
            password,
            e2ee_passphrase: None,
        },
    );
    {
        let state = app.state::<DesktopState>();
        let mut settings = state.settings.lock().unwrap();
        if !settings
            .accounts
            .iter()
            .any(|account| account.server == server && account.username == username)
        {
            settings.accounts.push(Account {
                server: server.clone(),
                username: username.clone(),
                pairs: Vec::new(),
            });
        }
    }
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Forget an account's password (keeps its configuration).
#[tauri::command]
fn sign_out(app: AppHandle, server: String, username: String) {
    delete_secrets(&account_key(&server, &username));
    run_sync(app);
}

/// Remove an account entirely (configuration + password).
#[tauri::command]
fn remove_account(app: AppHandle, server: String, username: String) -> Result<(), String> {
    delete_secrets(&account_key(&server, &username));
    {
        let state = app.state::<DesktopState>();
        let mut settings = state.settings.lock().unwrap();
        settings
            .accounts
            .retain(|account| !(account.server == server && account.username == username));
    }
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
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
) -> Result<(), String> {
    let local = expand_home(&dir);
    if local.is_empty() {
        return Err("directory is required".to_string());
    }
    std::fs::create_dir_all(&local).map_err(|error| format!("cannot create {local}: {error}"))?;
    {
        let state = app.state::<DesktopState>();
        let mut settings = state.settings.lock().unwrap();
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
            encrypted_roots: Vec::new(),
        });
    }
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
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
    {
        let state = app.state::<DesktopState>();
        let mut settings = state.settings.lock().unwrap();
        let account = settings
            .accounts
            .iter_mut()
            .find(|account| account.server == server && account.username == username)
            .ok_or_else(|| "account not found".to_string())?;
        account.pairs.retain(|pair| pair.local_dir != dir);
    }
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
    save_settings_file(&settings)?;
    run_sync(app);
    Ok(())
}

/// Toggle the "start on login" autostart entry.
#[tauri::command]
fn set_autostart_enabled(app: AppHandle, enabled: bool) -> Result<(), String> {
    set_autostart(enabled)?;
    {
        let state = app.state::<DesktopState>();
        state.settings.lock().unwrap().autostart = enabled;
    }
    let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
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
// main
// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_settings,
            sign_in,
            sign_out,
            remove_account,
            add_pair,
            remove_pair,
            set_autostart_enabled,
            sync_now,
            open_account
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
            let menu = Menu::with_items(
                app,
                &[
                    &status,
                    &open,
                    &folder,
                    &sync_now_item,
                    &pause,
                    &autostart,
                    &settings_item,
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
                        let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
                        match settings.accounts.first() {
                            Some(account) => {
                                let _ = open_main(app, &account.server);
                            }
                            None => open_settings(app),
                        }
                    }
                    "folder" => {
                        let settings = app.state::<DesktopState>().settings.lock().unwrap().clone();
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
                        let paused = {
                            let state = app.state::<DesktopState>();
                            let paused = !state.paused.load(Ordering::SeqCst);
                            state.paused.store(paused, Ordering::SeqCst);
                            paused
                        };
                        let _ = pause_item.set_text(if paused {
                            "Resume syncing"
                        } else {
                            "Pause syncing"
                        });
                        let _ = app.state::<DesktopState>().status_item.set_text(if paused {
                            "Paused"
                        } else {
                            "Idle"
                        });
                        if paused {
                            set_tray_icon(app, "paused");
                        } else {
                            set_tray_icon(app, "idle");
                            run_sync(app.clone());
                        }
                    }
                    "autostart" => {
                        let enabled = autostart_item.is_checked().unwrap_or(false);
                        if let Err(error) = set_autostart(enabled) {
                            notify_user("Kolimi", &format!("autostart: {error}"));
                            let _ = autostart_item.set_checked(!enabled);
                        } else {
                            let saved = {
                                let state = app.state::<DesktopState>();
                                let mut settings = state.settings.lock().unwrap();
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
}
