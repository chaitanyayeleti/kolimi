//! Kolimi desktop client (phase 1, Option A: remote webview).
//!
//! A native Tauri window loads the server's `/app/` UI (the same Leptos app
//! the browser uses), with a tray icon and background sync alongside. Reads
//! `~/.config/kolimi/desktop.json` (or `$KOLIMI_DESKTOP_CONFIG`):
//!
//! ```json
//! {
//!   "server": "https://cloud.example.com",
//!   "username": "alice",
//!   "password": "…",
//!   "local_dir": "/home/alice/Kolimi",
//!   "encrypted_roots": ["Private"],
//!   "e2ee_passphrase": "…",
//!   "autostart": false
//! }
//! ```
//!
//! When no config exists, a first-run setup window writes it. It syncs on
//! startup, every five minutes, and on demand from the tray menu, with a tray
//! icon that reflects idle/syncing/error and a desktop notification on
//! failures and conflicts. The `password` and `e2ee_passphrase` live in the
//! **OS keychain** (Secret Service via zbus on Linux). If no keychain is
//! running they fall back to the Linux **kernel session keyring** (`keyctl`,
//! session-only, never written to disk); only if both are unavailable do they
//! fall back to the file, which is written `chmod 600` and warned about.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{
    Manager, WebviewUrl, WebviewWindowBuilder,
    image::Image,
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    webview::DownloadEvent,
};
use url::Url;

/// Background sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// On-disk settings. (Secrets move to the OS keychain in week 4.)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DesktopConfig {
    server: String,
    username: String,
    password: String,
    local_dir: String,
    #[serde(default)]
    encrypted_roots: Vec<String>,
    #[serde(default)]
    e2ee_passphrase: Option<String>,
    /// Launch in the background on login (XDG autostart entry).
    #[serde(default)]
    autostart: bool,
}

impl DesktopConfig {
    fn sync_config(&self) -> kolimi_sync::SyncConfig {
        kolimi_sync::SyncConfig {
            server: self.server.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            local_dir: PathBuf::from(&self.local_dir),
            e2ee: (!self.encrypted_roots.is_empty()).then(|| kolimi_sync::E2eeOptions {
                passphrase: self.e2ee_passphrase.clone(),
                recovery_code: None,
                prf_secret: None,
                encrypted_roots: self.encrypted_roots.clone(),
            }),
        }
    }
}

struct DesktopState {
    config: Mutex<Option<DesktopConfig>>,
    status_item: MenuItem<tauri::Wry>,
    encryption_item: MenuItem<tauri::Wry>,
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

fn load_config_file() -> Result<DesktopConfig, String> {
    let path = config_path();
    let bytes =
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut config: DesktopConfig =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if let Some(secrets) = keyring_get(&config.server) {
        if !secrets.password.is_empty() {
            config.password = secrets.password;
        }
        if secrets.e2ee_passphrase.is_some() {
            config.e2ee_passphrase = secrets.e2ee_passphrase;
        }
    }
    Ok(config)
}

fn save_config_file(config: &DesktopConfig) -> Result<SecretStorage, String> {
    // Prefer the OS keychain, then a session-only kernel keyring; only write
    // secrets into the (0600) file as a last resort.
    let secrets = Secrets {
        password: config.password.clone(),
        e2ee_passphrase: config.e2ee_passphrase.clone(),
    };
    let storage = store_secrets(&config.server, &secrets);
    let mut on_disk = config.clone();
    if storage != SecretStorage::File {
        on_disk.password = String::new();
        on_disk.e2ee_passphrase = None;
    }
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(&on_disk).map_err(|error| error.to_string())?;
    std::fs::write(&path, json)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(storage)
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

/// One-line E2EE status for the tray/setup UI.
fn e2ee_summary(config: Option<&DesktopConfig>) -> String {
    match config {
        Some(config) if !config.encrypted_roots.is_empty() => {
            let unlocked = config
                .e2ee_passphrase
                .as_deref()
                .is_some_and(|passphrase| !passphrase.is_empty());
            format!(
                "Encryption: {} root(s), {}",
                config.encrypted_roots.len(),
                if unlocked { "unlocked" } else { "locked" }
            )
        }
        _ => "Encryption: off".to_string(),
    }
}

/// Secrets kept in the OS keychain (keyed by server URL).
#[derive(Serialize, Deserialize)]
struct Secrets {
    password: String,
    #[serde(default)]
    e2ee_passphrase: Option<String>,
}

/// Keychain service name for secret entries.
const KEYRING_SERVICE: &str = "kolimi-desktop";

/// Read stored secrets for `server`: OS keychain first, then session keyring.
fn keyring_get(server: &str) -> Option<Secrets> {
    let raw = secret_service_get(server).or_else(|| session_get(server))?;
    serde_json::from_str(&raw).ok()
}

/// Store secrets: OS keychain, else session keyring, else the file.
fn store_secrets(server: &str, secrets: &Secrets) -> SecretStorage {
    let Ok(raw) = serde_json::to_string(secrets) else {
        return SecretStorage::File;
    };
    if secret_service_set(server, &raw) {
        return SecretStorage::Keychain;
    }
    if session_set(server, &raw) {
        return SecretStorage::Session;
    }
    SecretStorage::File
}

fn secret_service_get(server: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, server).ok()?;
    entry.get_password().ok()
}

fn secret_service_set(server: &str, raw: &str) -> bool {
    let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, server) else {
        return false;
    };
    entry.set_password(raw).is_ok()
}

/// Session-keyring description for a server.
fn session_description(server: &str) -> String {
    format!("{KEYRING_SERVICE}:{server}")
}

fn session_set(server: &str, raw: &str) -> bool {
    keyctl::session_set(&session_description(server), raw.as_bytes())
}

fn session_get(server: &str) -> Option<String> {
    let bytes = keyctl::session_get(&session_description(server))?;
    String::from_utf8(bytes).ok()
}

/// Linux kernel session keyring (`keyctl`): a session-only fallback that never
/// touches disk. Non-Linux platforms are no-ops.
#[cfg(target_os = "linux")]
mod keyctl {
    use std::ffi::CString;

    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;

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

    /// Read the payload of a "user" key in the session keyring.
    pub fn session_get(description: &str) -> Option<Vec<u8>> {
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
        if id < 0 {
            return None;
        }
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
}

#[cfg(not(target_os = "linux"))]
mod keyctl {
    pub fn session_set(_description: &str, _payload: &[u8]) -> bool {
        false
    }
    pub fn session_get(_description: &str) -> Option<Vec<u8>> {
        None
    }
}

/// Path of the XDG autostart entry.
fn autostart_path() -> PathBuf {
    config_base()
        .join("autostart")
        .join("kolimi-desktop.desktop")
}

/// Create or remove the XDG autostart entry.
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
             Exec={}\n\
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

/// The user's download directory (`$HOME/Downloads`).
fn downloads_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| PathBuf::from(home).join("Downloads"))
}

/// A desktop notification; a no-op if no notification daemon is present.
fn notify_user(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname("Kolimi")
        .summary(summary)
        .body(body)
        .show();
}

/// Swap the tray icon + tooltip to reflect sync state.
fn set_tray_icon(app: &tauri::AppHandle, state: &str) {
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

fn open_main(app: &tauri::AppHandle, config: &DesktopConfig) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_focus();
        return Ok(());
    }
    let base = config.server.trim_end_matches('/');
    let url = Url::parse(&format!("{base}/app/"))
        .map_err(|error| format!("invalid server URL: {error}"))?;
    WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("Kolimi")
        .inner_size(1100.0, 720.0)
        // Let the web UI's own drag & drop handle OS file drops (upload) and
        // internal moves; Tauri's native file-drop handler would swallow them.
        .disable_drag_drop_handler()
        // Route the web UI's downloads to the user's Downloads folder and
        // reflect the result in the tray instead of failing silently.
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
    Ok(())
}

fn open_settings(app: &tauri::AppHandle) {
    if app.get_webview_window("settings").is_some() {
        return;
    }
    let _ = WebviewWindowBuilder::new(app, "settings", WebviewUrl::App("index.html".into()))
        .title("Kolimi — setup")
        .inner_size(560.0, 640.0)
        .build();
}

fn run_sync(app: tauri::AppHandle) {
    let (config, status_item) = {
        let state = app.state::<DesktopState>();
        if state.paused.load(Ordering::SeqCst) || state.syncing.swap(true, Ordering::SeqCst) {
            return;
        }
        let config = state.config.lock().unwrap().clone();
        (config, state.status_item.clone())
    };
    let Some(config) = config else {
        let _ = status_item.set_text("Not configured");
        app.state::<DesktopState>()
            .syncing
            .store(false, Ordering::SeqCst);
        return;
    };
    let sync_config = config.sync_config();
    let app_handle = app.clone();
    let _ = status_item.set_text("Syncing…");
    set_tray_icon(&app, "syncing");
    tauri::async_runtime::spawn(async move {
        let result = kolimi_sync::sync_once(&sync_config).await;
        let state = app_handle.state::<DesktopState>();
        state.syncing.store(false, Ordering::SeqCst);
        match result {
            Ok(report) => {
                let _ = state.status_item.set_text(format!(
                    "Last sync: ↑{} ↓{} ⚠{}",
                    report.pushed, report.pulled, report.conflicts
                ));
                if report.conflicts > 0 {
                    set_tray_icon(&app_handle, "error");
                    notify_user(
                        "Kolimi sync",
                        &format!(
                            "{} conflict(s) — local edits kept as .conflict-* files",
                            report.conflicts
                        ),
                    );
                } else {
                    set_tray_icon(&app_handle, "idle");
                }
            }
            Err(error) => {
                let _ = state.status_item.set_text(format!("Sync failed: {error}"));
                set_tray_icon(&app_handle, "error");
                notify_user("Kolimi sync failed", &error.to_string());
            }
        }
    });
}

/// Return the saved settings, or `null` for first run (prefills the form).
#[tauri::command]
fn load_config() -> Option<DesktopConfig> {
    load_config_file().ok()
}

/// Persist settings, apply autostart, open the main window, and sync.
#[tauri::command]
fn save_config(app: tauri::AppHandle, config: DesktopConfig) -> Result<(), String> {
    let storage = save_config_file(&config)?;
    if storage == SecretStorage::File {
        notify_user(
            "Kolimi",
            "No OS keychain or session keyring — the password is stored in the 0600 config file.",
        );
    }
    if let Err(error) = set_autostart(config.autostart) {
        notify_user("Kolimi", &format!("autostart: {error}"));
    }
    {
        let state = app.state::<DesktopState>();
        *state.config.lock().unwrap() = Some(config.clone());
        let _ = state.encryption_item.set_text(e2ee_summary(Some(&config)));
    }
    open_main(&app, &config)?;
    if let Some(window) = app.get_webview_window("settings") {
        let _ = window.close();
    }
    run_sync(app);
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![load_config, save_config])
        .setup(|app| {
            let config = load_config_file().ok();
            let autostart_on = config.as_ref().is_some_and(|config| config.autostart);

            let status = MenuItem::with_id(app, "status", "Last sync: never", false, None::<&str>)?;
            let encryption = MenuItem::with_id(
                app,
                "encryption",
                e2ee_summary(config.as_ref()),
                false,
                None::<&str>,
            )?;
            let open = MenuItem::with_id(app, "open", "Open Kolimi", true, None::<&str>)?;
            let folder = MenuItem::with_id(app, "folder", "Open folder", true, None::<&str>)?;
            let sync_now = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "Pause syncing", true, None::<&str>)?;
            let autostart = CheckMenuItem::with_id(
                app,
                "autostart",
                "Start on login",
                true,
                autostart_on,
                None::<&str>,
            )?;
            let setup = MenuItem::with_id(app, "setup", "Setup…", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &status,
                    &encryption,
                    &open,
                    &folder,
                    &sync_now,
                    &pause,
                    &autostart,
                    &setup,
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
                        let config = app.state::<DesktopState>().config.lock().unwrap().clone();
                        match config {
                            Some(config) => {
                                let _ = open_main(app, &config);
                            }
                            None => open_settings(app),
                        }
                    }
                    "folder" => {
                        let config = app.state::<DesktopState>().config.lock().unwrap().clone();
                        if let Some(config) = config {
                            open_folder(&config.local_dir);
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
                                match state.config.lock().unwrap().as_mut() {
                                    Some(config) => {
                                        config.autostart = enabled;
                                        Some(config.clone())
                                    }
                                    None => None,
                                }
                            };
                            if let Some(config) = saved {
                                let _ = save_config_file(&config);
                            }
                        }
                    }
                    "setup" => open_settings(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            app.manage(DesktopState {
                config: Mutex::new(config.clone()),
                status_item: status,
                encryption_item: encryption,
                syncing: AtomicBool::new(false),
                paused: AtomicBool::new(false),
            });

            match config {
                Some(config) => {
                    if let Err(error) = open_main(app.handle(), &config) {
                        eprintln!("kolimi-desktop: {error}");
                        open_settings(app.handle());
                    }
                }
                None => open_settings(app.handle()),
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
    #[test]
    #[cfg(target_os = "linux")]
    fn session_keyring_round_trip() {
        let description = "kolimi-desktop:selftest";
        if !super::keyctl::session_set(description, b"secret-value") {
            // No session keyring in this environment; nothing to assert.
            return;
        }
        assert_eq!(
            super::keyctl::session_get(description),
            Some(b"secret-value".to_vec())
        );
        // Updating the same description replaces the payload.
        assert!(super::keyctl::session_set(description, b"other"));
        assert_eq!(
            super::keyctl::session_get(description),
            Some(b"other".to_vec())
        );
    }
}
