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
//!   "e2ee_passphrase": "…"
//! }
//! ```
//!
//! When no config exists, a first-run setup window writes it. It syncs on
//! startup, every five minutes, and on demand from the tray menu. Platform
//! keychains (week 3) will move the `password`/`e2ee_passphrase` fields out of
//! this file; until then it is written `chmod 600`.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{
    Manager, WebviewUrl, WebviewWindowBuilder,
    image::Image,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    webview::DownloadEvent,
};
use url::Url;

/// Background sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// On-disk settings. (Secrets move to the OS keychain in week 3.)
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
    syncing: AtomicBool,
}

fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("KOLIMI_DESKTOP_CONFIG") {
        return PathBuf::from(path);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("kolimi").join("desktop.json")
}

fn load_config_file() -> Result<DesktopConfig, String> {
    let path = config_path();
    let bytes =
        std::fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn save_config_file(config: &DesktopConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(config).map_err(|error| error.to_string())?;
    std::fs::write(&path, json)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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
        if state.syncing.swap(true, Ordering::SeqCst) {
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
    tauri::async_runtime::spawn(async move {
        let text = match kolimi_sync::sync_once(&sync_config).await {
            Ok(report) => format!(
                "Last sync: ↑{} ↓{} ⚠{}",
                report.pushed, report.pulled, report.conflicts
            ),
            Err(error) => format!("Sync failed: {error}"),
        };
        let state = app_handle.state::<DesktopState>();
        state.syncing.store(false, Ordering::SeqCst);
        let _ = status_item.set_text(text);
    });
}

/// Return the saved settings, or `null` for first run (prefills the form).
#[tauri::command]
fn load_config() -> Option<DesktopConfig> {
    load_config_file().ok()
}

/// Persist settings, open the main window, and kick off a first sync.
#[tauri::command]
fn save_config(app: tauri::AppHandle, config: DesktopConfig) -> Result<(), String> {
    save_config_file(&config)?;
    *app.state::<DesktopState>().config.lock().unwrap() = Some(config.clone());
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
            let status = MenuItem::with_id(app, "status", "Last sync: never", false, None::<&str>)?;
            let open = MenuItem::with_id(app, "open", "Open Kolimi", true, None::<&str>)?;
            let folder = MenuItem::with_id(app, "folder", "Open folder", true, None::<&str>)?;
            let sync_now = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
            let setup = MenuItem::with_id(app, "setup", "Setup…", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status, &open, &folder, &sync_now, &setup, &quit])?;

            let icon = Image::from_bytes(include_bytes!("../icon.png"))?;
            TrayIconBuilder::new()
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
                    "setup" => open_settings(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            let config = load_config_file().ok();
            app.manage(DesktopState {
                config: Mutex::new(config.clone()),
                status_item: status,
                syncing: AtomicBool::new(false),
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
