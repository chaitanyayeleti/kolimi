//! Kolimi tray: a background sync shell around the `kolimi-sync` core.
//!
//! Reads `~/.config/kolimi/tray.json` (or `$KOLIMI_TRAY_CONFIG`):
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
//! It syncs on startup, every five minutes, and on demand from the tray
//! menu. Platform keychains are the next step for the password and
//! passphrase fields; for now the file should be `chmod 600`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tauri::{
    Manager,
    image::Image,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};

/// Sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Deserialize)]
struct TrayConfig {
    server: String,
    username: String,
    password: String,
    local_dir: String,
    #[serde(default)]
    encrypted_roots: Vec<String>,
    e2ee_passphrase: Option<String>,
}

impl TrayConfig {
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

struct TrayState {
    config: TrayConfig,
    status_item: MenuItem<tauri::Wry>,
    syncing: AtomicBool,
}

fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("KOLIMI_TRAY_CONFIG") {
        return PathBuf::from(path);
    }
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            PathBuf::from(home).join(".config")
        });
    base.join("kolimi").join("tray.json")
}

fn load_config() -> Result<TrayConfig, String> {
    let path = config_path();
    let bytes = std::fs::read(&path).map_err(|error| {
        format!(
            "cannot read {}: {error} (see the doc comment for the format)",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
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

fn run_sync(app: tauri::AppHandle) {
    let state = app.state::<TrayState>();
    if state.syncing.swap(true, Ordering::SeqCst) {
        return;
    }
    let config = state.config.sync_config();
    let status_item = state.status_item.clone();
    let app_handle = app.clone();
    let _ = status_item.set_text("Syncing…");
    tauri::async_runtime::spawn(async move {
        let result = kolimi_sync::sync_once(&config).await;
        let text = match result {
            Ok(report) => format!(
                "Last sync: ↑{} ↓{} ⚠{}",
                report.pushed, report.pulled, report.conflicts
            ),
            Err(error) => format!("Sync failed: {error}"),
        };
        let state = app_handle.state::<TrayState>();
        state.syncing.store(false, Ordering::SeqCst);
        let _ = status_item.set_text(text);
    });
}

fn main() {
    let config = match load_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("kolimi-tray: {error}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        .setup(move |app| {
            let status = MenuItem::with_id(app, "status", "Last sync: never", false, None::<&str>)?;
            let sync_now = MenuItem::with_id(app, "sync", "Sync now", true, None::<&str>)?;
            let open = MenuItem::with_id(app, "open", "Open folder", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status, &sync_now, &open, &quit])?;

            let icon = Image::from_bytes(include_bytes!("../icon.png"))?;
            let local_dir = config.local_dir.clone();
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Kolimi")
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "sync" => run_sync(app.clone()),
                    "open" => open_folder(&local_dir),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            app.manage(TrayState {
                config,
                status_item: status,
                syncing: AtomicBool::new(false),
            });

            // Initial sync shortly after startup, then on the interval.
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
        .expect("error while running the Kolimi tray");
}
