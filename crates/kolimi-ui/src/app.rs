//! The authenticated application: login, file browser, shares, trash.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, closure::Closure};

use crate::api;

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Loading,
    Login,
    Browser,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Files,
    Trash,
}

#[derive(Clone, PartialEq)]
struct Entry {
    name: String,
    path: String,
    kind: String,
    size: u64,
    modified_at: i64,
    shared: bool,
    owner: Option<String>,
    permission: Option<String>,
    encrypted: bool,
}

#[derive(Clone, PartialEq)]
struct TrashItem {
    id: i64,
    name: String,
    original_path: Option<String>,
    size: u64,
}

#[derive(Clone, PartialEq)]
struct SearchHit {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    modified_at: i64,
    snippet: String,
    encrypted: bool,
}

/// Upload-tray status for one file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadStatus {
    Uploading,
    Done,
    Failed,
}

/// One file in the upload tray.
///
/// Progress and status are their own signals so a row reads them in O(1)
/// instead of scanning the whole tray on every update.
#[derive(Clone)]
struct UploadItem {
    id: u32,
    name: String,
    dir: String,
    progress: RwSignal<u8>,
    status: RwSignal<UploadStatus>,
    file: web_sys::File,
}

fn parse_results(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<SearchHit> {
    body.get("results")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let path = item["path"].as_str().unwrap_or_default().to_string();
                    SearchHit {
                        name: crate::e2ee::display_name_with_shares(master, &path, shares),
                        path,
                        is_dir: item["is_dir"].as_bool().unwrap_or(false),
                        size: item["size"].as_u64().unwrap_or(0),
                        modified_at: item["modified_at"].as_i64().unwrap_or(0),
                        snippet: item["snippet"].as_str().unwrap_or_default().to_string(),
                        encrypted: item["encrypted"].as_bool().unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parent_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        _ => "/".to_string(),
    }
}

fn is_image_name(name: &str) -> bool {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp")
}

fn is_text_name(name: &str) -> bool {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        extension.as_str(),
        "txt"
            | "md"
            | "markdown"
            | "log"
            | "json"
            | "xml"
            | "html"
            | "htm"
            | "css"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "rs"
            | "py"
            | "sh"
            | "toml"
            | "yaml"
            | "yml"
            | "csv"
            | "ini"
            | "conf"
            | "c"
            | "h"
            | "go"
            | "java"
    )
}

/// Sanitizes SVG content to prevent XSS via `inner_html`.
fn sanitize_svg(svg: &str) -> String {
    svg.replace("<script", "<!-script")
        .replace("</script>", "<-/script>")
        .replace("onload=", "data-onload=")
        .replace("onerror=", "data-onerror=")
        .replace("onclick=", "data-onclick=")
}

pub fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Fetches received mounts and unwraps their display names/keys.
async fn received_mounts(
    master: Option<&MasterKey>,
) -> (Vec<Value>, Vec<crate::e2ee::ShareDisplay>) {
    let mut mounts = Vec::new();
    if let Ok(response) = api::get("/api/shares/received").await
        && response.status == 200
    {
        mounts = response.body["mounts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
    }
    let mut shares = Vec::new();
    if let Some(master) = master {
        for mount in &mounts {
            let (Some(wrapped), Some(prefix)) =
                (mount["wrapped_name"].as_str(), mount["mount"].as_str())
            else {
                continue;
            };
            if let Ok((name, key)) = crate::e2ee::unwrap_share_name(master, wrapped).await {
                shares.push(crate::e2ee::ShareDisplay {
                    prefix: prefix.to_string(),
                    name,
                    key,
                });
            }
        }
    }
    (mounts, shares)
}

/// Client-side name search over encrypted items.
///
/// The server indexes only ciphertext (`k1_…`), so it cannot match a
/// plaintext query. This walks the tree (and received share files), decodes
/// names with the unlocked key, and returns name matches. Content search
/// inside encrypted files remains impossible by design.
async fn encrypted_name_hits(
    master: &MasterKey,
    query: &str,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<SearchHit> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();
    #[allow(clippy::too_many_arguments)]
    fn add(
        hits: &mut Vec<SearchHit>,
        seen: &mut std::collections::HashSet<String>,
        master: &MasterKey,
        needle: &str,
        shares: &[crate::e2ee::ShareDisplay],
        path: &str,
        kind: &str,
        size: u64,
        modified_at: i64,
        need_encoded: bool,
    ) {
        if hits.len() >= 50 || !seen.insert(path.to_string()) {
            return;
        }
        if need_encoded
            && !path.split('/').any(kolimi_crypto::is_encoded_name)
            && !shares.iter().any(|share| path.starts_with(&share.prefix))
        {
            return;
        }
        let display = crate::e2ee::decode_display_path_with_shares(Some(master), path, shares);
        let name = display.rsplit('/').next().unwrap_or_default();
        if !name.to_lowercase().contains(needle) {
            return;
        }
        hits.push(SearchHit {
            name: name.to_string(),
            path: path.to_string(),
            is_dir: kind == "dir",
            size,
            modified_at,
            snippet: "Encrypted name match".to_string(),
            encrypted: true,
        });
    }

    let mut after = 0i64;
    loop {
        let url = format!("/api/sync/tree?after_id={after}&limit=1000");
        let Ok(response) = api::get(&url).await else {
            break;
        };
        if response.status != 200 {
            break;
        }
        for entry in response.body["entries"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(path) = entry["path"].as_str() else {
                continue;
            };
            add(
                &mut hits,
                &mut seen,
                master,
                &needle,
                shares,
                path,
                entry["kind"].as_str().unwrap_or("file"),
                entry["size"].as_u64().unwrap_or(0),
                entry["modified_at"].as_i64().unwrap_or(0),
                true,
            );
        }
        if !response.body["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        let last = response.body["last_id"].as_i64().unwrap_or(after);
        if last <= after {
            break;
        }
        after = last;
        if hits.len() >= 50 {
            break;
        }
    }

    // Files received through encrypted shares (folder names inside a share
    // are covered when the client has already browsed them; the shared-tree
    // API lists files).
    if let Ok(response) = api::get("/api/sync/shared-tree").await
        && response.status == 200
        && let Some(entries) = response.body["entries"].as_array()
    {
        for entry in entries {
            let Some(path) = entry["path"].as_str() else {
                continue;
            };
            add(
                &mut hits,
                &mut seen,
                master,
                &needle,
                shares,
                path,
                entry["kind"].as_str().unwrap_or("file"),
                entry["size"].as_u64().unwrap_or(0),
                entry["modified_at"].as_i64().unwrap_or(0),
                false,
            );
        }
    }
    hits
}

fn parse_entries(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<Entry> {
    body.get("entries")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let path = item["path"].as_str().unwrap_or_default().to_string();
                    Entry {
                        name: crate::e2ee::display_name_with_shares(master, &path, shares),
                        path,
                        kind: item["kind"].as_str().unwrap_or("file").to_string(),
                        size: item["size"].as_u64().unwrap_or(0),
                        modified_at: item["modified_at"].as_i64().unwrap_or(0),
                        shared: item["shared"].as_bool().unwrap_or(false),
                        owner: item["owner"].as_str().map(str::to_string),
                        permission: item["permission"].as_str().map(str::to_string),
                        encrypted: item["encrypted"].as_bool().unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_trash(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<TrashItem> {
    body.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let original = item["original_path"].as_str();
                    let display_path = original.map(|path| {
                        crate::e2ee::decode_display_path_with_shares(master, path, shares)
                    });
                    TrashItem {
                        id: item["id"].as_i64().unwrap_or(0),
                        name: display_path
                            .as_deref()
                            .and_then(|path| path.rsplit('/').next())
                            .filter(|name| !name.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| {
                                crate::e2ee::decode_display_name(
                                    master,
                                    item["name"].as_str().unwrap_or_default(),
                                )
                            }),
                        original_path: display_path,
                        size: item["size"].as_u64().unwrap_or(0),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Inline SVG path data for the icon set.
fn icon_svg(name: &str) -> String {
    let body = match name {
        "folder" => {
            r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>"#
        }
        "file" => {
            r#"<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>"#
        }
        "image" => {
            r#"<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.6"/><path d="m5 18 4.5-4.5L13 17l3-2.5L21 18"/>"#
        }
        "trash" => {
            r#"<path d="M4 7h16"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><path d="M7 7l1 13a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2l1-13"/>"#
        }
        "search" => r#"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>"#,
        "menu" => r#"<path d="M4 7h16M4 12h16M4 17h16"/>"#,
        "upload" => r#"<path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 20h16"/>"#,
        "folder-plus" => {
            r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 10v6M9 13h6"/>"#
        }
        "share" => {
            r#"<circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"/>"#
        }
        "edit" => r#"<path d="M4 20h4l10-10-4-4L4 16z"/><path d="m14 6 4 4"/>"#,
        "download" => r#"<path d="M12 4v12"/><path d="m7 11 5 5 5-5"/><path d="M4 20h16"/>"#,
        "users" => {
            r#"<circle cx="9" cy="8" r="3.2"/><path d="M3.5 20a5.5 5.5 0 0 1 11 0"/><path d="M16 5.5a3 3 0 0 1 0 5.8"/><path d="M17 20a5.5 5.5 0 0 0-3-4.9"/>"#
        }
        "key" => r#"<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3"/>"#,
        "settings" => {
            r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>"#
        }
        "sun" => {
            r#"<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>"#
        }
        "logout" => {
            r#"<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="m10 17-5-5 5-5"/><path d="M5 12h12"/>"#
        }
        "dots" => {
            r#"<circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/>"#
        }
        "grid" => {
            r#"<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>"#
        }
        "list" => {
            r#"<path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4.5" cy="6" r="1.3"/><circle cx="4.5" cy="12" r="1.3"/><circle cx="4.5" cy="18" r="1.3"/>"#
        }
        "x" => r#"<path d="M6 6l12 12M18 6 6 18"/>"#,
        "cloud" => r#"<path d="M6 18a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.5A3.5 3.5 0 0 1 18 18z"/>"#,
        "lock" => {
            r#"<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>"#
        }
        "refresh" => r#"<path d="M20 11a8 8 0 1 0-2.3 6.3"/><path d="M20 5v6h-6"/>"#,
        "history" => {
            r#"<path d="M4 5v5h5"/><path d="M4.5 10a8 8 0 1 1-.6 5"/><path d="M12 8v4l3 2"/>"#
        }
        "link" => {
            r#"<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>"#
        }
        _ => r#"<circle cx="12" cy="12" r="8"/>"#,
    };
    format!(
        r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{body}</svg>"#
    )
}

/// A single inline SVG icon.
#[component]
fn Icon(name: &'static str) -> impl IntoView {
    view! { <span class="icon" inner_html=icon_svg(name)></span> }
}

/// The Kolimi brand mark: a gradient tile with a cloud. Matches the app/tray
/// icons (`assets/branding/logo.svg`).
fn logo_svg() -> String {
    r##"<svg viewBox="0 0 32 32" width="100%" height="100%" aria-hidden="true">
<defs><linearGradient id="kolimi-bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#5b8def"/><stop offset="0.55" stop-color="#6f7bf0"/><stop offset="1" stop-color="#9b5cf6"/>
</linearGradient>
<linearGradient id="kolimi-cloud" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#eaf0ff"/>
</linearGradient></defs>
<rect x="0" y="0" width="32" height="32" rx="8.5" fill="url(#kolimi-bg)"/>
<rect x="0.5" y="0.5" width="31" height="31" rx="8" fill="none" stroke="#ffffff" stroke-opacity="0.18"/>
<g fill="url(#kolimi-cloud)">
<circle cx="12.6" cy="18.4" r="3.7"/><circle cx="17.1" cy="15.5" r="5.1"/>
<circle cx="21.6" cy="18.6" r="3.4"/><rect x="12.6" y="17.4" width="9.4" height="4.6" rx="2.3"/>
</g></svg>"##
        .to_string()
}

/// The brand mark, sized for a header badge.
#[component]
fn Logo() -> impl IntoView {
    view! { <span class="logo" inner_html=logo_svg()></span> }
}

/// The icon used for a file-list entry.
fn file_icon(name: &str, kind: &str) -> &'static str {
    if kind == "dir" {
        return "folder";
    }
    if is_image_name(name) {
        return "image";
    }
    "file"
}

/// Flips the `.dark` / `.light` class on `<html>` and persists the choice.
fn toggle_theme() {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return;
    };
    let classes = root.class_list();
    let prefers_dark = web_sys::window()
        .and_then(|window| {
            window
                .match_media("(prefers-color-scheme: dark)")
                .ok()
                .flatten()
        })
        .map(|media| media.matches())
        .unwrap_or(false);
    let is_dark = classes.contains("dark") || (!classes.contains("light") && prefers_dark);
    let _ = classes.remove_1("dark");
    let _ = classes.remove_1("light");
    let _ = classes.add_1(if is_dark { "light" } else { "dark" });
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item("kolimi-theme", if is_dark { "light" } else { "dark" });
    }
}

/// Marks that the session expired, so the login screen can explain why.
fn mark_session_expired() {
    if let Some(storage) =
        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
    {
        let _ = storage.set_item("kolimi-session-expired", "1");
    }
}

/// Formats a Unix-millisecond timestamp as a short relative time.
fn relative_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let seconds = ((js_sys::Date::now() as i64 - ms) / 1000).max(0);
    match seconds {
        s if s < 45 => "just now".to_string(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s if s < 2_592_000 => format!("{}d ago", s / 86_400),
        s if s < 31_536_000 => format!("{}mo ago", s / 2_592_000),
        s => format!("{}y ago", s / 31_536_000),
    }
}

/// Root component.
#[component]
pub fn App() -> impl IntoView {
    let view = RwSignal::new(View::Loading);
    Effect::new(move |_| {
        spawn_local(async move {
            let signed_in = matches!(api::get("/api/me").await, Ok(r) if r.status == 200);
            view.set(if signed_in {
                View::Browser
            } else {
                View::Login
            });
        });
    });

    view! {
        {move || match view.get() {
            View::Loading => view! {
                <div class="login-wrap">
                    <span class="muted">"Loading…"</span>
                </div>
            }
                .into_any(),
            View::Login => view! { <Login view=view/> }.into_any(),
            View::Browser => view! { <Browser view=view/> }.into_any(),
        }}
    }
}

#[component]
fn Login(view: RwSignal<View>) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let needs_code = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    // If we were sent here because a session expired, say so once.
    Effect::new(move |_| {
        if let Some(storage) =
            web_sys::window().and_then(|window| window.session_storage().ok().flatten())
            && storage
                .get_item("kolimi-session-expired")
                .ok()
                .flatten()
                .is_some()
        {
            let _ = storage.remove_item("kolimi-session-expired");
            notice.set("Your session expired — please sign in again.".to_string());
        }
    });

    let submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let (user, pass) = (username.get_untracked(), password.get_untracked());
        if user.is_empty() || pass.is_empty() {
            error.set("Enter username and password".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let payload = if needs_code.get_untracked() {
                json!({ "username": user, "password": pass, "code": code.get_untracked() })
            } else {
                json!({ "username": user, "password": pass })
            };
            let result = api::send_json("POST", "/api/session", &payload).await;
            busy.set(false);
            match result {
                Ok(r) if r.status == 200 => view.set(View::Browser),
                Ok(r) if r.body["totp_required"].as_bool() == Some(true) => {
                    needs_code.set(true);
                    error.set("Enter your two-factor code".to_string());
                }
                Ok(r) if r.status == 401 => {
                    error.set("Incorrect username or password.".to_string())
                }
                Ok(r) if r.status == 429 => {
                    error.set("Too many attempts — wait a minute, then try again.".to_string())
                }
                Ok(r) if r.status == 403 => {
                    error.set("Sign-in was blocked. Please try again.".to_string())
                }
                Ok(r) => error.set(
                    r.error()
                        .unwrap_or("Sign-in failed. Please try again.")
                        .to_string(),
                ),
                Err(_) => {
                    error.set("Couldn't reach the server. Check your connection.".to_string())
                }
            }
        });
    };

    let passkey_login = move |_| {
        let user = username.get_untracked();
        if user.is_empty() {
            error.set("Enter your username, then use the passkey button".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let result = crate::passkey::login(&user).await;
            busy.set(false);
            match result {
                Ok(()) => view.set(View::Browser),
                Err(e) => error.set(e),
            }
        });
    };

    view! {
        <div class="login-wrap">
        <button
            class="icon-btn login-theme"
            aria-label="Toggle theme"
            on:click=move |_| toggle_theme()
        >
            <Icon name="sun"/>
        </button>
        <form class="card login" on:submit=submit>
            <div class="hero">
                <Logo/>
                <h2>"Sign in to Kolimi"</h2>
                <p class="muted">"Your self-hosted cloud."</p>
            </div>
            <Show when=move || !notice.get().is_empty()>
                <p class="muted">{move || notice.get()}</p>
            </Show>
            <label>
                "Username"
                <input
                    type="text"
                    autocomplete="username"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Password"
                <input
                    type="password"
                    autocomplete="current-password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                />
            </label>
            <p class="muted">
                "This is your account password. Your encryption passphrase is separate — you only need it inside the app, to unlock encrypted files."
            </p>
            <Show when=move || needs_code.get()>
                <label>
                    "Two-factor or recovery code"
                    <input
                        type="text"
                        autocomplete="one-time-code"
                        placeholder="6-digit code or recovery code"
                        prop:value=move || code.get()
                        on:input=move |ev| code.set(event_target_value(&ev))
                    />
                </label>
            </Show>
            <button class="primary" type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "Signing in…" } else { "Sign in" }}
            </button>
            <div class="divider">"or"</div>
            <button class="ghost" type="button" disabled=move || busy.get() on:click=passkey_login>
                <Icon name="key"/>
                "Sign in with a passkey"
            </button>
            <Show when=move || !error.get().is_empty()>
                <p class="error">{move || error.get()}</p>
            </Show>
        </form>
        </div>
    }
}

#[component]
fn Browser(view: RwSignal<View>) -> impl IntoView {
    let path = RwSignal::new("/".to_string());
    let entries = RwSignal::new(Vec::<Entry>::new());
    let parent = RwSignal::new(Option::<String>::None);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let tab = RwSignal::new(Tab::Files);
    let trash = RwSignal::new(Vec::<TrashItem>::new());
    let share_target = RwSignal::new(Option::<Entry>::None);
    let versions_for = RwSignal::new(Option::<Entry>::None);
    let vault_setup = RwSignal::new(false);
    let upload_label = RwSignal::new("Upload".to_string());
    let query = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<SearchHit>::new());
    let search_active = RwSignal::new(false);
    let passkeys_open = RwSignal::new(false);
    let admin_open = RwSignal::new(false);
    let is_admin = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let nav_open = RwSignal::new(false);
    let grid = RwSignal::new(false);
    let dragging = RwSignal::new(false);
    let e2ee_master = RwSignal::new(Option::<MasterKey>::None);
    let e2ee_open = RwSignal::new(false);
    let quota_warn = RwSignal::new(Option::<u8>::None);
    let usage = RwSignal::new(Value::Null);
    let loading = RwSignal::new(false);
    // Whether the folder being shown is encrypted (so it can be hidden while
    // locked). Comes from the browse response, which inherits the folder flag.
    let folder_encrypted = RwSignal::new(false);
    let context_menu = RwSignal::new(Option::<(Entry, i32, i32)>::None);
    let lightbox = RwSignal::new(Option::<Entry>::None);
    let lightbox_url = RwSignal::new(String::new());
    let lightbox_text = RwSignal::new(String::new());
    // Decrypts the lightbox file client-side when it is encrypted, fetches
    // text previews, and revokes the previous blob URL whenever the
    // lightbox changes.
    Effect::new(move |_| {
        let old = lightbox_url.get_untracked();
        if old.starts_with("blob:") {
            let _ = web_sys::Url::revoke_object_url(&old);
        }
        lightbox_url.set(String::new());
        lightbox_text.set(String::new());
        let current = lightbox.get();
        let master = e2ee_master.get();
        let Some(entry) = current else {
            return;
        };
        let preview_text = is_text_name(&entry.name);
        if entry.encrypted {
            let Some(master) = master else {
                error.set("Unlock encryption first (Settings → Encryption).".to_string());
                e2ee_open.set(true);
                lightbox.set(None);
                return;
            };
            // Previews decrypt in memory: refuse absurd sizes instead of
            // OOMing the tab (the server preview caps at 20 MiB too).
            let cap = if preview_text {
                5 * 1024 * 1024
            } else {
                20 * 1024 * 1024
            };
            if entry.size > cap {
                error.set("This file is too large to preview — download it instead.".to_string());
                lightbox.set(None);
                return;
            }
            let path = entry.path.clone();
            let display_name = entry.name.clone();
            let shared = entry.shared;
            spawn_local(async move {
                let result = if shared {
                    crate::e2ee::decrypt_shared_file(&master, &path, &display_name).await
                } else {
                    crate::e2ee::decrypt_file(&master, &path).await
                };
                match result {
                    Ok((name, bytes)) => {
                        if preview_text {
                            lightbox_text.set(String::from_utf8_lossy(&bytes).into_owned());
                        } else {
                            lightbox_url.set(crate::e2ee::blob_url(&name, &bytes));
                        }
                    }
                    Err(e) => {
                        error.set(e);
                        lightbox.set(None);
                    }
                }
            });
        } else if preview_text {
            let path = entry.path.clone();
            spawn_local(async move {
                match api::get_text(&format!("/api/preview?path={}", encode(&path))).await {
                    Ok(text) => lightbox_text.set(text),
                    Err(e) => {
                        error.set(e);
                        lightbox.set(None);
                    }
                }
            });
        }
    });
    let move_drag = RwSignal::new(Option::<Entry>::None);
    // A reload in the same tab keeps the unlock: the master key lives in
    // sessionStorage until the tab closes, Lock, or sign out.
    if e2ee_master.get_untracked().is_none()
        && let Some(recalled) = crate::e2ee::recalled_master()
    {
        e2ee_master.set(Some(recalled));
    }
    let undo = RwSignal::new(Option::<(String, i64)>::None);
    let uploads = RwSignal::new(Vec::<UploadItem>::new());
    let upload_seq = RwSignal::new(0u32);
    let selected = RwSignal::new(std::collections::HashSet::<String>::new());
    // Administrators get the user-management panel.
    spawn_local(async move {
        if let Ok(r) = api::get("/api/me").await
            && r.status == 200
        {
            is_admin.set(r.body["is_admin"].as_bool().unwrap_or(false));
            username.set(r.body["username"].as_str().unwrap_or_default().to_string());
        }
        if let Ok(r) = api::get("/api/me/usage").await
            && r.status == 200
        {
            usage.set(r.body);
        }
    });

    // First login: offer to create the Vault passphrase. Dismissal is
    // remembered, and Vault prompts again the first time it is used, so
    // nobody is forced through it before they need encryption.
    Effect::new(move |_| {
        if e2ee_master.get_untracked().is_some() || vault_setup.get_untracked() {
            return;
        }
        let dismissed = web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item("kolimi.vault.dismissed").ok().flatten())
            .is_some();
        if dismissed {
            return;
        }
        spawn_local(async move {
            if crate::e2ee::keyring_exists().await == Ok(false) {
                vault_setup.set(true);
            }
        });
    });

    // Detect session expiry while the app stays open: poll and fall back to
    // the login view instead of leaving a dead Browser view.
    {
        let check = Closure::<dyn FnMut()>::new(move || {
            spawn_local(async move {
                if let Ok(r) = api::get("/api/me").await
                    && r.status == 401
                {
                    view.set(View::Login);
                }
            });
        });
        if let Some(window) = web_sys::window() {
            let _ = window.set_interval_with_callback_and_timeout_and_arguments_0(
                check.as_ref().unchecked_ref(),
                60_000,
            );
        }
        check.forget();
    }

    // Navigation is a signal: setting `nav` loads it, so a missing folder can
    // fall back to the root without recursive closures.
    let nav = RwSignal::new("/".to_string());
    let load = move |next: String| nav.set(next);
    let load_seq = RwSignal::new(0u32);
    // Mounts received from others, with their permissions: gates Upload /
    // New folder inside read-only shared folders. `shared_names` carries the
    // unwrapped display name (and, for folders, the name key) per mount.
    let received = RwSignal::new(Vec::<Value>::new());
    let shared_names = RwSignal::new(Vec::<crate::e2ee::ShareDisplay>::new());
    // Whether the current folder accepts writes: the own tree always does;
    // a received mount only with "write" permission.
    let can_write_here = move |current: &str| {
        let current = current.trim_end_matches('/');
        if current.is_empty() || current == "/Shared with me" {
            return current.is_empty();
        }
        if let Some(rest) = current.strip_prefix("/Shared with me/") {
            let mount = format!("/Shared with me/{}", rest.split('/').next().unwrap_or(""));
            return received.get_untracked().iter().any(|m| {
                m["mount"].as_str() == Some(mount.as_str()) && m["permission"] == "write"
            });
        }
        true
    };
    let refresh_usage = move || {
        spawn_local(async move {
            if let Ok(r) = api::get("/api/me/usage").await
                && r.status == 200
            {
                usage.set(r.body);
            }
        });
    };
    Effect::new(move |_| {
        let requested = nav.get();
        // Navigating leaves any multi-select behind.
        selected.set(std::collections::HashSet::new());
        loading.set(true);
        let seq = load_seq.get_untracked().wrapping_add(1);
        load_seq.set(seq);
        spawn_local(async move {
            let master = e2ee_master.get_untracked();
            let (mounts, names) = received_mounts(master.as_ref()).await;
            received.set(mounts);
            shared_names.set(names);
            let shares = shared_names.get_untracked();
            let url = format!("/api/browse?path={}", encode(&requested));
            let result = api::get(&url).await;
            // A newer navigation supersedes this response: don't apply it or
            // clear the loading state.
            if load_seq.get_untracked() != seq {
                return;
            }
            match result {
                Ok(r) if r.status == 200 => {
                    folder_encrypted.set(r.body["encrypted"].as_bool().unwrap_or(false));
                    entries.set(parse_entries(&r.body, master.as_ref(), &shares));
                    parent.set(
                        r.body
                            .get("parent")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    );
                    path.set(
                        r.body
                            .get("path")
                            .and_then(Value::as_str)
                            .unwrap_or(&requested)
                            .to_string(),
                    );
                    error.set(String::new());
                }
                Ok(r) if r.status == 401 => {
                    crate::e2ee::forget_master();
                    mark_session_expired();
                    view.set(View::Login);
                }
                Ok(r) if r.status == 404 && requested != "/" => {
                    // Renamed or removed: show the files instead of an error
                    // the user cannot act on.
                    error.set("That folder no longer exists — showing your files.".to_string());
                    nav.set("/".to_string());
                }
                Ok(r) if r.status == 403 => {
                    error.set("You don't have access to that folder.".to_string());
                }
                Ok(r) => error.set(format!(
                    "Couldn't load this folder (HTTP {}). Please try again.",
                    r.status
                )),
                Err(_) => error.set(
                    "Couldn't reach the server. Check your connection and try again.".to_string(),
                ),
            }
            loading.set(false);
        });
    });

    let load_trash = move || {
        spawn_local(async move {
            match api::get("/api/trash").await {
                Ok(r) if r.status == 200 => trash.set(parse_trash(
                    &r.body,
                    e2ee_master.get_untracked().as_ref(),
                    &shared_names.get_untracked(),
                )),
                Ok(r) => error.set(r.error().unwrap_or("Could not load trash").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    // Toasts fade themselves out. A timer only clears the toast if it still
    // shows the message it was scheduled for, so a stale timer cannot wipe a
    // newer one.
    Effect::new(move |_| {
        let current = error.get();
        if !current.is_empty() {
            let clear = Closure::once_into_js(move || {
                if error.get_untracked() == current {
                    error.set(String::new());
                }
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    6000,
                );
            }
        }
    });
    Effect::new(move |_| {
        let current = notice.get();
        if !current.is_empty() {
            let clear = Closure::once_into_js(move || {
                if notice.get_untracked() == current {
                    notice.set(String::new());
                }
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    4000,
                );
            }
        }
    });
    // Undo and quota toasts dismiss themselves too, so they never cover
    // the screen until clicked.
    Effect::new(move |_| {
        if undo.get().is_some() {
            let clear = Closure::once_into_js(move || {
                undo.set(None);
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    15000,
                );
            }
        }
    });
    Effect::new(move |_| {
        if quota_warn.get().is_some() {
            let clear = Closure::once_into_js(move || {
                quota_warn.set(None);
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    15000,
                );
            }
        }
    });

    let sign_out = move |_| {
        // Full navigation, not a fetch: the server deletes the session row,
        // clears the cookies and redirects to the app. No SPA state, cache
        // entry or stale cookie can bring the session back on refresh.
        crate::e2ee::forget_master();
        if let Some(window) = web_sys::window() {
            let _ = window.location().assign("/logout");
        }
    };

    let open = move |entry: Entry| {
        if entry.kind == "dir" {
            load(entry.path);
        } else if is_image_name(&entry.name) || is_text_name(&entry.name) {
            lightbox.set(Some(entry));
        }
    };

    // Uploads one file, tracking it in the tray via its own signals.
    // Encrypted destinations are encrypted client-side first (chunks +
    // manifest + wrapped key, like the sync client); plaintext uploads
    // stream the Blob straight from disk with no WASM-side copy.
    let start_upload = move |file: web_sys::File,
                             dir: String,
                             progress: RwSignal<u8>,
                             status: RwSignal<UploadStatus>| {
        let plain_name = file.name();
        let tray = uploads;
        spawn_local(async move {
            // Shared helper: mark this row done/failed and refresh when the
            // tray has no in-flight uploads left.
            let finish = move |ok: bool, warning: Option<u8>| {
                if let Some(percent) = warning {
                    quota_warn.set(Some(percent));
                }
                status.set(if ok {
                    UploadStatus::Done
                } else {
                    UploadStatus::Failed
                });
                if !tray
                    .get_untracked()
                    .iter()
                    .any(|item| item.status.get_untracked() == UploadStatus::Uploading)
                {
                    let snapshot = tray.get_untracked();
                    let done = snapshot
                        .iter()
                        .filter(|item| item.status.get_untracked() == UploadStatus::Done)
                        .count();
                    let failed = snapshot
                        .iter()
                        .filter(|item| item.status.get_untracked() == UploadStatus::Failed)
                        .count();
                    if failed == 0 {
                        notice.set(format!(
                            "Uploaded {done} file{}",
                            if done == 1 { "" } else { "s" }
                        ));
                    } else {
                        error.set(format!("Uploaded {done}, {failed} failed"));
                    }
                    tray.update(|list| {
                        list.retain(|item| item.status.get_untracked() != UploadStatus::Done);
                    });
                    load(path.get_untracked());
                    refresh_usage();
                }
            };
            let encrypted = crate::e2ee::file_info(&dir)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    finish(false, None);
                    // First use of an encrypted folder: create the Vault
                    // passphrase if none exists, otherwise unlock it.
                    if crate::e2ee::keyring_exists().await == Ok(false) {
                        vault_setup.set(true);
                    } else {
                        error.set(
                            "This folder is encrypted — unlock it to upload (Encryption in the sidebar)."
                                .to_string(),
                        );
                        e2ee_open.set(true);
                    }
                    return;
                };
                let bytes = match api::read_file(&file).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                        return;
                    }
                };
                // The server must not learn the name: encode it as one
                // opaque path segment inside the encrypted folder.
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dir);
                let target =
                    match crate::e2ee::encode_component(&master, &parent_plaintext, &plain_name) {
                        Ok(encoded) => format!("{}/{}", dir.trim_end_matches('/'), encoded),
                        Err(e) => {
                            finish(false, None);
                            error.set(e);
                            return;
                        }
                    };
                progress.set(50);
                match crate::e2ee::upload_encrypted(&master, &target, &bytes).await {
                    Ok(()) => {
                        progress.set(100);
                        finish(true, None);
                    }
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                    }
                }
                return;
            }
            let target = format!("{}/{}", dir.trim_end_matches('/'), plain_name);
            let url = format!("/dav{}", encode_path(&target));
            let file_name = plain_name;
            let blob = web_sys::Blob::from(file);
            api::upload_blob(
                &url,
                &blob,
                move |pct| progress.set(pct),
                move |result| {
                    let (ok, warning) = match result {
                        Ok((code, warning)) => {
                            if !matches!(code, 201 | 204) {
                                error.set(format!(
                                    "Upload of “{}” failed (HTTP {code}){}.{}",
                                    file_name,
                                    if code == 403 {
                                        " — the session or CSRF token was rejected"
                                    } else if code == 413 {
                                        " — file too large"
                                    } else {
                                        ""
                                    },
                                    if code == 403 {
                                        " Try signing out and in again."
                                    } else {
                                        ""
                                    },
                                ));
                            }
                            (matches!(code, 201 | 204), warning)
                        }
                        Err(e) => {
                            error.set(format!("Upload of “{}” failed: {e}", file_name));
                            (false, None)
                        }
                    };
                    finish(ok, warning);
                },
            );
        });
    };

    let upload_files = move |files: Vec<web_sys::File>| {
        if files.is_empty() {
            return;
        }
        let dir = path.get_untracked();
        for file in files {
            let id = upload_seq.get_untracked() + 1;
            upload_seq.set(id);
            let progress = RwSignal::new(0u8);
            let status = RwSignal::new(UploadStatus::Uploading);
            uploads.update(|list| {
                list.push(UploadItem {
                    id,
                    name: file.name(),
                    dir: dir.clone(),
                    progress,
                    status,
                    file: file.clone(),
                });
            });
            start_upload(file, dir.clone(), progress, status);
        }
    };

    let collect_files = move |files: web_sys::FileList| {
        let mut selected = Vec::new();
        for index in 0..files.length() {
            if let Some(file) = files.get(index) {
                selected.push(file);
            }
        }
        selected
    };

    let upload = move |ev: ev::Event| {
        let Some(input) = ev
            .target()
            .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        else {
            return;
        };
        let Some(files) = input.files() else {
            return;
        };
        let selected = collect_files(files);
        // Reset so the same files can be chosen again later.
        input.set_value("");
        upload_files(selected);
    };

    let drop_files = move |ev: ev::DragEvent| {
        ev.prevent_default();
        dragging.set(false);
        let Some(transfer) = ev.data_transfer() else {
            return;
        };
        if let Some(files) = transfer.files() {
            let selected = collect_files(files);
            if selected.is_empty() {
                // A folder (not files) was dropped: browsers only expose
                // files here, so say so instead of failing silently.
                let types = transfer.types();
                if (0..types.length())
                    .filter_map(|i| types.get(i).as_string())
                    .any(|kind| kind == "Files")
                {
                    error.set(
                        "That looks like a folder — drag-and-drop takes files only. Create the folder first, then drop the files inside.".to_string(),
                    );
                }
                return;
            }
            upload_files(selected);
        }
    };

    let mkdir = move |_| {
        let Some(name) = api::prompt("New folder name", "") else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let current = path.get_untracked();
        spawn_local(async move {
            let encrypted = crate::e2ee::file_info(&current)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            let folder_name = if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Unlock encryption first (Settings → Encryption).".to_string());
                    e2ee_open.set(true);
                    return;
                };
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &current);
                match crate::e2ee::encode_component(&master, &parent_plaintext, &name) {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        error.set(e);
                        return;
                    }
                }
            } else {
                name
            };
            let url = format!(
                "/dav{}",
                encode_path(&format!(
                    "{}/{}",
                    current.trim_end_matches('/'),
                    folder_name
                ))
            );
            match api::dav("MKCOL", &url, None, &[]).await {
                Ok(r) if r.status == 201 => load(current),
                Ok(r) => error.set(format!("Could not create folder (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    // Encrypted content must be unlocked before it can be shared, renamed,
    // moved, or deleted: while locked, Vault is read-only. (The server
    // cannot verify key possession, so this guard is client-side — but it
    // stops the accidental "I deleted my Vault while it was locked".)
    let require_unlock = move |entry: &Entry| -> bool {
        if !entry.encrypted || e2ee_master.get_untracked().is_some() {
            return true;
        }
        error.set("Vault is locked — unlock encryption first (Settings → Encryption).".to_string());
        e2ee_open.set(true);
        false
    };

    let delete_entry = move |entry: Entry| {
        if !require_unlock(&entry) {
            return;
        }
        if !api::confirm(&format!("Move “{}” to trash?", entry.name)) {
            return;
        }
        let current = path.get_untracked();
        let entry_path = entry.path.clone();
        let entry_name = entry.name.clone();
        spawn_local(async move {
            let url = format!("/dav{}", encode_path(&entry_path));
            match api::dav("DELETE", &url, None, &[]).await {
                Ok(r) if r.status == 204 => {
                    // Find the trashed node so the move can be undone.
                    if let Ok(tr) = api::get("/api/trash").await
                        && tr.status == 200
                        && let Some(items) = tr.body.as_array()
                        && let Some(id) = items
                            .iter()
                            .find(|item| {
                                item["original_path"].as_str() == Some(entry_path.as_str())
                            })
                            .and_then(|item| item["id"].as_i64())
                    {
                        undo.set(Some((entry_name.clone(), id)));
                    }
                    load(current);
                    refresh_usage();
                }
                Ok(r) => error.set(format!("Delete failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    let rename_entry = move |entry: Entry| {
        if !require_unlock(&entry) {
            return;
        }
        let Some(name) = api::prompt("New name", &entry.name) else {
            return;
        };
        if name.is_empty() || name == entry.name {
            return;
        }
        let current = path.get_untracked();
        let encrypted = entry.encrypted && !entry.shared;
        let source = entry.path.clone();
        spawn_local(async move {
            if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    e2ee_open.set(true);
                    return;
                };
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &current);
                let encoded = match crate::e2ee::encode_component(&master, &parent_plaintext, &name)
                {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        error.set(e);
                        return;
                    }
                };
                // Metadata-only server move: works on ciphertext.
                let destination = format!("{}/{}", current.trim_end_matches('/'), encoded);
                match crate::e2ee::move_file(&source, &destination).await {
                    Ok(()) => load(current),
                    Err(e) => error.set(e),
                }
                return;
            }
            let destination = format!(
                "/dav{}",
                encode_path(&format!("{}/{}", current.trim_end_matches('/'), name))
            );
            let url = format!("/dav{}", encode_path(&source));
            match api::dav("MOVE", &url, None, &[("destination", &destination)]).await {
                Ok(r) if matches!(r.status, 201 | 204) => load(current),
                Ok(r) => error.set(format!("Rename failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    // Moves `entry` into `dest_dir` (drag-to-move onto a folder or crumb).
    // Crossing the encryption boundary is refused: plaintext must never land
    // in an encrypted tree, and ciphertext must not become unreadable in a
    // plaintext one.
    let move_into = move |entry: Entry, dest_dir: String| {
        if !require_unlock(&entry) {
            return;
        }
        let source = entry.path.clone();
        let encrypted = entry.encrypted && !entry.shared;
        let name = entry.name.clone();
        spawn_local(async move {
            let dest_encrypted = crate::e2ee::file_info(&dest_dir)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            if !encrypted && dest_encrypted {
                error.set(format!(
                    "“{name}” is not encrypted — upload it into the Vault so it is encrypted on your device."
                ));
                return;
            }
            if encrypted && !dest_encrypted {
                error.set(
                    "This item is encrypted — it can only move between encrypted folders."
                        .to_string(),
                );
                return;
            }
            let destination = if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    e2ee_open.set(true);
                    return;
                };
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dest_dir);
                let encoded = match crate::e2ee::encode_component(&master, &parent_plaintext, &name)
                {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        error.set(e);
                        return;
                    }
                };
                format!("{}/{}", dest_dir.trim_end_matches('/'), encoded)
            } else {
                format!("{}/{}", dest_dir.trim_end_matches('/'), name)
            };
            if destination == source {
                return;
            }
            if encrypted {
                match crate::e2ee::move_file(&source, &destination).await {
                    Ok(()) => {
                        notice.set(format!("Moved {name}"));
                        load(path.get_untracked());
                    }
                    Err(e) => error.set(e),
                }
                return;
            }
            let dav_source = format!("/dav{}", encode_path(&source));
            let dav_dest = format!("/dav{}", encode_path(&destination));
            match api::dav("MOVE", &dav_source, None, &[("destination", &dav_dest)]).await {
                Ok(r) if matches!(r.status, 201 | 204) => {
                    notice.set(format!("Moved {name}"));
                    load(path.get_untracked());
                }
                Ok(r) => error.set(format!("Move failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    // ---- Multi-select + bulk actions ----
    let toggle_select = move |target: String| {
        selected.update(|set| {
            if !set.insert(target.clone()) {
                set.remove(&target);
            }
        });
    };

    let bulk_trash = move |_| {
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        // Encrypted selections need an unlock, exactly like single delete.
        let encrypted_selected = entries
            .get_untracked()
            .into_iter()
            .any(|entry| entry.encrypted && paths.contains(&entry.path));
        if encrypted_selected && e2ee_master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            e2ee_open.set(true);
            return;
        }
        let current = path.get_untracked();
        let count = paths.len();
        spawn_local(async move {
            let mut failed = 0usize;
            for target in &paths {
                let url = format!("/dav{}", encode_path(target));
                match api::dav("DELETE", &url, None, &[]).await {
                    Ok(r) if (200..300).contains(&r.status) => {}
                    Ok(r) => {
                        failed += 1;
                        error.set(format!("Delete failed (HTTP {})", r.status));
                    }
                    Err(e) => {
                        failed += 1;
                        error.set(e);
                    }
                }
            }
            selected.set(std::collections::HashSet::new());
            if failed == 0 {
                notice.set(format!("Moved {count} item(s) to trash"));
            }
            load(current);
            refresh_usage();
        });
    };

    let bulk_move = move |_| {
        let Some(dest) = api::prompt("Move selected to (folder path)", "/") else {
            return;
        };
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        // Encrypted entries go through the metadata-only API move; the
        // rest keep using WebDAV.
        let encrypted: std::collections::HashSet<String> = entries
            .get_untracked()
            .into_iter()
            .filter(|e| e.encrypted && !e.shared)
            .map(|e| e.path)
            .collect();
        if encrypted.iter().any(|path| paths.contains(path))
            && e2ee_master.get_untracked().is_none()
        {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            e2ee_open.set(true);
            return;
        }
        let count = paths.len();
        spawn_local(async move {
            let mut failed = 0usize;
            for target in &paths {
                let name = target.rsplit('/').next().unwrap_or("file");
                let destination = format!("{}/{}", dest.trim_end_matches('/'), name);
                if encrypted.contains(target) {
                    match crate::e2ee::move_file(target, &destination).await {
                        Ok(()) => {}
                        Err(e) => {
                            failed += 1;
                            error.set(e);
                        }
                    }
                    continue;
                }
                let source = format!("/dav{}", encode_path(target));
                let dav_dest = format!("/dav{}", encode_path(&destination));
                match api::dav("MOVE", &source, None, &[("destination", &dav_dest)]).await {
                    Ok(r) if (200..300).contains(&r.status) => {}
                    Ok(r) => {
                        failed += 1;
                        error.set(format!("Move failed (HTTP {})", r.status));
                    }
                    Err(e) => {
                        failed += 1;
                        error.set(e);
                    }
                }
            }
            selected.set(std::collections::HashSet::new());
            if failed == 0 {
                notice.set(format!("Moved {count} item(s)"));
            }
            load(path.get_untracked());
        });
    };

    let decrypt_entry = move |entry: Entry| {
        let Some(master) = e2ee_master.get_untracked() else {
            error.set("Unlock encryption first (Settings → Encryption).".to_string());
            e2ee_open.set(true);
            return;
        };
        let path = entry.path.clone();
        let display_name = entry.name.clone();
        let shared = entry.shared;
        spawn_local(async move {
            let result = if shared {
                crate::e2ee::decrypt_shared_file(&master, &path, &display_name).await
            } else {
                crate::e2ee::decrypt_file(&master, &path).await
            };
            match result {
                Ok((name, bytes)) => {
                    crate::e2ee::save_bytes(&name, &bytes);
                    notice.set(format!("Decrypted {name}"));
                }
                Err(e) => error.set(e),
            }
        });
    };

    let bulk_download = move |_| {
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        let known: std::collections::HashMap<String, Entry> = entries
            .get_untracked()
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        for target in paths {
            // Encrypted files cannot be fetched as-is: decrypt client-side.
            if let Some(entry) = known.get(&target).filter(|entry| entry.encrypted) {
                decrypt_entry(entry.clone());
                continue;
            }
            let url = format!("/dav{}", encode_path(&target));
            if let Some(document) = web_sys::window().and_then(|window| window.document())
                && let Ok(element) = document.create_element("a")
                && let Ok(anchor) = element.dyn_into::<web_sys::HtmlAnchorElement>()
            {
                anchor.set_href(&url);
                anchor.set_download("");
                anchor.click();
            }
        }
        selected.set(std::collections::HashSet::new());
    };

    let restore = move |item: TrashItem| {
        spawn_local(async move {
            match api::send_json(
                "POST",
                &format!("/api/trash/{}/restore", item.id),
                &json!({}),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(format!("Restored {}", item.name));
                    load_trash();
                    refresh_usage();
                }
                Ok(r) => error.set(r.error().unwrap_or("Restore failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let purge = move |item: TrashItem| {
        if !api::confirm(&format!("Permanently delete “{}”?", item.name)) {
            return;
        }
        spawn_local(async move {
            match api::delete(&format!("/api/trash/{}", item.id)).await {
                Ok(r) if r.status == 204 => {
                    load_trash();
                    refresh_usage();
                }
                Ok(r) => error.set(r.error().unwrap_or("Delete failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let share_entry = move |entry: Entry| {
        if entry.encrypted && e2ee_master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption before sharing, or the recipient gets no key."
                    .to_string(),
            );
            e2ee_open.set(true);
            return;
        }
        share_target.set(Some(entry));
    };

    // Declares a folder encrypted (or plaintext). The server flag is what
    // every client reads, so this is the only switch that matters. Making a
    // non-empty folder encrypted first re-uploads every plaintext file
    // encrypted, then flips the flag: the server refuses a mixed folder, and
    // leaving plaintext behind would break the "anything inside is encrypted"
    // promise. Already-encrypted files are skipped, so an interrupted run can
    // simply be retried.
    let encrypting = RwSignal::new(false);
    let toggle_encryption = move |entry: Entry| {
        if encrypting.get_untracked() {
            return;
        }
        let path = entry.path.clone();
        let parent = path
            .rsplit_once('/')
            .map(|(dir, _)| {
                if dir.is_empty() {
                    "/".to_string()
                } else {
                    dir.to_string()
                }
            })
            .unwrap_or_else(|| "/".to_string());
        if entry.encrypted {
            spawn_local(async move {
                match api::send_json(
                    "POST",
                    "/api/files/encrypt",
                    &json!({ "path": path, "encrypted": false }),
                )
                .await
                {
                    Ok(r) if r.status == 200 => {
                        notice.set("Folder is now plaintext".to_string());
                        load(parent);
                    }
                    Ok(r) => error.set(
                        r.error()
                            .unwrap_or("Could not change encryption")
                            .to_string(),
                    ),
                    Err(e) => error.set(e),
                }
            });
            return;
        }
        let Some(master) = e2ee_master.get_untracked() else {
            error.set("Unlock encryption first (Settings → Encryption).".to_string());
            e2ee_open.set(true);
            return;
        };
        encrypting.set(true);
        spawn_local(async move {
            let files = match crate::e2ee::plaintext_files_under(&path).await {
                Ok(files) => files,
                Err(e) => {
                    error.set(e);
                    encrypting.set(false);
                    return;
                }
            };
            if !files.is_empty() {
                let message = format!(
                    "Encrypt {} existing file{} in this folder now? They will be re-uploaded encrypted — keep this tab open until it finishes.",
                    files.len(),
                    if files.len() == 1 { "" } else { "s" }
                );
                let confirmed = web_sys::window()
                    .and_then(|window| window.confirm_with_message(&message).ok())
                    .unwrap_or(false);
                if !confirmed {
                    encrypting.set(false);
                    return;
                }
            }
            let total = files.len();
            for (index, file) in files.iter().enumerate() {
                let name = file.path.rsplit('/').next().unwrap_or(&file.path);
                notice.set(format!("Encrypting {} of {}: {name}", index + 1, total));
                let bytes = match api::get_bytes(&format!("/dav{}", encode_path(&file.path))).await
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error.set(format!("Could not read “{}”: {e}", file.path));
                        load(parent.clone());
                        encrypting.set(false);
                        return;
                    }
                };
                // Also encrypt the name. A legacy plaintext name is first
                // moved to its encoded form (metadata-only), then the content
                // is encrypted in place. Names that are already encoded
                // (an interrupted earlier run) are left alone.
                let (dir, name) = file
                    .path
                    .rsplit_once('/')
                    .map(|(dir, name)| (dir.to_string(), name.to_string()))
                    .unwrap_or_else(|| ("/".to_string(), file.path.clone()));
                let target = if kolimi_crypto::is_encoded_name(&name) {
                    file.path.clone()
                } else {
                    let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dir);
                    let encoded =
                        match crate::e2ee::encode_component(&master, &parent_plaintext, &name) {
                            Ok(encoded) => encoded,
                            Err(e) => {
                                error.set(e);
                                encrypting.set(false);
                                return;
                            }
                        };
                    let target = format!("{dir}/{encoded}");
                    if let Err(e) = crate::e2ee::move_file(&file.path, &target).await {
                        error.set(format!("Renaming “{name}” for encryption failed: {e}"));
                        load(parent.clone());
                        encrypting.set(false);
                        return;
                    }
                    target
                };
                if let Err(e) = crate::e2ee::upload_encrypted_versioned(
                    &master,
                    &target,
                    &bytes,
                    file.content_id.as_deref(),
                )
                .await
                {
                    error.set(format!("Encrypting “{}” failed: {e}", file.path));
                    load(parent.clone());
                    encrypting.set(false);
                    return;
                }
            }
            match api::send_json(
                "POST",
                "/api/files/encrypt",
                &json!({ "path": path, "encrypted": true }),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(if total == 0 {
                        "Folder encrypted — new files are encrypted on your device".to_string()
                    } else {
                        format!(
                            "Folder encrypted — {total} file{} encrypted on your device",
                            if total == 1 { "" } else { "s" }
                        )
                    });
                    load(parent);
                }
                Ok(r) => error.set(
                    r.error()
                        .unwrap_or("Could not change encryption")
                        .to_string(),
                ),
                Err(e) => error.set(e),
            }
            encrypting.set(false);
        });
    };

    let search_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let text = query.get_untracked();
        if text.trim().is_empty() {
            search_active.set(false);
            return;
        }
        spawn_local(async move {
            let url = format!("/api/search?q={}&limit=50", encode(&text));
            match api::get(&url).await {
                Ok(r) if r.status == 200 => {
                    let master = e2ee_master.get_untracked();
                    let shares = shared_names.get_untracked();
                    let mut hits = parse_results(&r.body, master.as_ref(), &shares);
                    // The server cannot search ciphertext names; supplement
                    // with a client-side name search while unlocked.
                    if let Some(master) = &master {
                        let known: std::collections::HashSet<String> =
                            hits.iter().map(|hit| hit.path.clone()).collect();
                        for hit in encrypted_name_hits(master, &text, &shares).await {
                            if !known.contains(&hit.path) {
                                hits.push(hit);
                            }
                        }
                    }
                    results.set(hits);
                    search_active.set(true);
                    error.set(String::new());
                }
                Ok(r) => error.set(r.error().unwrap_or("Search failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };
    let clear_search = move |_| {
        search_active.set(false);
        results.set(Vec::new());
        query.set(String::new());
    };

    view! {
        <div
            class="shell"
            class:nav-open=move || nav_open.get()
            on:dragover=move |ev| {
                ev.prevent_default();
                dragging.set(true);
            }
            on:dragleave=move |_| dragging.set(false)
            on:drop=drop_files
        >
            <div class="nav-scrim" on:click=move |_| nav_open.set(false)></div>
            <div class="dropzone" class:active=move || dragging.get()>
                <div class="dropzone-inner">
                    <Icon name="upload"/>
                    <p>"Drop files to upload"</p>
                </div>
            </div>
            <aside class="sidebar">
                <a class="side-brand" href="/app/">
                    <Logo/>
                    "Kolimi"
                </a>
                <nav class="nav">
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Files && !search_active.get()
                        on:click=move |_| {
                            search_active.set(false);
                            tab.set(Tab::Files);
                            load(path.get_untracked());
                            nav_open.set(false);
                        }
                    >
                        <Icon name="folder"/>
                        "Files"
                    </button>
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Trash
                        on:click=move |_| {
                            search_active.set(false);
                            tab.set(Tab::Trash);
                            load_trash();
                            nav_open.set(false);
                        }
                    >
                        <Icon name="trash"/>
                        "Trash"
                    </button>
                    <div class="nav-sep"></div>
                    <button class="nav-item" on:click=move |_| passkeys_open.set(true)>
                        <Icon name="key"/>
                        "Passkeys"
                    </button>
                    <button class="nav-item" on:click=move |_| e2ee_open.set(true)>
                        <Icon name="settings"/>
                        "Settings"
                    </button>
                    {move || {
                        is_admin
                            .get()
                            .then(|| {
                                view! {
                                    <button
                                        class="nav-item"
                                        on:click=move |_| admin_open.set(true)
                                    >
                                        <Icon name="users"/>
                                        "Admin"
                                    </button>
                                }
                            })
                    }}
                </nav>
                <div class="side-foot">
                    <div class="storage">
                        {move || {
                            let data = usage.get();
                            let used = data["used_bytes"].as_u64().unwrap_or(0);
                            let quota = data["effective_quota_bytes"].as_u64().unwrap_or(0);
                            let pct = if quota == 0 {
                                0.0
                            } else {
                                (used as f64 / quota as f64).clamp(0.0, 1.0)
                            };
                            let dash = format!("{:.2} {:.2}", pct * 100.0, 100.0 - pct * 100.0);
                            let label = if quota == 0 {
                                format!("{} used", human_size(used))
                            } else {
                                format!("{} of {}", human_size(used), human_size(quota))
                            };
                            view! {
                                <div class="storage-ring">
                                    <svg viewBox="0 0 36 36" role="img" aria-label="Storage used">
                                        <circle class="ring-bg" cx="18" cy="18" r="15.9155"></circle>
                                        <circle
                                            class="ring-fg"
                                            cx="18"
                                            cy="18"
                                            r="15.9155"
                                            stroke-dasharray=dash
                                        ></circle>
                                    </svg>
                                    <div class="storage-info">
                                        <b>{format!("{:.0}%", pct * 100.0)}</b>
                                        <small class="muted">{label}</small>
                                    </div>
                                </div>
                            }
                        }}
                    </div>
                    <div class="account">
                        <span class="avatar">
                            {move || {
                                username
                                    .get()
                                    .chars()
                                    .next()
                                    .map(|c| c.to_uppercase().to_string())
                                    .unwrap_or_else(|| "?".to_string())
                            }}
                        </span>
                        <div class="who">
                            <b>
                                {move || {
                                    if username.get().is_empty() {
                                        "Signed in".to_string()
                                    } else {
                                        username.get()
                                    }
                                }}
                            </b>
                            <small>"Account"</small>
                        </div>
                    </div>
                    <button class="nav-item" on:click=move |_| toggle_theme()>
                        <Icon name="sun"/>
                        "Theme"
                    </button>
                    <button class="nav-item" on:click=sign_out>
                        <Icon name="logout"/>
                        "Sign out"
                    </button>
                </div>
            </aside>

            <div class="main">
                <header class="topbar">
                    <button
                        class="icon-btn menu-btn"
                        aria-label="Menu"
                        on:click=move |_| nav_open.set(!nav_open.get_untracked())
                    >
                        <Icon name="menu"/>
                    </button>
                    <div class="crumbs">
                        {move || {
                            if search_active.get() {
                                return vec![
                                    view! { <span class="crumb current">"Search"</span> }
                                        .into_any(),
                                ];
                            }
                            if tab.get() == Tab::Trash {
                                return vec![
                                    view! { <span class="crumb current">"Trash"</span> }
                                        .into_any(),
                                ];
                            }
                            let current = path.get();
                            let segments: Vec<&str> = current
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .collect();
                            let decoded_path = crate::e2ee::decode_display_path_with_shares(
                                e2ee_master.get_untracked().as_ref(),
                                &current,
                                &shared_names.get_untracked(),
                            );
                            let labels: Vec<String> = decoded_path
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect();

                            let mut crumbs = vec![
                                view! {
                                    <button
                                        class="crumb"
                                        on:click=move |_| load("/".to_string())
                                        on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                        on:drop=move |ev: ev::DragEvent| {
                                            ev.prevent_default();
                                            if let Some(src) = move_drag.get_untracked() {
                                                move_into(src, "/".to_string());
                                                move_drag.set(None);
                                            }
                                        }
                                    >
                                        <Icon name="cloud"/>
                                    </button>
                                }
                                    .into_any(),
                            ];
                            let mut accumulated = String::new();
                            for (label_index, segment) in segments.into_iter().enumerate() {
                                accumulated.push('/');
                                accumulated.push_str(segment);
                                let target = accumulated.clone();
                                let drop_target = accumulated.clone();
                                let label = labels
                                    .get(label_index)
                                    .cloned()
                                    .unwrap_or_else(|| segment.to_string());
                                crumbs.push(
                                    view! {
                                        <span class="sep">"/"</span>
                                        <button
                                            class="crumb"
                                            on:click=move |_| load(target.clone())
                                            on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                            on:drop=move |ev: ev::DragEvent| {
                                                ev.prevent_default();
                                                if let Some(src) = move_drag.get_untracked() {
                                                    move_into(src, drop_target.clone());
                                                    move_drag.set(None);
                                                }
                                            }
                                        >
                                            {label}
                                        </button>
                                    }
                                        .into_any(),
                                );
                            }
                            crumbs
                        }}
                    </div>
                    <div class="topbar-spacer"></div>
                    <div class="topbar-actions">
                        <form class="search" on:submit=search_submit>
                            <Icon name="search"/>
                            <input
                                type="search"
                                placeholder="Search files…"
                                prop:value=move || query.get()
                                on:input=move |ev| query.set(event_target_value(&ev))
                            />
                        </form>
                        <Show when=move || can_write_here(&path.get())>
                            <label class="button primary" title="Upload files">
                                <Icon name="upload"/>
                                <span>{move || upload_label.get()}</span>
                                <input type="file" class="hidden" multiple on:change=upload/>
                            </label>
                            <button on:click=mkdir title="New folder">
                                <Icon name="folder-plus"/>
                                <span class="hide-sm">"New folder"</span>
                            </button>
                        </Show>
                        <div class="segmented" role="group" aria-label="View">
                            <button
                                class="icon-btn"
                                class:active=move || !grid.get()
                                on:click=move |_| grid.set(false)
                                aria-label="List view"
                            >
                                <Icon name="list"/>
                            </button>
                            <button
                                class="icon-btn"
                                class:active=move || grid.get()
                                on:click=move |_| grid.set(true)
                                aria-label="Grid view"
                            >
                                <Icon name="grid"/>
                            </button>
                        </div>
                    </div>
                </header>
                <main class="content">
                    <Show when=move || !selected.get().is_empty()>
                        <div class="bulk-bar">
                            <span class="bulk-count">
                                {move || format!("{} selected", selected.get().len())}
                            </span>
                            <button on:click=bulk_download>"Download"</button>
                            <button on:click=bulk_move>"Move to…"</button>
                            <button class="danger" on:click=bulk_trash>"Trash"</button>
                            <button
                                on:click=move |_| selected.set(std::collections::HashSet::new())
                            >
                                "Clear"
                            </button>
                        </div>
                    </Show>

        {move || {
            if search_active.get() {
                let clear = clear_search;
                return view! {
                    <div class="section-head">
                        <h2>"Search"</h2>
                        <button on:click=clear>"Clear"</button>
                    </div>
                    <ul class="files">
                        <For
                            each=move || results.get()
                            key=|hit| hit.path.clone()
                            children=move |hit| {
                                let navigate = parent_of(&hit.path);
                                let download_path = hit.path.clone();
                                let is_dir = hit.is_dir;
                                let name = hit.name.clone();
                                let snippet = hit.snippet.clone();
                                let path = hit.path.clone();
                                let path_click = path.clone();
                                let encrypted = hit.encrypted;
                                let kind = if is_dir { "dir".to_string() } else { "file".to_string() };
                                view! {
                                    <li class="file">
                                        <button
                                            class="file-open"
                                            on:click=move |_| {
                                                search_active.set(false);
                                                if is_dir {
                                                    load(path_click.clone());
                                                } else {
                                                    load(navigate.clone());
                                                }
                                            }
                                        >
                                            <span class="file-icon">
                                                <Icon name=file_icon(&name, &kind)/>
                                            </span>
                                            <span class="file-body">
                                                <span class="file-name">{name.clone()}</span>
                                                <span class="file-meta">
                                                    {crate::e2ee::decode_display_path_with_shares(
                                                        e2ee_master.get_untracked().as_ref(),
                                                        &path,
                                                        &shared_names.get_untracked(),
                                                    )}
                                                    {(!snippet.is_empty())
                                                        .then(|| {
                                                            view! {
                                                                <span class="muted">" — " {snippet.clone()}</span>
                                                            }
                                                        })}
                                                </span>
                                            </span>
                                        </button>
                                        {(!is_dir)
                                            .then(|| {
                                                if encrypted {
                                                    let dl = Entry {
                                                        name: name.clone(),
                                                        path: download_path.clone(),
                                                        kind: kind.clone(),
                                                        size: 0,
                                                        modified_at: 0,
                                                        shared: false,
                                                        owner: None,
                                                        permission: None,
                                                        encrypted: true,
                                                    };
                                                    view! {
                                                        <span class="file-actions">
                                                            <button
                                                                class="icon-btn"
                                                                title="Download (decrypt)"
                                                                on:click=move |_| decrypt_entry(dl.clone())
                                                            >
                                                                <Icon name="download"/>
                                                            </button>
                                                        </span>
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <span class="file-actions">
                                                            <a
                                                                class="icon-btn"
                                                                title="Download"
                                                                href=format!("/dav{}", encode_path(&download_path))
                                                                download
                                                            >
                                                                <Icon name="download"/>
                                                            </a>
                                                        </span>
                                                    }
                                                        .into_any()
                                                }
                                            })}
                                    </li>
                                }
                            }
                        />
                    </ul>
                }.into_any();
            }
            match tab.get() {
                Tab::Files => {
                    view! {
                        {move || {
                            parent
                                .get()
                                .map(|target| {
                                    view! {
                                        <button class="nav-item" on:click=move |_| load(target.clone())>
                                            <Icon name="folder"/>
                                            "Up one level"
                                        </button>
                                    }
                                })
                        }}
                        {move || {
                            if loading.get() {
                                return view! {
                                    <ul class="files skeleton-list">
                                        {(0..6)
                                            .map(|_| {
                                                view! {
                                                    <li class="file skeleton">
                                                        <span class="sk sk-icon"></span>
                                                        <span class="file-body">
                                                            <span class="sk sk-line"></span>
                                                            <span class="sk sk-line short"></span>
                                                        </span>
                                                    </li>
                                                }
                                            })
                                            .collect_view()}
                                    </ul>
                                }
                                    .into_any();
                            }
                            // A locked encrypted folder shows no names: the
                            // client hides them until the key is available.
                            if folder_encrypted.get() && e2ee_master.get().is_none() {
                                return view! {
                                    <div class="empty">
                                        <Icon name="lock"/>
                                        <p>"Vault is locked"</p>
                                        <small class="muted">
                                            "Unlock encryption to see what's inside."
                                        </small>
                                        <button
                                            class="primary"
                                            on:click=move |_| e2ee_open.set(true)
                                        >
                                            "Unlock"
                                        </button>
                                    </div>
                                }
                                    .into_any();
                            }
                            if entries.get().is_empty() {
                                return view! {
                                    <div class="empty">
                                        <Icon name="folder"/>
                                        <p>"This folder is empty"</p>
                                        <small class="muted">
                                            "Upload a file or create a folder to get started."
                                        </small>
                                    </div>
                                }
                                    .into_any();
                            }
                            if grid.get() {
                                view! {
                                    <div class="grid">
                                        <For
                                            each=move || entries.get()
                                            key=|entry| entry.path.clone()
                                            children=move |entry| {
                                                let is_dir = entry.kind == "dir";
                                                let is_img = !is_dir
                                                    && !entry.encrypted
                                                    && is_image_name(&entry.name);
                                                let shared = entry.shared;
                                                // Rename/Delete need ownership or a "write"
                                                // share; Share stays owner-only.
                                                let can_edit = !shared
                                                    || entry.permission.as_deref() == Some("write");
                                                let name = entry.name.clone();
                                                let kind = entry.kind.clone();
                                                let meta = if is_dir {
                                                    "Folder".to_string()
                                                } else {
                                                    let when = relative_time(entry.modified_at);
                                                    let size = if entry.encrypted {
                                                        "Encrypted".to_string()
                                                    } else {
                                                        human_size(entry.size)
                                                    };
                                                    if when.is_empty() {
                                                        size
                                                    } else {
                                                        format!("{size} · {when}")
                                                    }
                                                };
                                                let open_entry = entry.clone();
                                                let share_copy = entry.clone();
                                                let rename_copy = entry.clone();
                                                let delete_copy = entry.clone();
                                                let preview = entry.path.clone();
                                                let download = entry.path.clone();
                                                let encrypted = entry.encrypted;
                                                let download_copy = entry.clone();
                                                let ctx_copy = entry.clone();
                                                let lightbox_copy = entry.clone();
                                                let drag_copy = entry.clone();
                                                let drop_copy = entry.clone();
                                                let select_path = entry.path.clone();
                                                let selected_path = entry.path.clone();
                                                view! {
                                                    <div
                                                        class="tile"
                                                        class:selected=move || {
                                                            selected.get().contains(&selected_path)
                                                        }
                                                        draggable="true"
                                                        on:dragstart=move |_| {
                                                            move_drag.set(Some(drag_copy.clone()));
                                                        }
                                                        on:contextmenu=move |ev: ev::MouseEvent| {
                                                            ev.prevent_default();
                                                            context_menu
                                                                .set(
                                                                    Some((
                                                                        ctx_copy.clone(),
                                                                        ev.client_x(),
                                                                        ev.client_y(),
                                                                    )),
                                                                );
                                                        }
                                                        on:dragover=move |ev: ev::DragEvent| {
                                                            if is_dir {
                                                                ev.prevent_default();
                                                            }
                                                        }
                                                        on:drop=move |ev: ev::DragEvent| {
                                                            if is_dir {
                                                                ev.prevent_default();
                                                                if let Some(src) = move_drag.get_untracked() {
                                                                    move_into(src, drop_copy.path.clone());
                                                                    move_drag.set(None);
                                                                }
                                                            }
                                                        }
                                                    >
                                                        <button
                                                            class="tile-open"
                                                            on:click=move |ev: ev::MouseEvent| {
                                                                if ev.ctrl_key()
                                                                    || ev.meta_key()
                                                                    || ev.shift_key()
                                                                {
                                                                    toggle_select(select_path.clone());
                                                                } else {
                                                                    open(open_entry.clone());
                                                                }
                                                            }
                                                        >
                                                            <span class=format!(
                                                                "tile-thumb {}",
                                                                if is_dir { "folder" } else { "" },
                                                            )>
                                                                {is_img
                                                                    .then(|| {
                                                                        view! {
                                                                            <img
                                                                                loading="lazy"
                                                                                alt=""
                                                                                src=format!(
                                                                                    "/api/preview?path={}&size=256",
                                                                                    encode(&preview),
                                                                                )
                                                                                on:click=move |ev: ev::MouseEvent| {
                                                                                    ev.stop_propagation();
                                                                                    lightbox.set(Some(lightbox_copy.clone()));
                                                                                }
                                                                            />
                                                                        }
                                                                    })}
                                                                {(!is_img)
                                                                    .then(|| {
                                                                        view! { <Icon name=file_icon(&name, &kind)/> }
                                                                    })}
                                                            </span>
                                                            <span class="tile-name">{name.clone()}</span>
                                                            <span class="tile-meta">{meta}</span>
                                                        </button>
                                                        <div class="tile-actions">
                                                            {encrypted
                                                                .then(|| {
                                                                    // Informational only: Download already
                                                                    // decrypts, so a second button would just
                                                                    // do the same thing twice.
                                                                    view! {
                                                                        <span
                                                                            class="icon-btn"
                                                                            title="Encrypted — downloads decrypt in your browser"
                                                                        >
                                                                            <Icon name="lock"/>
                                                                        </span>
                                                                    }
                                                                })}
                                                            {(!is_dir)
                                                                .then(|| {
                                                                    if encrypted {
                                                                        view! {
                                                                            <button
                                                                                class="icon-btn"
                                                                                title="Download (decrypt)"
                                                                                on:click=move |_| decrypt_entry(download_copy.clone())
                                                                            >
                                                                                <Icon name="download"/>
                                                                            </button>
                                                                        }
                                                                            .into_any()
                                                                    } else {
                                                                        view! {
                                                                            <a
                                                                                class="icon-btn"
                                                                                title="Download"
                                                                                href=format!("/dav{}", encode_path(&download))
                                                                                download
                                                                            >
                                                                                <Icon name="download"/>
                                                                            </a>
                                                                        }
                                                                            .into_any()
                                                                    }
                                                                })}
                                                            {can_edit
                                                                .then(|| {
                                                                    view! {
                                                                        {(!shared)
                                                                            .then(|| {
                                                                                view! {
                                                                                    <button
                                                                                        class="icon-btn"
                                                                                        title="Share"
                                                                                        on:click=move |_| share_entry(share_copy.clone())
                                                                                    >
                                                                                        <Icon name="share"/>
                                                                                    </button>
                                                                                }
                                                                            })}
                                                                        <button
                                                                            class="icon-btn"
                                                                            title="Rename"
                                                                            on:click=move |_| rename_entry(rename_copy.clone())
                                                                        >
                                                                            <Icon name="edit"/>
                                                                        </button>
                                                                        <button
                                                                            class="icon-btn"
                                                                            title="Delete"
                                                                            on:click=move |_| delete_entry(delete_copy.clone())
                                                                        >
                                                                            <Icon name="trash"/>
                                                                        </button>
                                                                    }
                                                                })}
                                                        </div>
                                                    </div>
                                                }
                                            }
                                        />
                                    </div>
                                }
                                    .into_any()
                            } else {
                                view! {
                                    <ul class="files">
                                        <For
                                            each=move || entries.get()
                                            key=|entry| entry.path.clone()
                                            children=move |entry| {
                                                let is_dir = entry.kind == "dir";
                                                let is_img = !is_dir
                                                    && !entry.encrypted
                                                    && is_image_name(&entry.name);
                                                let shared = entry.shared;
                                                // Rename/Delete need ownership or a "write"
                                                // share; Share stays owner-only.
                                                let can_edit = !shared
                                                    || entry.permission.as_deref() == Some("write");
                                                let owner = entry.owner.clone().unwrap_or_default();
                                                let permission = entry
                                                    .permission
                                                    .clone()
                                                    .unwrap_or_default();
                                                let name = entry.name.clone();
                                                let kind = entry.kind.clone();
                                                let meta = if is_dir {
                                                    "Folder".to_string()
                                                } else {
                                                    let when = relative_time(entry.modified_at);
                                                    let size = if entry.encrypted {
                                                        "Encrypted".to_string()
                                                    } else {
                                                        human_size(entry.size)
                                                    };
                                                    if when.is_empty() {
                                                        size
                                                    } else {
                                                        format!("{size} · {when}")
                                                    }
                                                };
                                                let open_entry = entry.clone();
                                                let share_copy = entry.clone();
                                                let rename_copy = entry.clone();
                                                let delete_copy = entry.clone();
                                                let preview = entry.path.clone();
                                                let download = entry.path.clone();
                                                let encrypted = entry.encrypted;
                                                let download_copy = entry.clone();
                                                let ctx_copy = entry.clone();
                                                let drag_copy = entry.clone();
                                                let drop_copy = entry.clone();
                                                let select_path = entry.path.clone();
                                                let selected_path = entry.path.clone();
                                                view! {
                                                    <li
                                                        class="file"
                                                        class:selected=move || {
                                                            selected.get().contains(&selected_path)
                                                        }
                                                        draggable="true"
                                                        on:dragstart=move |_| {
                                                            move_drag.set(Some(drag_copy.clone()));
                                                        }
                                                        on:contextmenu=move |ev: ev::MouseEvent| {
                                                            ev.prevent_default();
                                                            context_menu
                                                                .set(
                                                                    Some((
                                                                        ctx_copy.clone(),
                                                                        ev.client_x(),
                                                                        ev.client_y(),
                                                                    )),
                                                                );
                                                        }
                                                        on:dragover=move |ev: ev::DragEvent| {
                                                            if is_dir {
                                                                ev.prevent_default();
                                                            }
                                                        }
                                                        on:drop=move |ev: ev::DragEvent| {
                                                            if is_dir {
                                                                ev.prevent_default();
                                                                if let Some(src) = move_drag.get_untracked() {
                                                                    move_into(src, drop_copy.path.clone());
                                                                    move_drag.set(None);
                                                                }
                                                            }
                                                        }
                                                    >
                                                        <button
                                                            class="file-open"
                                                            on:click=move |ev: ev::MouseEvent| {
                                                                if ev.ctrl_key()
                                                                    || ev.meta_key()
                                                                    || ev.shift_key()
                                                                {
                                                                    toggle_select(select_path.clone());
                                                                } else {
                                                                    open(open_entry.clone());
                                                                }
                                                            }
                                                        >
                                                            <span class=format!(
                                                                "file-icon {}",
                                                                if is_dir {
                                                                    "folder"
                                                                } else if is_img {
                                                                    "img"
                                                                } else {
                                                                    ""
                                                                },
                                                            )>
                                                                {is_img
                                                                    .then(|| {
                                                                        view! {
                                                                            <img
                                                                                loading="lazy"
                                                                                alt=""
                                                                                src=format!(
                                                                                    "/api/preview?path={}&size=64",
                                                                                    encode(&preview),
                                                                                )
                                                                            />
                                                                        }
                                                                    })}
                                                                {(!is_img)
                                                                    .then(|| {
                                                                        view! { <Icon name=file_icon(&name, &kind)/> }
                                                                    })}
                                                            </span>
                                                            <span class="file-body">
                                                                <span class="file-name">{name.clone()}</span>
                                                                <span class="file-meta">
                                                                    {meta}
                                                                    {shared
                                                                        .then(|| {
                                                                            view! {
                                                                                <span class="badge">
                                                                                    {format!("shared by {owner} ({permission})")}
                                                                                </span>
                                                                            }
                                                                        })}
                                                                </span>
                                                            </span>
                                                        </button>
                                                        <span class="file-actions">
                                                            {encrypted
                                                                .then(|| {
                                                                    // Informational: Download decrypts.
                                                                    view! {
                                                                        <span
                                                                            class="icon-btn"
                                                                            title="Encrypted — downloads decrypt in your browser"
                                                                        >
                                                                            <Icon name="lock"/>
                                                                        </span>
                                                                    }
                                                                })}
                                                            {(!is_dir)
                                                                .then(|| {
                                                                    if encrypted {
                                                                        view! {
                                                                            <button
                                                                                class="icon-btn"
                                                                                title="Download (decrypt)"
                                                                                on:click=move |_| decrypt_entry(download_copy.clone())
                                                                            >
                                                                                <Icon name="download"/>
                                                                            </button>
                                                                        }
                                                                            .into_any()
                                                                    } else {
                                                                        view! {
                                                                            <a
                                                                                class="icon-btn"
                                                                                title="Download"
                                                                                href=format!("/dav{}", encode_path(&download))
                                                                                download
                                                                            >
                                                                                <Icon name="download"/>
                                                                            </a>
                                                                        }
                                                                            .into_any()
                                                                    }
                                                                })}
                                                            {can_edit
                                                                .then(|| {
                                                                    view! {
                                                                        {(!shared)
                                                                            .then(|| {
                                                                                view! {
                                                                                    <button
                                                                                        class="icon-btn"
                                                                                        title="Share"
                                                                                        on:click=move |_| share_entry(share_copy.clone())
                                                                                    >
                                                                                        <Icon name="share"/>
                                                                                    </button>
                                                                                }
                                                                            })}
                                                                        <button
                                                                            class="icon-btn"
                                                                            title="Rename"
                                                                            on:click=move |_| rename_entry(rename_copy.clone())
                                                                        >
                                                                            <Icon name="edit"/>
                                                                        </button>
                                                                        <button
                                                                            class="icon-btn"
                                                                            title="Delete"
                                                                            on:click=move |_| delete_entry(delete_copy.clone())
                                                                        >
                                                                            <Icon name="trash"/>
                                                                        </button>
                                                                    }
                                                                })}
                                                        </span>
                                                    </li>
                                                }
                                            }
                                        />
                                    </ul>
                                }
                                    .into_any()
                            }
                        }}
                    }
                        .into_any()
                }
                Tab::Trash => {
                    view! {
                        {move || {
                            if trash.get().is_empty() {
                                return view! {
                                    <div class="empty">
                                        <Icon name="trash"/>
                                        <p>"Trash is empty"</p>
                                        <small class="muted">
                                            "Deleted files appear here for 30 days."
                                        </small>
                                    </div>
                                }
                                    .into_any();
                            }
                            view! {
                                <ul class="files">
                                    <For
                                        each=move || trash.get()
                                        key=|item| item.id
                                        children=move |item| {
                                            let restore_copy = item.clone();
                                            let purge_copy = item.clone();
                                            let original = item.original_path.clone().unwrap_or_default();
                                            let size = human_size(item.size);
                                            view! {
                                                <li class="file">
                                                    <div class="file-open">
                                                        <span class="file-icon">
                                                            <Icon name="trash"/>
                                                        </span>
                                                        <span class="file-body">
                                                            <span class="file-name">{item.name.clone()}</span>
                                                            <span class="file-meta">
                                                                {size}
                                                                <span class="muted">{original}</span>
                                                            </span>
                                                        </span>
                                                    </div>
                                                    <span class="file-actions">
                                                        <button on:click=move |_| restore(restore_copy.clone())>
                                                            <Icon name="refresh"/>
                                                            "Restore"
                                                        </button>
                                                        <button
                                                            class="danger"
                                                            on:click=move |_| purge(purge_copy.clone())
                                                        >
                                                            <Icon name="trash"/>
                                                            "Delete forever"
                                                        </button>
                                                    </span>
                                                </li>
                                            }
                                        }
                                    />
                                </ul>
                            }
                                .into_any()
                        }}
                    }
                        .into_any()
                }
            }
        }}
                </main>
            </div>

            <div class="toasts">
                <Show when=move || !error.get().is_empty()>
                    <div class="toast error">
                        <span class="toast-msg">{move || error.get()}</span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| error.set(String::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || !notice.get().is_empty()>
                    <div class="toast ok">
                        <span class="toast-msg">{move || notice.get()}</span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| notice.set(String::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || quota_warn.get().is_some()>
                    <div class="toast error">
                        <span class="toast-msg">
                            {move || {
                                quota_warn
                                    .get()
                                    .map(|percent| {
                                        format!(
                                            "Storage almost full: {percent}% of your quota used.",
                                        )
                                    })
                                    .unwrap_or_default()
                            }}
                        </span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| quota_warn.set(None)
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || undo.get().is_some()>
                    <div class="toast ok">
                        <span class="toast-msg">
                            {move || {
                                undo
                                    .get()
                                    .map(|(name, _)| format!("Moved “{name}” to trash"))
                                    .unwrap_or_default()
                            }}
                        </span>
                        <button
                            on:click=move |_| {
                                if let Some((_, id)) = undo.get_untracked() {
                                    spawn_local(async move {
                                        let _ = api::send_json(
                                            "POST",
                                            &format!("/api/trash/{id}/restore"),
                                            &json!({}),
                                        )
                                        .await;
                                        undo.set(None);
                                        load(path.get_untracked());
                                    });
                                }
                            }
                        >
                            "Undo"
                        </button>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| undo.set(None)
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
            </div>

            <Show when=move || !uploads.get().is_empty()>
                <div class="upload-tray">
                    <div class="upload-tray-head">
                        <b>"Uploads"</b>
                        <button
                            class="icon-btn"
                            aria-label="Clear"
                            on:click=move |_| uploads.set(Vec::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                    <ul>
                        <For
                            each=move || uploads.get()
                            key=|item| item.id
                            children=move |item| {
                                let name = item.name.clone();
                                let dir = item.dir.clone();
                                let file = item.file.clone();
                                // Per-item signals: O(1) reads, no tray scan.
                                let progress = item.progress;
                                let status = item.status;
                                view! {
                                    <li class="upload-item">
                                        <span class="upload-name">{name}</span>
                                        <span class="upload-bar">
                                            <span
                                                class="upload-bar-fill"
                                                style=move || format!("width:{}%", progress.get())
                                            ></span>
                                        </span>
                                        <span class="upload-status">
                                            {move || match status.get() {
                                                UploadStatus::Uploading => {
                                                    view! { <span class="muted">{format!("{}%", progress.get())}</span> }
                                                        .into_any()
                                                }
                                                UploadStatus::Done => {
                                                    view! { <span class="ok">"done"</span> }.into_any()
                                                }
                                                UploadStatus::Failed => {
                                                    let file = file.clone();
                                                    let dir = dir.clone();
                                                    view! {
                                                        <button
                                                            class="icon-btn"
                                                            title="Retry"
                                                            on:click=move |_| {
                                                                progress.set(0);
                                                                status.set(UploadStatus::Uploading);
                                                                start_upload(
                                                                    file.clone(),
                                                                    dir.clone(),
                                                                    progress,
                                                                    status,
                                                                );
                                                            }
                                                        >
                                                            <Icon name="refresh"/>
                                                        </button>
                                                    }
                                                        .into_any()
                                                }
                                            }}
                                        </span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </div>
            </Show>

            {move || {
                context_menu
                    .get()
                    .map(|(entry, x, y)| {
                        let is_dir = entry.kind == "dir";
                        let shared = entry.shared;
                        // Rename/Delete need ownership or a "write" share.
                        let ctx_edit = !shared
                            || entry.permission.as_deref() == Some("write");
                        let encrypted = entry.encrypted;
                        let open_e = entry.clone();
                        let download = entry.path.clone();
                        let copy_path = entry.path.clone();
                        let share_e = entry.clone();
                        let rename_e = entry.clone();
                        let delete_e = entry.clone();
                        let versions_e = entry.clone();
                        let encrypt_e = entry.clone();
                        // Only top-level folders own their flag; nested
                        // folders inherit their parent's policy.
                        let encrypt_toggle =
                            is_dir && !shared && entry.path.matches('/').count() == 1;
                        view! {
                            <div class="ctx-scrim" on:click=move |_| context_menu.set(None)></div>
                            <div class="ctx-menu" style=format!("left:{}px; top:{}px;", x.max(0), y.max(0))>
                                {is_dir
                                    .then(|| {
                                        view! {
                                            <button
                                                class="ctx-item"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    open(open_e.clone());
                                                }
                                            >
                                                <Icon name="folder"/>
                                                "Open"
                                            </button>
                                        }
                                    })}
                                {(!is_dir)
                                    .then(|| {
                                        if encrypted {
                                            view! {
                                                <button
                                                    class="ctx-item"
                                                    title="Download (decrypt)"
                                                    on:click=move |_| {
                                                        context_menu.set(None);
                                                        decrypt_entry(entry.clone());
                                                    }
                                                >
                                                    <Icon name="download"/>
                                                    "Download"
                                                </button>
                                            }
                                                .into_any()
                                        } else {
                                            view! {
                                                <a
                                                    class="ctx-item"
                                                    href=format!("/dav{}", encode_path(&download))
                                                    download
                                                    on:click=move |_| context_menu.set(None)
                                                >
                                                    <Icon name="download"/>
                                                    "Download"
                                                </a>
                                            }
                                                .into_any()
                                        }
                                    })}
                                <button
                                    class="ctx-item"
                                    on:click=move |_| {
                                        context_menu.set(None);
                                        let path = copy_path.clone();
                                        spawn_local(async move {
                                            crate::api::copy_to_clipboard(&path).await;
                                        });
                                    }
                                >
                                    <Icon name="link"/>
                                    "Copy path"
                                </button>
                                {ctx_edit
                                    .then(|| {
                                        view! {
                                            {(!shared)
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                share_entry(share_e.clone());
                                                            }
                                                        >
                                                            <Icon name="share"/>
                                                            "Share"
                                                        </button>
                                                    }
                                                })}
                                            <button
                                                class="ctx-item"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    rename_entry(rename_e.clone());
                                                }
                                            >
                                                <Icon name="edit"/>
                                                "Rename"
                                            </button>
                                            <button
                                                class="ctx-item danger"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    delete_entry(delete_e.clone());
                                                }
                                            >
                                                <Icon name="trash"/>
                                                "Move to trash"
                                            </button>
                                            {(!is_dir && !shared)
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                versions_for.set(Some(versions_e.clone()));
                                                            }
                                                        >
                                                            <Icon name="history"/>
                                                            "Versions"
                                                        </button>
                                                    }
                                                })}
                                            {encrypt_toggle
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                toggle_encryption(encrypt_e.clone());
                                                            }
                                                        >
                                                            <Icon name="lock"/>
                                                            {if encrypted {
                                                                "Make this folder plaintext"
                                                            } else {
                                                                "Encrypt this folder"
                                                            }}
                                                        </button>
                                                    }
                                                })}
                                        }
                                    })}
                            </div>
                        }
                    })
            }}

            {move || {
                lightbox
                    .get()
                    .map(|entry| {
                        let name = entry.name.clone();
                        let name2 = name.clone();
                        let name3 = name.clone();
                        let encrypted = entry.encrypted;
                        let preview_text = is_text_name(&entry.name);
                        let src = if encrypted {
                            lightbox_url.get()
                        } else {
                            format!("/api/preview?path={}&size=1024", encode(&entry.path))
                        };
                        let download = entry.path.clone();
                        let dl_entry = entry.clone();
                        view! {
                            <div class="lightbox" on:click=move |_| lightbox.set(None)>
                                {preview_text
                                    .then(|| {
                                        view! {
                                            <Show
                                                when=move || !lightbox_text.get().is_empty()
                                                fallback=|| view! { <p class="muted">"Loading preview…"</p> }
                                            >
                                                <pre class="lightbox-text">{move || lightbox_text.get()}</pre>
                                            </Show>
                                        }
                                    })}
                                {(!preview_text)
                                    .then(|| {
                                        view! {
                                            {encrypted
                                                .then(|| {
                                                    view! {
                                                        <Show
                                                            when=move || !lightbox_url.get().is_empty()
                                                            fallback=|| view! { <p class="muted">"Decrypting…"</p> }
                                                        >
                                                            <img src=move || lightbox_url.get() alt=name2.clone()/>
                                                        </Show>
                                                    }
                                                })}
                                            {(!encrypted)
                                                .then(|| {
                                                    view! { <img src=src alt=name3.clone()/> }
                                                })}
                                        }
                                    })}
                                <div
                                    class="lightbox-bar"
                                    on:click=move |ev: ev::MouseEvent| ev.stop_propagation()
                                >
                                    <span class="lightbox-name">{name.clone()}</span>
                                    {if encrypted {
                                        view! {
                                            <button
                                                class="icon-btn"
                                                title="Download (decrypt)"
                                                on:click=move |_| {
                                                    lightbox.set(None);
                                                    decrypt_entry(dl_entry.clone());
                                                }
                                            >
                                                <Icon name="download"/>
                                            </button>
                                        }
                                            .into_any()
                                    } else {
                                        view! {
                                            <a
                                                class="icon-btn"
                                                title="Download"
                                                href=format!("/dav{}", encode_path(&download))
                                                download
                                            >
                                                <Icon name="download"/>
                                            </a>
                                        }
                                            .into_any()
                                    }}
                                    <button
                                        class="icon-btn"
                                        aria-label="Close"
                                        on:click=move |_| lightbox.set(None)
                                    >
                                        <Icon name="x"/>
                                    </button>
                                </div>
                            </div>
                        }
                    })
            }}

            {move || {
                vault_setup
                .get()
                .then(|| {
                    view! {
                        <VaultSetupDialog
                            on_close=Callback::new(move |_| {
                                if let Some(storage) = web_sys::window()
                                    .and_then(|window| window.local_storage().ok().flatten())
                                {
                                    let _ = storage.set_item("kolimi.vault.dismissed", "1");
                                }
                                vault_setup.set(false);
                            })
                            on_done=Callback::new(move |master| {
                                crate::e2ee::remember_master(&master);
                                e2ee_master.set(Some(master));
                                vault_setup.set(false);
                                notice.set("Vault ready — anything you put inside it is encrypted".to_string());
                                load(path.get_untracked());
                            })
                        />
                    }
                })
        }}

            {move || {
                share_target
                .get()
                .map(|entry| {
                    view! {
                        <ShareDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            encrypted=entry.encrypted
                            master=e2ee_master.get()
                            on_close=Callback::new(move |_| share_target.set(None))
                        />
                    }
                })
        }}

            {move || {
                versions_for
                .get()
                .map(|entry| {
                    let current = path.get();
                    view! {
                        <VersionsDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            on_close=Callback::new(move |_| versions_for.set(None))
                            on_restored=Callback::new(move |_| load(current.clone()))
                        />
                    }
                })
        }}

        {move || {
            passkeys_open
                .get()
                .then(|| {
                    view! {
                        <PasskeysDialog on_close=Callback::new(move |_| passkeys_open.set(false))/>
                    }
                })
        }}

        {move || {
            admin_open
                .get()
                .then(|| {
                    view! {
                        <AdminDialog on_close=Callback::new(move |_| admin_open.set(false))/>
                    }
                })
        }}
        {move || {
            e2ee_open
                .get()
                .then(|| {
                    view! {
                        <E2eeDialog
                            master=e2ee_master
                            on_close=Callback::new(move |_| e2ee_open.set(false))
                        />
                    }
                })
        }}
        </div>
    }
}

/// Formats a byte count compactly.
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Renders a per-user quota value.
fn quota_label(quota: Option<i64>) -> String {
    match quota {
        None => "default".to_string(),
        Some(0) => "unlimited".to_string(),
        Some(n) if n > 0 => fmt_bytes(n as u64),
        Some(_) => "unlimited".to_string(),
    }
}

/// Admin panel: per-user quotas, roles, and account lifecycle.
#[component]
fn AdminDialog(on_close: Callback<()>) -> impl IntoView {
    let users = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let sort_usage = RwSignal::new(false);
    let over_only = RwSignal::new(false);

    let load = Callback::new(move |_: ()| {
        spawn_local(async move {
            let mut url = if sort_usage.get() {
                "/api/users?limit=200&sort=used_bytes&order=desc".to_string()
            } else {
                "/api/users?limit=200".to_string()
            };
            if over_only.get() {
                url.push_str("&filter=over_quota");
            }
            match api::get(&url).await {
                Ok(r) if r.status == 200 => {
                    error.set(String::new());
                    users.set(r.body["users"].as_array().cloned().unwrap_or_default());
                }
                Ok(r) => error.set(r.error().unwrap_or("Could not load users").to_string()),
                Err(e) => error.set(e),
            }
        });
    });
    Effect::new(move |_| load.run(()));

    let set_quota = move |username: String| {
        let Some(input) = api::prompt(
            "Quota in bytes ('0' = unlimited, 'default' = server default)",
            "",
        ) else {
            return;
        };
        let quota = match input.trim() {
            "default" | "" => json!(null),
            "unlimited" => json!(0),
            other => match other.parse::<i64>() {
                Ok(n) if n >= 0 => json!(n),
                _ => {
                    error.set("invalid quota (bytes, 'unlimited' or 'default')".to_string());
                    return;
                }
            },
        };
        spawn_local(async move {
            match api::send_json(
                "PATCH",
                &format!("/api/users/{}", encode(&username)),
                &json!({ "quota_bytes": quota }),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(format!("quota updated for {username}"));
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("update failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let patch = move |username: String, body: Value, ok: &'static str| {
        spawn_local(async move {
            match api::send_json("PATCH", &format!("/api/users/{}", encode(&username)), &body).await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(ok.to_string());
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("update failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let remove = move |username: String| {
        if !api::confirm(&format!(
            "Delete {username} and all of their data? This cannot be undone."
        )) {
            return;
        }
        spawn_local(async move {
            match api::delete(&format!("/api/users/{}", encode(&username))).await {
                Ok(r) if r.status == 204 => {
                    notice.set(format!("deleted {username}"));
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("delete failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let recheck = move |username: String| {
        spawn_local(async move {
            match api::get(&format!("/api/users/{}/usage", encode(&username))).await {
                Ok(r) if r.status == 200 => {
                    notice.set(format!(
                        "{username}: {} used",
                        fmt_bytes(r.body["used_bytes"].as_u64().unwrap_or(0))
                    ));
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("usage failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>"Admin — users"</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <p class="muted">
                    "Storage quotas, administrator rights, and account lifecycle."
                </p>
                <p class="error">{move || error.get()}</p>
                <p class="notice">{move || notice.get()}</p>
                <div class="row-actions">
                    <button on:click=move |_| load.run(())>"Refresh"</button>
                    <button on:click=move |_| {
                        sort_usage.update(|value| *value = !*value);
                        load.run(());
                    }>
                        {move || if sort_usage.get() { "By usage ▾" } else { "By name" }}
                    </button>
                    <button on:click=move |_| {
                        over_only.update(|value| *value = !*value);
                        load.run(());
                    }>
                        {move || if over_only.get() { "Over quota only ✓" } else { "Over quota only" }}
                    </button>
                </div>
                <ul class="shares">
                    <For
                        each=move || users.get()
                        key=|user| user["id"].as_i64().unwrap_or(0)
                        children=move |user| {
                            let username = user["username"].as_str().unwrap_or_default().to_string();
                            let is_admin = user["is_admin"].as_bool().unwrap_or(false);
                            let disabled = user["disabled"].as_bool().unwrap_or(false);
                            let used = user["used_bytes"].as_u64().unwrap_or(0);
                            let quota = user["quota_bytes"].as_i64();
                            let near = quota.is_some_and(|q| {
                                q > 0
                                    && used < q as u64
                                    && used.saturating_mul(10) >= (q as u64).saturating_mul(9)
                            });
                            let over = quota.is_some_and(|q| q > 0 && used >= q as u64);
                            let q = username.clone();
                            let a = username.clone();
                            let d = username.clone();
                            let r = username.clone();
                            let u = username.clone();
                            view! {
                                <li class="file">
                                    <div class="file-open">
                                        <span class="file-icon">
                                            <Icon name="users"/>
                                        </span>
                                        <span class="file-body">
                                            <span class="file-name">{username}</span>
                                            <span class="file-meta">
                                                {is_admin
                                                    .then(|| view! { <span class="badge">"admin"</span> })}
                                                {disabled
                                                    .then(|| view! { <span class="badge">"disabled"</span> })}
                                                {over
                                                    .then(|| view! { <span class="badge">"over quota"</span> })}
                                                {near
                                                    .then(|| view! { <span class="badge">"near quota"</span> })}
                                                <span class="muted">
                                                    {fmt_bytes(used)} " / " {quota_label(quota)}
                                                </span>
                                            </span>
                                        </span>
                                    </div>
                                    <span class="file-actions">
                                        <button
                                            class="icon-btn"
                                            title="Recheck usage"
                                            on:click=move |_| recheck(r.clone())
                                        >
                                            <Icon name="refresh"/>
                                        </button>
                                        <button on:click=move |_| set_quota(q.clone())>"Quota"</button>
                                        <button on:click=move |_| patch(a.clone(), json!({ "admin": !is_admin }), "role updated")>
                                            {if is_admin { "Revoke admin" } else { "Make admin" }}
                                        </button>
                                        <button on:click=move |_| patch(d.clone(), json!({ "disabled": !disabled }), "access updated")>
                                            {if disabled { "Enable" } else { "Disable" }}
                                        </button>
                                        <button
                                            class="icon-btn"
                                            title="Delete user"
                                            on:click=move |_| remove(u.clone())
                                        >
                                            <Icon name="trash"/>
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                </ul>
            </div>
        </div>
    }
}

/// Unlock end-to-end encryption in the browser (passphrase).
#[component]
fn E2eeDialog(master: RwSignal<Option<MasterKey>>, on_close: Callback<()>) -> impl IntoView {
    let passphrase = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let enrollments = RwSignal::new(Vec::<Value>::new());
    let devices = RwSignal::new(Vec::<Value>::new());
    let device_name = RwSignal::new(String::new());
    let enrolling = RwSignal::new(Option::<(i64, [u8; 32], String)>::None);
    // An in-progress enrollment survives a reload: the pending id + device
    // secret live in sessionStorage until the enrollment finishes.
    const PENDING_KEY: &str = "kolimi.enrollment.pending";
    fn store_pending(id: i64, secret: &[u8; 32], code: &str) {
        if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
            let value = serde_json::json!({
                "id": id,
                "secret": URL_SAFE_NO_PAD.encode(secret),
                "code": code,
            })
            .to_string();
            let _ = storage.set_item(PENDING_KEY, &value);
        }
    }
    fn clear_pending() {
        if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
            let _ = storage.remove_item(PENDING_KEY);
        }
    }
    Effect::new(move |_| {
        if enrolling.get_untracked().is_some() {
            return;
        }
        let restored: Option<(i64, [u8; 32], String)> = web_sys::window()
            .and_then(|w| w.session_storage().ok().flatten())
            .and_then(|storage| storage.get_item(PENDING_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
            .and_then(|value| {
                let id = value["id"].as_i64()?;
                let secret = URL_SAFE_NO_PAD
                    .decode(value["secret"].as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?;
                let code = value["code"].as_str()?.to_string();
                Some((id, secret, code))
            });
        if let Some(pending) = restored {
            enrolling.set(Some(pending));
            notice.set(
                "Resumed your pending enrollment — approve it on another device, then unlock."
                    .to_string(),
            );
        }
    });
    let use_recovery = RwSignal::new(false);
    let has_keyring = RwSignal::new(Option::<bool>::None);
    // `None` with `keyring_error` unset means "still checking" — never show
    // the unlock form for an unknown state, or a new account looks like it
    // already has encryption.
    let keyring_error = RwSignal::new(false);
    let check_keyring = Callback::new(move |_: ()| {
        keyring_error.set(false);
        spawn_local(async move {
            match crate::e2ee::keyring_exists().await {
                Ok(exists) => has_keyring.set(Some(exists)),
                Err(_) => keyring_error.set(true),
            }
        });
    });
    Effect::new(move |_| {
        check_keyring.run(());
    });
    let setup_pass = RwSignal::new(String::new());
    let setup_confirm = RwSignal::new(String::new());
    let change_open = RwSignal::new(false);
    let new_pass = RwSignal::new(String::new());
    let new_confirm = RwSignal::new(String::new());
    let recovery = RwSignal::new(Option::<String>::None);
    let close = move |_| on_close.run(());

    let load_devices = Callback::new(move |_: ()| {
        spawn_local(async move {
            if let Ok(list) = crate::e2ee::pending_enrollments().await {
                enrollments.set(list);
            }
            if let Ok(list) = crate::e2ee::devices().await {
                devices.set(list);
            }
        });
    });
    Effect::new(move |_| {
        if master.get().is_some() {
            load_devices.run(());
        }
    });

    let unlock = move |_| {
        let secret = passphrase.get_untracked();
        if secret.is_empty() {
            error.set("Enter your passphrase or recovery code".to_string());
            return;
        }
        let recovery = use_recovery.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let result = if recovery {
                crate::e2ee::unlock_recovery(&secret).await
            } else {
                crate::e2ee::unlock(&secret).await
            };
            match result {
                Ok(key) => {
                    crate::e2ee::remember_master(&key);
                    master.set(Some(key));
                    busy.set(false);
                }
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let setup = move |_| {
        let passphrase = setup_pass.get_untracked();
        if passphrase.is_empty() {
            error.set("Enter a passphrase".to_string());
            return;
        }
        if passphrase != setup_confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::setup(&passphrase).await {
                Ok(code) => {
                    match crate::e2ee::unlock(&passphrase).await {
                        Ok(key) => {
                            crate::e2ee::remember_master(&key);
                            master.set(Some(key));
                        }
                        Err(e) => error.set(e),
                    }
                    has_keyring.set(Some(true));
                    recovery.set(Some(code));
                    busy.set(false);
                }
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let change_pass = move |_| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        let pass = new_pass.get_untracked();
        if pass.is_empty() {
            error.set("Enter a new passphrase".to_string());
            return;
        }
        if pass != new_confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::change_passphrase(&unlocked, &pass).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Passphrase changed — use the new one next time".to_string());
                    change_open.set(false);
                    new_pass.set(String::new());
                    new_confirm.set(String::new());
                }
                Err(e) => error.set(e),
            }
            busy.set(false);
        });
    };

    let migrate_names = move |_| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        if !api::confirm(
            "Encrypt the names of existing items in your encrypted folders? They are renamed on the server; contents are not re-uploaded. Plaintext files are skipped — encrypt those first.",
        ) {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::migrate_names(&unlocked).await {
                Ok(0) => {
                    notice.set("No readable names left to encrypt.".to_string());
                    busy.set(false);
                }
                Ok(count) => {
                    // The old paths are gone; reload so the list rebuilds
                    // from the renamed tree (the unlocked key survives in
                    // sessionStorage).
                    notice.set(format!("Renamed {count} item(s) — reloading…"));
                    if let Some(window) = web_sys::window() {
                        let _ = window.location().reload();
                    }
                }
                Err(e) => {
                    error.set(e);
                    busy.set(false);
                }
            }
        });
    };

    let approve = move |id: i64, key: String, code: Option<String>| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match crate::e2ee::approve_enrollment(id, &key, code.as_deref(), &unlocked).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Device approved".to_string());
                    load_devices.run(());
                }
                Err(e) => error.set(e),
            }
        });
    };

    let revoke = move |id: i64| {
        spawn_local(async move {
            match crate::e2ee::revoke_device(id).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Device revoked".to_string());
                    load_devices.run(());
                }
                Err(e) => error.set(e),
            }
        });
    };

    let start_enroll = move |_| {
        let name = device_name.get_untracked().trim().to_string();
        if name.is_empty() {
            error.set("Enter a name for this device".to_string());
            return;
        }
        spawn_local(async move {
            match crate::e2ee::start_enrollment(&name).await {
                Ok((id, secret, code)) => {
                    error.set(String::new());
                    notice.set(format!(
                        "Compare code {code} on the approving device, then approve it there."
                    ));
                    store_pending(id, &secret, &code);
                    enrolling.set(Some((id, secret, code)));
                }
                Err(e) => error.set(e),
            }
        });
    };

    let finish_enroll = move |_| {
        let Some((id, secret, _)) = enrolling.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match crate::e2ee::poll_enrollment(id, &secret).await {
                Ok(Some(key)) => {
                    crate::e2ee::remember_master(&key);
                    master.set(Some(key));
                    enrolling.set(None);
                    clear_pending();
                    notice.set("This browser is now enrolled".to_string());
                }
                Ok(None) => notice
                    .set("Not approved yet — approve it on another device, then retry".to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>"Settings"</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <h3>"Encryption"</h3>
                <p class="muted">
                    "Your passphrase is used locally and is never sent to the server."
                </p>
                <Show when=move || recovery.get().is_some()>
                    <p class="notice">
                        "Write down these 24 words now — they are shown once and are the only other way to unlock."
                    </p>
                    <code class="recovery">{move || recovery.get().unwrap_or_default()}</code>
                    <div class="row-actions">
                        <button on:click=move |_| {
                            let code = recovery.get_untracked().unwrap_or_default();
                            spawn_local(async move { crate::api::copy_to_clipboard(&code).await });
                        }>"Copy"</button>
                        <button class="primary" on:click=move |_| recovery.set(None)>"I saved it"</button>
                    </div>
                </Show>
                <Show when=move || master.get().is_none() && recovery.get().is_none()>
                    <Show when=move || has_keyring.get().is_none() && !keyring_error.get()>
                        <p class="muted">"Checking encryption status…"</p>
                    </Show>
                    <Show when=move || keyring_error.get()>
                        <p class="error">
                            "Couldn't check the encryption status — the server didn't answer. Check your connection and retry."
                        </p>
                        <div class="row-actions">
                            <button class="primary" on:click=move |_| check_keyring.run(())>
                                "Retry"
                            </button>
                        </div>
                    </Show>
                    <Show when=move || has_keyring.get() == Some(false)>
                        <p class="muted">
                            "Encryption is not set up for this account yet. Choose a passphrase — it never leaves this browser."
                        </p>
                        <label>
                            "New passphrase"
                            <input
                                type="password"
                                autocomplete="new-password"
                                prop:value=move || setup_pass.get()
                                on:input=move |ev| setup_pass.set(event_target_value(&ev))
                            />
                        </label>
                        <label>
                            "Repeat passphrase"
                            <input
                                type="password"
                                autocomplete="new-password"
                                prop:value=move || setup_confirm.get()
                                on:input=move |ev| setup_confirm.set(event_target_value(&ev))
                            />
                        </label>
                        <div class="row-actions">
                            <button class="primary" disabled=move || busy.get() on:click=setup>
                                <Icon name="lock"/>
                                {move || {
                                    if busy.get() { "Setting up…" } else { "Set up encryption" }
                                }}
                            </button>
                        </div>
                    </Show>
                    <Show when=move || has_keyring.get() == Some(true)>
                        <label>
                            {move || {
                                if use_recovery.get() {
                                    "Recovery phrase (24 words)"
                                } else {
                                    "Passphrase"
                                }
                            }}
                            <input
                                type="password"
                                autocomplete="off"
                                prop:value=move || passphrase.get()
                                on:input=move |ev| passphrase.set(event_target_value(&ev))
                            />
                        </label>
                        <div class="row-actions">
                            <button class="primary" disabled=move || busy.get() on:click=unlock>
                                <Icon name="lock"/>
                                {move || if busy.get() { "Unlocking…" } else { "Unlock" }}
                            </button>
                            <button
                                class="ghost"
                                on:click=move |_| {
                                    use_recovery.set(!use_recovery.get_untracked());
                                    error.set(String::new());
                                }
                            >
                                {move || {
                                    if use_recovery.get() {
                                        "Use passphrase"
                                    } else {
                                        "Use recovery phrase"
                                    }
                                }}
                            </button>
                        </div>
                    </Show>
                </Show>
                <Show when=move || master.get().is_some()>
                    <p class="notice">"Keyring unlocked for this browser."</p>
                    <div class="row-actions">
                        <button
                            class="ghost"
                            on:click=move |_| {
                                crate::e2ee::forget_master();
                                master.set(None);
                                notice.set(String::new());
                            }
                        >
                            "Lock again"
                        </button>
                    </div>

                    <h3>"Passphrase"</h3>
                    <p class="muted">
                        "Change the passphrase that wraps this account's master key. Nothing is re-uploaded, and your recovery phrase and other devices keep working."
                    </p>
                    <Show when=move || !change_open.get()>
                        <div class="row-actions">
                            <button
                                class="ghost"
                                on:click=move |_| {
                                    error.set(String::new());
                                    change_open.set(true);
                                }
                            >
                                "Change passphrase"
                            </button>
                        </div>
                    </Show>
                    <Show when=move || change_open.get()>
                        <label>
                            "New passphrase"
                            <input
                                type="password"
                                autocomplete="new-password"
                                prop:value=move || new_pass.get()
                                on:input=move |ev| new_pass.set(event_target_value(&ev))
                            />
                        </label>
                        <label>
                            "Repeat new passphrase"
                            <input
                                type="password"
                                autocomplete="new-password"
                                prop:value=move || new_confirm.get()
                                on:input=move |ev| new_confirm.set(event_target_value(&ev))
                            />
                        </label>
                        <div class="row-actions">
                            <button class="primary" disabled=move || busy.get() on:click=change_pass>
                                {move || if busy.get() { "Saving…" } else { "Save new passphrase" }}
                            </button>
                            <button
                                class="ghost"
                                on:click=move |_| {
                                    change_open.set(false);
                                    new_pass.set(String::new());
                                    new_confirm.set(String::new());
                                    error.set(String::new());
                                }
                            >
                                "Cancel"
                            </button>
                        </div>
                    </Show>

                    <h3>"Existing names"</h3>
                    <p class="muted">
                        "Items created before names were encrypted may still have readable names. Rename them in place; contents are not re-uploaded. Plaintext files are skipped."
                    </p>
                    <div class="row-actions">
                        <button disabled=move || busy.get() on:click=migrate_names>
                            "Encrypt existing names"
                        </button>
                    </div>

                    <h3>"Pending enrollments"</h3>
                    <p class="muted">
                        "One click approves a new device. If you don't fully trust this server, verify the code first."
                    </p>
                    <ul class="shares">
                        <For
                            each=move || enrollments.get()
                            key=|e| e["id"].as_i64().unwrap_or(0)
                            children=move |entry| {
                                let id = entry["id"].as_i64().unwrap_or(0);
                                let name = entry["device_name"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                let key = entry["device_public_key"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string();
                                let code = crate::e2ee::device_code(&key, id);
                                let fingerprint = crate::e2ee::key_fingerprint(&key);
                                let entered = RwSignal::new(String::new());
                                let verify = RwSignal::new(false);
                                let k = key.clone();
                                view! {
                                    <li class="file">
                                        <span class="file-body">
                                            <span class="file-name">{name}</span>
                                            <Show when=move || verify.get()>
                                                <span class="file-meta">
                                                    <span class="muted">"code " {code.clone()}</span>
                                                    <span class="muted">"key " {fingerprint.clone()}</span>
                                                </span>
                                                <input
                                                    type="text"
                                                    autocomplete="off"
                                                    placeholder="Type the code shown on the new device"
                                                    prop:value=move || entered.get()
                                                    on:input=move |ev| entered.set(event_target_value(&ev))
                                                />
                                            </Show>
                                        </span>
                                        <span class="file-actions">
                                            <button
                                                class="ghost"
                                                title="Compare the code shown on the new device first"
                                                on:click=move |_| verify.set(!verify.get_untracked())
                                            >
                                                "Verify code"
                                            </button>
                                            <button
                                                class="primary"
                                                on:click=move |_| {
                                                    let typed = entered.get_untracked();
                                                    let check = if verify.get_untracked() && !typed.trim().is_empty() {
                                                        Some(typed)
                                                    } else {
                                                        None
                                                    };
                                                    approve(id, k.clone(), check)
                                                }
                                            >
                                                "Approve"
                                            </button>
                                        </span>
                                    </li>
                                }
                            }
                        />
                    </ul>

                    <h3>"Devices"</h3>
                    <ul class="shares">
                        <For
                            each=move || devices.get()
                            key=|d| d["id"].as_i64().unwrap_or(0)
                            children=move |device| {
                                let id = device["id"].as_i64().unwrap_or(0);
                                let name =
                                    device["name"].as_str().unwrap_or_default().to_string();
                                view! {
                                    <li class="file">
                                        <span class="file-body">
                                            <span class="file-name">{name}</span>
                                        </span>
                                        <span class="file-actions">
                                            <button
                                                class="icon-btn"
                                                title="Revoke device"
                                                on:click=move |_| revoke(id)
                                            >
                                                <Icon name="trash"/>
                                            </button>
                                        </span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </Show>

                <h3>"Add this browser as a device"</h3>
                <p class="muted">
                    "Name this browser, start the enrollment, then approve it on another unlocked device — "
                    "no passphrase retyping needed."
                </p>
                <label>
                    "Device name"
                    <input
                        type="text"
                        autocomplete="off"
                        prop:value=move || device_name.get()
                        on:input=move |ev| device_name.set(event_target_value(&ev))
                    />
                </label>
                <div class="row-actions">
                    <button on:click=start_enroll>"Start enrollment"</button>
                    <Show when=move || enrolling.get().is_some()>
                        <button class="primary" on:click=finish_enroll>"Unlock now"</button>
                    </Show>
                </div>
                <Show when=move || enrolling.get().is_some()>
                    {move || {
                        enrolling
                            .get()
                            .map(|(id, _, code)| {
                                view! {
                                    <div class="enroll-qr">
                                        <p class="muted">
                                            "Waiting for approval on another device — then press “Unlock now”."
                                        </p>
                                        <details>
                                            <summary class="muted">"Approval code (advanced)"</summary>
                                            <div
                                                class="qr"
                                                inner_html=crate::e2ee::qr_svg(
                                                    &format!("kolimi-enroll:{id}:{code}"),
                                                )
                                            ></div>
                                            <p class="muted">"Enrollment " {id}</p>
                                            <p class="muted">"Code " {code}</p>
                                        </details>
                                    </div>
                                }
                            })
                    }}
                </Show>

                <p class="notice">{move || notice.get()}</p>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}

#[component]
fn PasskeysDialog(on_close: Callback<()>) -> impl IntoView {
    let passkeys = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let totp = RwSignal::new(Value::Null);
    let enroll = RwSignal::new(Option::<Value>::None);
    let totp_code = RwSignal::new(String::new());
    let recovery = RwSignal::new(Vec::<String>::new());

    let load = Callback::new(move |_: ()| {
        spawn_local(async move {
            if let Ok(r) = api::get("/api/passkeys").await
                && r.status == 200
            {
                passkeys.set(r.body.as_array().cloned().unwrap_or_default());
            }
            if let Ok(r) = api::get("/api/totp").await
                && r.status == 200
            {
                totp.set(r.body);
            }
        });
    });
    Effect::new(move |_| load.run(()));

    let totp_begin = move |_| {
        spawn_local(async move {
            match api::send_json("POST", "/api/totp/begin", &json!({})).await {
                Ok(r) if r.status == 200 => {
                    error.set(String::new());
                    recovery.set(Vec::new());
                    enroll.set(Some(r.body));
                }
                Ok(r) => error.set(
                    r.error()
                        .unwrap_or("Could not start enrollment")
                        .to_string(),
                ),
                Err(e) => error.set(e),
            }
        });
    };

    let totp_confirm = move |_| {
        let Some(begin) = enroll.get_untracked() else {
            return;
        };
        let secret = begin["secret"].clone();
        let code = totp_code.get_untracked();
        spawn_local(async move {
            match api::send_json(
                "POST",
                "/api/totp/enable",
                &json!({ "secret": secret, "code": code }),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    error.set(String::new());
                    recovery.set(
                        r.body["recovery_codes"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_string))
                            .collect(),
                    );
                    enroll.set(None);
                    totp_code.set(String::new());
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("Could not enable").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let totp_disable = move |_| {
        let Some(code) = api::prompt("Enter a current code or a recovery code", "") else {
            return;
        };
        spawn_local(async move {
            match api::send_json("POST", "/api/totp/disable", &json!({ "code": code })).await {
                Ok(r) if r.status == 204 => {
                    error.set(String::new());
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("Could not disable").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let add = move |_| {
        let Some(name) = api::prompt("Name this passkey (e.g. \"laptop\")", "laptop") else {
            return;
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let result = crate::passkey::register(&name).await;
            busy.set(false);
            match result {
                Ok(()) => {
                    error.set(String::new());
                    load.run(());
                }
                Err(e) => error.set(e),
            }
        });
    };

    let remove = move |id: i64| {
        spawn_local(async move {
            match api::delete(&format!("/api/passkeys/{id}")).await {
                Ok(r) if r.status == 204 => load.run(()),
                Ok(r) => error.set(r.error().unwrap_or("Could not remove passkey").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>"Passkeys"</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <p class="muted">
                    "Passkeys sign you in without a password. Add one, then you can "
                    "switch this account to passkey-only."
                </p>
                <ul class="shares">
                    <For
                        each=move || passkeys.get()
                        key=|passkey| passkey["id"].as_i64().unwrap_or(0)
                        children=move |passkey| {
                            let id = passkey["id"].as_i64().unwrap_or(0);
                            let name = passkey["name"].as_str().unwrap_or_default().to_string();
                            view! {
                                <li class="row">
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="key"/>
                                        </span>
                                        {name}
                                    </span>
                                    <span class="row-actions">
                                        <button class="danger" on:click=move |_| remove(id)>
                                            <Icon name="trash"/>
                                            "Remove"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                    <Show when=move || passkeys.get().is_empty()>
                        <li class="row muted">"No passkeys yet."</li>
                    </Show>
                </ul>
                <div class="row-actions">
                    <button class="primary" disabled=move || busy.get() on:click=add>
                        <Icon name="key"/>
                        {move || if busy.get() { "Waiting for authenticator…" } else { "Add passkey" }}
                    </button>
                </div>

                <h3>"Two-factor (TOTP)"</h3>
                {move || {
                    if totp.get()["enabled"].as_bool() == Some(true) {
                        let remaining = totp.get()["recovery_codes_remaining"]
                            .as_i64()
                            .unwrap_or(0);
                        view! {
                            <p class="muted">
                                {format!("Enabled — {remaining} recovery code(s) left.")}
                            </p>
                            <div class="row-actions">
                                <button on:click=totp_disable>"Disable two-factor"</button>
                            </div>
                        }
                            .into_any()
                    } else {
                        view! {
                            <p class="muted">
                                "Sign-in codes from an authenticator app (RFC 6238)."
                            </p>
                            <div class="row-actions">
                                <button on:click=totp_begin>"Enable two-factor"</button>
                            </div>
                        }
                            .into_any()
                    }
                }}

                {move || {
                    enroll
                        .get()
                        .map(|begin| {
                            let svg = begin["qr_svg"].as_str().unwrap_or_default().to_string();
                            let secret = begin["secret"].as_str().unwrap_or_default().to_string();
                            view! {
                                <div class="totp-enroll">
                                    <div class="qr" inner_html=sanitize_svg(&svg)></div>
                                    <p class="muted">
                                        "Scan the QR code, or add this secret manually:"
                                    </p>
                                    <code>{secret}</code>
                                    <label>
                                        "Code from the app"
                                        <input
                                            type="text"
                                            inputmode="numeric"
                                            prop:value=move || totp_code.get()
                                            on:input=move |ev| totp_code.set(event_target_value(&ev))
                                        />
                                    </label>
                                    <button on:click=totp_confirm>"Confirm and enable"</button>
                                </div>
                            }
                        })
                }}

                <Show when=move || !recovery.get().is_empty()>
                    <div class="recovery-codes">
                        <p class="muted">
                            "Recovery codes (shown once — store them somewhere safe):"
                        </p>
                        <ul>
                            <For
                                each=move || recovery.get()
                                key=|code| code.clone()
                                children=|code| view! { <li><code>{code}</code></li> }
                            />
                        </ul>
                    </div>
                </Show>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}

#[component]
fn VaultSetupDialog(on_close: Callback<()>, on_done: Callback<MasterKey>) -> impl IntoView {
    let pass = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let phrase = RwSignal::new(Option::<String>::None);
    let unlocked = RwSignal::new(Option::<MasterKey>::None);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    let create = move |_| {
        let passphrase = pass.get_untracked();
        if passphrase.trim().is_empty() {
            error.set("Choose a passphrase".to_string());
            return;
        }
        if passphrase != confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::setup(&passphrase).await {
                Ok(words) => match crate::e2ee::unlock(&passphrase).await {
                    Ok(master) => {
                        busy.set(false);
                        // Show the phrase first: closing here would skip the
                        // only chance to save the recovery words.
                        unlocked.set(Some(master));
                        phrase.set(Some(words));
                    }
                    Err(e) => {
                        busy.set(false);
                        error.set(e);
                    }
                },
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>"Set up your Vault"</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <Show when=move || phrase.get().is_none()>
                    <p class="muted">
                        "Your Vault is encrypted on this device. We can never read it — and if you lose both the passphrase and the recovery phrase, the files inside are gone for good."
                    </p>
                    <p class="muted">
                        "This is separate from your login password."
                    </p>
                    <label>
                        "Passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || pass.get()
                            on:input=move |ev| pass.set(event_target_value(&ev))
                        />
                    </label>
                    <label>
                        "Repeat passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || confirm.get()
                            on:input=move |ev| confirm.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="row-actions">
                        <button class="primary" disabled=move || busy.get() on:click=create>
                            <Icon name="lock"/>
                            {move || if busy.get() { "Creating…" } else { "Create Vault" }}
                        </button>
                        <button class="ghost" on:click=close>"Later"</button>
                    </div>
                </Show>
                <Show when=move || phrase.get().is_some()>
                    <p class="notice">
                        "Write down these 24 words. They are the only other way to open your Vault."
                    </p>
                    <code class="recovery">{move || phrase.get().unwrap_or_default()}</code>
                    <div class="row-actions">
                        <button
                            on:click=move |_| {
                                let words = phrase.get_untracked().unwrap_or_default();
                                spawn_local(async move { crate::api::copy_to_clipboard(&words).await });
                            }
                        >"Copy"</button>
                        <button
                            class="primary"
                            on:click=move |_| {
                                if let Some(master) = unlocked.get_untracked() {
                                    // Keep the unlocked key so the first
                                    // upload works immediately.
                                    on_done.run(master);
                                } else {
                                    on_close.run(());
                                }
                            }
                        >"I saved it"</button>
                    </div>
                </Show>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}

#[component]
fn VersionsDialog(
    path: String,
    name: String,
    on_close: Callback<()>,
    on_restored: Callback<()>,
) -> impl IntoView {
    let versions = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let load = {
        let path = path.clone();
        Callback::new(move |_: ()| {
            let path = path.clone();
            spawn_local(async move {
                match api::get(&format!("/api/versions?path={}", encode(&path))).await {
                    Ok(r) if r.status == 200 => {
                        versions.set(r.body.as_array().cloned().unwrap_or_default());
                    }
                    Ok(r) => error.set(r.error().unwrap_or("Could not load versions").to_string()),
                    Err(e) => error.set(e),
                }
            });
        })
    };
    Effect::new(move |_| load.run(()));

    let restore = {
        let path = path.clone();
        Callback::new(move |id: i64| {
            let path = path.clone();
            busy.set(true);
            spawn_local(async move {
                match api::send_json(
                    "POST",
                    &format!("/api/versions/{id}/restore"),
                    &json!({ "path": path }),
                )
                .await
                {
                    Ok(r) if r.status == 200 => {
                        busy.set(false);
                        load.run(());
                        on_restored.run(());
                    }
                    Ok(r) => {
                        busy.set(false);
                        error.set(r.error().unwrap_or("Restore failed").to_string());
                    }
                    Err(e) => {
                        busy.set(false);
                        error.set(e);
                    }
                }
            });
        })
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>{format!("Versions of “{name}”")}</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <p class="muted">"Restoring a version makes it current; the replaced content is kept as a version too."</p>
                <ul class="shares">
                    <For
                        each=move || versions.get()
                        key=|v| v["id"].as_i64().unwrap_or(0)
                        children=move |v| {
                            let id = v["id"].as_i64().unwrap_or(0);
                            let size = v["size"].as_u64().unwrap_or(0);
                            let when = v["created_at"].as_i64().unwrap_or(0);
                            view! {
                                <li class="row">
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="history"/>
                                        </span>
                                        {format!("{} · {}", human_size(size), relative_time(when))}
                                    </span>
                                    <span class="row-actions">
                                        <button
                                            class="ghost"
                                            disabled=move || busy.get()
                                            on:click=move |_| restore.run(id)
                                        >
                                            "Restore"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                    <Show when=move || versions.get().is_empty()>
                        <li class="row muted">"No older versions."</li>
                    </Show>
                </ul>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}

#[component]
fn ShareDialog(
    path: String,
    name: String,
    encrypted: bool,
    master: Option<MasterKey>,
    on_close: Callback<()>,
) -> impl IntoView {
    let shares = RwSignal::new(Vec::<Value>::new());
    let users = RwSignal::new(Vec::<String>::new());
    let groups = RwSignal::new(Vec::<String>::new());
    let kind = RwSignal::new("user".to_string());
    let recipient = RwSignal::new(String::new());
    let permission = RwSignal::new("read".to_string());
    let error = RwSignal::new(String::new());
    let created = RwSignal::new(Option::<(String, Option<String>)>::None);

    let load = {
        let path = path.clone();
        Callback::new(move |_: ()| {
            let path = path.clone();
            spawn_local(async move {
                if let Ok(r) = api::get(&format!("/api/shares?path={}", encode(&path))).await
                    && r.status == 200
                {
                    shares.set(r.body["shares"].as_array().cloned().unwrap_or_default());
                }
                if let Ok(r) = api::get("/api/shareable").await
                    && r.status == 200
                {
                    users.set(string_list(&r.body["users"]));
                    groups.set(string_list(&r.body["groups"]));
                }
            });
        })
    };
    Effect::new(move |_| load.run(()));

    let link_frags = RwSignal::new(std::collections::HashMap::<i64, String>::new());

    let create = {
        let path = path.clone();
        let master = master.clone();
        let display_name = name.clone();
        move |_| {
            let kind_value = kind.get_untracked();
            let mut payload = json!({
                "path": path,
                "kind": kind_value,
                "permission": permission.get_untracked(),
            });
            if kind_value != "link" {
                let target = recipient.get_untracked();
                if target.is_empty() {
                    error.set("Choose a recipient".to_string());
                    return;
                }
                payload["recipient"] = json!(target);
            }
            if encrypted && master.is_none() {
                error.set(
                    "Unlock encryption first — without the key a share or link cannot be opened."
                        .to_string(),
                );
                return;
            }
            let path = path.clone();
            let master = master.clone();
            let display_name = display_name.clone();
            spawn_local(async move {
                match api::send_json("POST", "/api/shares", &payload).await {
                    Ok(r) if r.status == 201 => {
                        error.set(String::new());
                        if r.body["kind"] == "link" {
                            let mut url = r.body["url"].as_str().unwrap_or_default().to_string();
                            // For encrypted files, carry the file key + chunk
                            // lengths in the URL fragment (never sent to the
                            // server).
                            if encrypted
                                && let Some(master) = &master
                                && let Ok((key, lengths)) =
                                    crate::e2ee::file_key_and_lengths(master, &path).await
                            {
                                let key = URL_SAFE_NO_PAD.encode(key);
                                let lengths = lengths
                                    .iter()
                                    .map(|len| len.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",");
                                // `n` lets the public page show the real
                                // name; it is in the fragment, never sent
                                // to the server.
                                let display = js_sys::encode_uri_component(&display_name)
                                    .as_string()
                                    .unwrap_or_default();
                                url = format!("{url}#k={key}&l={lengths}&n={display}");
                                if let Some(id) = r.body["id"].as_i64() {
                                    let frag = url
                                        .split_once('#')
                                        .map(|(_, f)| format!("#{f}"))
                                        .unwrap_or_default();
                                    link_frags.update(|map| {
                                        map.insert(id, frag);
                                    });
                                }
                            }
                            if encrypted && master.is_none() {
                                error.set("Link created, but the file key was not attached (encryption is locked). Unlock encryption and create a new link to share the file.".to_string());
                            }
                            created
                                .set(Some((url, r.body["password"].as_str().map(str::to_string))));
                        } else if encrypted {
                            // User/group shares of encrypted files: wrap the
                            // file key(s) for every recipient so they can
                            // actually decrypt. Without this the share is an
                            // ACL without keys.
                            if let Some(master) = &master {
                                let recipients: Vec<String> = if r.body["kind"] == "group" {
                                    match crate::e2ee::group_members(
                                        r.body["recipient"].as_str().unwrap_or_default(),
                                    )
                                    .await
                                    {
                                        Ok(members) => members,
                                        Err(e) => {
                                            error.set(e);
                                            Vec::new()
                                        }
                                    }
                                } else {
                                    r.body["recipient"]
                                        .as_str()
                                        .map(|u| vec![u.to_string()])
                                        .unwrap_or_default()
                                };
                                let mut skipped = Vec::new();
                                for username in &recipients {
                                    if crate::e2ee::share_encrypted_with(master, &path, username)
                                        .await
                                        .is_err()
                                    {
                                        skipped.push(username.clone());
                                    }
                                }
                                if !skipped.is_empty() {
                                    error.set(format!("Shared, but {} recipient(s) have not set up encryption yet ({}). They can read only plaintext files.", skipped.len(), skipped.join(", ")));
                                }
                            } else {
                                error.set("Shared, but the file key was not wrapped (encryption is locked). Unlock encryption, then revoke and re-share to grant file access.".to_string());
                            }
                        }
                        load.run(());
                    }
                    Ok(r) => error.set(r.error().unwrap_or("Could not share").to_string()),
                    Err(e) => error.set(e),
                }
            });
        }
    };

    let revoke = move |id: i64| {
        spawn_local(async move {
            match api::delete(&format!("/api/shares/{id}")).await {
                Ok(r) if r.status == 204 => load.run(()),
                Ok(r) => error.set(r.error().unwrap_or("Could not revoke share").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>{format!("Share “{name}”")}</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <p class="muted">"Share with a user or group, or create a public link."</p>

                <ul class="shares">
                    <For
                        each=move || shares.get()
                        key=|share| share["id"].as_i64().unwrap_or(0)
                        children=move |share| {
                            let id = share["id"].as_i64().unwrap_or(0);
                            let kind = share["kind"].as_str().unwrap_or_default().to_string();
                            let recipient = share["recipient"].as_str().unwrap_or("").to_string();
                            let permission = share["permission"].as_str().unwrap_or("").to_string();
                            let url = share["url"].as_str().map(str::to_string);
                            view! {
                                <li class="row">
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="share"/>
                                        </span>
                                        {format!("{kind} → {recipient} ({permission})")}
                                    </span>
                                    <span class="row-actions">
                                        {url
                                            .map(|url| {
                                                // Links created this session carry
                                                // their `#k=` fragment here (the
                                                // server never sees it).
                                                let frag = link_frags
                                                    .get()
                                                    .get(&id)
                                                    .cloned()
                                                    .unwrap_or_default();
                                                let full = format!("{}{}", url, frag);
                                                view! {
                                                    <button
                                                        class="ghost"
                                                        on:click=move |_| {
                                                            let full = full.clone();
                                                            spawn_local(async move {
                                                                api::copy_to_clipboard(&full_url(&full)).await;
                                                            });
                                                        }
                                                    >
                                                        <Icon name="share"/>
                                                        "Copy link"
                                                    </button>
                                                }
                                            })}
                                        <button class="danger" on:click=move |_| revoke(id)>
                                            <Icon name="trash"/>
                                            "Revoke"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                </ul>

                <div class="share-form">
                    <label>
                        "Type"
                        <select
                            prop:value=move || kind.get()
                            on:change=move |ev| kind.set(event_target_value(&ev))
                        >
                            <option value="user">"User"</option>
                            <option value="group">"Group"</option>
                            <option value="link">"Public link"</option>
                        </select>
                    </label>
                    <Show when=move || kind.get() != "link">
                        <label>
                            "Recipient"
                            <input
                                list="shareable"
                                prop:value=move || recipient.get()
                                on:input=move |ev| recipient.set(event_target_value(&ev))
                            />
                            <datalist id="shareable">
                                <For
                                    each=move || {
                                        let mut all = users.get();
                                        all.extend(groups.get());
                                        all
                                    }
                                    key=|name| name.clone()
                                    children=move |name| view! { <option value=name></option> }
                                />
                            </datalist>
                        </label>
                        <label>
                            "Permission"
                            <select
                                prop:value=move || permission.get()
                                on:change=move |ev| permission.set(event_target_value(&ev))
                            >
                                <option value="read">"Can view"</option>
                                <option value="write">"Can edit"</option>
                            </select>
                        </label>
                    </Show>
                    <button class="primary" on:click=create>
                        <Icon name="share"/>
                        "Create share"
                    </button>
                </div>

                {move || {
                    created
                        .get()
                        .map(|(url, password)| {
                            let full = full_url(&url);
                            let qr = crate::e2ee::qr_svg(&full);
                            view! {
                                <div class="created">
                                    <p>"Link created:"</p>
                                    <code>{full.clone()}</code>
                                    <div class="qr" inner_html=sanitize_svg(&qr)></div>
                                    {password
                                        .map(|password| {
                                            view! { <p>{format!("Password: {password}")}</p> }
                                        })}
                                    <button on:click=move |_| {
                                        let url = url.clone();
                                        spawn_local(async move {
                                            api::copy_to_clipboard(&full_url(&url)).await;
                                        });
                                    }>"Copy link"</button>
                                </div>
                            }
                        })
                }}
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn full_url(path: &str) -> String {
    let origin = web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default();
    format!("{origin}{path}")
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn human_size_formats_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[wasm_bindgen_test]
    fn encode_path_escapes_each_segment() {
        assert_eq!(encode_path("a/b c"), "a/b%20c");
        // The unreserved set is not exempted, so '.' is escaped too.
        assert_eq!(encode_path("a.txt"), "a%2Etxt");
        assert_eq!(encode_path(""), "");
    }

    #[wasm_bindgen_test]
    fn sanitize_svg_strips_scripts() {
        let out = sanitize_svg("<svg><script>alert(1)</script><rect onload='x'/></svg>");
        assert!(!out.contains("<script"));
        assert!(!out.contains("</script>"));
        // onload= is rewritten to data-onload= so it is inert.
        assert!(out.contains("data-onload="));
    }
}
