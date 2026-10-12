//! The authenticated application: login, file browser, shares, trash.

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
}

fn parse_results(body: &Value) -> Vec<SearchHit> {
    body.get("results")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| SearchHit {
                    name: item["name"].as_str().unwrap_or_default().to_string(),
                    path: item["path"].as_str().unwrap_or_default().to_string(),
                    is_dir: item["is_dir"].as_bool().unwrap_or(false),
                    size: item["size"].as_u64().unwrap_or(0),
                    modified_at: item["modified_at"].as_i64().unwrap_or(0),
                    snippet: item["snippet"].as_str().unwrap_or_default().to_string(),
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

fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn parse_entries(body: &Value) -> Vec<Entry> {
    body.get("entries")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| Entry {
                    name: item["name"].as_str().unwrap_or_default().to_string(),
                    path: item["path"].as_str().unwrap_or_default().to_string(),
                    kind: item["kind"].as_str().unwrap_or("file").to_string(),
                    size: item["size"].as_u64().unwrap_or(0),
                    modified_at: item["modified_at"].as_i64().unwrap_or(0),
                    shared: item["shared"].as_bool().unwrap_or(false),
                    owner: item["owner"].as_str().map(str::to_string),
                    permission: item["permission"].as_str().map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_trash(body: &Value) -> Vec<TrashItem> {
    body.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| TrashItem {
                    id: item["id"].as_i64().unwrap_or(0),
                    name: item["name"].as_str().unwrap_or_default().to_string(),
                    original_path: item["original_path"].as_str().map(str::to_string),
                    size: item["size"].as_u64().unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn human_size(bytes: u64) -> String {
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
    let busy = RwSignal::new(false);

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
                Ok(r) => error.set(r.error().unwrap_or("Sign-in failed").to_string()),
                Err(e) => error.set(e),
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
                <span class="logo">"K"</span>
                <h2>"Sign in to Kolimi"</h2>
                <p class="muted">"Your self-hosted cloud."</p>
            </div>
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
            <Show when=move || needs_code.get()>
                <label>
                    "Two-factor code"
                    <input
                        type="text"
                        inputmode="numeric"
                        autocomplete="one-time-code"
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
    // Administrators get the user-management panel.
    spawn_local(async move {
        if let Ok(r) = api::get("/api/me").await
            && r.status == 200
        {
            is_admin.set(r.body["is_admin"].as_bool().unwrap_or(false));
            username.set(r.body["username"].as_str().unwrap_or_default().to_string());
        }
    });

    let load = move |target: String| {
        spawn_local(async move {
            let url = format!("/api/browse?path={}", encode(&target));
            match api::get(&url).await {
                Ok(r) if r.status == 200 => {
                    entries.set(parse_entries(&r.body));
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
                            .unwrap_or(&target)
                            .to_string(),
                    );
                    error.set(String::new());
                }
                Ok(r) => error.set(r.error().unwrap_or("Could not list folder").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let load_trash = move || {
        spawn_local(async move {
            match api::get("/api/trash").await {
                Ok(r) if r.status == 200 => trash.set(parse_trash(&r.body)),
                Ok(r) => error.set(r.error().unwrap_or("Could not load trash").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    Effect::new(move |_| load("/".to_string()));

    // Toasts fade themselves out.
    Effect::new(move |_| {
        if !error.get().is_empty() {
            let clear = Closure::once_into_js(move || error.set(String::new()));
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    6000,
                );
            }
        }
    });
    Effect::new(move |_| {
        if !notice.get().is_empty() {
            let clear = Closure::once_into_js(move || notice.set(String::new()));
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    4000,
                );
            }
        }
    });

    let sign_out = move |_| {
        spawn_local(async move {
            let _ = api::delete("/api/session").await;
            view.set(View::Login);
        });
    };

    let open = move |entry: Entry| {
        if entry.kind == "dir" {
            load(entry.path);
        }
    };

    let upload_files = move |selected: Vec<web_sys::File>| {
        if selected.is_empty() {
            return;
        }
        let current = path.get_untracked();
        let total = selected.len();
        upload_label.set(format!("0/{total}"));
        spawn_local(async move {
            let mut uploaded = 0usize;
            let mut failed = 0usize;
            for (index, file) in selected.into_iter().enumerate() {
                let name = file.name();
                upload_label.set(format!("{}/{total}", index + 1));
                let result = match api::read_file(&file).await {
                    Ok(bytes) => {
                        let url = format!(
                            "/dav{}",
                            encode_path(&format!("{}/{}", current.trim_end_matches('/'), name))
                        );
                        api::dav("PUT", &url, Some(bytes), &[]).await
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(201 | 204) => uploaded += 1,
                    _ => failed += 1,
                }
            }
            upload_label.set("Upload".to_string());
            if failed == 0 {
                notice.set(format!(
                    "Uploaded {uploaded} file{}",
                    if uploaded == 1 { "" } else { "s" }
                ));
            } else {
                error.set(format!("Uploaded {uploaded}, {failed} failed"));
            }
            load(current);
        });
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
            upload_files(collect_files(files));
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
            let url = format!(
                "/dav{}",
                encode_path(&format!("{}/{}", current.trim_end_matches('/'), name))
            );
            match api::dav("MKCOL", &url, None, &[]).await {
                Ok(201) => load(current),
                Ok(status) => error.set(format!("Could not create folder (HTTP {status})")),
                Err(e) => error.set(e),
            }
        });
    };

    let delete_entry = move |entry: Entry| {
        if !api::confirm(&format!("Move “{}” to trash?", entry.name)) {
            return;
        }
        let current = path.get_untracked();
        spawn_local(async move {
            let url = format!("/dav{}", encode_path(&entry.path));
            match api::dav("DELETE", &url, None, &[]).await {
                Ok(204) => load(current),
                Ok(status) => error.set(format!("Delete failed (HTTP {status})")),
                Err(e) => error.set(e),
            }
        });
    };

    let rename_entry = move |entry: Entry| {
        let Some(name) = api::prompt("New name", &entry.name) else {
            return;
        };
        if name.is_empty() || name == entry.name {
            return;
        }
        let current = path.get_untracked();
        spawn_local(async move {
            let destination = format!(
                "/dav{}",
                encode_path(&format!("{}/{}", current.trim_end_matches('/'), name))
            );
            let url = format!("/dav{}", encode_path(&entry.path));
            match api::dav("MOVE", &url, None, &[("destination", &destination)]).await {
                Ok(201 | 204) => load(current),
                Ok(status) => error.set(format!("Rename failed (HTTP {status})")),
                Err(e) => error.set(e),
            }
        });
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
                Ok(r) if r.status == 204 => load_trash(),
                Ok(r) => error.set(r.error().unwrap_or("Delete failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let share_entry = move |entry: Entry| share_target.set(Some(entry));

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
                    results.set(parse_results(&r.body));
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
                    <span class="logo">"K"</span>
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
                    <div class="account">
                        <span class="avatar">
                            {move || {
                                username
                                    .get()
                                    .chars()
                                    .next()
                                    .map(|c| c.to_ascii_uppercase().to_string())
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
                            let mut crumbs = vec![
                                view! {
                                    <button
                                        class="crumb"
                                        on:click=move |_| load("/".to_string())
                                    >
                                        <Icon name="cloud"/>
                                    </button>
                                }
                                    .into_any(),
                            ];
                            let mut accumulated = String::new();
                            for segment in segments {
                                accumulated.push('/');
                                accumulated.push_str(segment);
                                let target = accumulated.clone();
                                let label = segment.to_string();
                                crumbs.push(
                                    view! {
                                        <span class="sep">"/"</span>
                                        <button
                                            class="crumb"
                                            on:click=move |_| load(target.clone())
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
                        <label class="button primary">
                            <Icon name="upload"/>
                            <span>{move || upload_label.get()}</span>
                            <input type="file" class="hidden" multiple on:change=upload/>
                        </label>
                        <button on:click=mkdir title="New folder">
                            <Icon name="folder-plus"/>
                            <span class="hide-sm">"New folder"</span>
                        </button>
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
                                let kind = if is_dir { "dir".to_string() } else { "file".to_string() };
                                view! {
                                    <li class="file">
                                        <button
                                            class="file-open"
                                            on:click=move |_| load(navigate.clone())
                                        >
                                            <span class="file-icon">
                                                <Icon name=file_icon(&name, &kind)/>
                                            </span>
                                            <span class="file-body">
                                                <span class="file-name">{name.clone()}</span>
                                                <span class="file-meta">
                                                    {path}
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
                                                let is_img = !is_dir && is_image_name(&entry.name);
                                                let shared = entry.shared;
                                                let name = entry.name.clone();
                                                let kind = entry.kind.clone();
                                                let meta = if is_dir {
                                                    "Folder".to_string()
                                                } else {
                                                    let when = relative_time(entry.modified_at);
                                                    if when.is_empty() {
                                                        human_size(entry.size)
                                                    } else {
                                                        format!("{} · {}", human_size(entry.size), when)
                                                    }
                                                };
                                                let open_entry = entry.clone();
                                                let share_copy = entry.clone();
                                                let rename_copy = entry.clone();
                                                let delete_copy = entry.clone();
                                                let preview = entry.path.clone();
                                                let download = entry.path.clone();
                                                view! {
                                                    <div class="tile">
                                                        <button
                                                            class="tile-open"
                                                            on:click=move |_| open(open_entry.clone())
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
                                                            {(!is_dir)
                                                                .then(|| {
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
                                                                })}
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
                                                let is_img = !is_dir && is_image_name(&entry.name);
                                                let shared = entry.shared;
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
                                                    if when.is_empty() {
                                                        human_size(entry.size)
                                                    } else {
                                                        format!("{} · {}", human_size(entry.size), when)
                                                    }
                                                };
                                                let open_entry = entry.clone();
                                                let share_copy = entry.clone();
                                                let rename_copy = entry.clone();
                                                let delete_copy = entry.clone();
                                                let preview = entry.path.clone();
                                                let download = entry.path.clone();
                                                view! {
                                                    <li class="file">
                                                        <button
                                                            class="file-open"
                                                            on:click=move |_| open(open_entry.clone())
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
                                                            {(!is_dir)
                                                                .then(|| {
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
                                                                })}
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
            </div>

            {move || {
                share_target
                .get()
                .map(|entry| {
                    view! {
                        <ShareDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            on_close=Callback::new(move |_| share_target.set(None))
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

    let load = Callback::new(move |_: ()| {
        spawn_local(async move {
            match api::get("/api/users?limit=200").await {
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
            if let Ok(r) = api::delete(&format!("/api/passkeys/{id}")).await
                && r.status == 204
            {
                load.run(());
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
                                    <div class="qr" inner_html=svg></div>
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
fn ShareDialog(path: String, name: String, on_close: Callback<()>) -> impl IntoView {
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

    let create = {
        let path = path.clone();
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
            spawn_local(async move {
                match api::send_json("POST", "/api/shares", &payload).await {
                    Ok(r) if r.status == 201 => {
                        error.set(String::new());
                        if r.body["kind"] == "link" {
                            created.set(Some((
                                r.body["url"].as_str().unwrap_or_default().to_string(),
                                r.body["password"].as_str().map(str::to_string),
                            )));
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
            if let Ok(r) = api::delete(&format!("/api/shares/{id}")).await
                && r.status == 204
            {
                load.run(());
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
                                                view! {
                                                    <button
                                                        class="ghost"
                                                        on:click=move |_| {
                                                            let url = url.clone();
                                                            spawn_local(async move {
                                                                api::copy_to_clipboard(&full_url(&url)).await;
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
                            view! {
                                <div class="created">
                                    <p>"Link created:"</p>
                                    <code>{full_url(&url)}</code>
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
