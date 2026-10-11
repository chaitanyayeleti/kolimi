//! The authenticated application: login, file browser, shares, trash.

use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use wasm_bindgen::JsCast;

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
        <header class="top">
            <a class="brand" href="/app/">"Kolimi"</a>
        </header>
        {move || match view.get() {
            View::Loading => view! { <p class="muted pad">"Loading…"</p> }.into_any(),
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
        <form class="card login" on:submit=submit>
            <h2>"Sign in"</h2>
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
            <button type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "Signing in…" } else { "Sign in" }}
            </button>
            <button type="button" disabled=move || busy.get() on:click=passkey_login>
                "Sign in with a passkey"
            </button>
            <p class="error">{move || error.get()}</p>
        </form>
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
    let uploading = RwSignal::new(false);
    let query = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<SearchHit>::new());
    let search_active = RwSignal::new(false);
    let passkeys_open = RwSignal::new(false);
    let admin_open = RwSignal::new(false);
    let is_admin = RwSignal::new(false);
    // Administrators get the user-management panel.
    spawn_local(async move {
        if let Ok(r) = api::get("/api/me").await
            && r.status == 200
        {
            is_admin.set(r.body["is_admin"].as_bool().unwrap_or(false));
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

    let upload = move |ev: ev::Event| {
        let Some(input) = ev
            .target()
            .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        else {
            return;
        };
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        let name = file.name();
        let current = path.get_untracked();
        uploading.set(true);
        spawn_local(async move {
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
            uploading.set(false);
            match result {
                Ok(201 | 204) => {
                    notice.set(format!("Uploaded {name}"));
                    load(current);
                }
                Ok(status) => error.set(format!("Upload failed (HTTP {status})")),
                Err(e) => error.set(e),
            }
        });
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
        <div class="toolbar">
            <nav class="crumbs">
                {move || {
                    let current = path.get();
                    let segments: Vec<&str> = current.split('/').filter(|s| !s.is_empty()).collect();
                    let mut crumbs = vec![
                        view! {
                            <button class="crumb" on:click=move |_| load("/".to_string())>
                                "Home"
                            </button>
                        }.into_any(),
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
                                <button class="crumb" on:click=move |_| load(target.clone())>
                                    {label}
                                </button>
                            }.into_any(),
                        );
                    }
                    crumbs
                }}
            </nav>
            <div class="actions">
                <form class="search" on:submit=search_submit>
                    <input
                        type="search"
                        placeholder="Search files…"
                        prop:value=move || query.get()
                        on:input=move |ev| query.set(event_target_value(&ev))
                    />
                    <button type="submit">"Search"</button>
                </form>
                <label class="button">
                    {move || if uploading.get() { "Uploading…" } else { "Upload" }}
                    <input type="file" class="hidden" on:change=upload/>
                </label>
                <button on:click=mkdir>"New folder"</button>
                <button
                    class:active=move || tab.get() == Tab::Trash
                    on:click=move |_| {
                        if tab.get_untracked() == Tab::Trash {
                            tab.set(Tab::Files);
                        } else {
                            tab.set(Tab::Trash);
                            load_trash();
                        }
                    }
                >
                    "Trash"
                </button>
                <button on:click=move |_| passkeys_open.set(true)>"Passkeys"</button>
                {move || {
                    is_admin
                        .get()
                        .then(|| {
                            view! {
                                <button on:click=move |_| admin_open.set(true)>"Admin"</button>
                            }
                        })
                }}
                <button on:click=sign_out>"Sign out"</button>
            </div>
        </div>

        <p class="error pad">{move || error.get()}</p>
        <p class="notice pad">{move || notice.get()}</p>

        {move || {
            if search_active.get() {
                let clear = clear_search;
                return view! {
                    <ul class="files">
                        <li class="row">
                            <span class="name muted">
                                {move || format!("{} result(s)", results.get().len())}
                            </span>
                            <span class="row-actions">
                                <button on:click=clear>"Clear"</button>
                            </span>
                        </li>
                        <For
                            each=move || results.get()
                            key=|hit| hit.path.clone()
                            children=move |hit| {
                                let navigate = parent_of(&hit.path);
                                let download_path = hit.path.clone();
                                let is_dir = hit.is_dir;
                                view! {
                                    <li class="row">
                                        <button class="name" on:click=move |_| load(navigate.clone())>
                                            {if is_dir { "📁 " } else { "📄 " }}
                                            {hit.name.clone()}
                                            <span class="muted">{hit.path.clone()}</span>
                                        </button>
                                        <span class="size">{hit.snippet.clone()}</span>
                                        {(!is_dir).then(|| {
                                            view! {
                                                <span class="row-actions">
                                                    <a
                                                        class="button"
                                                        href=format!("/dav{}", encode_path(&download_path))
                                                        download
                                                    >
                                                        "Download"
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
                        <ul class="files">
                            {move || {
                                parent.get().map(|parent| {
                                    let target = parent.clone();
                                    view! {
                                        <li class="row up">
                                            <button class="name" on:click=move |_| load(target.clone())>
                                                "↑ .."
                                            </button>
                                        </li>
                                    }
                                })
                            }}
                            <For
                                each=move || entries.get()
                                key=|entry| entry.path.clone()
                                children=move |entry| {
                                    let is_dir = entry.kind == "dir";
                                    let open_entry = entry.clone();
                                    let delete_copy = entry.clone();
                                    let rename_copy = entry.clone();
                                    let share_copy = entry.clone();
                                    view! {
                                        <li class="row">
                                            <button class="name" on:click=move |_| open(open_entry.clone())>
                                                {(!is_dir && is_image_name(&entry.name)).then(|| {
                                                    view! {
                                                        <img
                                                            class="thumb"
                                                            loading="lazy"
                                                            alt=""
                                                            src=format!(
                                                                "/api/preview?path={}&size=64",
                                                                encode(&entry.path),
                                                            )
                                                        />
                                                    }
                                                })}
                                                {if is_dir { "📁 " } else { "📄 " }}
                                                {entry.name.clone()}
                                                {entry.shared.then(|| view! {
                                                    <span class="badge">
                                                        {format!(
                                                            "shared by {} ({})",
                                                            entry.owner.clone().unwrap_or_default(),
                                                            entry.permission.clone().unwrap_or_default(),
                                                        )}
                                                    </span>
                                                })}
                                            </button>
                                            <span class="size">
                                                {if is_dir { String::new() } else { human_size(entry.size) }}
                                            </span>
                                            <span class="row-actions">
                                                {(!is_dir).then(|| {
                                                    view! {
                                                        <a class="button" href=format!(
                                                            "/dav{}",
                                                            encode_path(&entry.path),
                                                        ) download>
                                                            "Download"
                                                        </a>
                                                    }
                                                })}
                                                {(!entry.shared).then(|| {
                                                    view! {
                                                        <button on:click=move |_| share_entry(share_copy.clone())>
                                                            "Share"
                                                        </button>
                                                    }
                                                })}
                                                {(!entry.shared).then(|| {
                                                    view! {
                                                        <button on:click=move |_| rename_entry(rename_copy.clone())>
                                                            "Rename"
                                                        </button>
                                                    }
                                                })}
                                                {(!entry.shared).then(|| {
                                                    view! {
                                                        <button on:click=move |_| delete_entry(delete_copy.clone())>
                                                            "Delete"
                                                        </button>
                                                    }
                                                })}
                                            </span>
                                        </li>
                                    }
                                }
                            />
                            <Show when=move || entries.get().is_empty()>
                                <li class="row muted">"This folder is empty."</li>
                            </Show>
                        </ul>
                    }.into_any()
                }
                Tab::Trash => {
                    view! {
                        <ul class="files">
                            <For
                                each=move || trash.get()
                                key=|item| item.id
                                children=move |item| {
                                    let restore_copy = item.clone();
                                    let purge_copy = item.clone();
                                    view! {
                                        <li class="row">
                                            <span class="name">
                                                "🗑 "
                                                {item.name.clone()}
                                                <span class="muted">
                                                    {item.original_path.clone().unwrap_or_default()}
                                                </span>
                                            </span>
                                            <span class="size">{human_size(item.size)}</span>
                                            <span class="row-actions">
                                                <button on:click=move |_| restore(restore_copy.clone())>
                                                    "Restore"
                                                </button>
                                                <button on:click=move |_| purge(purge_copy.clone())>
                                                    "Delete forever"
                                                </button>
                                            </span>
                                        </li>
                                    }
                                }
                            />
                            <Show when=move || trash.get().is_empty()>
                                <li class="row muted">"Trash is empty."</li>
                            </Show>
                        </ul>
                    }.into_any()
                }
            }
        }}

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
            match api::send_json(
                "PATCH",
                &format!("/api/users/{}", encode(&username)),
                &body,
            )
            .await
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
                    <button on:click=close>"Close"</button>
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
                                <li class="row">
                                    <span class="name">
                                        {username}
                                        {is_admin
                                            .then(|| view! { <span class="muted">" · admin"</span> })}
                                        {disabled
                                            .then(|| view! { <span class="muted">" · disabled"</span> })}
                                        <span class="muted">
                                            "  " {fmt_bytes(used)} " / " {quota_label(quota)}
                                        </span>
                                    </span>
                                    <span class="row-actions">
                                        <button on:click=move |_| recheck(r.clone())>"Usage"</button>
                                        <button on:click=move |_| set_quota(q.clone())>"Quota"</button>
                                        <button on:click=move |_| patch(a.clone(), json!({ "admin": !is_admin }), "role updated")>
                                            {if is_admin { "Revoke admin" } else { "Make admin" }}
                                        </button>
                                        <button on:click=move |_| patch(d.clone(), json!({ "disabled": !disabled }), "access updated")>
                                            {if disabled { "Enable" } else { "Disable" }}
                                        </button>
                                        <button on:click=move |_| remove(u.clone())>"Delete"</button>
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
                    <button on:click=close>"Close"</button>
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
                                    <span class="name">{name}</span>
                                    <span class="row-actions">
                                        <button on:click=move |_| remove(id)>"Remove"</button>
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
                    <button disabled=move || busy.get() on:click=add>
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
                    <button on:click=close>"Close"</button>
                </div>

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
                                        {format!("{kind} → {recipient} ({permission})")}
                                        {url.map(|url| view! {
                                            <button on:click=move |_| {
                                                let url = url.clone();
                                                spawn_local(async move {
                                                    api::copy_to_clipboard(&full_url(&url)).await;
                                                });
                                            }>"Copy link"</button>
                                        })}
                                    </span>
                                    <span class="row-actions">
                                        <button on:click=move |_| revoke(id)>"Revoke"</button>
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
                    <button on:click=create>"Create share"</button>
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
