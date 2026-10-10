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
            let payload = json!({ "username": user, "password": pass });
            let result = api::send_json("POST", "/api/session", &payload).await;
            busy.set(false);
            match result {
                Ok(r) if r.status == 200 => view.set(View::Browser),
                Ok(r) => error.set(r.error().unwrap_or("Sign-in failed").to_string()),
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
            <button type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "Signing in…" } else { "Sign in" }}
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
                <button on:click=sign_out>"Sign out"</button>
            </div>
        </div>

        <p class="error pad">{move || error.get()}</p>
        <p class="notice pad">{move || notice.get()}</p>

        {move || {
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
