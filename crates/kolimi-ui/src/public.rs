//! The anonymous public-link page served at `/s/{token}`.

use std::rc::Rc;

use crate::app::{encode, encode_path, human_size};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};
use wasm_bindgen::JsCast;

use crate::api;
use crate::components::Icon;

/// The file key and chunk lengths carried in the URL fragment of a link to
/// an encrypted file (`#k=<base64url>&l=<len,len,…>`). The fragment is never
/// sent to the server, so the server cannot decrypt.
fn parse_fragment() -> Option<([u8; 32], Vec<u32>, Option<String>)> {
    let hash = web_sys::window()?.location().hash().ok()?;
    let mut key: Option<[u8; 32]> = None;
    let mut lengths: Vec<u32> = Vec::new();
    let mut name: Option<String> = None;
    for part in hash.trim_start_matches('#').split('&') {
        if let Some(value) = part.strip_prefix("k=") {
            let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
            key = Some(bytes.try_into().ok()?);
        } else if let Some(value) = part.strip_prefix("l=") {
            lengths = value.split(',').filter_map(|n| n.parse().ok()).collect();
        } else if let Some(value) = part.strip_prefix("n=") {
            name = js_sys::decode_uri_component(value).ok().map(|s| s.into());
        }
    }
    key.map(|key| (key, lengths, name))
}

#[derive(Clone, PartialEq)]
enum Meta {
    Loading,
    Ready(Value),
    Missing(String),
}

#[component]
pub fn PublicApp(token: String) -> impl IntoView {
    let meta = RwSignal::new(Meta::Loading);
    let sub = RwSignal::new(String::new());
    let locked = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    let load = {
        let token = token.clone();
        Callback::new(move |subpath: String| {
            let token = token.clone();
            spawn_local(async move {
                let url = if subpath.is_empty() {
                    format!("/public/{token}")
                } else {
                    format!("/public/{token}/list/{}", encode_path(&subpath))
                };
                match api::get(&url).await {
                    Ok(r) if r.status == 200 => {
                        let mut body = r.body;
                        // `GET /public/{token}/list/{subpath}` returns only
                        // `{ path, entries }` with no `kind`/`name`: treat
                        // list responses as dirs.
                        if body.get("kind").is_none() && body.get("entries").is_some() {
                            body["kind"] = json!("dir");
                        }
                        meta.set(Meta::Ready(body));
                        sub.set(subpath);
                        locked.set(false);
                        error.set(String::new());
                    }
                    Ok(r) if r.status == 401 => locked.set(true),
                    Ok(r) if r.status == 410 => {
                        meta.set(Meta::Missing("This link has expired.".to_string()));
                    }
                    Ok(r) if r.status == 404 => {
                        meta.set(Meta::Missing(
                            "This link does not exist or was revoked.".to_string(),
                        ));
                    }
                    Ok(r) => error.set(r.error().unwrap_or("Unavailable").to_string()),
                    Err(e) => error.set(e),
                }
            });
        })
    };
    Effect::new(move |_| load.run(String::new()));

    let unlock = {
        let token = token.clone();
        Callback::new(move |ev: ev::SubmitEvent| {
            ev.prevent_default();
            let token = token.clone();
            let candidate = password.get_untracked();
            spawn_local(async move {
                let payload = json!({ "password": candidate });
                match api::send_json("POST", &format!("/public/{token}/unlock"), &payload).await {
                    Ok(r) if r.status == 204 => {
                        password.set(String::new());
                        load.run(sub.get_untracked());
                    }
                    Ok(r) => error.set(r.error().unwrap_or("Wrong password").to_string()),
                    Err(e) => error.set(e),
                }
            });
        })
    };

    let token_sv = StoredValue::new(token);
    let link_key = StoredValue::new(parse_fragment());

    view! {
        <header class="top">
            <span class="brand">"Kolimi"</span>
        </header>
        <div class="pad">
            {move || {
                if locked.get() {
                    return view! {
                        <form class="card login" on:submit=move |ev| unlock.run(ev)>
                            <h2>"This link is password protected"</h2>
                            <label>
                                "Password"
                                <input
                                    type="password"
                                    prop:value=move || password.get()
                                    on:input=move |ev| password.set(event_target_value(&ev))
                                />
                            </label>
                            <button type="submit">"Unlock"</button>
                            <p class="error">{move || error.get()}</p>
                        </form>
                    }.into_any();
                }
                match meta.get() {
                    Meta::Loading => view! { <p class="muted">"Loading…"</p> }.into_any(),
                    Meta::Missing(message) => {
                        view! { <p class="error">{message}</p> }.into_any()
                    }
                    Meta::Ready(meta) => {
                        let name = link_key
                            .get_value()
                            .and_then(|(_, _, name)| name)
                            .unwrap_or_else(|| {
                                meta["name"].as_str().unwrap_or_default().to_string()
                            });
                        if meta["upload_only"].as_bool() == Some(true) {
                            let token = token_sv.get_value();
                            return view! {
                                <UploadPanel token=token name=name meta=meta error=error/>
                            }
                                .into_any();
                        }
                        // List responses carry `entries` but no `kind`: treat as dir.
                        let is_dir = meta["kind"].as_str() == Some("dir")
                            || (meta.get("kind").is_none()
                                && meta.get("entries").is_some());
                        let subpath = sub.get();
                        let token = token_sv.get_value();
                        let download_url = if subpath.is_empty() {
                            format!("/public/{token}/download")
                        } else {
                            format!(
                                "/public/{token}/download/{}",
                                encode_path(&subpath),
                            )
                        };
                        let entries: Vec<Value> = meta["entries"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        let load_for_back = load;
                        let token_for_nav = token.clone();
                        let back_subpath = subpath.clone();
                        view! {
                            <div class="card">
                                <h2>{name.clone()}</h2>
                                {(!subpath.is_empty())
                                    .then(|| {
                                        view! {
                                            <button on:click=move |_| {
                                                let parent = back_subpath
                                                    .rsplit_once('/')
                                                    .map(|(parent, _)| parent.to_string())
                                                    .unwrap_or_default();
                                                load_for_back.run(parent);
                                            }>"↑ Back"</button>
                                        }
                                    })}
                                {if is_dir {
                                    view! {
                                        <ul class="files">
                                            <For
                                                each=move || entries.clone()
                                                key=|entry| {
                                                    entry["name"].as_str().unwrap_or_default().to_string()
                                                }
                                                children=move |entry| {
                                                    let entry_name = entry["name"]
                                                        .as_str()
                                                        .unwrap_or_default()
                                                        .to_string();
                                                    let entry_kind = entry["kind"]
                                                        .as_str()
                                                        .unwrap_or("file")
                                                        .to_string();
                                                    let size = entry["size"].as_u64().unwrap_or(0);
                                                    let child_path = if subpath.is_empty() {
                                                        entry_name.clone()
                                                    } else {
                                                        format!("{subpath}/{entry_name}")
                                                    };
                                                    let child_path_download = child_path.clone();
                                                    let token = token_for_nav.clone();
                                                    let load_for_dir = load;
                                                    view! {
                                                        <li class="row">
                                                            {if entry_kind == "dir" {
                                                                view! {
                                                                    <button
                                                                        class="name"
                                                                        on:click=move |_| load_for_dir.run(child_path.clone())
                                                                    >
                                                                        "📁 "
                                                                        {entry_name.clone()}
                                                                    </button>
                                                                }.into_any()
                                                            } else {
                                                                view! {
                                                                    <span class="name">
                                                                        "📄 "
                                                                        {entry_name.clone()}
                                                                    </span>
                                                                }.into_any()
                                                            }}
                                                            <span class="size">
                                                                {if entry_kind == "dir" {
                                                                    String::new()
                                                                } else {
                                                                    human_size(size)
                                                                }}
                                                            </span>
                                                            <span class="row-actions">
                                                                {if entry_kind != "dir" {
                                                                    view! {
                                                                        <a
                                                                            class="button"
                                                                            href=format!(
                                                                                "/public/{token}/download/{}",
                                                                                encode_path(&child_path_download),
                                                                            )
                                                                            download
                                                                        >
                                                                            "Download"
                                                                        </a>
                                                                    }.into_any()
                                                                } else {
                                                                    view! { <span></span> }.into_any()
                                                                }}
                                                            </span>
                                                        </li>
                                                    }
                                                }
                                            />
                                        </ul>
                                    }.into_any()
                                } else if let Some((key, lengths, _)) = link_key.get_value() {
                                    let file_name = name.clone();
                                    let download = download_url.clone();
                                    let decrypt = move |_| {
                                        let key = key;
                                        let lengths = lengths.clone();
                                        let file_name = file_name.clone();
                                        let download = download.clone();
                                        spawn_local(async move {
                                            match api::get_bytes(&download).await {
                                                Ok(bytes) => {
                                                    match crate::e2ee::decrypt_public(
                                                        &key, &lengths, &bytes,
                                                    ) {
                                                        Ok(plain) => {
                                                            crate::e2ee::save_bytes(&file_name, &plain)
                                                        }
                                                        Err(e) => error.set(e),
                                                    }
                                                }
                                                Err(e) => error.set(e),
                                            }
                                        });
                                    };
                                    view! {
                                        <p class="muted">"This file is end-to-end encrypted."</p>
                                        <button class="primary" on:click=decrypt>
                                            "Decrypt & download"
                                        </button>
                                        <p class="error">{move || error.get()}</p>
                                    }
                                        .into_any()
                                } else {
                                    view! {
                                        <p>
                                            {if link_key.get_value().is_some() {
                                                "Encrypted · shared file".to_string()
                                            } else {
                                                format!(
                                                    "{} · {}",
                                                    human_size(meta["size"].as_u64().unwrap_or(0)),
                                                    "shared file",
                                                )
                                            }}
                                        </p>
                                        <a class="button" href=download_url download>
                                            "Download"
                                        </a>
                                    }
                                        .into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
}

/// The upload form shown by an upload-only ("file request") link.
#[component]
fn UploadPanel(token: String, name: String, meta: Value, error: RwSignal<String>) -> impl IntoView {
    let uploading = RwSignal::new(false);
    let progress = RwSignal::new(0u8);
    let current = RwSignal::new(String::new());
    let uploaded = RwSignal::new(Vec::<String>::new());

    let max_files = meta["max_files"].as_i64().unwrap_or(20);
    let max_bytes = meta["max_bytes"].as_u64().unwrap_or(1024 * 1024 * 1024);
    let used_files = meta["uploaded_files"].as_i64().unwrap_or(0);
    let used_bytes = meta["uploaded_bytes"].as_u64().unwrap_or(0);

    let start: Rc<dyn Fn(Vec<web_sys::File>)> = Rc::new(move |files: Vec<web_sys::File>| {
        if files.is_empty() || uploading.get_untracked() {
            return;
        }
        error.set(String::new());
        uploading.set(true);
        progress.set(0);
        upload_at(
            0,
            token.clone(),
            Rc::new(files),
            uploading,
            progress,
            current,
            uploaded,
            error,
        );
    });

    let start_input = start.clone();
    let start_drop = start.clone();

    view! {
        <div class="card upload-card">
            <h2>{name}</h2>
            <p class="muted">
                "Files go to the owner's folder. You cannot see what is already there, and uploads never overwrite existing files."
            </p>
            <p class="muted">
                {format!(
                    "Up to {} files · {} total · {} already received",
                    max_files,
                    human_size(max_bytes),
                    human_size(used_bytes),
                )}
            </p>
            <label
                class="drop-upload"
                class:busy=move || uploading.get()
                on:dragover=move |event: ev::DragEvent| {
                    event.prevent_default();
                }
                on:drop=move |event: ev::DragEvent| {
                    event.prevent_default();
                    if let Some(transfer) = event.data_transfer()
                        && let Some(list) = transfer.files()
                    {
                        start_drop(file_list(&list));
                    }
                }
            >
                <Icon name="upload"/>
                <span>
                    {move || {
                        if uploading.get() {
                            format!("Uploading {}…", current.get())
                        } else {
                            "Choose files or drop them here".to_string()
                        }
                    }}
                </span>
                <input
                    type="file"
                    class="hidden"
                    multiple
                    disabled=move || uploading.get()
                    on:change=move |event| {
                        let Some(input) = event.target()
                            .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
                        else {
                            return;
                        };
                        if let Some(list) = input.files() {
                            start_input(file_list(&list));
                        }
                        input.set_value("");
                    }
                />
            </label>
            <Show when=move || uploading.get()>
                <div class="upload-meter" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow=move || progress.get().to_string()>
                    <span style:width=move || format!("{}%", progress.get())></span>
                </div>
            </Show>
            <Show when=move || !uploaded.get().is_empty()>
                <div class="created">
                    <strong>"Uploaded in this session:"</strong>
                    <ul class="files">
                        {move || {
                            uploaded
                                .get()
                                .into_iter()
                                .map(|name| view! { <li class="row">{name}</li> })
                                .collect::<Vec<_>>()
                        }}
                    </ul>
                    <p class="muted">
                        {move || {
                            let sent = uploaded.get().len() as i64;
                            format!(
                                "{} of {} files used · {} received",
                                used_files + sent,
                                max_files,
                                human_size(used_bytes),
                            )
                        }}
                    </p>
                </div>
            </Show>
            <p class="error">{move || error.get()}</p>
        </div>
    }
}

fn file_list(list: &web_sys::FileList) -> Vec<web_sys::File> {
    (0..list.length())
        .filter_map(|index| list.get(index))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn upload_at(
    index: usize,
    token: String,
    files: Rc<Vec<web_sys::File>>,
    uploading: RwSignal<bool>,
    progress: RwSignal<u8>,
    current: RwSignal<String>,
    uploaded: RwSignal<Vec<String>>,
    error: RwSignal<String>,
) {
    if index >= files.len() {
        uploading.set(false);
        current.set(String::new());
        progress.set(0);
        return;
    }
    let file = files[index].clone();
    let name = file.name();
    current.set(name.clone());
    let url = format!("/public/{token}/upload?name={}", encode(&name));
    let next = {
        let token = token.clone();
        let files = files.clone();
        move |result: Result<(u16, Option<u8>), String>| match result {
            Ok((201, _)) => {
                uploaded.update(|names| names.push(name.clone()));
                upload_at(
                    index + 1,
                    token.clone(),
                    files.clone(),
                    uploading,
                    progress,
                    current,
                    uploaded,
                    error,
                );
            }
            Ok((status, _)) => {
                error.set(match status {
                    413 => "This link has reached its upload limit.".to_string(),
                    401 => "Unlock the link again, then retry.".to_string(),
                    403 => "This link does not accept uploads.".to_string(),
                    _ => format!("Upload failed (HTTP {status})."),
                });
                uploading.set(false);
                current.set(String::new());
            }
            Err(message) => {
                error.set(message);
                uploading.set(false);
                current.set(String::new());
            }
        }
    };
    let on_progress = move |percent: u8| progress.set(percent);
    api::upload_blob(&url, &file, on_progress, next);
}
