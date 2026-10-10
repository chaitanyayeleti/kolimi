//! The anonymous public-link page served at `/s/{token}`.

use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

use crate::api;

#[derive(Clone, PartialEq)]
enum Meta {
    Loading,
    Ready(Value),
    Missing(String),
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
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
                        meta.set(Meta::Ready(r.body));
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
                        let name = meta["name"].as_str().unwrap_or_default().to_string();
                        let is_dir = meta["kind"].as_str() == Some("dir");
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
                                } else {
                                    view! {
                                        <p>
                                            {format!(
                                                "{} · {}",
                                                human_size(meta["size"].as_u64().unwrap_or(0)),
                                                "shared file",
                                            )}
                                        </p>
                                        <a class="button" href=download_url download>
                                            "Download"
                                        </a>
                                    }.into_any()
                                }}
                            </div>
                        }.into_any()
                    }
                }
            }}
        </div>
    }
}
