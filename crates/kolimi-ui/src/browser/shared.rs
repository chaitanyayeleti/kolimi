//! The Shared page: received shares, created shares, and public links.
//!
//! All data comes from the existing share APIs. The page never asks the
//! server for an encrypted link's key: while the vault is unlocked it
//! rebuilds the `#k=…&l=…&n=…` fragment locally, and while locked it offers
//! the unlock action instead of copying a broken URL.

use std::collections::HashMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{human_size, relative_time};
use crate::components::Icon;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedTab {
    Received,
    Created,
    Links,
}

#[component]
pub(crate) fn SharedPage(
    master: RwSignal<Option<MasterKey>>,
    error: RwSignal<String>,
    notice: RwSignal<String>,
    on_open: Callback<String>,
    on_unlock: Callback<()>,
) -> impl IntoView {
    let tab = RwSignal::new(SharedTab::Received);
    let owned = RwSignal::new(Vec::<Value>::new());
    let received = RwSignal::new(Vec::<Value>::new());
    let loading = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let link_frags = RwSignal::new(HashMap::<i64, String>::new());

    let load = Callback::new(move |_: ()| {
        let master = master.get_untracked();
        loading.set(true);
        spawn_local(async move {
            match api::get("/api/shares/owned").await {
                Ok(response) if response.status == 200 => {
                    owned.set(
                        response.body["shares"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load created shares")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }

            let (mut mounts, names) = super::search::received_mounts(master.as_ref()).await;
            let display_names: HashMap<String, String> = names
                .iter()
                .map(|share| (share.prefix.clone(), share.name.clone()))
                .collect();
            for mount in &mut mounts {
                if let Some(name) = mount["mount"]
                    .as_str()
                    .and_then(|prefix| display_names.get(prefix))
                {
                    mount["display_name"] = json!(name);
                }
            }
            received.set(mounts);

            // Rebuild fragments for encrypted file links while unlocked.
            let mut fragments = HashMap::new();
            if let Some(master) = master.as_ref() {
                for share in owned.get_untracked() {
                    if share["kind"].as_str() != Some("link")
                        || share["encrypted"].as_bool() != Some(true)
                        || share["is_dir"].as_bool() == Some(true)
                    {
                        continue;
                    }
                    let Some(id) = share["id"].as_i64() else {
                        continue;
                    };
                    let Some(path) = share["path"].as_str() else {
                        continue;
                    };
                    let Some(name) = share["name"].as_str() else {
                        continue;
                    };
                    if let Ok((key, lengths)) =
                        crate::e2ee::file_key_and_lengths(master, path).await
                    {
                        fragments.insert(id, link_fragment(&key, &lengths, name));
                    }
                }
            }
            link_frags.set(fragments);
            loading.set(false);
        });
    });

    // The page must rebuild fragments when the vault is unlocked or locked.
    Effect::new(move |_| {
        let _ = master.get();
        load.run(());
    });

    let revoke = Callback::new(move |id: i64| {
        busy.set(true);
        spawn_local(async move {
            match api::delete(&format!("/api/shares/{id}")).await {
                Ok(response) if response.status == 204 => {
                    notice.set("Share revoked".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not revoke share")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let set_permission = Callback::new(move |(id, permission): (i64, String)| {
        busy.set(true);
        spawn_local(async move {
            match api::send_json(
                "PATCH",
                &format!("/api/shares/{id}"),
                &json!({ "permission": permission }),
            )
            .await
            {
                Ok(response) if response.status == 200 => {
                    notice.set("Permission updated".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not update permission")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let set_expiry = Callback::new(move |(id, secs): (i64, i64)| {
        busy.set(true);
        spawn_local(async move {
            match api::send_json(
                "PATCH",
                &format!("/api/shares/{id}"),
                &json!({ "expires_in_secs": secs }),
            )
            .await
            {
                Ok(response) if response.status == 200 => {
                    notice.set("Link expiry updated".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not update expiry")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let set_password = Callback::new(move |id: i64| {
        let Some(password) = api::prompt(
            "New link password (leave empty to remove password protection)",
            "",
        ) else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            match api::send_json(
                "PATCH",
                &format!("/api/shares/{id}"),
                &json!({ "password": password }),
            )
            .await
            {
                Ok(response) if response.status == 200 => {
                    notice.set("Link password updated".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not update password")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let copy_link = Callback::new(move |share: Value| {
        let Some(url) = share["url"].as_str().map(str::to_string) else {
            return;
        };
        let encrypted = share["encrypted"].as_bool() == Some(true);
        let is_dir = share["is_dir"].as_bool() == Some(true);
        let id = share["id"].as_i64().unwrap_or_default();
        let path = share["path"].as_str().unwrap_or_default().to_string();
        let name = share["name"].as_str().unwrap_or_default().to_string();
        let current_master = master.get_untracked();
        if encrypted && is_dir {
            error.set(
                "Encrypted folder links cannot be rebuilt from this page. Open the folder, then share it again to copy a working link."
                    .to_string(),
            );
            return;
        }
        if encrypted && current_master.is_none() {
            notice.set("Unlock encryption to copy the full link".to_string());
            on_unlock.run(());
            return;
        }
        spawn_local(async move {
            let full = if encrypted {
                let Some(master) = current_master else {
                    return;
                };
                match crate::e2ee::file_key_and_lengths(&master, &path).await {
                    Ok((key, lengths)) => {
                        let fragment = link_fragment(&key, &lengths, &name);
                        // Cache it for the row and for subsequent copies.
                        link_frags.update(|map| {
                            map.insert(id, fragment.clone());
                        });
                        format!("{}{url}{fragment}", origin())
                    }
                    Err(message) => {
                        error.set(format!("Could not rebuild the encrypted link: {message}"));
                        return;
                    }
                }
            } else {
                format!("{}{url}", origin())
            };
            api::copy_to_clipboard(&full).await;
            notice.set("Link copied".to_string());
        });
    });

    let remove_received = Callback::new(move |id: i64| {
        let confirmed = api::confirm("Remove this shared item from your account?");
        if !confirmed {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match api::delete(&format!("/api/shares/{id}")).await {
                Ok(response) if response.status == 204 => {
                    notice.set("Share removed".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not remove share")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let created = move || {
        owned
            .get()
            .into_iter()
            .filter(|share| share["kind"].as_str() != Some("link"))
            .collect::<Vec<_>>()
    };
    let links = move || {
        owned
            .get()
            .into_iter()
            .filter(|share| share["kind"].as_str() == Some("link"))
            .collect::<Vec<_>>()
    };

    view! {
        <div class="shared-page">
            <div class="settings-head">
                <div>
                    <h2>"Shared"</h2>
                    <p class="muted">
                        "What you have shared, what others shared with you, and every public link."
                    </p>
                </div>
                <button
                    class="ghost"
                    disabled=move || loading.get()
                    on:click=move |_| load.run(())
                >
                    <Icon name="share"/>
                    {move || if loading.get() { "Refreshing…" } else { "Refresh" }}
                </button>
            </div>

            <div class="segmented share-tabs" role="tablist" aria-label="Shared views">
                <button
                    role="tab"
                    aria-selected=move || (tab.get() == SharedTab::Received).to_string()
                    class:active=move || tab.get() == SharedTab::Received
                    on:click=move |_| tab.set(SharedTab::Received)
                >
                    "Received"
                    <span class="count">{move || received.get().len()}</span>
                </button>
                <button
                    role="tab"
                    aria-selected=move || (tab.get() == SharedTab::Created).to_string()
                    class:active=move || tab.get() == SharedTab::Created
                    on:click=move |_| tab.set(SharedTab::Created)
                >
                    "Shared by me"
                    <span class="count">{move || created().len()}</span>
                </button>
                <button
                    role="tab"
                    aria-selected=move || (tab.get() == SharedTab::Links).to_string()
                    class:active=move || tab.get() == SharedTab::Links
                    on:click=move |_| tab.set(SharedTab::Links)
                >
                    "Links"
                    <span class="count">{move || links().len()}</span>
                </button>
            </div>

            {move || match tab.get() {
                SharedTab::Received => {
                    view! {
                        <ul class="shares" aria-label="Shares received">
                            <For
                                each=move || received.get()
                                key=|mount| mount["share_id"].as_i64().unwrap_or(0)
                                children={
                                    move |mount| {
                                        let id = mount["share_id"].as_i64().unwrap_or(0);
                                        let mount_path = mount["mount"]
                                            .as_str()
                                            .unwrap_or_default()
                                            .to_string();
                                        let encrypted = mount["encrypted"].as_bool() == Some(true);
                                        let display = mount["display_name"]
                                            .as_str()
                                            .map(str::to_string)
                                            .or_else(|| {
                                                mount["name"].as_str().map(str::to_string)
                                            })
                                            .filter(|name| !name.is_empty())
                                            .unwrap_or_else(|| {
                                                if encrypted {
                                                    "Encrypted share".to_string()
                                                } else {
                                                    "Shared item".to_string()
                                                }
                                            });
                                        let owner = mount["owner"]
                                            .as_str()
                                            .unwrap_or("unknown")
                                            .to_string();
                                        let permission = mount["permission"]
                                            .as_str()
                                            .unwrap_or("read")
                                            .to_string();
                                        let kind = mount["kind"].as_str().unwrap_or("file").to_string();
                                        let size = mount["size"].as_u64().unwrap_or(0);
                                        let modified = mount["modified_at"].as_i64().unwrap_or(0);
                                        let open_path = mount_path.clone();
                                        view! {
                                            <li class="row">
                                                <span class="name">
                                                    <span class="lead-icon">
                                                        <Icon name=if kind == "dir" { "folder" } else { "file" }/>
                                                    </span>
                                                    <span>
                                                        <strong>{display}</strong>
                                                        <span class="muted">
                                                            {format!(" · from {owner}")}
                                                        </span>
                                                        <span class="muted">
                                                            {format!(
                                                                " · {} · {}",
                                                                permission_label(&permission, false),
                                                                if kind == "dir" {
                                                                    "folder".to_string()
                                                                } else {
                                                                    human_size(size)
                                                                },
                                                            )}
                                                        </span>
                                                        {(!mount_path.is_empty() && modified > 0)
                                                            .then(|| {
                                                                view! {
                                                                    <span class="muted">
                                                                        {format!(" · {}", relative_time(modified))}
                                                                    </span>
                                                                }
                                                            })}
                                                    </span>
                                                </span>
                                                <span class="badges">
                                                    {encrypted
                                                        .then(|| {
                                                            view! { <span class="badge lock">"Encrypted"</span> }
                                                        })}
                                                    {move || {
                                                        (master.get().is_none() && encrypted)
                                                            .then(|| {
                                                                view! { <span class="badge">"Locked"</span> }
                                                            })
                                                    }}
                                                </span>
                                                <span class="row-actions">
                                                    <button
                                                        class="primary"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| on_open.run(open_path.clone())
                                                    >
                                                        "Open"
                                                    </button>
                                                    <button
                                                        class="danger"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| remove_received.run(id)
                                                    >
                                                        <Icon name="trash"/>
                                                        "Remove"
                                                    </button>
                                                </span>
                                            </li>
                                        }
                                    }
                                }
                            />
                            <Show when=move || received.get().is_empty() && !loading.get()>
                                <li class="row muted">
                                    "Nothing has been shared with you yet."
                                </li>
                            </Show>
                        </ul>
                    }
                        .into_any()
                }
                SharedTab::Created => {
                    view! {
                        <ShareList
                            shares=Signal::derive(created)
                            links_only=false
                            busy=busy
                            link_frags=link_frags
                            on_revoke=revoke
                            on_permission=set_permission
                            on_expiry=set_expiry
                            on_password=set_password
                            on_copy=copy_link
                        />
                    }
                        .into_any()
                }
                SharedTab::Links => {
                    view! {
                        <ShareList
                            shares=Signal::derive(links)
                            links_only=true
                            busy=busy
                            link_frags=link_frags
                            on_revoke=revoke
                            on_permission=set_permission
                            on_expiry=set_expiry
                            on_password=set_password
                            on_copy=copy_link
                        />
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

#[component]
fn ShareList(
    shares: Signal<Vec<Value>>,
    links_only: bool,
    busy: RwSignal<bool>,
    link_frags: RwSignal<HashMap<i64, String>>,
    on_revoke: Callback<i64>,
    on_permission: Callback<(i64, String)>,
    on_expiry: Callback<(i64, i64)>,
    on_password: Callback<i64>,
    on_copy: Callback<Value>,
) -> impl IntoView {
    view! {
        <ul class="shares" aria-label=if links_only { "Public links" } else { "Shares you created" }>
            <For
                each=move || shares.get()
                key=|share| share["id"].as_i64().unwrap_or(0)
                children=move |share| {
                    let id = share["id"].as_i64().unwrap_or(0);
                    let kind = share["kind"].as_str().unwrap_or_default().to_string();
                    let is_link = kind == "link";
                    let recipient = share["recipient"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| if is_link { "Public link".to_string() } else { "Unknown".to_string() });
                    let path = share["path"].as_str().unwrap_or_default().to_string();
                    let name = share["name"].as_str().unwrap_or_default().to_string();
                    let permission = share["permission"].as_str().unwrap_or("read").to_string();
                    let missing = share["missing"].as_bool() == Some(true);
                    let encrypted = share["encrypted"].as_bool() == Some(true);
                    let upload_only = share["upload_only"].as_bool() == Some(true);
                    let expires_at = share["expires_at"].as_i64();
                    let created_at = share["created_at"].as_i64().unwrap_or(0);
                    let uploaded_files = share["uploaded_files"].as_i64().unwrap_or(0);
                    let max_files = share["max_files"].as_i64();
                    let uploaded_bytes = share["uploaded_bytes"].as_u64().unwrap_or(0);
                    let max_bytes = share["max_bytes"].as_i64();
                    let frag = link_frags.get().get(&id).cloned().unwrap_or_default();
                    let copy_share = share.clone();
                    let current_expiry = expiry_value(expires_at);
                    view! {
                        <li class="row">
                            <span class="name">
                                <span class="lead-icon">
                                    <Icon name=if is_link { "share" } else { "users" }/>
                                </span>
                                <span>
                                    <strong>{if name.is_empty() { path.clone() } else { name }}</strong>
                                    <span class="muted">
                                        {format!(" · {recipient} · {}", permission_label(&permission, upload_only))}
                                    </span>
                                    <span class="muted">
                                        {format!(" · shared {}", relative_time(created_at))}
                                    </span>
                                    {upload_only
                                        .then(|| {
                                            view! {
                                                <span class="muted">
                                                    {format!(
                                                        " · {} of {} files · {} of {}",
                                                        uploaded_files,
                                                        max_files.unwrap_or(20),
                                                        human_size(uploaded_bytes),
                                                        human_size(max_bytes.unwrap_or(0) as u64),
                                                    )}
                                                </span>
                                            }
                                        })}
                                    {is_link
                                        .then(|| {
                                            view! {
                                                <span class="muted">
                                                    {format!(" · {}", expiry_label(expires_at))}
                                                </span>
                                            }
                                        })}
                                </span>
                            </span>
                            <span class="badges">
                                {missing
                                    .then(|| view! { <span class="badge danger">"Missing"</span> })}
                                {encrypted
                                    .then(|| view! { <span class="badge lock">"Encrypted"</span> })}
                                {upload_only
                                    .then(|| view! { <span class="badge">"File request"</span> })}
                                {is_expired(expires_at)
                                    .then(|| view! { <span class="badge danger">"Expired"</span> })}
                            </span>
                            <span class="row-actions">
                                {is_link
                                    .then(|| {
                                        let copy_share = copy_share.clone();
                                        view! {
                                            <button
                                                class="ghost"
                                                disabled=move || busy.get()
                                                title=if frag.is_empty() && encrypted {
                                                    "Unlock encryption to copy the full link"
                                                } else {
                                                    "Copy link"
                                                }
                                                on:click=move |_| on_copy.run(copy_share.clone())
                                            >
                                                <Icon name="share"/>
                                                "Copy link"
                                            </button>
                                        }
                                    })}
                                {(!is_link)
                                    .then(|| {
                                        let value = permission.clone();
                                        view! {
                                            <label class="inline-field">
                                                "Access"
                                                <select
                                                    prop:value=value.clone()
                                                    disabled=move || busy.get()
                                                    on:change=move |event| {
                                                        let next = event_target_value(&event);
                                                        on_permission.run((id, next));
                                                    }
                                                >
                                                    <option value="read">"Can view"</option>
                                                    <option value="write">"Can edit"</option>
                                                </select>
                                            </label>
                                        }
                                    })}
                                {is_link
                                    .then(|| {
                                        let value = current_expiry;
                                        view! {
                                            <label class="inline-field">
                                                "Expiry"
                                                <select
                                                    prop:value=value
                                                    disabled=move || busy.get()
                                                    on:change=move |event| {
                                                        let next = event_target_value(&event);
                                                        if let Ok(secs) = next.parse::<i64>() {
                                                            on_expiry.run((id, secs));
                                                        }
                                                    }
                                                >
                                                    <option value="keep">"Keep current"</option>
                                                    <option value="0">"Never"</option>
                                                    <option value="86400">"1 day"</option>
                                                    <option value="604800">"7 days"</option>
                                                    <option value="2592000">"30 days"</option>
                                                </select>
                                            </label>
                                        }
                                    })}
                                {is_link
                                    .then(|| {
                                        view! {
                                            <button
                                                class="ghost"
                                                disabled=move || busy.get()
                                                on:click=move |_| on_password.run(id)
                                            >
                                                <Icon name="key"/>
                                                "Password"
                                            </button>
                                        }
                                    })}
                                <button
                                    class="danger"
                                    disabled=move || busy.get()
                                    on:click=move |_| on_revoke.run(id)
                                >
                                    <Icon name="trash"/>
                                    "Revoke"
                                </button>
                            </span>
                        </li>
                    }
                }
            />
            <Show when=move || shares.get().is_empty()>
                <li class="row muted">
                    {if links_only {
                        "No public links yet. Use Share on a file or folder to create one."
                    } else {
                        "You have not shared anything with a person or group yet."
                    }}
                </li>
            </Show>
        </ul>
    }
}

fn origin() -> String {
    web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default()
}

fn link_fragment(key: &[u8; 32], lengths: &[u32], name: &str) -> String {
    let key = URL_SAFE_NO_PAD.encode(key);
    let lengths = lengths
        .iter()
        .map(|length| length.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let name = js_sys::encode_uri_component(name)
        .as_string()
        .unwrap_or_default();
    format!("#k={key}&l={lengths}&n={name}")
}

fn permission_label(permission: &str, upload_only: bool) -> &'static str {
    match (permission, upload_only) {
        ("write", true) => "Upload only",
        ("write", false) => "Can edit",
        _ => "Can view",
    }
}

fn is_expired(expires_at: Option<i64>) -> bool {
    expires_at.is_some_and(|at| at <= js_sys::Date::now() as i64)
}

fn expiry_value(expires_at: Option<i64>) -> String {
    let Some(at) = expires_at else {
        return "0".to_string();
    };
    let remaining = at - js_sys::Date::now() as i64;
    let day = 86_400_000i64;
    if remaining <= 0 {
        return "keep".to_string();
    }
    if (remaining - day).abs() < 3_600_000 {
        "86400".to_string()
    } else if (remaining - 7 * day).abs() < day {
        "604800".to_string()
    } else if (remaining - 30 * day).abs() < 2 * day {
        "2592000".to_string()
    } else {
        "keep".to_string()
    }
}

fn expiry_label(expires_at: Option<i64>) -> String {
    let Some(at) = expires_at else {
        return "Never expires".to_string();
    };
    let remaining = at - js_sys::Date::now() as i64;
    if remaining <= 0 {
        return "Expired".to_string();
    }
    let minutes = remaining / 60_000;
    if minutes < 60 {
        format!("Expires in {minutes}m")
    } else if minutes < 24 * 60 {
        format!("Expires in {}h", minutes / 60)
    } else {
        format!("Expires in {}d", minutes / (24 * 60))
    }
}
