use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::encode;
use crate::components::{Icon, sanitize_svg};

#[component]
pub(crate) fn ShareDialog(
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
                            // User/group shares of encrypted content need a
                            // key path. Folders use an MLS group + keyring;
                            // files keep the per-recipient X25519 wrap.
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
                                let permission_now = permission.get_untracked();
                                {
                                    match crate::mls::share_folder(
                                        master,
                                        &path,
                                        &recipients,
                                        &permission_now,
                                    )
                                    .await
                                    {
                                        Ok(()) => {}
                                        Err(e) if permission_now == "write" => {
                                            // A write ACL without a keyring would
                                            // let the recipient corrupt the
                                            // share; revoke it instead.
                                            if let Some(id) = r.body["id"].as_i64() {
                                                let _ =
                                                    api::delete(&format!("/api/shares/{id}")).await;
                                            }
                                            error.set(format!(
                                                "Could not create the MLS group, so the write share was revoked: {e}"
                                            ));
                                        }
                                        Err(e) => {
                                            // Older recipients may have no key
                                            // package; fall back to per-file
                                            // wraps so a read share still works.
                                            let mut skipped = Vec::new();
                                            for username in &recipients {
                                                if crate::e2ee::share_encrypted_with(
                                                    master, &path, username,
                                                )
                                                .await
                                                .is_err()
                                                {
                                                    skipped.push(username.clone());
                                                }
                                            }
                                            if !skipped.is_empty() {
                                                error.set(format!(
                                                    "Shared read-only, but {e}; {} recipient(s) have no MLS key package ({}).",
                                                    skipped.len(),
                                                    skipped.join(", ")
                                                ));
                                            } else {
                                                error.set(format!(
                                                    "Shared with legacy file keys; MLS setup failed: {e}"
                                                ));
                                            }
                                        }
                                    }
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

    let revoke = Callback::new(move |(id, kind, recipient): (i64, String, String)| {
        let path = path.clone();
        let master = master.clone();
        spawn_local(async move {
            let mut members = if kind == "group" {
                crate::e2ee::group_members(&recipient)
                    .await
                    .unwrap_or_default()
            } else {
                vec![recipient.clone()]
            };
            // A user may still have access through another share of the
            // same node; only remove members that are not covered.
            let mut keep = std::collections::BTreeSet::new();
            for share in shares.get_untracked() {
                if share["id"].as_i64() == Some(id) {
                    continue;
                }
                match share["kind"].as_str() {
                    Some("user") => {
                        if let Some(name) = share["recipient"].as_str() {
                            keep.insert(name.to_string());
                        }
                    }
                    Some("group") => {
                        if let Some(name) = share["recipient"].as_str() {
                            for member in crate::e2ee::group_members(name).await.unwrap_or_default()
                            {
                                keep.insert(member);
                            }
                        }
                    }
                    _ => {}
                }
            }
            members.retain(|member| !keep.contains(member));
            match api::delete(&format!("/api/shares/{id}")).await {
                Ok(r) if r.status == 204 => {
                    if let Some(master) = &master {
                        let _ = crate::mls::remove_recipients(master, &path, &members).await;
                    }
                    load.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("Could not revoke share").to_string()),
                Err(e) => error.set(e),
            }
        });
    });

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
                                        <button class="danger" on:click=move |_| revoke.run((id, kind.clone(), recipient.clone()))>
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
