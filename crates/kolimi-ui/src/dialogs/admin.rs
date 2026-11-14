use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{encode, relative_time};
use crate::components::{ErrorText, Icon, Modal, Notice};

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

fn quota_label(quota: Option<i64>) -> String {
    match quota {
        None => "default".to_string(),
        Some(0) => "unlimited".to_string(),
        Some(n) if n > 0 => fmt_bytes(n as u64),
        Some(_) => "unlimited".to_string(),
    }
}

/// Parses a quota input such as `default`, `unlimited`, `10GB`, or bytes.
fn parse_quota(input: &str) -> Result<Option<i64>, String> {
    let value = input.trim().to_ascii_lowercase();
    if value.is_empty() || value == "default" {
        return Ok(None);
    }
    if value == "unlimited" {
        return Ok(Some(0));
    }
    let suffixes = [
        ("tib", 1_i64 << 40),
        ("tb", 1_i64 << 40),
        ("gib", 1_i64 << 30),
        ("gb", 1_i64 << 30),
        ("mib", 1_i64 << 20),
        ("mb", 1_i64 << 20),
        ("kib", 1_i64 << 10),
        ("kb", 1_i64 << 10),
        ("b", 1),
    ];
    for (suffix, multiplier) in suffixes {
        if let Some(number) = value.strip_suffix(suffix) {
            let number = number
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("invalid quota: {input}"))?;
            return number
                .checked_mul(multiplier)
                .map(Some)
                .ok_or_else(|| "quota is too large".to_string());
        }
    }
    value
        .parse::<i64>()
        .map(Some)
        .map_err(|_| format!("invalid quota: {input}"))
}

fn random_password() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        return String::new();
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Admin page: users, quotas, account recovery, and lifecycle actions.
#[component]
pub(crate) fn AdminPage(current_username: RwSignal<String>) -> impl IntoView {
    let users = RwSignal::new(Vec::<Value>::new());
    let query = RwSignal::new(String::new());
    let filter = RwSignal::new("all".to_string());
    let sort_usage = RwSignal::new(false);
    let cursor = RwSignal::new(Option::<i64>::None);
    let has_more = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let create_open = RwSignal::new(false);
    let detail_user = RwSignal::new(Option::<String>::None);

    let load = Callback::new(move |reset: bool| {
        let q = query.get_untracked();
        let filter_value = filter.get_untracked();
        let by_usage = sort_usage.get_untracked();
        let after = if reset { None } else { cursor.get_untracked() };
        loading.set(true);
        error.set(String::new());
        spawn_local(async move {
            let mut url = format!(
                "/api/users?limit=100&sort={}",
                if by_usage { "used_bytes" } else { "id" }
            );
            if !by_usage && let Some(after) = after {
                url.push_str(&format!("&cursor={after}"));
            }
            url.push_str("&order=desc");
            let q = q.trim();
            if !q.is_empty() {
                url.push_str(&format!("&q={}", encode(q)));
            }
            if filter_value != "all" {
                url.push_str(&format!("&filter={filter_value}"));
            }
            match api::get(&url).await {
                Ok(response) if response.status == 200 => {
                    let fresh = response.body["users"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if reset {
                        users.set(fresh);
                    } else {
                        users.update(|current| current.extend(fresh));
                    }
                    cursor.set(response.body["next_cursor"].as_i64());
                    has_more.set(response.body["has_more"].as_bool().unwrap_or(false));
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load users")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            loading.set(false);
        });
    });
    Effect::new(move |_| load.run(true));

    let reload = Callback::new(move |_: ()| load.run(true));
    let close_create = Callback::new(move |_: ()| create_open.set(false));
    let created = Callback::new(move |_: ()| {
        notice.set("User created.".to_string());
        load.run(true);
    });
    let close_detail = Callback::new(move |_: ()| detail_user.set(None));
    let changed = Callback::new(move |_: ()| {
        load.run(true);
    });

    view! {
        <div class="section-head">
            <h2>"Admin — users"</h2>
            <button class="primary" on:click=move |_| create_open.set(true)>
                <Icon name="users"/>
                "Create user"
            </button>
        </div>
        <p class="muted">
            "Search, inspect, recover, and remove accounts. Administrators can also manage quotas and sessions."
        </p>

        <div class="row-actions">
            <form
                class="search"
                on:submit=move |ev| {
                    ev.prevent_default();
                    load.run(true);
                }
            >
                <Icon name="search"/>
                <input
                    type="search"
                    placeholder="Search users…"
                    prop:value=move || query.get()
                    on:input=move |ev| query.set(event_target_value(&ev))
                />
            </form>
            <select
                aria-label="Filter users"
                prop:value=move || filter.get()
                on:change=move |ev| {
                    filter.set(event_target_value(&ev));
                    load.run(true);
                }
            >
                <option value="all">All users</option>
                <option value="admin">Administrators</option>
                <option value="disabled">Disabled</option>
                <option value="over_quota">Over quota</option>
            </select>
            <button
                on:click=move |_| {
                    sort_usage.update(|value| *value = !*value);
                    load.run(true);
                }
            >
                {move || if sort_usage.get() { "By usage" } else { "Newest first" }}
            </button>
            <button on:click=move |_| reload.run(()) disabled=move || loading.get()>
                <Icon name="refresh"/>
                "Refresh"
            </button>
        </div>

        <ErrorText message=error/>
        <Notice message=notice/>
        <p class="muted">{move || format!("{} user(s) loaded", users.get().len())}</p>

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
                    let detail = username.clone();
                    view! {
                        <li class="row">
                            <span class="name">
                                <span class="lead-icon">
                                    <Icon name="users"/>
                                </span>
                                <span class="file-body">
                                    <span class="file-name">
                                        {username}
                                        {is_admin
                                            .then(|| view! { <span class="badge">"admin"</span> })}
                                        {disabled
                                            .then(|| view! { <span class="badge">"disabled"</span> })}
                                        {over
                                            .then(|| view! { <span class="badge">"over quota"</span> })}
                                        {near
                                            .then(|| view! { <span class="badge">"near quota"</span> })}
                                    </span>
                                    <span class="file-meta">
                                        {fmt_bytes(used)} " / " {quota_label(quota)}
                                        {quota
                                            .is_some_and(|q| q > 0)
                                            .then(|| {
                                                let percent = (used as f64 / quota.unwrap_or(1) as f64
                                                    * 100.0)
                                                    .min(999.0);
                                                format!(" · {percent:.0}%")
                                            })}
                                    </span>
                                </span>
                            </span>
                            <span class="row-actions">
                                <button on:click=move |_| detail_user.set(Some(detail.clone()))>
                                    "Manage"
                                </button>
                            </span>
                        </li>
                    }
                }
            />
            <Show when=move || !loading.get() && users.get().is_empty()>
                <li class="row muted">"No users match this search."</li>
            </Show>
        </ul>

        <Show when=move || has_more.get() && !sort_usage.get()>
            <div class="row-actions">
                <button on:click=move |_| load.run(false) disabled=move || loading.get()>
                    "Load more"
                </button>
            </div>
        </Show>

        {move || {
            create_open
                .get()
                .then(|| {
                    view! {
                        <CreateUserDialog on_close=close_create on_created=created/>
                    }
                })
        }}
        {move || {
            detail_user
                .get()
                .map(|username| {
                    view! {
                        <UserDetailDialog
                            username=username
                            current_username=current_username
                            on_close=close_detail
                            on_changed=changed
                        />
                    }
                })
        }}
    }
}

/// Create-user modal.
#[component]
fn CreateUserDialog(on_close: Callback<()>, on_created: Callback<()>) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    let generate = move |_| {
        let value = random_password();
        password.set(value.clone());
        confirm.set(value);
    };

    let submit = move |_| {
        let user = username.get_untracked().trim().to_string();
        let pass = password.get_untracked();
        if user.is_empty() {
            error.set("Username is required".to_string());
            return;
        }
        if pass.chars().count() < 8 {
            error.set("Use at least 8 characters for the password".to_string());
            return;
        }
        if pass != confirm.get_untracked() {
            error.set("The password and confirmation do not match".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::send_json(
                "POST",
                "/api/users",
                &json!({
                    "username": user,
                    "password": pass,
                    "admin": admin.get_untracked(),
                }),
            )
            .await
            {
                Ok(response) if response.status == 201 => {
                    on_created.run(());
                    on_close.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not create the user")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    view! {
        <Modal title="Create user" on_close=on_close>
            <label>
                "Username"
                <input
                    type="text"
                    autocomplete="off"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Initial password"
                <input
                    type="text"
                    autocomplete="new-password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Confirm password"
                <input
                    type="text"
                    autocomplete="new-password"
                    prop:value=move || confirm.get()
                    on:input=move |ev| confirm.set(event_target_value(&ev))
                />
            </label>
            <div class="row-actions">
                <button on:click=generate disabled=move || busy.get()>
                    <Icon name="key"/>
                    "Generate password"
                </button>
            </div>
            <label class="row">
                <input
                    type="checkbox"
                    prop:checked=move || admin.get()
                    on:change=move |ev| admin.set(event_target_checked(&ev))
                />
                "Make administrator"
            </label>
            <ErrorText message=error/>
            <div class="row-actions">
                <button class="primary" on:click=submit disabled=move || busy.get()>
                    {move || if busy.get() { "Creating…" } else { "Create user" }}
                </button>
                <button class="ghost" on:click=move |_| on_close.run(())>
                    "Cancel"
                </button>
            </div>
        </Modal>
    }
}

#[derive(Clone, Copy)]
enum PendingAction {
    Recover,
    Logout,
}

/// User detail, recovery, quota, and lifecycle actions.
#[component]
fn UserDetailDialog(
    username: String,
    current_username: RwSignal<String>,
    on_close: Callback<()>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let detail = RwSignal::new(Value::Null);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let quota = RwSignal::new(String::new());
    let delete_name = RwSignal::new(String::new());
    let generated = RwSignal::new(Option::<String>::None);
    let pending = RwSignal::new(Option::<PendingAction>::None);
    let reauth_password = RwSignal::new(String::new());
    let reauth_code = RwSignal::new(String::new());

    let load_name = username.clone();
    let load = Callback::new(move |_: ()| {
        let name = load_name.clone();
        spawn_local(async move {
            match api::get(&format!("/api/users/{}", encode(&name))).await {
                Ok(response) if response.status == 200 => {
                    quota.set(match response.body["quota_bytes"].as_i64() {
                        Some(bytes) => bytes.to_string(),
                        None => "default".to_string(),
                    });
                    detail.set(response.body);
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load the user")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
        });
    });
    Effect::new(move |_| load.run(()));

    let patch_name = username.clone();
    let patch = Callback::new(move |(body, message): (Value, &'static str)| {
        let name = patch_name.clone();
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::send_json("PATCH", &format!("/api/users/{}", encode(&name)), &body).await {
                Ok(response) if response.status == 200 => {
                    notice.set(message.to_string());
                    load.run(());
                    on_changed.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not update the user")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let apply_quota = move |_| {
        let value = match parse_quota(&quota.get_untracked()) {
            Ok(value) => value,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        patch.run((json!({ "quota_bytes": value }), "Quota updated"));
    };

    let delete = Callback::new({
        let username = username.clone();
        move |_: ()| {
            if delete_name.get_untracked() != username {
                error.set("Type the username exactly to confirm deletion".to_string());
                return;
            }
            let name = username.clone();
            busy.set(true);
            error.set(String::new());
            spawn_local(async move {
                match api::delete(&format!("/api/users/{}", encode(&name))).await {
                    Ok(response) if response.status == 204 => {
                        on_changed.run(());
                        on_close.run(());
                    }
                    Ok(response) => error.set(
                        response
                            .error()
                            .unwrap_or("Could not delete the user")
                            .to_string(),
                    ),
                    Err(message) => error.set(message),
                }
                busy.set(false);
            });
        }
    });

    let confirm_reauth = Callback::new({
        let username = username.clone();
        move |_: ()| {
            let Some(action) = pending.get_untracked() else {
                return;
            };
            let password = reauth_password.get_untracked();
            let code = reauth_code.get_untracked();
            if password.is_empty() && code.is_empty() {
                error.set("Enter your account password or a two-factor code".to_string());
                return;
            }
            let name = username.clone();
            busy.set(true);
            error.set(String::new());
            spawn_local(async move {
                let result = async {
                    let token = api::reauth(&password, &code).await?;
                    let (url, body) = match action {
                        PendingAction::Recover => {
                            (format!("/api/users/{}/recover", encode(&name)), json!({}))
                        }
                        PendingAction::Logout => {
                            (format!("/api/users/{}/logout", encode(&name)), json!({}))
                        }
                    };
                    let response = api::send_json_with(
                        "POST",
                        &url,
                        &body,
                        Some(("x-reauth-token", token.as_str())),
                    )
                    .await?;
                    if response.status != 200 {
                        return Err(response.error().unwrap_or("The action failed").to_string());
                    }
                    Ok(response.body)
                }
                .await;
                match result {
                    Ok(body) => {
                        match action {
                            PendingAction::Recover => {
                                generated.set(body["password"].as_str().map(str::to_string));
                                notice.set(
                                    "Password reset. Share the new password securely.".to_string(),
                                );
                            }
                            PendingAction::Logout => {
                                notice.set(format!(
                                    "{} session(s) signed out.",
                                    body["sessions_revoked"].as_u64().unwrap_or(0)
                                ));
                            }
                        }
                        load.run(());
                        on_changed.run(());
                    }
                    Err(message) => error.set(message),
                }
                reauth_password.set(String::new());
                reauth_code.set(String::new());
                pending.set(None);
                busy.set(false);
            });
        }
    });

    let is_self = {
        let username = username.clone();
        Callback::new(move |_: ()| current_username.get() == username)
    };
    let delete_expected = username.clone();

    view! {
        <Modal title=format!("User — {username}") on_close=on_close>
            <ErrorText message=error/>
            <Notice message=notice/>

            <ul class="shares">
                <li class="row">
                    <span class="name">"ID"</span>
                    <span class="muted">
                        {move || detail.get()["id"].as_i64().unwrap_or(0).to_string()}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Role"</span>
                    <span class="badge">
                        {move || {
                            if detail.get()["is_admin"].as_bool() == Some(true) {
                                "administrator".to_string()
                            } else {
                                "member".to_string()
                            }
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Status"</span>
                    <span class="badge">
                        {move || {
                            if detail.get()["disabled"].as_bool() == Some(true) {
                                "disabled".to_string()
                            } else {
                                "active".to_string()
                            }
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Created"</span>
                    <span class="muted">
                        {move || relative_time(detail.get()["created_at"].as_i64().unwrap_or(0))}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Last login"</span>
                    <span class="muted">
                        {move || {
                            detail
                                .get()["last_login_at"]
                                .as_i64()
                                .map(relative_time)
                                .unwrap_or_else(|| "never".to_string())
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Storage"</span>
                    <span class="muted">
                        {move || {
                            format!(
                                "{} / {}",
                                fmt_bytes(detail.get()["used_bytes"].as_u64().unwrap_or(0)),
                                quota_label(detail.get()["quota_bytes"].as_i64()),
                            )
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Sign-in factors"</span>
                    <span class="muted">
                        {move || {
                            let value = detail.get();
                            let passkeys = value["passkey_count"].as_i64().unwrap_or(0);
                            let totp = value["totp_enabled"].as_bool().unwrap_or(false);
                            let password = value["password_login"].as_bool().unwrap_or(false);
                            format!(
                                "{} passkey(s) · TOTP {} · password {}",
                                passkeys,
                                if totp { "on" } else { "off" },
                                if password { "on" } else { "off" },
                            )
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Sessions / groups / shares"</span>
                    <span class="muted">
                        {move || {
                            let value = detail.get();
                            let groups = value["groups"]
                                .as_array()
                                .map(|list| {
                                    list.iter()
                                        .filter_map(Value::as_str)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .filter(|text| !text.is_empty())
                                .unwrap_or_else(|| "none".to_string());
                            format!(
                                "{} session(s) · {} group(s): {} · {} owned / {} received share(s)",
                                value["session_count"].as_i64().unwrap_or(0),
                                value["groups"].as_array().map(Vec::len).unwrap_or(0),
                                groups,
                                value["owned_shares"].as_i64().unwrap_or(0),
                                value["received_shares"].as_i64().unwrap_or(0),
                            )
                        }}
                    </span>
                </li>
            </ul>

            <h3>"Storage quota"</h3>
            <div class="share-form">
                <label>
                    "Quota"
                    <input
                        type="text"
                        placeholder="default, unlimited, 10GB"
                        prop:value=move || quota.get()
                        on:input=move |ev| quota.set(event_target_value(&ev))
                    />
                </label>
                <button on:click=apply_quota disabled=move || busy.get()>
                    "Apply"
                </button>
            </div>

            <Show when=move || !is_self.run(())>
                <h3>"Access"</h3>
                <div class="row-actions">
                    <button
                        on:click=move |_| {
                            let admin = detail.get_untracked()["is_admin"].as_bool().unwrap_or(false);
                            patch.run((json!({ "admin": !admin }), "Role updated"));
                        }
                        disabled=move || busy.get()
                    >
                        {move || {
                            if detail.get()["is_admin"].as_bool() == Some(true) {
                                "Revoke admin"
                            } else {
                                "Make admin"
                            }
                        }}
                    </button>
                    <button
                        on:click=move |_| {
                            let disabled = detail.get_untracked()["disabled"].as_bool().unwrap_or(false);
                            patch.run((json!({ "disabled": !disabled }), "Access updated"));
                        }
                        disabled=move || busy.get()
                    >
                        {move || {
                            if detail.get()["disabled"].as_bool() == Some(true) {
                                "Enable"
                            } else {
                                "Disable"
                            }
                        }}
                    </button>
                    <button
                        on:click=move |_| {
                            pending.set(Some(PendingAction::Logout));
                            generated.set(None);
                        }
                        disabled=move || busy.get()
                    >
                        "Force sign-out"
                    </button>
                    <button
                        on:click=move |_| {
                            pending.set(Some(PendingAction::Recover));
                            generated.set(None);
                        }
                        disabled=move || busy.get()
                    >
                        "Reset password"
                    </button>
                </div>
            </Show>

            {move || {
                generated
                    .get()
                    .map(|password| {
                        let copy = password.clone();
                        view! {
                            <div class="created">
                                <p class="muted">"New password — shown once. Share it securely."</p>
                                <code>{password}</code>
                                <div class="row-actions">
                                    <button on:click=move |_| {
                                        let copy = copy.clone();
                                        spawn_local(async move {
                                            api::copy_to_clipboard(&copy).await;
                                        });
                                    }>"Copy"</button>
                                </div>
                            </div>
                        }
                    })
            }}

            {move || {
                pending
                    .get()
                    .map(|action| {
                        let description = match action {
                            PendingAction::Recover => "reset this password",
                            PendingAction::Logout => "sign this user out everywhere",
                        };
                        view! {
                            <div class="reauth">
                                <h3>"Confirm admin action"</h3>
                                <p class="muted">
                                    {format!(
                                        "Confirm your admin password or a two-factor code to {description}.",
                                    )}
                                </p>
                                <label>
                                    "Your password"
                                    <input
                                        type="password"
                                        autocomplete="current-password"
                                        prop:value=move || reauth_password.get()
                                        on:input=move |ev| {
                                            reauth_password.set(event_target_value(&ev))
                                        }
                                    />
                                </label>
                                <label>
                                    "Two-factor / recovery code"
                                    <input
                                        type="text"
                                        autocomplete="one-time-code"
                                        prop:value=move || reauth_code.get()
                                        on:input=move |ev| reauth_code.set(event_target_value(&ev))
                                    />
                                </label>
                                <div class="row-actions">
                                    <button
                                        class="primary"
                                        on:click=move |_| confirm_reauth.run(())
                                        disabled=move || busy.get()
                                    >
                                        {move || if busy.get() { "Confirming…" } else { "Confirm" }}
                                    </button>
                                    <button
                                        class="ghost"
                                        on:click=move |_| {
                                            pending.set(None);
                                            reauth_password.set(String::new());
                                            reauth_code.set(String::new());
                                        }
                                    >
                                        "Cancel"
                                    </button>
                                </div>
                            </div>
                        }
                    })
            }}

            <Show when=move || !is_self.run(())>
                <h3>"Delete account"</h3>
                <p class="muted">
                    "This removes the account, its files, shares, keys and blobs. Type the username to confirm."
                </p>
                <div class="share-form">
                    <label>
                        "Username"
                        <input
                            type="text"
                            autocomplete="off"
                            placeholder=username.clone()
                            prop:value=move || delete_name.get()
                            on:input=move |ev| delete_name.set(event_target_value(&ev))
                        />
                    </label>
                    <button
                        class="danger"
                        on:click=move |_| delete.run(())
                        disabled={
                            let expected = delete_expected.clone();
                            move || busy.get() || delete_name.get() != expected
                        }
                    >
                        "Delete user"
                    </button>
                </div>
            </Show>
        </Modal>
    }
}

#[cfg(test)]
mod tests {
    use super::parse_quota;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn quota_inputs_use_binary_units() {
        assert_eq!(parse_quota("default").unwrap(), None);
        assert_eq!(parse_quota("unlimited").unwrap(), Some(0));
        assert_eq!(parse_quota("10GB").unwrap(), Some(10 * (1 << 30)));
        assert_eq!(parse_quota("512MiB").unwrap(), Some(512 * (1 << 20)));
        assert!(parse_quota("ten").is_err());
    }
}
