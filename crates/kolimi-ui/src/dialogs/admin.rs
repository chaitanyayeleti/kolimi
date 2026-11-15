use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{encode, plural, relative_time};
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdminTab {
    Users,
    Invites,
    Groups,
    Audit,
}

/// Admin page: users, groups, and the audit log.
#[component]
pub(crate) fn AdminPage(current_username: RwSignal<String>) -> impl IntoView {
    let tab = RwSignal::new(AdminTab::Users);
    view! {
        <div class="segmented settings-tabs" role="tablist">
            <button
                role="tab"
                aria-selected=move || tab.get() == AdminTab::Users
                class:active=move || tab.get() == AdminTab::Users
                on:click=move |_| tab.set(AdminTab::Users)
            >
                "Users"
            </button>
            <button
                role="tab"
                aria-selected=move || tab.get() == AdminTab::Invites
                class:active=move || tab.get() == AdminTab::Invites
                on:click=move |_| tab.set(AdminTab::Invites)
            >
                "Invites"
            </button>
            <button
                role="tab"
                aria-selected=move || tab.get() == AdminTab::Groups
                class:active=move || tab.get() == AdminTab::Groups
                on:click=move |_| tab.set(AdminTab::Groups)
            >
                "Groups"
            </button>
            <button
                role="tab"
                aria-selected=move || tab.get() == AdminTab::Audit
                class:active=move || tab.get() == AdminTab::Audit
                on:click=move |_| tab.set(AdminTab::Audit)
            >
                "Audit"
            </button>
        </div>

        <Show when=move || tab.get() == AdminTab::Users>
            <UsersPanel current_username=current_username/>
        </Show>
        <Show when=move || tab.get() == AdminTab::Invites>
            <InvitesPanel/>
        </Show>
        <Show when=move || tab.get() == AdminTab::Groups>
            <GroupsPanel/>
        </Show>
        <Show when=move || tab.get() == AdminTab::Audit>
            <AuditPanel/>
        </Show>
    }
}

/// Users tab: search, create, inspect, recover, and lifecycle actions.
#[component]
fn UsersPanel(current_username: RwSignal<String>) -> impl IntoView {
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
            <h2>"Users"</h2>
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
            <select
                aria-label="Sort users"
                prop:value=move || if sort_usage.get() { "usage" } else { "newest" }
                on:change=move |ev| {
                    sort_usage.set(event_target_value(&ev) == "usage");
                    load.run(true);
                }
            >
                <option value="newest">"Newest"</option>
                <option value="usage">"Usage"</option>
            </select>
            <button on:click=move |_| reload.run(()) disabled=move || loading.get()>
                <Icon name="refresh"/>
                "Refresh"
            </button>
        </div>

        <ErrorText message=error/>
        <Notice message=notice/>
        <p class="muted">{move || plural(users.get().len(), "user", "users")}</p>

        <div class="table-wrap">
            <table class="data-table users-table">
                <thead>
                    <tr>
                        <th scope="col">"User"</th>
                        <th scope="col">"Role"</th>
                        <th scope="col">"Status"</th>
                        <th scope="col">"Usage"</th>
                        <th scope="col" class="cell-actions">"Actions"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || users.get()
                        key=|user| user["id"].as_i64().unwrap_or(0)
                        children=move |user| {
                            let username =
                                user["username"].as_str().unwrap_or_default().to_string();
                            let is_admin = user["is_admin"].as_bool().unwrap_or(false);
                            let disabled = user["disabled"].as_bool().unwrap_or(false);
                            let used = user["used_bytes"].as_u64().unwrap_or(0);
                            let quota = user["quota_bytes"].as_i64();
                            let quota_total = quota.filter(|value| *value > 0).map(|value| value as u64);
                            let percent = quota_total.map(|total| {
                                (used as f64 / total as f64 * 100.0).min(999.0)
                            });
                            let near =
                                percent.is_some_and(|value| (90.0..100.0).contains(&value));
                            let over = percent.is_some_and(|value| value >= 100.0);
                            let usage_class = if over {
                                "usage-bar-fill danger"
                            } else if near {
                                "usage-bar-fill warn"
                            } else {
                                "usage-bar-fill"
                            };
                            let last_login = user["last_login_at"].as_i64().unwrap_or(0);
                            let detail = username.clone();
                            view! {
                                <tr>
                                    <td>
                                        <span class="cell-user">
                                            <span class="lead-icon">
                                                <Icon name="users"/>
                                            </span>
                                            <span class="file-body">
                                                <span class="file-name">{username}</span>
                                                <span class="file-meta">
                                                    {if last_login > 0 {
                                                        format!("last seen {}", relative_time(last_login))
                                                    } else {
                                                        "never signed in".to_string()
                                                    }}
                                                </span>
                                            </span>
                                        </span>
                                    </td>
                                    <td>
                                        {if is_admin {
                                            view! { <span class="badge">"admin"</span> }.into_any()
                                        } else {
                                            view! { <span class="badge muted">"member"</span> }
                                                .into_any()
                                        }}
                                    </td>
                                    <td>
                                        <span class="status-pills">
                                            {if disabled {
                                                view! { <span class="badge danger">"disabled"</span> }
                                                    .into_any()
                                            } else {
                                                view! { <span class="badge ok">"active"</span> }
                                                    .into_any()
                                            }}
                                            {over
                                                .then(|| {
                                                    view! { <span class="badge danger">"over quota"</span> }
                                                })}
                                            {near
                                                .then(|| {
                                                    view! { <span class="badge warn">"near quota"</span> }
                                                })}
                                        </span>
                                    </td>
                                    <td class="cell-usage">
                                        <span class="usage-line">
                                            <span>
                                                {fmt_bytes(used)}
                                                " / "
                                                {quota_label(quota)}
                                            </span>
                                            {percent
                                                .map(|value| {
                                                    view! { <span class="muted">{format!("{value:.0}%")}</span> }
                                                })}
                                        </span>
                                        {percent
                                            .map(|value| {
                                                view! {
                                                    <span class="usage-bar">
                                                        <span
                                                            class=usage_class
                                                            style:width=format!("{value:.0}%")
                                                        ></span>
                                                    </span>
                                                }
                                            })}
                                    </td>
                                    <td class="cell-actions">
                                        <button on:click=move |_| detail_user.set(Some(detail.clone()))>
                                            "Manage"
                                        </button>
                                    </td>
                                </tr>
                            }
                        }
                    />
                    <Show when=move || !loading.get() && users.get().is_empty()>
                        <tr>
                            <td colspan="5" class="muted">"No users match this search."</td>
                        </tr>
                    </Show>
                </tbody>
            </table>
        </div>

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
    let display_name = RwSignal::new(String::new());
    let email = RwSignal::new(String::new());
    let admin = RwSignal::new(false);
    let must_change_password = RwSignal::new(true);
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
                    "display_name": display_name.get_untracked(),
                    "email": email.get_untracked(),
                    "must_change_password": must_change_password.get_untracked(),
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
            <label>
                "Display name"
                <input
                    type="text"
                    autocomplete="off"
                    prop:value=move || display_name.get()
                    on:input=move |ev| display_name.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Email"
                <input
                    type="email"
                    autocomplete="off"
                    prop:value=move || email.get()
                    on:input=move |ev| email.set(event_target_value(&ev))
                />
            </label>
            <label class="row">
                <input
                    type="checkbox"
                    prop:checked=move || admin.get()
                    on:change=move |ev| admin.set(event_target_checked(&ev))
                />
                "Make administrator"
            </label>
            <label class="row">
                <input
                    type="checkbox"
                    prop:checked=move || must_change_password.get()
                    on:change=move |ev| {
                        must_change_password.set(event_target_checked(&ev))
                    }
                />
                "Require password change at next sign-in"
            </label>
            <p class="muted">
                "New users must also set up an authenticator app or a passkey on their first sign-in."
            </p>
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

#[derive(Clone)]
enum PendingAction {
    Recover,
    Logout,
    Patch {
        body: Value,
        notice: String,
        description: &'static str,
    },
    Delete,
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
    let recover_name = RwSignal::new(String::new());

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

    let apply_quota = move |_| {
        let value = match parse_quota(&quota.get_untracked()) {
            Ok(value) => value,
            Err(message) => {
                error.set(message);
                return;
            }
        };
        pending.set(Some(PendingAction::Patch {
            body: json!({ "quota_bytes": value }),
            notice: "Quota updated".to_string(),
            description: "update this storage quota",
        }));
    };

    let confirm_reauth = Callback::new({
        let username = username.clone();
        move |_: ()| {
            let Some(action) = pending.get_untracked() else {
                return;
            };
            if matches!(action, PendingAction::Recover) && recover_name.get_untracked() != username
            {
                error.set("Type the username exactly to confirm recovery".to_string());
                return;
            }
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
                let result: Result<Value, String> = async {
                    let token = api::reauth(&password, &code).await?;
                    let extra = ("x-reauth-token", token.as_str());
                    let url = format!("/api/users/{}", encode(&name));
                    match &action {
                        PendingAction::Recover => {
                            let response = api::send_json_with(
                                "POST",
                                &format!("{url}/recover"),
                                &json!({}),
                                Some(extra),
                            )
                            .await?;
                            if response.status != 200 {
                                return Err(response
                                    .error()
                                    .unwrap_or("The action failed")
                                    .to_string());
                            }
                            Ok(response.body)
                        }
                        PendingAction::Logout => {
                            let response = api::send_json_with(
                                "POST",
                                &format!("{url}/logout"),
                                &json!({}),
                                Some(extra),
                            )
                            .await?;
                            if response.status != 200 {
                                return Err(response
                                    .error()
                                    .unwrap_or("The action failed")
                                    .to_string());
                            }
                            Ok(response.body)
                        }
                        PendingAction::Patch { body, .. } => {
                            let response =
                                api::send_json_with("PATCH", &url, body, Some(extra)).await?;
                            if response.status != 200 {
                                return Err(response
                                    .error()
                                    .unwrap_or("Could not update the user")
                                    .to_string());
                            }
                            Ok(response.body)
                        }
                        PendingAction::Delete => {
                            let response = api::delete_with(&url, Some(extra)).await?;
                            if response.status != 204 {
                                return Err(response
                                    .error()
                                    .unwrap_or("Could not delete the user")
                                    .to_string());
                            }
                            Ok(Value::Null)
                        }
                    }
                }
                .await;
                match result {
                    Ok(body) => {
                        match &action {
                            PendingAction::Recover => {
                                generated.set(body["password"].as_str().map(str::to_string));
                                notice.set(
                                    "Password reset. Share the new password securely.".to_string(),
                                );
                            }
                            PendingAction::Logout => {
                                let sessions =
                                    body["sessions_revoked"].as_u64().unwrap_or(0) as usize;
                                notice.set(format!(
                                    "{} signed out.",
                                    plural(sessions, "session", "sessions")
                                ));
                            }
                            PendingAction::Patch {
                                notice: message, ..
                            } => {
                                notice.set(message.clone());
                            }
                            PendingAction::Delete => {
                                on_changed.run(());
                                on_close.run(());
                            }
                        }
                        if !matches!(action, PendingAction::Delete) {
                            load.run(());
                            on_changed.run(());
                        }
                        pending.set(None);
                    }
                    Err(message) => error.set(message),
                }
                reauth_password.set(String::new());
                reauth_code.set(String::new());
                busy.set(false);
            });
        }
    });

    let is_self = {
        let username = username.clone();
        Callback::new(move |_: ()| current_username.get() == username)
    };
    let delete_expected = username.clone();
    let delete_click_user = username.clone();
    let recover_expected = username.clone();

    view! {
        <Modal title=format!("User — {username}") on_close=on_close drawer=true>
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
                    <span class="name">"Display name"</span>
                    <span class="muted">
                        {move || {
                            detail.get()["display_name"]
                                .as_str()
                                .unwrap_or("—")
                                .to_string()
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Email"</span>
                    <span class="muted">
                        {move || {
                            detail.get()["email"].as_str().unwrap_or("—").to_string()
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Password rotation"</span>
                    <span class="badge">
                        {move || {
                            if detail.get()["must_change_password"].as_bool() == Some(true) {
                                "change required".to_string()
                            } else {
                                "normal".to_string()
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
                                "{} · TOTP {} · password {}",
                                plural(passkeys.max(0) as usize, "passkey", "passkeys"),
                                if totp { "on" } else { "off" },
                                if password { "on" } else { "off" },
                            )
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Sessions"</span>
                    <span class="muted">
                        {move || {
                            let sessions =
                                detail.get()["session_count"].as_i64().unwrap_or(0).max(0)
                                    as usize;
                            plural(sessions, "session", "sessions")
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Groups"</span>
                    <span class="muted">
                        {move || {
                            detail
                                .get()["groups"]
                                .as_array()
                                .map(|list| {
                                    list.iter()
                                        .filter_map(Value::as_str)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .filter(|text| !text.is_empty())
                                .unwrap_or_else(|| "none".to_string())
                        }}
                    </span>
                </li>
                <li class="row">
                    <span class="name">"Shares"</span>
                    <span class="muted">
                        {move || {
                            let value = detail.get();
                            let owned =
                                value["owned_shares"].as_i64().unwrap_or(0).max(0) as usize;
                            let received =
                                value["received_shares"].as_i64().unwrap_or(0).max(0) as usize;
                            format!(
                                "{} / {}",
                                plural(owned, "owned", "owned"),
                                plural(received, "received", "received"),
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
                            pending.set(Some(PendingAction::Patch {
                                body: json!({ "admin": !admin }),
                                notice: "Role updated".to_string(),
                                description: "grant or revoke administrator rights",
                            }));
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
                            pending.set(Some(PendingAction::Patch {
                                body: json!({ "disabled": !disabled }),
                                notice: "Access updated".to_string(),
                                description: "change this account's access",
                            }));
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
                            recover_name.set(String::new());
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
                        let description = match &action {
                            PendingAction::Recover => "reset this password",
                            PendingAction::Logout => "sign this user out everywhere",
                            PendingAction::Patch { description, .. } => *description,
                            PendingAction::Delete => "delete this account",
                        };
                        let requires_username = matches!(action, PendingAction::Recover);
                        let expected = recover_expected.clone();
                        view! {
                            <div class="reauth">
                                <h3>"Confirm admin action"</h3>
                                <p class="muted">
                                    {format!(
                                        "Confirm your admin password or a two-factor code to {description}.",
                                    )}
                                </p>
                                {requires_username
                                    .then(|| {
                                        view! {
                                            <label>
                                                "Username"
                                                <input
                                                    type="text"
                                                    autocomplete="off"
                                                    prop:value=move || recover_name.get()
                                                    on:input=move |ev| {
                                                        recover_name.set(event_target_value(&ev))
                                                    }
                                                />
                                            </label>
                                        }
                                    })}
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
                                        disabled=move || {
                                            busy.get()
                                                || (requires_username
                                                    && recover_name.get() != expected)
                                        }
                                    >
                                        {move || if busy.get() { "Confirming…" } else { "Confirm" }}
                                    </button>
                                    <button
                                        class="ghost"
                                        on:click=move |_| {
                                            pending.set(None);
                                            reauth_password.set(String::new());
                                            reauth_code.set(String::new());
                                            recover_name.set(String::new());
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
                        on:click={
                            let expected = delete_click_user.clone();
                            move |_| {
                                if delete_name.get_untracked() != expected {
                                    error.set(
                                        "Type the username exactly to confirm deletion".to_string(),
                                    );
                                    return;
                                }
                                pending.set(Some(PendingAction::Delete));
                            }
                        }
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

fn actor_label(entry: &Value) -> String {
    entry["actor"]
        .as_str()
        .map(str::to_string)
        .or_else(|| entry["actor_id"].as_i64().map(|id| format!("user #{id}")))
        .unwrap_or_else(|| "system".to_string())
}

fn detail_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "—".to_string(),
        other => other.to_string(),
    }
}

fn detail_rows(details: &Value) -> Vec<(String, String)> {
    match details.as_object() {
        Some(map) if !map.is_empty() => map
            .iter()
            .map(|(key, value)| (key.clone(), detail_text(value)))
            .collect(),
        _ => Vec::new(),
    }
}

fn time_until(ms: i64) -> String {
    let seconds = ((ms - js_sys::Date::now() as i64) / 1000).max(0);
    match seconds {
        0 => "expired".to_string(),
        s if s < 3600 => format!("in {}m", (s / 60).max(1)),
        s if s < 86_400 => format!("in {}h", s / 3600),
        s => format!("in {}d", s / 86_400),
    }
}

fn absolute_url(path: &str) -> String {
    let origin = web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .unwrap_or_default();
    format!("{origin}{path}")
}

/// Invites tab: one-time onboarding links.
#[component]
fn InvitesPanel() -> impl IntoView {
    let invites = RwSignal::new(Vec::<Value>::new());
    let loading = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let create_open = RwSignal::new(false);
    let created_link = RwSignal::new(Option::<String>::None);
    let created_user = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let load = Callback::new(move |_: ()| {
        loading.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::get("/api/invites").await {
                Ok(response) if response.status == 200 => {
                    invites.set(
                        response.body["invites"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load invites")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            loading.set(false);
        });
    });
    Effect::new(move |_| load.run(()));

    let close_create = Callback::new(move |_: ()| create_open.set(false));
    let created = Callback::new(move |(url, username): (String, String)| {
        created_link.set(Some(url));
        created_user.set(username);
        load.run(());
    });

    let revoke = Callback::new(move |id: i64| {
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::delete(&format!("/api/invites/{id}")).await {
                Ok(response) if response.status == 204 => {
                    notice.set("Invite revoked.".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not revoke the invite")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    view! {
        <div class="section-head">
            <h2>"Invites"</h2>
            <button class="primary" on:click=move |_| create_open.set(true)>
                <Icon name="link"/>
                "Create invite"
            </button>
        </div>
        <p class="muted">
            "Invite links create an account when accepted. They are single-use, expire, and the token is shown only once."
        </p>
        <ErrorText message=error/>
        <Notice message=notice/>

        <Show when=move || created_link.get().is_some()>
            <div class="created">
                <p class="muted">
                    {move || {
                        format!(
                            "Invite link for {}. Shown once — share it securely.",
                            created_user.get(),
                        )
                    }}
                </p>
                <code>
                    {move || {
                        created_link
                            .get()
                            .map(|path| absolute_url(&path))
                            .unwrap_or_default()
                    }}
                </code>
                <div class="row-actions">
                    <button on:click=move |_| {
                        let link = created_link
                            .get_untracked()
                            .map(|path| absolute_url(&path))
                            .unwrap_or_default();
                        spawn_local(async move {
                            api::copy_to_clipboard(&link).await;
                        });
                    }>"Copy link"</button>
                    <button
                        class="ghost"
                        on:click=move |_| {
                            created_link.set(None);
                            created_user.set(String::new());
                        }
                    >
                        "Dismiss"
                    </button>
                </div>
            </div>
        </Show>

        <p class="muted">
            {move || format!("{} pending", plural(invites.get().len(), "invite", "invites"))}
        </p>
        <ul class="shares">
            <For
                each=move || invites.get()
                key=|invite| invite["id"].as_i64().unwrap_or(0)
                children=move |invite| {
                    let id = invite["id"].as_i64().unwrap_or(0);
                    let username = invite["username"].as_str().unwrap_or_default().to_string();
                    let display = invite["display_name"].as_str().unwrap_or_default().to_string();
                    let email = invite["email"].as_str().unwrap_or_default().to_string();
                    let expired = invite["expired"].as_bool().unwrap_or(false);
                    let expires_at = invite["expires_at"].as_i64().unwrap_or(0);
                    let soon = !expired
                        && expires_at.saturating_sub(js_sys::Date::now() as i64)
                            < 60 * 60 * 1000;
                    let profile = [display, email]
                        .into_iter()
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    view! {
                        <li class="row">
                            <span class="name">
                                <span class="lead-icon">
                                    <Icon name="link"/>
                                </span>
                                <span class="file-body">
                                    <span class="file-name">
                                        {username}
                                        {if expired {
                                            view! { <span class="badge danger">"expired"</span> }
                                                .into_any()
                                        } else if soon {
                                            view! { <span class="badge warn">"expires soon"</span> }
                                                .into_any()
                                        } else {
                                            view! { <span class="badge ok">"active"</span> }
                                                .into_any()
                                        }}
                                    </span>
                                    <span class="file-meta">
                                        {if profile.is_empty() {
                                            "no profile fields".to_string()
                                        } else {
                                            profile
                                        }}
                                    </span>
                                    <span class="file-meta">
                                        {format!("expires {}", time_until(expires_at))}
                                    </span>
                                </span>
                            </span>
                            <span class="row-actions">
                                <button
                                    class="danger"
                                    on:click=move |_| revoke.run(id)
                                    disabled=move || busy.get()
                                >
                                    "Revoke"
                                </button>
                            </span>
                        </li>
                    }
                }
            />
            <Show when=move || !loading.get() && invites.get().is_empty()>
                <li class="row muted">"No pending invites."</li>
            </Show>
        </ul>

        {move || {
            create_open
                .get()
                .then(|| {
                    view! {
                        <CreateInviteDialog
                            on_close=close_create
                            on_created=created
                        />
                    }
                })
        }}
    }
}

/// Create-invite modal.
#[component]
fn CreateInviteDialog(
    on_close: Callback<()>,
    on_created: Callback<(String, String)>,
) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let display_name = RwSignal::new(String::new());
    let email = RwSignal::new(String::new());
    let expires = RwSignal::new("604800".to_string());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    let submit = move |_| {
        let user = username.get_untracked().trim().to_string();
        if user.is_empty() {
            error.set("Username is required".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            let body = json!({
                "username": user,
                "display_name": display_name.get_untracked(),
                "email": email.get_untracked(),
                "expires_in_secs": expires
                    .get_untracked()
                    .parse::<i64>()
                    .unwrap_or(604_800),
            });
            match api::send_json("POST", "/api/invites", &body).await {
                Ok(response) if response.status == 201 => {
                    let url = response.body["url"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let username = response.body["username"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    on_created.run((url, username));
                    on_close.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not create the invite")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    view! {
        <Modal title="Create invite" on_close=on_close>
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
                "Display name"
                <input
                    type="text"
                    autocomplete="off"
                    prop:value=move || display_name.get()
                    on:input=move |ev| display_name.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Email"
                <input
                    type="email"
                    autocomplete="off"
                    prop:value=move || email.get()
                    on:input=move |ev| email.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Expires in"
                <select
                    prop:value=move || expires.get()
                    on:change=move |ev| expires.set(event_target_value(&ev))
                >
                    <option value="3600">"1 hour"</option>
                    <option value="86400">"1 day"</option>
                    <option value="604800">"7 days"</option>
                    <option value="2592000">"30 days"</option>
                </select>
            </label>
            <p class="muted">
                "The link is shown once after creation. The account does not exist until the link is accepted."
            </p>
            <ErrorText message=error/>
            <div class="row-actions">
                <button class="primary" on:click=submit disabled=move || busy.get()>
                    {move || if busy.get() { "Creating…" } else { "Create invite" }}
                </button>
                <button class="ghost" on:click=move |_| on_close.run(())>
                    "Cancel"
                </button>
            </div>
        </Modal>
    }
}

/// Groups tab: rosters, membership, and group lifecycle.
#[component]
fn GroupsPanel() -> impl IntoView {
    let groups = RwSignal::new(Vec::<Value>::new());
    let loading = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let create_open = RwSignal::new(false);
    let selected = RwSignal::new(Option::<String>::None);

    let load = Callback::new(move |_: ()| {
        loading.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::get("/api/groups").await {
                Ok(response) if response.status == 200 => {
                    groups.set(
                        response.body["groups"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load groups")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            loading.set(false);
        });
    });
    Effect::new(move |_| load.run(()));

    let close_create = Callback::new(move |_: ()| create_open.set(false));
    let created = Callback::new(move |_: ()| {
        notice.set("Group created.".to_string());
        load.run(());
    });
    let close_detail = Callback::new(move |_: ()| selected.set(None));
    let changed = Callback::new(move |_: ()| load.run(()));

    view! {
        <div class="section-head">
            <h2>"Groups"</h2>
            <button class="primary" on:click=move |_| create_open.set(true)>
                <Icon name="users"/>
                "Create group"
            </button>
        </div>
        <p class="muted">
            "Groups target shares to several accounts. Membership changes do not rotate MLS keys, so re-share affected encrypted folders after editing members."
        </p>
        <ErrorText message=error/>
        <Notice message=notice/>
        <p class="muted">
            {move || plural(groups.get().len(), "group", "groups")}
        </p>

        <ul class="shares">
            <For
                each=move || groups.get()
                key=|group| group["id"].as_i64().unwrap_or(0)
                children=move |group| {
                    let name = group["name"].as_str().unwrap_or_default().to_string();
                    let members = group["members"].as_array().cloned().unwrap_or_default();
                    let count = members.len();
                    let member_chips = members
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|member| {
                            view! { <span class="chip">{member.to_string()}</span> }
                        })
                        .collect_view();
                    let manage = name.clone();
                    view! {
                        <li class="row">
                            <span class="name">
                                <span class="lead-icon">
                                    <Icon name="users"/>
                                </span>
                                <span class="file-body">
                                    <span class="file-name">
                                        {name}
                                        <span class="badge">
                                            {plural(count, "member", "members")}
                                        </span>
                                    </span>
                                    <span class="file-meta">
                                        {if count == 0 {
                                            view! { <span class="muted">"no members"</span> }
                                                .into_any()
                                        } else {
                                            view! { <span class="chips">{member_chips}</span> }
                                                .into_any()
                                        }}
                                    </span>
                                </span>
                            </span>
                            <span class="row-actions">
                                <button on:click=move |_| selected.set(Some(manage.clone()))>
                                    "Manage"
                                </button>
                            </span>
                        </li>
                    }
                }
            />
            <Show when=move || !loading.get() && groups.get().is_empty()>
                <li class="row muted">"No groups yet."</li>
            </Show>
        </ul>

        {move || {
            create_open
                .get()
                .then(|| {
                    view! {
                        <CreateGroupDialog on_close=close_create on_created=created/>
                    }
                })
        }}
        {move || {
            selected
                .get()
                .map(|name| {
                    view! {
                        <GroupDetailDialog
                            name=name
                            on_close=close_detail
                            on_changed=changed
                        />
                    }
                })
        }}
    }
}

/// Create-group modal.
#[component]
fn CreateGroupDialog(on_close: Callback<()>, on_created: Callback<()>) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    let submit = move |_| {
        let value = name.get_untracked().trim().to_string();
        if value.is_empty() {
            error.set("Group name is required".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::send_json("POST", "/api/groups", &json!({ "name": value })).await {
                Ok(response) if response.status == 201 => {
                    on_created.run(());
                    on_close.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not create the group")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    view! {
        <Modal title="Create group" on_close=on_close>
            <label>
                "Name"
                <input
                    type="text"
                    autocomplete="off"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
            </label>
            <ErrorText message=error/>
            <div class="row-actions">
                <button class="primary" on:click=submit disabled=move || busy.get()>
                    {move || if busy.get() { "Creating…" } else { "Create group" }}
                </button>
                <button class="ghost" on:click=move |_| on_close.run(())>
                    "Cancel"
                </button>
            </div>
        </Modal>
    }
}

/// Group detail: add/remove members and delete the group.
#[component]
fn GroupDetailDialog(
    name: String,
    on_close: Callback<()>,
    on_changed: Callback<()>,
) -> impl IntoView {
    let members = RwSignal::new(Vec::<String>::new());
    let new_member = RwSignal::new(String::new());
    let delete_name = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());

    let load_name = name.clone();
    let load = Callback::new(move |_: ()| {
        let group = load_name.clone();
        spawn_local(async move {
            match api::get(&format!("/api/groups/{}/members", encode(&group))).await {
                Ok(response) if response.status == 200 => {
                    members.set(
                        response.body["members"]
                            .as_array()
                            .map(|list| {
                                list.iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    );
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load the group")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
        });
    });
    Effect::new(move |_| load.run(()));

    let add_name = name.clone();
    let add_member = Callback::new(move |_: ()| {
        let member = new_member.get_untracked().trim().to_string();
        if member.is_empty() {
            error.set("Enter a username to add".to_string());
            return;
        }
        let group = add_name.clone();
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            let url = format!("/api/groups/{}/members/{}", encode(&group), encode(&member));
            match api::send_json("POST", &url, &json!({})).await {
                Ok(response) if response.status == 204 => {
                    new_member.set(String::new());
                    notice.set(format!("Added {member}."));
                    load.run(());
                    on_changed.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not add the member")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let remove_name = name.clone();
    let remove_member = Callback::new(move |member: String| {
        let group = remove_name.clone();
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            let url = format!("/api/groups/{}/members/{}", encode(&group), encode(&member));
            match api::delete(&url).await {
                Ok(response) if response.status == 204 => {
                    notice.set(format!("Removed {member}."));
                    load.run(());
                    on_changed.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not remove the member")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    });

    let delete_group = Callback::new({
        let group = name.clone();
        move |_: ()| {
            if delete_name.get_untracked() != group {
                error.set("Type the group name exactly to confirm deletion".to_string());
                return;
            }
            let group = group.clone();
            busy.set(true);
            error.set(String::new());
            spawn_local(async move {
                match api::delete(&format!("/api/groups/{}", encode(&group))).await {
                    Ok(response) if response.status == 204 => {
                        on_changed.run(());
                        on_close.run(());
                    }
                    Ok(response) => error.set(
                        response
                            .error()
                            .unwrap_or("Could not delete the group")
                            .to_string(),
                    ),
                    Err(message) => error.set(message),
                }
                busy.set(false);
            });
        }
    });
    let delete_expected = name.clone();

    view! {
        <Modal title=format!("Group — {name}") on_close=on_close>
            <ErrorText message=error/>
            <Notice message=notice/>
            <p class="muted">
                "Changing membership does not rotate MLS keys. Re-share affected encrypted folders so added members receive the current key and removed members stop receiving future epochs."
            </p>

            <h3>"Members"</h3>
            <ul class="shares">
                <For
                    each=move || members.get()
                    key=|member| member.clone()
                    children=move |member| {
                        let remove = member.clone();
                        view! {
                            <li class="row">
                                <span class="name">{member}</span>
                                <span class="row-actions">
                                    <button
                                        on:click=move |_| remove_member.run(remove.clone())
                                        disabled=move || busy.get()
                                    >
                                        "Remove"
                                    </button>
                                </span>
                            </li>
                        }
                    }
                />
                <Show when=move || members.get().is_empty()>
                    <li class="row muted">"No members."</li>
                </Show>
            </ul>

            <div class="share-form">
                <label>
                    "Add member"
                    <input
                        type="text"
                        autocomplete="off"
                        placeholder="username"
                        prop:value=move || new_member.get()
                        on:input=move |ev| new_member.set(event_target_value(&ev))
                    />
                </label>
                <button
                    on:click=move |_| add_member.run(())
                    disabled=move || busy.get()
                >
                    "Add"
                </button>
            </div>

            <h3>"Delete group"</h3>
            <p class="muted">
                "This removes the group, its memberships, and every group share. Type the group name to confirm."
            </p>
            <div class="share-form">
                <label>
                    "Group name"
                    <input
                        type="text"
                        autocomplete="off"
                        placeholder=name.clone()
                        prop:value=move || delete_name.get()
                        on:input=move |ev| delete_name.set(event_target_value(&ev))
                    />
                </label>
                <button
                    class="danger"
                    on:click=move |_| delete_group.run(())
                    disabled={
                        let expected = delete_expected.clone();
                        move || busy.get() || delete_name.get() != expected
                    }
                >
                    "Delete group"
                </button>
            </div>
        </Modal>
    }
}

/// Audit tab: newest-first entries, filters, and chain verification.
#[component]
fn AuditPanel() -> impl IntoView {
    let entries = RwSignal::new(Vec::<Value>::new());
    let action = RwSignal::new(String::new());
    let subject = RwSignal::new(String::new());
    let before = RwSignal::new(Option::<i64>::None);
    let has_more = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let verifying = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());

    let load = Callback::new(move |reset: bool| {
        let action_value = action.get_untracked();
        let subject_value = subject.get_untracked();
        let after = if reset { None } else { before.get_untracked() };
        loading.set(true);
        error.set(String::new());
        spawn_local(async move {
            let mut url = "/api/audit?limit=100".to_string();
            if let Some(after) = after {
                url.push_str(&format!("&before={after}"));
            }
            let action_value = action_value.trim();
            if !action_value.is_empty() {
                url.push_str(&format!("&action={}", encode(action_value)));
            }
            let subject_value = subject_value.trim();
            if !subject_value.is_empty() {
                url.push_str(&format!("&subject={}", encode(subject_value)));
            }
            match api::get(&url).await {
                Ok(response) if response.status == 200 => {
                    let fresh = response.body["entries"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default();
                    if reset {
                        entries.set(fresh);
                    } else {
                        entries.update(|current| current.extend(fresh));
                    }
                    before.set(response.body["next_before"].as_i64());
                    has_more.set(response.body["has_more"].as_bool().unwrap_or(false));
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not load the audit log")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            loading.set(false);
        });
    });
    Effect::new(move |_| load.run(true));

    let verify = Callback::new(move |_: ()| {
        verifying.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            match api::get("/api/audit/verify").await {
                Ok(response) if response.status == 200 => {
                    let entries = response.body["entries"].as_u64().unwrap_or(0);
                    if response.body["ok"].as_bool() == Some(true) {
                        notice.set(format!("Audit chain verified ({entries} entries)."));
                    } else {
                        error.set(format!(
                            "Audit chain is broken at entry {} ({} entries checked).",
                            response.body["first_bad"]
                                .as_i64()
                                .map(|id| id.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            entries
                        ));
                    }
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not verify the audit chain")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            verifying.set(false);
        });
    });

    view! {
        <div class="section-head">
            <h2>"Audit"</h2>
            <button on:click=move |_| verify.run(()) disabled=move || verifying.get()>
                <Icon name="history"/>
                {move || if verifying.get() { "Verifying…" } else { "Verify chain" }}
            </button>
        </div>
        <p class="muted">
            "Newest-first hash-chained events. Filters match the action name or subject exactly."
        </p>
        <ErrorText message=error/>
        <Notice message=notice/>

        <div class="row-actions">
            <form
                class="row-actions"
                on:submit=move |ev| {
                    ev.prevent_default();
                    load.run(true);
                }
            >
                <label>
                    "Action"
                    <input
                        type="text"
                        autocomplete="off"
                        placeholder="e.g. group.add"
                        prop:value=move || action.get()
                        on:input=move |ev| action.set(event_target_value(&ev))
                    />
                </label>
                <label>
                    "Subject"
                    <input
                        type="text"
                        autocomplete="off"
                        placeholder="username or group"
                        prop:value=move || subject.get()
                        on:input=move |ev| subject.set(event_target_value(&ev))
                    />
                </label>
                <button class="primary" type="submit" disabled=move || loading.get()>
                    "Apply"
                </button>
                <button
                    type="button"
                    on:click=move |_| {
                        action.set(String::new());
                        subject.set(String::new());
                        load.run(true);
                    }
                >
                    "Clear"
                </button>
                <button
                    type="button"
                    on:click=move |_| load.run(true)
                    disabled=move || loading.get()
                >
                    <Icon name="refresh"/>
                    "Refresh"
                </button>
            </form>
        </div>

        <p class="muted">{move || plural(entries.get().len(), "entry", "entries")}</p>

        <div class="table-wrap">
            <table class="data-table audit-table">
                <thead>
                    <tr>
                        <th scope="col">"Time"</th>
                        <th scope="col">"Action"</th>
                        <th scope="col">"Actor"</th>
                        <th scope="col">"Subject"</th>
                        <th scope="col">"Details"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || entries.get()
                        key=|entry| entry["id"].as_i64().unwrap_or(0)
                        children=move |entry| {
                            let rows = detail_rows(&entry["details"]);
                            let has_details = !rows.is_empty();
                            let rows = rows
                                .into_iter()
                                .map(|(key, value)| {
                                    view! {
                                        <dt>{key}</dt>
                                        <dd>{value}</dd>
                                    }
                                })
                                .collect_view();
                            let action = entry["action"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            let subject = entry["subject"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            view! {
                                <tr>
                                    <td class="nowrap">
                                        {relative_time(entry["ts"].as_i64().unwrap_or(0))}
                                    </td>
                                    <td>
                                        <span class="badge">{action}</span>
                                    </td>
                                    <td>
                                        <span class="badge muted">{actor_label(&entry)}</span>
                                    </td>
                                    <td class="mono-cell">{subject}</td>
                                    <td>
                                        <details class="audit-details">
                                            <summary>"View"</summary>
                                            {if has_details {
                                                view! { <dl>{rows}</dl> }.into_any()
                                            } else {
                                                view! {
                                                    <p class="muted">"No details recorded."</p>
                                                }
                                                    .into_any()
                                            }}
                                        </details>
                                    </td>
                                </tr>
                            }
                        }
                    />
                    <Show when=move || !loading.get() && entries.get().is_empty()>
                        <tr>
                            <td colspan="5" class="muted">
                                "No audit entries match these filters."
                            </td>
                        </tr>
                    </Show>
                </tbody>
            </table>
        </div>

        <Show when=move || has_more.get()>
            <div class="row-actions">
                <button on:click=move |_| load.run(false) disabled=move || loading.get()>
                    "Load more"
                </button>
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::{detail_rows, parse_quota};
    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn audit_details_become_key_value_rows() {
        let rows = detail_rows(&json!({ "by": "api", "count": 2 }));
        assert_eq!(
            rows,
            [
                ("by".to_string(), "api".to_string()),
                ("count".to_string(), "2".to_string())
            ]
        );
        assert!(detail_rows(&json!({})).is_empty());
        assert!(detail_rows(&json!("text")).is_empty());
    }

    #[wasm_bindgen_test]
    fn quota_inputs_use_binary_units() {
        assert_eq!(parse_quota("default").unwrap(), None);
        assert_eq!(parse_quota("unlimited").unwrap(), Some(0));
        assert_eq!(parse_quota("10GB").unwrap(), Some(10 * (1 << 30)));
        assert_eq!(parse_quota("512MiB").unwrap(), Some(512 * (1 << 20)));
        assert!(parse_quota("ten").is_err());
    }
}
