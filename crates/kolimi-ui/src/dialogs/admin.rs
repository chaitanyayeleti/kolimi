use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::encode;
use crate::components::Icon;

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
pub(crate) fn AdminDialog(on_close: Callback<()>) -> impl IntoView {
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
