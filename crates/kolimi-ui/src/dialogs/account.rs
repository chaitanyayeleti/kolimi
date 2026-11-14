use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::relative_time;
use crate::components::{ErrorText, Icon, Notice};

/// A readable label for a session's raw `User-Agent`.
fn device_label(user_agent: &str) -> String {
    let agent = user_agent.trim();
    if agent.is_empty() {
        return "Unknown device".to_string();
    }
    let browser = if agent.contains("Kolimi") {
        "Kolimi desktop"
    } else if agent.contains("Firefox") {
        "Firefox"
    } else if agent.contains("Edg/") {
        "Edge"
    } else if agent.contains("Chrome") {
        "Chrome"
    } else if agent.contains("Safari") {
        "Safari"
    } else if agent.contains("WebKitGTK") {
        "WebKit"
    } else {
        "Browser"
    };
    let os = if agent.contains("Android") {
        "Android"
    } else if agent.contains("iPhone") || agent.contains("iPad") {
        "iOS"
    } else if agent.contains("Windows") {
        "Windows"
    } else if agent.contains("Mac OS X") {
        "macOS"
    } else if agent.contains("Linux") {
        "Linux"
    } else {
        ""
    };
    if os.is_empty() {
        browser.to_string()
    } else {
        format!("{browser} on {os}")
    }
}

/// Account summary, password change, and active sessions.
#[component]
pub(crate) fn AccountPanel() -> impl IntoView {
    let me = RwSignal::new(Value::Null);
    let sessions = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let sessions_busy = RwSignal::new(false);
    let current_password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let new_password = RwSignal::new(String::new());
    let confirm_password = RwSignal::new(String::new());
    let display_name = RwSignal::new(String::new());
    let email = RwSignal::new(String::new());
    let profile_busy = RwSignal::new(false);

    let load = Callback::new(move |_: ()| {
        spawn_local(async move {
            if let Ok(response) = api::get("/api/me").await
                && response.status == 200
            {
                display_name.set(
                    response.body["display_name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                email.set(
                    response.body["email"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                me.set(response.body);
            }
            match api::get("/api/me/sessions").await {
                Ok(response) if response.status == 200 => {
                    sessions.set(
                        response.body["sessions"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
                Ok(response) => {
                    error.set(
                        response
                            .error()
                            .unwrap_or("Could not load sessions")
                            .to_string(),
                    );
                }
                Err(message) => error.set(message),
            }
        });
    });
    Effect::new(move |_| load.run(()));

    let change_password = move |_| {
        let new = new_password.get_untracked();
        if new.chars().count() < 8 {
            error.set("Use at least 8 characters for the new password".to_string());
            return;
        }
        if new != confirm_password.get_untracked() {
            error.set("The new password and confirmation do not match".to_string());
            return;
        }
        let password_value = current_password.get_untracked();
        let code_value = code.get_untracked();
        if password_value.is_empty() && code_value.is_empty() {
            error.set("Confirm your account password or a two-factor code".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let result = async {
                let token = api::reauth(&password_value, &code_value).await?;
                let response = api::send_json_with(
                    "POST",
                    "/api/me/password",
                    &json!({ "new_password": new }),
                    Some(("x-reauth-token", token.as_str())),
                )
                .await?;
                if response.status == 204 {
                    Ok(())
                } else {
                    Err(response
                        .error()
                        .unwrap_or("Could not change the password")
                        .to_string())
                }
            }
            .await;
            match result {
                Ok(()) => {
                    current_password.set(String::new());
                    code.set(String::new());
                    new_password.set(String::new());
                    confirm_password.set(String::new());
                    notice.set("Password changed. Other sessions were signed out.".to_string());
                    load.run(());
                }
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    let save_profile = move |_| {
        profile_busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let body = json!({
                "display_name": display_name.get_untracked(),
                "email": email.get_untracked(),
            });
            match api::send_json("PATCH", "/api/me", &body).await {
                Ok(response) if response.status == 200 => {
                    notice.set("Profile updated.".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not update the profile")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            profile_busy.set(false);
        });
    };

    let revoke = Callback::new(move |id: i64| {
        sessions_busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::delete(&format!("/api/me/sessions/{id}")).await {
                Ok(response) if response.status == 204 => {
                    notice.set("Session revoked.".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not revoke the session")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            sessions_busy.set(false);
        });
    });

    let revoke_others = move |_| {
        sessions_busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::delete("/api/me/sessions?keep_current=true").await {
                Ok(response) if response.status == 204 => {
                    notice.set("Other sessions were signed out.".to_string());
                    load.run(());
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not sign out other sessions")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            sessions_busy.set(false);
        });
    };

    let revoke_all = move |_| {
        if !api::confirm("Sign out of all devices, including this one?") {
            return;
        }
        sessions_busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::delete("/api/me/sessions").await {
                Ok(response) if response.status == 204 => {
                    if let Some(window) = web_sys::window() {
                        let _ = window.location().assign("/logout");
                    }
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not sign out all sessions")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            sessions_busy.set(false);
        });
    };

    view! {
        <h3>"Account"</h3>
        <p class="muted">
            "Your login account is separate from your encryption passphrase."
        </p>

        <ul class="shares">
            <li class="row">
                <span class="name">"Username"</span>
                <span>{move || me.get()["username"].as_str().unwrap_or("—").to_string()}</span>
            </li>
            <li class="row">
                <span class="name">"Role"</span>
                <span class="badge">
                    {move || {
                        if me.get()["is_admin"].as_bool() == Some(true) {
                            "administrator".to_string()
                        } else {
                            "member".to_string()
                        }
                    }}
                </span>
            </li>
            <li class="row">
                <span class="name">"Member since"</span>
                <span class="muted">
                    {move || relative_time(me.get()["created_at"].as_i64().unwrap_or(0))}
                </span>
            </li>
        </ul>

        <h3>"Profile"</h3>
        <p class="muted">
            "Optional. Email is informational only — Kolimi does not send mail or use it to sign in."
        </p>
        <div class="share-form">
            <label>
                "Display name"
                <input
                    type="text"
                    autocomplete="name"
                    prop:value=move || display_name.get()
                    on:input=move |ev| display_name.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Email"
                <input
                    type="email"
                    autocomplete="email"
                    prop:value=move || email.get()
                    on:input=move |ev| email.set(event_target_value(&ev))
                />
            </label>
            <button on:click=save_profile disabled=move || profile_busy.get()>
                {move || if profile_busy.get() { "Saving…" } else { "Save profile" }}
            </button>
        </div>

        <Show when=move || me.get()["password_login"].as_bool() == Some(false)>
            <p class="muted">
                "This account is passkey-only. Manage sign-in credentials in the Passkeys tab."
            </p>
        </Show>

        <Show when=move || me.get()["password_login"].as_bool() == Some(true)>
            <div class="reauth">
                <h3>"Change password"</h3>
                <p class="muted">
                    "Confirm your current password or a two-factor code. Other sessions will be signed out."
                </p>
                <label>
                    "Current password"
                    <input
                        type="password"
                        autocomplete="current-password"
                        prop:value=move || current_password.get()
                        on:input=move |ev| current_password.set(event_target_value(&ev))
                    />
                </label>
                <label>
                    "Two-factor / recovery code"
                    <input
                        type="text"
                        autocomplete="one-time-code"
                        prop:value=move || code.get()
                        on:input=move |ev| code.set(event_target_value(&ev))
                    />
                </label>
                <label>
                    "New password"
                    <input
                        type="password"
                        autocomplete="new-password"
                        prop:value=move || new_password.get()
                        on:input=move |ev| new_password.set(event_target_value(&ev))
                    />
                </label>
                <label>
                    "Confirm new password"
                    <input
                        type="password"
                        autocomplete="new-password"
                        prop:value=move || confirm_password.get()
                        on:input=move |ev| confirm_password.set(event_target_value(&ev))
                    />
                </label>
                <div class="row-actions">
                    <button
                        class="primary"
                        disabled=move || busy.get()
                        on:click=change_password
                    >
                        {move || if busy.get() { "Changing…" } else { "Change password" }}
                    </button>
                </div>
            </div>
        </Show>

        <h3>"Active sessions"</h3>
        <p class="muted">
            "Sessions that can access this account. Revoke anything you do not recognize."
        </p>
        <ul class="shares">
            <For
                each=move || sessions.get()
                key=|session| session["id"].as_i64().unwrap_or(0)
                children=move |session| {
                    let id = session["id"].as_i64().unwrap_or(0);
                    let current = session["current"].as_bool().unwrap_or(false);
                    let ip = session["ip"].as_str().unwrap_or("unknown address");
                    let agent = session["user_agent"].as_str().unwrap_or_default();
                    let last_seen = session["last_seen_at"].as_i64().unwrap_or(0);
                    let created = session["created_at"].as_i64().unwrap_or(0);
                    view! {
                        <li class="row">
                            <span class="name">
                                <span class="lead-icon">
                                    <Icon name="device"/>
                                </span>
                                <span class="file-body">
                                    <span class="file-name">
                                        {device_label(agent)}
                                        {current
                                            .then(|| view! { <span class="badge">"this device"</span> })}
                                    </span>
                                    <span class="file-meta">
                                        {format!("{ip} · last used {}", relative_time(last_seen))}
                                    </span>
                                    <span class="file-meta">
                                        {format!("started {}", relative_time(created))}
                                    </span>
                                </span>
                            </span>
                            <span class="row-actions">
                                {(!current)
                                    .then(|| {
                                        view! {
                                            <button
                                                class="danger"
                                                disabled=move || sessions_busy.get()
                                                on:click=move |_| revoke.run(id)
                                            >
                                                "Revoke"
                                            </button>
                                        }
                                    })}
                            </span>
                        </li>
                    }
                }
            />
            <Show when=move || sessions.get().is_empty()>
                <li class="row muted">"No active sessions."</li>
            </Show>
        </ul>
        <div class="row-actions">
            <button
                disabled=move || sessions_busy.get()
                on:click=revoke_others
            >
                "Sign out other devices"
            </button>
            <button
                class="danger"
                disabled=move || sessions_busy.get()
                on:click=revoke_all
            >
                "Sign out everywhere"
            </button>
        </div>

        <ErrorText message=error/>
        <Notice message=notice/>
    }
}
