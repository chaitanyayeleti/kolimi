use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{plural, relative_time};
use crate::components::{ErrorText, Icon, sanitize_svg};

/// A credential change waiting for re-authentication.
#[derive(Clone)]
enum PendingAction {
    Add(String),
    Remove(i64),
    AddAppPassword(String),
    RemoveAppPassword(i64),
}

/// Applies a pending change with a fresh re-authentication token. Returns the
/// new app-password token when one was created.
async fn apply_action(action: PendingAction, token: &str) -> Result<Option<String>, String> {
    match action {
        PendingAction::Add(name) => crate::passkey::register(&name, token).await.map(|()| None),
        PendingAction::Remove(id) => match api::delete_with(
            &format!("/api/passkeys/{id}"),
            Some(("x-reauth-token", token)),
        )
        .await
        {
            Ok(response) if response.status == 204 => Ok(None),
            Ok(response) => Err(response
                .error()
                .unwrap_or("Could not remove passkey")
                .to_string()),
            Err(error) => Err(error),
        },
        PendingAction::AddAppPassword(name) => {
            match api::send_json_with(
                "POST",
                "/api/me/app-passwords",
                &json!({ "name": name }),
                Some(("x-reauth-token", token)),
            )
            .await
            {
                Ok(response) if response.status == 201 => {
                    Ok(response.body["token"].as_str().map(str::to_string))
                }
                Ok(response) => Err(response
                    .error()
                    .unwrap_or("Could not create app password")
                    .to_string()),
                Err(error) => Err(error),
            }
        }
        PendingAction::RemoveAppPassword(id) => {
            match api::delete_with(
                &format!("/api/me/app-passwords/{id}"),
                Some(("x-reauth-token", token)),
            )
            .await
            {
                Ok(response) if response.status == 204 => Ok(None),
                Ok(response) => Err(response
                    .error()
                    .unwrap_or("Could not revoke app password")
                    .to_string()),
                Err(error) => Err(error),
            }
        }
    }
}

/// Passkeys and TOTP, rendered as a Settings section.
#[component]
pub(crate) fn PasskeysPanel() -> impl IntoView {
    let passkeys = RwSignal::new(Vec::<Value>::new());
    let error = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let totp = RwSignal::new(Value::Null);
    let enroll = RwSignal::new(Option::<Value>::None);
    let totp_code = RwSignal::new(String::new());
    let recovery = RwSignal::new(Vec::<String>::new());
    let pending = RwSignal::new(Option::<PendingAction>::None);
    let reauth_password = RwSignal::new(String::new());
    let reauth_code = RwSignal::new(String::new());
    let app_passwords = RwSignal::new(Vec::<Value>::new());
    let new_app_name = RwSignal::new(String::new());
    let new_app_password = RwSignal::new(Option::<String>::None);

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
            if let Ok(r) = api::get("/api/me/app-passwords").await
                && r.status == 200
            {
                app_passwords.set(
                    r.body["app_passwords"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default(),
                );
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
        error.set(String::new());
        pending.set(Some(PendingAction::Add(name)));
    };

    let remove = move |id: i64| {
        error.set(String::new());
        pending.set(Some(PendingAction::Remove(id)));
    };

    let add_app_password = move |_| {
        let name = new_app_name.get_untracked().trim().to_string();
        if name.is_empty() {
            error.set("Name this app password (e.g. \"Laptop sync\")".to_string());
            return;
        }
        error.set(String::new());
        pending.set(Some(PendingAction::AddAppPassword(name)));
    };

    let remove_app_password = move |id: i64| {
        error.set(String::new());
        pending.set(Some(PendingAction::RemoveAppPassword(id)));
    };

    let confirm = move |_| {
        let Some(action) = pending.get_untracked() else {
            return;
        };
        let password = reauth_password.get_untracked();
        let code = reauth_code.get_untracked();
        if password.is_empty() && code.is_empty() {
            error.set("Enter your account password or a two-factor code".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let result = match api::reauth(&password, &code).await {
                Ok(token) => apply_action(action, &token).await,
                Err(message) => Err(message),
            };
            match result {
                Ok(token) => {
                    error.set(String::new());
                    if token.is_some() {
                        new_app_password.set(token);
                        new_app_name.set(String::new());
                    }
                    load.run(());
                }
                Err(message) => error.set(message),
            }
            reauth_password.set(String::new());
            reauth_code.set(String::new());
            pending.set(None);
            busy.set(false);
        });
    };

    let use_passkey = move |_| {
        let Some(action) = pending.get_untracked() else {
            return;
        };
        busy.set(true);
        spawn_local(async move {
            let result = match crate::passkey::reauth().await {
                Ok(token) => apply_action(action, &token).await,
                Err(message) => Err(message),
            };
            match result {
                Ok(token) => {
                    error.set(String::new());
                    if token.is_some() {
                        new_app_password.set(token);
                        new_app_name.set(String::new());
                    }
                    load.run(());
                }
                Err(message) => error.set(message),
            }
            reauth_password.set(String::new());
            reauth_code.set(String::new());
            pending.set(None);
            busy.set(false);
        });
    };

    let cancel = move |_| {
        reauth_password.set(String::new());
        reauth_code.set(String::new());
        pending.set(None);
        error.set(String::new());
    };

    view! {
        <h3>"Passkeys"</h3>
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
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="key"/>
                                        </span>
                                        {name}
                                    </span>
                                    <span class="row-actions">
                                        <button
                                            class="danger"
                                            disabled=move || busy.get() || pending.get().is_some()
                                            on:click=move |_| remove(id)
                                        >
                                            <Icon name="trash"/>
                                            "Remove"
                                        </button>
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
                    <button
                        class="primary"
                        disabled=move || busy.get() || pending.get().is_some()
                        on:click=add
                    >
                        <Icon name="key"/>
                        {move || if busy.get() { "Waiting for authenticator…" } else { "Add passkey" }}
                    </button>
                </div>

                <h3>"App passwords"</h3>
                <p class="muted">
                    "Long-lived passwords for desktop sync, WebDAV/CalDAV, and other clients that cannot complete an interactive sign-in. Revoke a device here if it is lost."
                </p>
                <Show when=move || new_app_password.get().is_some()>
                    <div class="created">
                        <strong>"Copy this app password now — it is shown once:"</strong>
                        <code>{move || new_app_password.get().unwrap_or_default()}</code>
                        <div class="row-actions">
                            <button
                                class="ghost"
                                on:click=move |_| new_app_password.set(None)
                            >
                                "I saved it"
                            </button>
                        </div>
                    </div>
                </Show>
                <ul class="shares">
                    <For
                        each=move || app_passwords.get()
                        key=|password| password["id"].as_i64().unwrap_or(0)
                        children=move |password| {
                            let id = password["id"].as_i64().unwrap_or(0);
                            let name = password["name"].as_str().unwrap_or_default().to_string();
                            let created = relative_time(
                                password["created_at"].as_i64().unwrap_or(0),
                            );
                            let last_used = password["last_used_at"]
                                .as_i64()
                                .map(relative_time)
                                .unwrap_or_else(|| "never used".to_string());
                            view! {
                                <li class="row">
                                    <span class="name">
                                        <span class="lead-icon">
                                            <Icon name="key"/>
                                        </span>
                                        <span>
                                            <strong>{name}</strong>
                                            <span class="muted">
                                                {format!(" · created {created} · last used {last_used}")}
                                            </span>
                                        </span>
                                    </span>
                                    <span class="row-actions">
                                        <button
                                            class="danger"
                                            disabled=move || busy.get() || pending.get().is_some()
                                            on:click=move |_| remove_app_password(id)
                                        >
                                            <Icon name="trash"/>
                                            "Revoke"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                    <Show when=move || app_passwords.get().is_empty()>
                        <li class="row muted">"No app passwords yet."</li>
                    </Show>
                </ul>
                <div class="share-form">
                    <label>
                        "Name"
                        <input
                            type="text"
                            placeholder="e.g. Laptop sync"
                            prop:value=move || new_app_name.get()
                            on:input=move |ev| new_app_name.set(event_target_value(&ev))
                        />
                    </label>
                    <button
                        disabled=move || busy.get() || pending.get().is_some()
                        on:click=add_app_password
                    >
                        <Icon name="key"/>
                        "Create app password"
                    </button>
                </div>

                {move || {
                    pending
                        .get()
                        .map(|action| {
                            let description = match &action {
                                PendingAction::Add(name) => format!("add “{name}”"),
                                PendingAction::Remove(_) => "remove this passkey".to_string(),
                                PendingAction::AddAppPassword(name) => {
                                    format!("create the app password “{name}”")
                                }
                                PendingAction::RemoveAppPassword(_) => {
                                    "revoke this app password".to_string()
                                }
                            };
                            view! {
                                <div class="reauth">
                                    <p class="muted">
                                        {format!(
                                            "Confirm your account password (or a two-factor code) to {description}.",
                                        )}
                                    </p>
                                    <label>
                                        "Account password"
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
                                            disabled=move || busy.get()
                                            on:click=confirm
                                        >
                                            {move || if busy.get() { "Confirming…" } else { "Confirm" }}
                                        </button>
                                        <button
                                            class="ghost"
                                            disabled=move || busy.get()
                                            on:click=use_passkey
                                        >
                                            <Icon name="key"/>
                                            "Use a passkey instead"
                                        </button>
                                        <button class="ghost" on:click=cancel>"Cancel"</button>
                                    </div>
                                </div>
                            }
                        })
                }}

                <h3>"Two-factor (TOTP)"</h3>
                {move || {
                    if totp.get()["enabled"].as_bool() == Some(true) {
                        let remaining = totp.get()["recovery_codes_remaining"]
                            .as_i64()
                            .unwrap_or(0);
                        view! {
                            <p class="muted">
                                {format!(
                                    "Enabled — {} left.",
                                    plural(remaining.max(0) as usize, "recovery code", "recovery codes")
                                )}
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
                                    <div class="qr" inner_html=sanitize_svg(&svg)></div>
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
        <ErrorText message=error/>
    }
}
