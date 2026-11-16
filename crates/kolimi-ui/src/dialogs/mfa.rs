//! Mandatory first-login MFA enrollment for admin-created and invited users.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};

use crate::api;
use crate::app::{Logo, View, cycle_theme, signed_in_view};
use crate::components::{ErrorText, Icon, Notice, sanitize_svg};

fn sign_out() {
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign("/logout");
    }
}

/// Forces the user to add either TOTP or a passkey before entering the app.
#[component]
pub(crate) fn MfaSetup(view: RwSignal<View>) -> impl IntoView {
    let enroll = RwSignal::new(Option::<Value>::None);
    let code = RwSignal::new(String::new());
    let recovery = RwSignal::new(Vec::<String>::new());
    let passkey_name = RwSignal::new("This device".to_string());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let begin = move |_| {
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            match api::send_json("POST", "/api/totp/begin", &json!({})).await {
                Ok(response) if response.status == 200 => enroll.set(Some(response.body)),
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not start authenticator setup")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    let enable = move |_| {
        let Some(begin) = enroll.get_untracked() else {
            return;
        };
        if code.get_untracked().trim().is_empty() {
            error.set("Enter the code shown in your authenticator app".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        let secret = begin["secret"].clone();
        spawn_local(async move {
            match api::send_json(
                "POST",
                "/api/totp/enable",
                &json!({ "secret": secret, "code": code.get_untracked() }),
            )
            .await
            {
                Ok(response) if response.status == 200 => {
                    enroll.set(None);
                    code.set(String::new());
                    recovery.set(
                        response.body["recovery_codes"]
                            .as_array()
                            .cloned()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_string))
                            .collect(),
                    );
                    notice.set(
                        "Authenticator enabled. Save the recovery codes, then continue."
                            .to_string(),
                    );
                }
                Ok(response) => error.set(
                    response
                        .error()
                        .unwrap_or("Could not enable the authenticator")
                        .to_string(),
                ),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    let add_passkey = move |_| {
        let name = passkey_name.get_untracked().trim().to_string();
        let password_value = password.get_untracked();
        if name.is_empty() {
            error.set("Give this passkey a name".to_string());
            return;
        }
        if password_value.is_empty() {
            error.set("Confirm your account password to add a passkey".to_string());
            return;
        }
        busy.set(true);
        error.set(String::new());
        notice.set(String::new());
        spawn_local(async move {
            let result = async {
                let token = api::reauth(&password_value, "").await?;
                crate::passkey::register(&name, &token).await
            }
            .await;
            match result {
                Ok(()) => view.set(signed_in_view().await),
                Err(message) => error.set(message),
            }
            busy.set(false);
        });
    };

    let continue_to_app = move |_| {
        busy.set(true);
        spawn_local(async move {
            view.set(signed_in_view().await);
            busy.set(false);
        });
    };

    view! {
        <div class="login-wrap">
            <button
                class="icon-btn login-theme"
                aria-label="Switch theme"
                on:click=move |_| {
                    cycle_theme();
                }
            >
                <Icon name="sun"/>
            </button>
            <div class="card login mfa-card">
                <div class="hero">
                    <Logo/>
                    <h2>"Secure your account"</h2>
                    <p class="muted">
                        "Choose an authenticator app or a passkey. This is required before you can use Kolimi."
                    </p>
                </div>

                <section class="mfa-method">
                    <h3>"Authenticator app"</h3>
                    <p class="muted">
                        "Use any TOTP app. You will get one-time recovery codes."
                    </p>
                    <Show when=move || enroll.get().is_none() && recovery.get().is_empty()>
                        <button on:click=begin disabled=move || busy.get()>
                            "Set up authenticator"
                        </button>
                    </Show>
                    {move || {
                        enroll
                            .get()
                            .map(|begin| {
                                let svg = begin["qr_svg"].as_str().unwrap_or_default().to_string();
                                let secret =
                                    begin["secret"].as_str().unwrap_or_default().to_string();
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
                                                autocomplete="one-time-code"
                                                prop:value=move || code.get()
                                                on:input=move |ev| code.set(event_target_value(&ev))
                                            />
                                        </label>
                                        <button on:click=enable disabled=move || busy.get()>
                                            "Confirm and enable"
                                        </button>
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
                            <button
                                class="primary"
                                on:click=continue_to_app
                                disabled=move || busy.get()
                            >
                                "Continue to Kolimi"
                            </button>
                        </div>
                    </Show>
                </section>

                <section class="mfa-method">
                    <h3>"Passkey"</h3>
                    <p class="muted">
                        "Sign in with your device's fingerprint, face, or security key."
                    </p>
                    <label>
                        "Passkey name"
                        <input
                            type="text"
                            autocomplete="off"
                            prop:value=move || passkey_name.get()
                            on:input=move |ev| passkey_name.set(event_target_value(&ev))
                        />
                    </label>
                    <label>
                        "Confirm your account password"
                        <input
                            type="password"
                            autocomplete="current-password"
                            prop:value=move || password.get()
                            on:input=move |ev| password.set(event_target_value(&ev))
                        />
                    </label>
                    <button on:click=add_passkey disabled=move || busy.get()>
                        "Create passkey"
                    </button>
                </section>

                <Notice message=notice/>
                <ErrorText message=error/>

                <div class="form-actions end">
                    <button class="ghost" on:click=move |_| sign_out()>
                        <Icon name="logout"/>
                        "Sign out"
                    </button>
                </div>
            </div>
        </div>
    }
}
