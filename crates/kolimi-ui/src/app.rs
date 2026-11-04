//! The authenticated application: login, file browser, shares, trash.

use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::json;

use crate::api;
use crate::browser::Browser;
use crate::components::Icon;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum View {
    Loading,
    Login,
    Browser,
}

pub fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|segment| utf8_percent_encode(segment, NON_ALPHANUMERIC).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn human_size(bytes: u64) -> String {
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

/// The Kolimi brand mark: a gradient tile with a cloud. Matches the app/tray
/// icons (`assets/branding/logo.svg`).
fn logo_svg() -> String {
    r##"<svg viewBox="0 0 32 32" width="100%" height="100%" aria-hidden="true">
<defs><linearGradient id="kolimi-bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#5b8def"/><stop offset="0.55" stop-color="#6f7bf0"/><stop offset="1" stop-color="#9b5cf6"/>
</linearGradient>
<linearGradient id="kolimi-cloud" x1="0" y1="0" x2="0" y2="1">
<stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#eaf0ff"/>
</linearGradient></defs>
<rect x="0" y="0" width="32" height="32" rx="8.5" fill="url(#kolimi-bg)"/>
<rect x="0.5" y="0.5" width="31" height="31" rx="8" fill="none" stroke="#ffffff" stroke-opacity="0.18"/>
<g fill="url(#kolimi-cloud)">
<circle cx="12.6" cy="18.4" r="3.7"/><circle cx="17.1" cy="15.5" r="5.1"/>
<circle cx="21.6" cy="18.6" r="3.4"/><rect x="12.6" y="17.4" width="9.4" height="4.6" rx="2.3"/>
</g></svg>"##
        .to_string()
}

/// The brand mark, sized for a header badge.
#[component]
pub(crate) fn Logo() -> impl IntoView {
    view! { <span class="logo" inner_html=logo_svg()></span> }
}

/// Flips the `.dark` / `.light` class on `<html>` and persists the choice.
pub(crate) fn toggle_theme() {
    let Some(root) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.document_element())
    else {
        return;
    };
    let classes = root.class_list();
    let prefers_dark = web_sys::window()
        .and_then(|window| {
            window
                .match_media("(prefers-color-scheme: dark)")
                .ok()
                .flatten()
        })
        .map(|media| media.matches())
        .unwrap_or(false);
    let is_dark = classes.contains("dark") || (!classes.contains("light") && prefers_dark);
    let _ = classes.remove_1("dark");
    let _ = classes.remove_1("light");
    let _ = classes.add_1(if is_dark { "light" } else { "dark" });
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item("kolimi-theme", if is_dark { "light" } else { "dark" });
    }
}

/// Marks that the session expired, so the login screen can explain why.
pub(crate) fn mark_session_expired() {
    if let Some(storage) =
        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
    {
        let _ = storage.set_item("kolimi-session-expired", "1");
    }
}

/// Formats a Unix-millisecond timestamp as a short relative time.
pub(crate) fn relative_time(ms: i64) -> String {
    if ms <= 0 {
        return String::new();
    }
    let seconds = ((js_sys::Date::now() as i64 - ms) / 1000).max(0);
    match seconds {
        s if s < 45 => "just now".to_string(),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3600),
        s if s < 2_592_000 => format!("{}d ago", s / 86_400),
        s if s < 31_536_000 => format!("{}mo ago", s / 2_592_000),
        s => format!("{}y ago", s / 31_536_000),
    }
}

/// Root component.
#[component]
pub fn App() -> impl IntoView {
    let view = RwSignal::new(View::Loading);
    Effect::new(move |_| {
        spawn_local(async move {
            let signed_in = matches!(api::get("/api/me").await, Ok(r) if r.status == 200);
            view.set(if signed_in {
                View::Browser
            } else {
                View::Login
            });
        });
    });

    view! {
        {move || match view.get() {
            View::Loading => view! {
                <div class="login-wrap">
                    <span class="muted">"Loading…"</span>
                </div>
            }
                .into_any(),
            View::Login => view! { <Login view=view/> }.into_any(),
            View::Browser => view! { <Browser view=view/> }.into_any(),
        }}
    }
}

#[component]
fn Login(view: RwSignal<View>) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let code = RwSignal::new(String::new());
    let needs_code = RwSignal::new(false);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    // If we were sent here because a session expired, say so once.
    Effect::new(move |_| {
        if let Some(storage) =
            web_sys::window().and_then(|window| window.session_storage().ok().flatten())
            && storage
                .get_item("kolimi-session-expired")
                .ok()
                .flatten()
                .is_some()
        {
            let _ = storage.remove_item("kolimi-session-expired");
            notice.set("Your session expired — please sign in again.".to_string());
        }
    });

    let submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let (user, pass) = (username.get_untracked(), password.get_untracked());
        if user.is_empty() || pass.is_empty() {
            error.set("Enter username and password".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let payload = if needs_code.get_untracked() {
                json!({ "username": user, "password": pass, "code": code.get_untracked() })
            } else {
                json!({ "username": user, "password": pass })
            };
            let result = api::send_json("POST", "/api/session", &payload).await;
            busy.set(false);
            match result {
                Ok(r) if r.status == 200 => view.set(View::Browser),
                Ok(r) if r.body["totp_required"].as_bool() == Some(true) => {
                    needs_code.set(true);
                    error.set("Enter your two-factor code".to_string());
                }
                Ok(r) if r.status == 401 => {
                    error.set("Incorrect username or password.".to_string())
                }
                Ok(r) if r.status == 429 => {
                    error.set("Too many attempts — wait a minute, then try again.".to_string())
                }
                Ok(r) if r.status == 403 => {
                    error.set("Sign-in was blocked. Please try again.".to_string())
                }
                Ok(r) => error.set(
                    r.error()
                        .unwrap_or("Sign-in failed. Please try again.")
                        .to_string(),
                ),
                Err(_) => {
                    error.set("Couldn't reach the server. Check your connection.".to_string())
                }
            }
        });
    };

    let passkey_login = move |_| {
        let user = username.get_untracked();
        if user.is_empty() {
            error.set("Enter your username, then use the passkey button".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            let result = crate::passkey::login(&user).await;
            busy.set(false);
            match result {
                Ok(()) => view.set(View::Browser),
                Err(e) => error.set(e),
            }
        });
    };

    view! {
        <div class="login-wrap">
        <button
            class="icon-btn login-theme"
            aria-label="Toggle theme"
            on:click=move |_| toggle_theme()
        >
            <Icon name="sun"/>
        </button>
        <form class="card login" on:submit=submit>
            <div class="hero">
                <Logo/>
                <h2>"Sign in to Kolimi"</h2>
                <p class="muted">"Your self-hosted cloud."</p>
            </div>
            <Show when=move || !notice.get().is_empty()>
                <p class="muted">{move || notice.get()}</p>
            </Show>
            <label>
                "Username"
                <input
                    type="text"
                    autocomplete="username"
                    prop:value=move || username.get()
                    on:input=move |ev| username.set(event_target_value(&ev))
                />
            </label>
            <label>
                "Password"
                <input
                    type="password"
                    autocomplete="current-password"
                    prop:value=move || password.get()
                    on:input=move |ev| password.set(event_target_value(&ev))
                />
            </label>
            <p class="muted">
                "This is your account password. Your encryption passphrase is separate — you only need it inside the app, to unlock encrypted files."
            </p>
            <Show when=move || needs_code.get()>
                <label>
                    "Two-factor or recovery code"
                    <input
                        type="text"
                        autocomplete="one-time-code"
                        placeholder="6-digit code or recovery code"
                        prop:value=move || code.get()
                        on:input=move |ev| code.set(event_target_value(&ev))
                    />
                </label>
            </Show>
            <button class="primary" type="submit" disabled=move || busy.get()>
                {move || if busy.get() { "Signing in…" } else { "Sign in" }}
            </button>
            <div class="divider">"or"</div>
            <button class="ghost" type="button" disabled=move || busy.get() on:click=passkey_login>
                <Icon name="key"/>
                "Sign in with a passkey"
            </button>
            <Show when=move || !error.get().is_empty()>
                <p class="error">{move || error.get()}</p>
            </Show>
        </form>
        </div>
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn human_size_formats_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[wasm_bindgen_test]
    fn encode_path_escapes_each_segment() {
        assert_eq!(encode_path("a/b c"), "a/b%20c");
        // The unreserved set is not exempted, so '.' is escaped too.
        assert_eq!(encode_path("a.txt"), "a%2Etxt");
        assert_eq!(encode_path(""), "");
    }
}
