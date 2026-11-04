//! Small reusable view components.
//!
//! These are presentational: they own no network state and only render the
//! props and signals passed by the dialogs in `app.rs`.

use base64::{Engine, engine::general_purpose::STANDARD};
use leptos::prelude::*;

use crate::app::relative_time;
use crate::mls::MlsDevice;

/// A single inline SVG icon.
#[component]
pub fn Icon(name: &'static str) -> impl IntoView {
    view! { <span class="icon" inner_html=icon_svg(name)></span> }
}

/// Inline SVG path data for the icon set.
fn icon_svg(name: &str) -> String {
    let body = match name {
        "folder" => {
            r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>"#
        }
        "file" => {
            r#"<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>"#
        }
        "image" => {
            r#"<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.6"/><path d="m5 18 4.5-4.5L13 17l3-2.5L21 18"/>"#
        }
        "trash" => {
            r#"<path d="M4 7h16"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><path d="M7 7l1 13a2 2 0 0 0 2 2h4a2 2 0 0 0 2-2l1-13"/>"#
        }
        "search" => r#"<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>"#,
        "menu" => r#"<path d="M4 7h16M4 12h16M4 17h16"/>"#,
        "upload" => r#"<path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 20h16"/>"#,
        "folder-plus" => {
            r#"<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 10v6M9 13h6"/>"#
        }
        "share" => {
            r#"<circle cx="6" cy="12" r="2.4"/><circle cx="18" cy="6" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="m8.2 10.8 7.6-3.6M8.2 13.2l7.6 3.6"/>"#
        }
        "edit" => r#"<path d="M4 20h4l10-10-4-4L4 16z"/><path d="m14 6 4 4"/>"#,
        "download" => r#"<path d="M12 4v12"/><path d="m7 11 5 5 5-5"/><path d="M4 20h16"/>"#,
        "users" => {
            r#"<circle cx="9" cy="8" r="3.2"/><path d="M3.5 20a5.5 5.5 0 0 1 11 0"/><path d="M16 5.5a3 3 0 0 1 0 5.8"/><path d="M17 20a5.5 5.5 0 0 0-3-4.9"/>"#
        }
        "key" => r#"<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-3 3"/>"#,
        "settings" => {
            r#"<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.09a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.09a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>"#
        }
        "sun" => {
            r#"<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4"/>"#
        }
        "logout" => {
            r#"<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3"/><path d="m10 17-5-5 5-5"/><path d="M5 12h12"/>"#
        }
        "dots" => {
            r#"<circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/>"#
        }
        "grid" => {
            r#"<rect x="4" y="4" width="7" height="7" rx="1.5"/><rect x="13" y="4" width="7" height="7" rx="1.5"/><rect x="4" y="13" width="7" height="7" rx="1.5"/><rect x="13" y="13" width="7" height="7" rx="1.5"/>"#
        }
        "list" => {
            r#"<path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4.5" cy="6" r="1.3"/><circle cx="4.5" cy="12" r="1.3"/><circle cx="4.5" cy="18" r="1.3"/>"#
        }
        "x" => r#"<path d="M6 6l12 12M18 6 6 18"/>"#,
        "cloud" => r#"<path d="M6 18a4 4 0 0 1 0-8 5 5 0 0 1 9.6-1.5A3.5 3.5 0 0 1 18 18z"/>"#,
        "lock" => {
            r#"<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>"#
        }
        "refresh" => r#"<path d="M20 11a8 8 0 1 0-2.3 6.3"/><path d="M20 5v6h-6"/>"#,
        "history" => {
            r#"<path d="M4 5v5h5"/><path d="M4.5 10a8 8 0 1 1-.6 5"/><path d="M12 8v4l3 2"/>"#
        }
        "link" => {
            r#"<path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/>"#
        }
        _ => r#"<circle cx="12" cy="12" r="8"/>"#,
    };
    format!(
        r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{body}</svg>"#
    )
}

/// A modal card with a title, close button and scrollable body.
#[component]
pub fn Modal(
    #[prop(into)] title: String,
    on_close: Callback<()>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>{title}</h2>
                    <button class="icon-btn" aria-label="Close" on:click=move |_| on_close.run(())>
                        <Icon name="x"/>
                    </button>
                </div>
                {children()}
            </div>
        </div>
    }
}

/// A success/status message that renders only when it has text.
#[component]
pub fn Notice(#[prop(into)] message: Signal<String>) -> impl IntoView {
    view! {
        <Show when=move || !message.get().is_empty()>
            <p class="notice">{move || message.get()}</p>
        </Show>
    }
}

/// An error message that renders only when it has text.
#[component]
pub fn ErrorText(#[prop(into)] message: Signal<String>) -> impl IntoView {
    view! {
        <Show when=move || !message.get().is_empty()>
            <p class="error">{move || message.get()}</p>
        </Show>
    }
}

/// A centered empty state with an optional primary action.
#[component]
pub fn EmptyState(
    icon: &'static str,
    title: &'static str,
    hint: &'static str,
    #[prop(optional)] action_label: Option<&'static str>,
    #[prop(optional)] on_action: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        <div class="empty">
            <Icon name=icon/>
            <p>{title}</p>
            <small class="muted">{hint}</small>
            {on_action
                .map(|on_action| {
                    view! {
                        <button class="primary" on:click=move |_| on_action.run(())>
                            {action_label.unwrap_or("Continue")}
                        </button>
                    }
                })}
        </div>
    }
}

/// Sanitizes SVG content to prevent XSS via `inner_html`.
pub(crate) fn sanitize_svg(svg: &str) -> String {
    svg.replace("<script", "<!-script")
        .replace("</script>", "<-/script>")
        .replace("onload=", "data-onload=")
        .replace("onerror=", "data-onerror=")
        .replace("onclick=", "data-onclick=")
}

fn device_display_name(device: &MlsDevice) -> String {
    if device.device_name.is_empty() {
        "Unnamed MLS device".to_string()
    } else {
        device.device_name.clone()
    }
}

fn device_signature_label(device: &MlsDevice) -> String {
    device
        .signature_key
        .as_deref()
        .map(|key| STANDARD.encode(key))
        .unwrap_or_else(|| "not reported yet".to_string())
}

fn device_groups_label(device: &MlsDevice) -> String {
    if device.groups.is_empty() {
        "none visible".to_string()
    } else {
        device.groups.join(", ")
    }
}

/// The MLS device roster, including loading, empty and warning states.
#[component]
pub fn MlsDevicesPanel(
    #[prop(into)] devices: Signal<Vec<MlsDevice>>,
    #[prop(into)] warnings: Signal<Vec<String>>,
    #[prop(into)] error: Signal<String>,
    #[prop(into)] loading: Signal<bool>,
    #[prop(into)] busy: Signal<bool>,
    on_revoke: Callback<String>,
) -> impl IntoView {
    let empty = move || !loading.get() && devices.get().is_empty() && error.get().is_empty();
    view! {
        <h3>"MLS devices"</h3>
        <p class="muted">
            "Devices enrolled for encrypted group shares. Revoking removes the device's MLS leaf from every share this browser can open and rotates those keyrings. Files and keys it already downloaded stay readable to it; only future epochs are protected."
        </p>
        <Show when=move || loading.get()>
            <p class="muted">"Loading MLS devices…"</p>
        </Show>
        <ErrorText message=error/>
        <Show when=move || !warnings.get().is_empty()>
            <p class="muted">
                "Some groups cannot be inspected from this browser: "
                {move || warnings.get().join("; ")}
            </p>
        </Show>
        <Show when=empty>
            <p class="muted">"No MLS devices enrolled yet."</p>
        </Show>
        <ul class="shares">
            <For
                each=move || devices.get()
                key=|device| device.device_id.clone()
                children=move |device| {
                    let id = device.device_id.clone();
                    let button_id = id.clone();
                    let name = device_display_name(&device);
                    let current = device.current;
                    let last_seen = relative_time(device.last_seen_at);
                    let signature = device_signature_label(&device);
                    let groups = device_groups_label(&device);
                    view! {
                        <li class="file mls-device">
                            <span class="file-body">
                                <span class="file-name">
                                    {name}
                                    {current
                                        .then(|| view! { <span class="badge">"this device"</span> })}
                                </span>
                                <span class="file-meta">
                                    <span class="muted">"id " {id.clone()}</span>
                                    <span class="muted">"last seen " {last_seen}</span>
                                </span>
                                <span class="file-meta">
                                    <span class="muted">"signature key " {signature}</span>
                                </span>
                                <span class="file-meta">
                                    <span class="muted">"groups " {groups}</span>
                                </span>
                            </span>
                            <span class="file-actions">
                                <Show when=move || !current>
                                    {
                                        let button_id = button_id.clone();
                                        view! {
                                            <button
                                                class="icon-btn"
                                                title="Revoke MLS device"
                                                disabled=move || busy.get()
                                                on:click=move |_| {
                                                    on_revoke.run(button_id.clone())
                                                }
                                            >
                                                <Icon name="trash"/>
                                            </button>
                                        }
                                    }
                                </Show>
                            </span>
                        </li>
                    }
                }
            />
        </ul>
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn device(name: &str, current: bool) -> MlsDevice {
        MlsDevice {
            device_id: "device-1".to_string(),
            device_name: name.to_string(),
            signature_key: Some(vec![1, 2, 3]),
            last_seen_at: 0,
            groups: Vec::new(),
            current,
        }
    }

    #[wasm_bindgen_test]
    fn device_labels_fall_back_for_missing_fields() {
        let mut device = device("", false);
        device.groups.clear();
        device.signature_key = None;
        assert_eq!(device_display_name(&device), "Unnamed MLS device");
        assert_eq!(device_signature_label(&device), "not reported yet");
        assert_eq!(device_groups_label(&device), "none visible");
    }

    #[wasm_bindgen_test]
    fn sanitize_svg_strips_scripts() {
        let out = sanitize_svg("<svg><script>alert(1)</script><rect onload='x'/></svg>");
        assert!(!out.contains("<script"));
        assert!(!out.contains("</script>"));
        // onload= is rewritten to data-onload= so it is inert.
        assert!(out.contains("data-onload="));
    }

    #[wasm_bindgen_test]
    fn device_labels_use_reported_values() {
        let device = device("Laptop", true);
        assert_eq!(device_display_name(&device), "Laptop");
        assert_eq!(device_signature_label(&device), "AQID");
        assert_eq!(device_groups_label(&device), "none visible");
    }
}
