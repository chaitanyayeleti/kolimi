use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Starts and finishes the browser's own device enrollment.
#[component]
pub(crate) fn EnrollmentPanel(
    master: RwSignal<Option<MasterKey>>,
    notice: RwSignal<String>,
    error: RwSignal<String>,
) -> impl IntoView {
    let device_name = RwSignal::new(String::new());
    let enrolling = RwSignal::new(Option::<(i64, [u8; 32], String)>::None);
    // An in-progress enrollment survives a reload: the pending id + device
    // secret live in sessionStorage until the enrollment finishes.
    const PENDING_KEY: &str = "kolimi.enrollment.pending";
    fn store_pending(id: i64, secret: &[u8; 32], code: &str) {
        if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
            let value = serde_json::json!({
                "id": id,
                "secret": URL_SAFE_NO_PAD.encode(secret),
                "code": code,
            })
            .to_string();
            let _ = storage.set_item(PENDING_KEY, &value);
        }
    }
    fn clear_pending() {
        if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
            let _ = storage.remove_item(PENDING_KEY);
        }
    }
    Effect::new(move |_| {
        if enrolling.get_untracked().is_some() {
            return;
        }
        let restored: Option<(i64, [u8; 32], String)> = web_sys::window()
            .and_then(|w| w.session_storage().ok().flatten())
            .and_then(|storage| storage.get_item(PENDING_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
            .and_then(|value| {
                let id = value["id"].as_i64()?;
                let secret = URL_SAFE_NO_PAD
                    .decode(value["secret"].as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?;
                let code = value["code"].as_str()?.to_string();
                Some((id, secret, code))
            });
        if let Some(pending) = restored {
            enrolling.set(Some(pending));
            notice.set(
                "Resumed your pending enrollment — approve it on another device, then unlock."
                    .to_string(),
            );
        }
    });

    let start_enroll = move |_| {
        let name = device_name.get_untracked().trim().to_string();
        if name.is_empty() {
            error.set("Enter a name for this device".to_string());
            return;
        }
        spawn_local(async move {
            match crate::e2ee::start_enrollment(&name).await {
                Ok((id, secret, code)) => {
                    error.set(String::new());
                    notice.set(format!(
                        "Compare code {code} on the approving device, then approve it there."
                    ));
                    store_pending(id, &secret, &code);
                    enrolling.set(Some((id, secret, code)));
                }
                Err(e) => error.set(e),
            }
        });
    };

    let finish_enroll = move |_| {
        let Some((id, secret, _)) = enrolling.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match crate::e2ee::poll_enrollment(id, &secret).await {
                Ok(Some(key)) => {
                    crate::e2ee::remember_master(&key);
                    master.set(Some(key));
                    enrolling.set(None);
                    clear_pending();
                    notice.set("This browser is now enrolled".to_string());
                }
                Ok(None) => notice
                    .set("Not approved yet — approve it on another device, then retry".to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    view! {
            <h3>"Add this browser as a device"</h3>
            <p class="muted">
                "Name this browser, start the enrollment, then approve it on another unlocked device — "
                "no passphrase retyping needed."
            </p>
            <label>
                "Device name"
                <input
                    type="text"
                    autocomplete="off"
                    prop:value=move || device_name.get()
                    on:input=move |ev| device_name.set(event_target_value(&ev))
                />
            </label>
            <div class="row-actions">
                <button on:click=start_enroll>"Start enrollment"</button>
                <Show when=move || enrolling.get().is_some()>
                    <button class="primary" on:click=finish_enroll>"Unlock now"</button>
                </Show>
            </div>
            <Show when=move || enrolling.get().is_some()>
                {move || {
                    enrolling
                        .get()
                        .map(|(id, _, code)| {
                            view! {
                                <div class="enroll-qr">
                                    <p class="muted">
                                        "Waiting for approval on another device — then press “Unlock now”."
                                    </p>
                                    <details>
                                        <summary class="muted">"Approval code (advanced)"</summary>
                                        <div
                                            class="qr"
                                            inner_html=crate::e2ee::qr_svg(
                                                &format!("kolimi-enroll:{id}:{code}"),
                                            )
                                        ></div>
                                        <p class="muted">"Enrollment " {id}</p>
                                        <p class="muted">"Code " {code}</p>
                                    </details>
                                </div>
                            }
                        })
                }}
            </Show>
    }
}
