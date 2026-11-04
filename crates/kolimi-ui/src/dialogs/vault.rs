use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::components::Icon;

#[component]
pub(crate) fn VaultSetupDialog(
    on_close: Callback<()>,
    on_done: Callback<MasterKey>,
) -> impl IntoView {
    let pass = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let phrase = RwSignal::new(Option::<String>::None);
    let unlocked = RwSignal::new(Option::<MasterKey>::None);
    let busy = RwSignal::new(false);
    let error = RwSignal::new(String::new());

    let create = move |_| {
        let passphrase = pass.get_untracked();
        if passphrase.trim().is_empty() {
            error.set("Choose a passphrase".to_string());
            return;
        }
        if passphrase != confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::setup(&passphrase).await {
                Ok(words) => match crate::e2ee::unlock(&passphrase).await {
                    Ok(master) => {
                        busy.set(false);
                        // Show the phrase first: closing here would skip the
                        // only chance to save the recovery words.
                        unlocked.set(Some(master));
                        phrase.set(Some(words));
                    }
                    Err(e) => {
                        busy.set(false);
                        error.set(e);
                    }
                },
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let close = move |_| on_close.run(());

    view! {
        <div class="backdrop">
            <div class="card modal">
                <div class="modal-head">
                    <h2>"Set up your Vault"</h2>
                    <button class="icon-btn" aria-label="Close" on:click=close>
                        <Icon name="x"/>
                    </button>
                </div>
                <Show when=move || phrase.get().is_none()>
                    <p class="muted">
                        "Your Vault is encrypted on this device. We can never read it — and if you lose both the passphrase and the recovery phrase, the files inside are gone for good."
                    </p>
                    <p class="muted">
                        "This is separate from your login password."
                    </p>
                    <label>
                        "Passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || pass.get()
                            on:input=move |ev| pass.set(event_target_value(&ev))
                        />
                    </label>
                    <label>
                        "Repeat passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || confirm.get()
                            on:input=move |ev| confirm.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="row-actions">
                        <button class="primary" disabled=move || busy.get() on:click=create>
                            <Icon name="lock"/>
                            {move || if busy.get() { "Creating…" } else { "Create Vault" }}
                        </button>
                        <button class="ghost" on:click=close>"Later"</button>
                    </div>
                </Show>
                <Show when=move || phrase.get().is_some()>
                    <p class="notice">
                        "Write down these 24 words. They are the only other way to open your Vault."
                    </p>
                    <code class="recovery">{move || phrase.get().unwrap_or_default()}</code>
                    <div class="row-actions">
                        <button
                            on:click=move |_| {
                                let words = phrase.get_untracked().unwrap_or_default();
                                spawn_local(async move { crate::api::copy_to_clipboard(&words).await });
                            }
                        >"Copy"</button>
                        <button
                            class="primary"
                            on:click=move |_| {
                                if let Some(master) = unlocked.get_untracked() {
                                    // Keep the unlocked key so the first
                                    // upload works immediately.
                                    on_done.run(master);
                                } else {
                                    on_close.run(());
                                }
                            }
                        >"I saved it"</button>
                    </div>
                </Show>
                <p class="error">{move || error.get()}</p>
            </div>
        </div>
    }
}
