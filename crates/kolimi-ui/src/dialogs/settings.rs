use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::Value;

use super::enrollment::EnrollmentPanel;
use super::passkeys::PasskeysPanel;
use crate::api;
use crate::components::{ErrorText, Icon, MlsDevicesPanel, Modal, Notice};

/// Sections shown inside the Settings dialog.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettingsTab {
    Encryption,
    Sharing,
    Devices,
    Passkeys,
}

/// Unlock end-to-end encryption and manage the account's devices and shares.
#[component]
pub(crate) fn SettingsDialog(
    master: RwSignal<Option<MasterKey>>,
    tab: RwSignal<SettingsTab>,
    on_close: Callback<()>,
) -> impl IntoView {
    let passphrase = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let migrating = RwSignal::new(false);
    let resetting = RwSignal::new(false);
    let enrollments = RwSignal::new(Vec::<Value>::new());
    let devices = RwSignal::new(Vec::<Value>::new());
    let mls_devices = RwSignal::new(Vec::<crate::mls::MlsDevice>::new());
    let mls_warnings = RwSignal::new(Vec::<String>::new());
    let mls_error = RwSignal::new(String::new());
    let mls_loading = RwSignal::new(true);
    let mls_busy = RwSignal::new(false);
    let use_recovery = RwSignal::new(false);
    let has_keyring = RwSignal::new(Option::<bool>::None);
    // `None` with `keyring_error` unset means "still checking" — never show
    // the unlock form for an unknown state, or a new account looks like it
    // already has encryption.
    let keyring_error = RwSignal::new(false);
    let check_keyring = Callback::new(move |_: ()| {
        keyring_error.set(false);
        spawn_local(async move {
            match crate::e2ee::keyring_exists().await {
                Ok(exists) => has_keyring.set(Some(exists)),
                Err(_) => keyring_error.set(true),
            }
        });
    });
    Effect::new(move |_| {
        check_keyring.run(());
    });
    let setup_pass = RwSignal::new(String::new());
    let setup_confirm = RwSignal::new(String::new());
    let change_open = RwSignal::new(false);
    let new_pass = RwSignal::new(String::new());
    let new_confirm = RwSignal::new(String::new());
    let recovery = RwSignal::new(Option::<String>::None);
    let migrate_mls = move |_| {
        let Some(master) = master.get_untracked() else {
            error.set("Unlock encryption first.".to_string());
            return;
        };
        migrating.set(true);
        spawn_local(async move {
            match crate::mls::migrate_shares(&master).await {
                Ok(paths) if paths.is_empty() => {
                    notice.set("No encrypted folder shares needed migration.".to_string())
                }
                Ok(paths) => {
                    notice.set(format!("Upgraded {} folder share(s) to MLS.", paths.len()))
                }
                Err(e) => error.set(e),
            }
            migrating.set(false);
        });
    };
    let reset_mls = move |_| {
        if !api::confirm(
            "Reset this browser's MLS state? Encrypted folder shares will stop opening here until another member re-adds this browser. Your E2EE passphrase, recovery phrase and files are not deleted.",
        ) {
            return;
        }
        resetting.set(true);
        let master = master.get_untracked();
        spawn_local(async move {
            match crate::mls::reset_state(master.as_ref()).await {
                Ok(true) => notice.set(
                    "MLS state cleared. Run a sync or reopen an encrypted share to publish a new key package, then ask an owner to re-share each folder."
                        .to_string(),
                ),
                Ok(false) => notice.set("This browser had no stored MLS state.".to_string()),
                Err(message) => error.set(message),
            }
            resetting.set(false);
        });
    };

    let load_devices = Callback::new(move |_: ()| {
        spawn_local(async move {
            mls_loading.set(true);
            mls_error.set(String::new());
            mls_warnings.set(Vec::new());
            if let Ok(list) = crate::e2ee::pending_enrollments().await {
                enrollments.set(list);
            }
            if let Ok(list) = crate::e2ee::devices().await {
                devices.set(list);
            }
            if crate::mls::enabled()
                && let Some(master) = master.get_untracked()
            {
                match crate::mls::devices(&master).await {
                    Ok(list) => {
                        mls_devices.set(list.devices);
                        mls_warnings.set(list.warnings);
                    }
                    Err(message) => mls_error.set(message),
                }
            }
            mls_loading.set(false);
        });
    });
    Effect::new(move |_| {
        if master.get().is_some() {
            load_devices.run(());
        }
    });

    let unlock = move |_| {
        let secret = passphrase.get_untracked();
        if secret.is_empty() {
            error.set("Enter your passphrase or recovery code".to_string());
            return;
        }
        let recovery = use_recovery.get_untracked();
        busy.set(true);
        spawn_local(async move {
            let result = if recovery {
                crate::e2ee::unlock_recovery(&secret).await
            } else {
                crate::e2ee::unlock(&secret).await
            };
            match result {
                Ok(key) => {
                    crate::e2ee::remember_master(&key);
                    master.set(Some(key));
                    busy.set(false);
                }
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let setup = move |_| {
        let passphrase = setup_pass.get_untracked();
        if passphrase.is_empty() {
            error.set("Enter a passphrase".to_string());
            return;
        }
        if passphrase != setup_confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::setup(&passphrase).await {
                Ok(code) => {
                    match crate::e2ee::unlock(&passphrase).await {
                        Ok(key) => {
                            crate::e2ee::remember_master(&key);
                            master.set(Some(key));
                        }
                        Err(e) => error.set(e),
                    }
                    has_keyring.set(Some(true));
                    recovery.set(Some(code));
                    busy.set(false);
                }
                Err(e) => {
                    busy.set(false);
                    error.set(e);
                }
            }
        });
    };

    let change_pass = move |_| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        let pass = new_pass.get_untracked();
        if pass.is_empty() {
            error.set("Enter a new passphrase".to_string());
            return;
        }
        if pass != new_confirm.get_untracked() {
            error.set("Passphrases do not match".to_string());
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::change_passphrase(&unlocked, &pass).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Passphrase changed — use the new one next time".to_string());
                    change_open.set(false);
                    new_pass.set(String::new());
                    new_confirm.set(String::new());
                }
                Err(e) => error.set(e),
            }
            busy.set(false);
        });
    };

    let migrate_names = move |_| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        if !api::confirm(
            "Encrypt the names of existing items in your encrypted folders? They are renamed on the server; contents are not re-uploaded. Plaintext files are skipped — encrypt those first.",
        ) {
            return;
        }
        busy.set(true);
        spawn_local(async move {
            match crate::e2ee::migrate_names(&unlocked).await {
                Ok(0) => {
                    notice.set("No readable names left to encrypt.".to_string());
                    busy.set(false);
                }
                Ok(count) => {
                    // The old paths are gone; reload so the list rebuilds
                    // from the renamed tree (the unlocked key survives in
                    // sessionStorage).
                    notice.set(format!("Renamed {count} item(s) — reloading…"));
                    if let Some(window) = web_sys::window() {
                        let _ = window.location().reload();
                    }
                }
                Err(e) => {
                    error.set(e);
                    busy.set(false);
                }
            }
        });
    };

    let approve = move |id: i64, key: String, code: Option<String>| {
        let Some(unlocked) = master.get_untracked() else {
            return;
        };
        spawn_local(async move {
            match crate::e2ee::approve_enrollment(id, &key, code.as_deref(), &unlocked).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Device approved".to_string());
                    load_devices.run(());
                }
                Err(e) => error.set(e),
            }
        });
    };

    let revoke = move |id: i64| {
        spawn_local(async move {
            match crate::e2ee::revoke_device(id).await {
                Ok(()) => {
                    error.set(String::new());
                    notice.set("Device revoked".to_string());
                    load_devices.run(());
                }
                Err(e) => error.set(e),
            }
        });
    };

    let revoke_mls = Callback::new(move |device_id: String| {
        let Some(unlocked) = master.get_untracked() else {
            mls_error.set("Unlock encryption first.".to_string());
            return;
        };
        if !api::confirm(
            "Revoke this MLS device? This removes its leaf from every group this browser can write and rotates those share keyrings. A read-only received share must be handled by its owner first. It cannot erase files or keys the device already downloaded — only future epochs are protected.",
        ) {
            return;
        }
        mls_busy.set(true);
        mls_error.set(String::new());
        spawn_local(async move {
            match crate::mls::revoke_device(&unlocked, &device_id).await {
                Ok(report) if report.groups.is_empty() => {
                    notice.set("MLS device removed from the roster".to_string());
                }
                Ok(report) => {
                    notice.set(format!(
                        "Removed {} MLS leaf/leaves from {} share(s): {}",
                        report.leaves,
                        report.groups.len(),
                        report.groups.join(", ")
                    ));
                }
                Err(message) => mls_error.set(message),
            }
            mls_busy.set(false);
            load_devices.run(());
        });
    });

    view! {
        <Modal title="Settings" on_close=on_close>
            <div class="segmented settings-tabs" role="tablist">
                <button
                    role="tab"
                    class:active=move || tab.get() == SettingsTab::Encryption
                    on:click=move |_| tab.set(SettingsTab::Encryption)
                >
                    "Encryption"
                </button>
                <button
                    role="tab"
                    class:active=move || tab.get() == SettingsTab::Sharing
                    on:click=move |_| tab.set(SettingsTab::Sharing)
                >
                    "Sharing"
                </button>
                <button
                    role="tab"
                    class:active=move || tab.get() == SettingsTab::Devices
                    on:click=move |_| tab.set(SettingsTab::Devices)
                >
                    "Devices"
                </button>
                <button
                    role="tab"
                    class:active=move || tab.get() == SettingsTab::Passkeys
                    on:click=move |_| tab.set(SettingsTab::Passkeys)
                >
                    "Passkeys"
                </button>
            </div>

            <Show when=move || tab.get() == SettingsTab::Encryption>
                <div class="settings-section">
            <h3>"Encryption"</h3>
            <p class="muted">
                "Your passphrase is used locally and is never sent to the server."
            </p>
            <Show when=move || recovery.get().is_some()>
                <p class="notice">
                    "Write down these 24 words now — they are shown once and are the only other way to unlock."
                </p>
                <code class="recovery">{move || recovery.get().unwrap_or_default()}</code>
                <div class="row-actions">
                    <button on:click=move |_| {
                        let code = recovery.get_untracked().unwrap_or_default();
                        spawn_local(async move { crate::api::copy_to_clipboard(&code).await });
                    }>"Copy"</button>
                    <button class="primary" on:click=move |_| recovery.set(None)>"I saved it"</button>
                </div>
            </Show>
            <Show when=move || master.get().is_none() && recovery.get().is_none()>
                <Show when=move || has_keyring.get().is_none() && !keyring_error.get()>
                    <p class="muted">"Checking encryption status…"</p>
                </Show>
                <Show when=move || keyring_error.get()>
                    <p class="error">
                        "Couldn't check the encryption status — the server didn't answer. Check your connection and retry."
                    </p>
                    <div class="row-actions">
                        <button class="primary" on:click=move |_| check_keyring.run(())>
                            "Retry"
                        </button>
                    </div>
                </Show>
                <Show when=move || has_keyring.get() == Some(false)>
                    <p class="muted">
                        "Encryption is not set up for this account yet. Choose a passphrase — it never leaves this browser."
                    </p>
                    <label>
                        "New passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || setup_pass.get()
                            on:input=move |ev| setup_pass.set(event_target_value(&ev))
                        />
                    </label>
                    <label>
                        "Repeat passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || setup_confirm.get()
                            on:input=move |ev| setup_confirm.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="row-actions">
                        <button class="primary" disabled=move || busy.get() on:click=setup>
                            <Icon name="lock"/>
                            {move || {
                                if busy.get() { "Setting up…" } else { "Set up encryption" }
                            }}
                        </button>
                    </div>
                </Show>
                <Show when=move || has_keyring.get() == Some(true)>
                    <label>
                        {move || {
                            if use_recovery.get() {
                                "Recovery phrase (24 words)"
                            } else {
                                "Passphrase"
                            }
                        }}
                        <input
                            type="password"
                            autocomplete="off"
                            prop:value=move || passphrase.get()
                            on:input=move |ev| passphrase.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="row-actions">
                        <button class="primary" disabled=move || busy.get() on:click=unlock>
                            <Icon name="lock"/>
                            {move || if busy.get() { "Unlocking…" } else { "Unlock" }}
                        </button>
                        <button
                            class="ghost"
                            on:click=move |_| {
                                use_recovery.set(!use_recovery.get_untracked());
                                error.set(String::new());
                            }
                        >
                            {move || {
                                if use_recovery.get() {
                                    "Use passphrase"
                                } else {
                                    "Use recovery phrase"
                                }
                            }}
                        </button>
                    </div>
                </Show>
            </Show>
                    <Show when=move || master.get().is_some()>
                <p class="notice">"Keyring unlocked for this browser."</p>
                <div class="row-actions">
                    <button
                        class="ghost"
                        on:click=move |_| {
                            crate::e2ee::forget_master();
                            master.set(None);
                            notice.set(String::new());
                        }
                    >
                        "Lock again"
                    </button>
                </div>
                <h3>"Passphrase"</h3>
                <p class="muted">
                    "Change the passphrase that wraps this account's master key. Nothing is re-uploaded, and your recovery phrase and other devices keep working."
                </p>
                <Show when=move || !change_open.get()>
                    <div class="row-actions">
                        <button
                            class="ghost"
                            on:click=move |_| {
                                error.set(String::new());
                                change_open.set(true);
                            }
                        >
                            "Change passphrase"
                        </button>
                    </div>
                </Show>
                <Show when=move || change_open.get()>
                    <label>
                        "New passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || new_pass.get()
                            on:input=move |ev| new_pass.set(event_target_value(&ev))
                        />
                    </label>
                    <label>
                        "Repeat new passphrase"
                        <input
                            type="password"
                            autocomplete="new-password"
                            prop:value=move || new_confirm.get()
                            on:input=move |ev| new_confirm.set(event_target_value(&ev))
                        />
                    </label>
                    <div class="row-actions">
                        <button class="primary" disabled=move || busy.get() on:click=change_pass>
                            {move || if busy.get() { "Saving…" } else { "Save new passphrase" }}
                        </button>
                        <button
                            class="ghost"
                            on:click=move |_| {
                                change_open.set(false);
                                new_pass.set(String::new());
                                new_confirm.set(String::new());
                                error.set(String::new());
                            }
                        >
                            "Cancel"
                        </button>
                    </div>
                </Show>
                <h3>"Existing names"</h3>
                <p class="muted">
                    "Items created before names were encrypted may still have readable names. Rename them in place; contents are not re-uploaded. Plaintext files are skipped."
                </p>
                <div class="row-actions">
                    <button disabled=move || busy.get() on:click=migrate_names>
                        "Encrypt existing names"
                    </button>
                </div>
                    </Show>
                </div>
            </Show>

            <Show when=move || tab.get() == SettingsTab::Sharing>
                <div class="settings-section">
                    <h3>"MLS shares"</h3>
                    <Show when=move || master.get().is_some()>
                <p class="muted">
                    "Upgrade existing encrypted folder shares to MLS groups and epoch keyrings. Recipients must have unlocked the web app once so they have a key package."
                </p>
                <div class="row-actions">
                    <button disabled=move || migrating.get() on:click=migrate_mls>
                        "Upgrade shares to MLS"
                    </button>
                    <button
                        class="danger"
                        disabled=move || resetting.get()
                        on:click=reset_mls
                    >
                        {move || {
                            if resetting.get() {
                                "Resetting…"
                            } else {
                                "Reset this browser's MLS state"
                            }
                        }}
                    </button>
                </div>
                <p class="muted">
                    "Use reset if this browser lost or corrupted its MLS state. You will need another member to re-add it before encrypted folder shares open here again."
                </p>
                    </Show>
                    <Show when=move || master.get().is_none()>
                        <p class="muted">"Unlock encryption to manage MLS shares."</p>
                    </Show>
                </div>
            </Show>

            <Show when=move || tab.get() == SettingsTab::Devices>
                <div class="settings-section">
                    <Show when=move || master.get().is_some()>
                <h3>"Pending enrollments"</h3>
                <p class="muted">
                    "One click approves a new device. If you don't fully trust this server, verify the code first."
                </p>
                <ul class="shares">
                    <For
                        each=move || enrollments.get()
                        key=|e| e["id"].as_i64().unwrap_or(0)
                        children=move |entry| {
                            let id = entry["id"].as_i64().unwrap_or(0);
                            let name = entry["device_name"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            let key = entry["device_public_key"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string();
                            let code = crate::e2ee::device_code(&key, id);
                            let fingerprint = crate::e2ee::key_fingerprint(&key);
                            let entered = RwSignal::new(String::new());
                            let verify = RwSignal::new(false);
                            let k = key.clone();
                            view! {
                                <li class="file">
                                    <span class="file-body">
                                        <span class="file-name">{name}</span>
                                        <Show when=move || verify.get()>
                                            <span class="file-meta">
                                                <span class="muted">"code " {code.clone()}</span>
                                                <span class="muted">"key " {fingerprint.clone()}</span>
                                            </span>
                                            <input
                                                type="text"
                                                autocomplete="off"
                                                placeholder="Type the code shown on the new device"
                                                prop:value=move || entered.get()
                                                on:input=move |ev| entered.set(event_target_value(&ev))
                                            />
                                        </Show>
                                    </span>
                                    <span class="file-actions">
                                        <button
                                            class="ghost"
                                            title="Compare the code shown on the new device first"
                                            on:click=move |_| verify.set(!verify.get_untracked())
                                        >
                                            "Verify code"
                                        </button>
                                        <button
                                            class="primary"
                                            on:click=move |_| {
                                                let typed = entered.get_untracked();
                                                let check = if verify.get_untracked() && !typed.trim().is_empty() {
                                                    Some(typed)
                                                } else {
                                                    None
                                                };
                                                approve(id, k.clone(), check)
                                            }
                                        >
                                            "Approve"
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                </ul>

                <h3>"Devices"</h3>
                <ul class="shares">
                    <For
                        each=move || devices.get()
                        key=|d| d["id"].as_i64().unwrap_or(0)
                        children=move |device| {
                            let id = device["id"].as_i64().unwrap_or(0);
                            let name =
                                device["name"].as_str().unwrap_or_default().to_string();
                            view! {
                                <li class="file">
                                    <span class="file-body">
                                        <span class="file-name">{name}</span>
                                    </span>
                                    <span class="file-actions">
                                        <button
                                            class="icon-btn"
                                            title="Revoke device"
                                            on:click=move |_| revoke(id)
                                        >
                                            <Icon name="trash"/>
                                        </button>
                                    </span>
                                </li>
                            }
                        }
                    />
                </ul>

                <MlsDevicesPanel
                    devices=mls_devices
                    warnings=mls_warnings
                    error=mls_error
                    loading=mls_loading
                    busy=mls_busy
                    on_revoke=revoke_mls
                />
                    </Show>
                    <Show when=move || master.get().is_none()>
                        <h3>"Devices"</h3>
                        <p class="muted">
                            "Unlock encryption to manage approved devices and MLS leaves. You can still start an enrollment below."
                        </p>
                    </Show>
                    <EnrollmentPanel master=master notice=notice error=error/>
                </div>
            </Show>

            <Show when=move || tab.get() == SettingsTab::Passkeys>
                <div class="settings-section">
                    <PasskeysPanel/>
                </div>
            </Show>

            <Notice message=notice/>
            <ErrorText message=error/>
        </Modal>
    }
}
