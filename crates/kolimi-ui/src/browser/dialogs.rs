//! Modal dialogs owned by the browser.

use kolimi_crypto::MasterKey;
use leptos::prelude::*;

use super::types::Entry;
use crate::dialogs::{
    AdminDialog, SettingsDialog, SettingsTab, ShareDialog, VaultSetupDialog, VersionsDialog,
};

/// Vault setup, share, versions, admin and Settings dialogs.
#[component]
pub(crate) fn BrowserDialogs(
    vault_setup: RwSignal<bool>,
    share_target: RwSignal<Option<Entry>>,
    versions_for: RwSignal<Option<Entry>>,
    admin_open: RwSignal<bool>,
    e2ee_open: RwSignal<bool>,
    master_signal: RwSignal<Option<MasterKey>>,
    settings_tab: RwSignal<SettingsTab>,
    current_path: RwSignal<String>,
    notice: RwSignal<String>,
    on_load: Callback<String>,
) -> impl IntoView {
    view! {
            {move || {
                vault_setup
                .get()
                .then(|| {
                    view! {
                        <VaultSetupDialog
                            on_close=Callback::new(move |_| {
                                if let Some(storage) = web_sys::window()
                                    .and_then(|window| window.local_storage().ok().flatten())
                                {
                                    let _ = storage.set_item("kolimi.vault.dismissed", "1");
                                }
                                vault_setup.set(false);
                            })
                            on_done=Callback::new(move |master| {
                                crate::e2ee::remember_master(&master);
                                master_signal.set(Some(master));
                                vault_setup.set(false);
                                notice.set("Vault ready — anything you put inside it is encrypted".to_string());
                                on_load.run(current_path.get_untracked());
                            })
                        />
                    }
                })
        }}

            {move || {
                share_target
                .get()
                .map(|entry| {
                    view! {
                        <ShareDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            encrypted=entry.encrypted
                            master=master_signal.get()
                            on_close=Callback::new(move |_| share_target.set(None))
                        />
                    }
                })
        }}

            {move || {
                versions_for
                .get()
                .map(|entry| {
                    let current = current_path.get();
                    view! {
                        <VersionsDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            on_close=Callback::new(move |_| versions_for.set(None))
                            on_restored=Callback::new(move |_| on_load.run(current.clone()))
                        />
                    }
                })
        }}

        {move || {
            admin_open
                .get()
                .then(|| {
                    view! {
                        <AdminDialog on_close=Callback::new(move |_| admin_open.set(false))/>
                    }
                })
        }}
        {move || {
            e2ee_open
                .get()
                .then(|| {
                    view! {
                        <SettingsDialog
                            master=master_signal
                            tab=settings_tab
                            on_close=Callback::new(move |_| e2ee_open.set(false))
                        />
                    }
                })
        }}
    }
}
