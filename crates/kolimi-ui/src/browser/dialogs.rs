//! Modal dialogs owned by the browser.

use kolimi_crypto::MasterKey;
use leptos::prelude::*;

use super::types::Entry;
use crate::app::{encode_path, human_size, relative_time};
use crate::components::{Icon, Modal};
use crate::dialogs::{ShareDialog, VaultSetupDialog, VersionsDialog};

/// Vault setup, share, versions, admin and Settings dialogs.
#[component]
pub(crate) fn BrowserDialogs(
    vault_setup: RwSignal<bool>,
    share_target: RwSignal<Option<Entry>>,
    versions_for: RwSignal<Option<Entry>>,
    details_for: RwSignal<Option<Entry>>,
    master_signal: RwSignal<Option<MasterKey>>,
    current_path: RwSignal<String>,
    notice: RwSignal<String>,
    on_load: Callback<String>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
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
            details_for
                .get()
                .map(|entry| {
                    view! {
                        <FileDetailsDialog
                            entry=entry
                            on_close=Callback::new(move |_| details_for.set(None))
                            on_decrypt=on_decrypt
                            on_share=on_share
                            on_rename=on_rename
                            on_delete=on_delete
                            on_versions=Callback::new(move |entry| versions_for.set(Some(entry)))
                        />
                    }
                })
        }}
    }
}

/// File metadata and quick actions in a right-side drawer.
#[component]
fn FileDetailsDialog(
    entry: Entry,
    on_close: Callback<()>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
    on_versions: Callback<Entry>,
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let shared = entry.shared;
    let can_edit = !shared || entry.permission.as_deref() == Some("write");
    let encrypted = entry.encrypted;
    let name = entry.name.clone();
    let title = format!("Details — {name}");
    let path = entry.path.clone();
    let download = entry.path.clone();
    let kind = if is_dir { "Folder" } else { "File" };
    let size = if is_dir {
        "—".to_string()
    } else if encrypted {
        "Encrypted".to_string()
    } else {
        human_size(entry.size)
    };
    let modified = {
        let label = relative_time(entry.modified_at);
        if label.is_empty() {
            "—".to_string()
        } else {
            label
        }
    };
    let owner = entry.owner.clone().unwrap_or_else(|| "you".to_string());
    let access = entry
        .permission
        .clone()
        .unwrap_or_else(|| if entry.shared { "shared" } else { "owner" }.to_string());
    let decrypt_copy = entry.clone();
    let share_copy = entry.clone();
    let rename_copy = entry.clone();
    let delete_copy = entry.clone();
    let versions_copy = entry.clone();
    view! {
        <Modal title=title on_close=on_close drawer=true>
            <dl class="details-list">
                <dt>"Name"</dt>
                <dd>{name}</dd>
                <dt>"Path"</dt>
                <dd class="mono-cell">{path}</dd>
                <dt>"Type"</dt>
                <dd>{kind}</dd>
                <dt>"Size"</dt>
                <dd>{size}</dd>
                <dt>"Modified"</dt>
                <dd>{modified}</dd>
                <dt>"Owner"</dt>
                <dd>{owner}</dd>
                <dt>"Access"</dt>
                <dd>{access}</dd>
                <dt>"Encryption"</dt>
                <dd>{if encrypted { "Encrypted" } else { "Not encrypted" }}</dd>
            </dl>
            <div class="row-actions">
                {(!is_dir)
                    .then(|| {
                        if encrypted {
                            view! {
                                <button
                                    on:click=move |_| {
                                        on_close.run(());
                                        on_decrypt.run(decrypt_copy.clone());
                                    }
                                >
                                    <Icon name="download"/>
                                    "Download & decrypt"
                                </button>
                            }
                                .into_any()
                        } else {
                            view! {
                                <a
                                    class="button"
                                    href=format!("/dav{}", encode_path(&download))
                                    download
                                    on:click=move |_| on_close.run(())
                                >
                                    <Icon name="download"/>
                                    "Download"
                                </a>
                            }
                                .into_any()
                        }
                    })}
                {(!shared && can_edit)
                    .then(|| {
                        view! {
                            <button
                                on:click=move |_| {
                                    on_close.run(());
                                    on_share.run(share_copy.clone());
                                }
                            >
                                <Icon name="share"/>
                                "Share"
                            </button>
                        }
                    })}
                {can_edit
                    .then(|| {
                        view! {
                            <button
                                on:click=move |_| {
                                    on_close.run(());
                                    on_rename.run(rename_copy.clone());
                                }
                            >
                                <Icon name="edit"/>
                                "Rename"
                            </button>
                            <button
                                class="danger"
                                on:click=move |_| {
                                    on_close.run(());
                                    on_delete.run(delete_copy.clone());
                                }
                            >
                                <Icon name="trash"/>
                                "Delete"
                            </button>
                        }
                    })}
                {(!is_dir && !shared)
                    .then(|| {
                        view! {
                            <button
                                on:click=move |_| {
                                    on_close.run(());
                                    on_versions.run(versions_copy.clone());
                                }
                            >
                                <Icon name="history"/>
                                "Versions"
                            </button>
                        }
                    })}
                <button class="ghost" on:click=move |_| on_close.run(())>
                    "Done"
                </button>
            </div>
        </Modal>
    }
}
