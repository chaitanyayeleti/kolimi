//! Browser overlays: toasts, uploads, the context menu and the lightbox.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;

use super::types::{Entry, UploadItem, UploadStatus, is_text_name};
use crate::api;
use crate::app::{encode, encode_path};
use crate::components::Icon;

/// Dismissible error, notice, quota and undo toasts.
#[component]
pub(crate) fn Toasts(
    error: RwSignal<String>,
    notice: RwSignal<String>,
    quota_warn: RwSignal<Option<u8>>,
    undo: RwSignal<Option<(String, i64)>>,
    on_undo: Callback<()>,
) -> impl IntoView {
    view! {
            <div class="toasts">
                <Show when=move || !error.get().is_empty()>
                    <div class="toast error">
                        <span class="toast-msg">{move || error.get()}</span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| error.set(String::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || !notice.get().is_empty()>
                    <div class="toast ok">
                        <span class="toast-msg">{move || notice.get()}</span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| notice.set(String::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || quota_warn.get().is_some()>
                    <div class="toast error">
                        <span class="toast-msg">
                            {move || {
                                quota_warn
                                    .get()
                                    .map(|percent| {
                                        format!(
                                            "Storage almost full: {percent}% of your quota used.",
                                        )
                                    })
                                    .unwrap_or_default()
                            }}
                        </span>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| quota_warn.set(None)
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
                <Show when=move || undo.get().is_some()>
                    <div class="toast ok">
                        <span class="toast-msg">
                            {move || {
                                undo
                                    .get()
                                    .map(|(name, _)| format!("Moved “{name}” to trash"))
                                    .unwrap_or_default()
                            }}
                        </span>
                        <button on:click=move |_| on_undo.run(())>
                            "Undo"
                        </button>
                        <button
                            class="icon-btn"
                            aria-label="Dismiss"
                            on:click=move |_| undo.set(None)
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                </Show>
            </div>
    }
}

/// The in-flight upload list, including per-file retry.
#[component]
pub(crate) fn UploadTray(
    uploads: RwSignal<Vec<UploadItem>>,
    on_retry: Callback<(web_sys::File, String, RwSignal<u8>, RwSignal<UploadStatus>)>,
) -> impl IntoView {
    view! {
            <Show when=move || !uploads.get().is_empty()>
                <div class="upload-tray">
                    <div class="upload-tray-head">
                        <b>"Uploads"</b>
                        <button
                            class="icon-btn"
                            aria-label="Clear"
                            on:click=move |_| uploads.set(Vec::new())
                        >
                            <Icon name="x"/>
                        </button>
                    </div>
                    <ul>
                        <For
                            each=move || uploads.get()
                            key=|item| item.id
                            children=move |item| {
                                let name = item.name.clone();
                                let dir = item.dir.clone();
                                let file = item.file.clone();
                                // Per-item signals: O(1) reads, no tray scan.
                                let progress = item.progress;
                                let status = item.status;
                                view! {
                                    <li class="upload-item">
                                        <span class="upload-name">{name}</span>
                                        <span class="upload-bar">
                                            <span
                                                class="upload-bar-fill"
                                                style:width=move || format!("{}%", progress.get())
                                            ></span>
                                        </span>
                                        <span class="upload-status">
                                            {move || match status.get() {
                                                UploadStatus::Uploading => {
                                                    view! { <span class="muted">{format!("{}%", progress.get())}</span> }
                                                        .into_any()
                                                }
                                                UploadStatus::Done => {
                                                    view! { <span class="ok">"done"</span> }.into_any()
                                                }
                                                UploadStatus::Failed => {
                                                    let file = file.clone();
                                                    let dir = dir.clone();
                                                    view! {
                                                        <button
                                                            class="icon-btn"
                                                            title="Retry"
                                                            on:click=move |_| {
                                                                on_retry.run((
                                                                    file.clone(),
                                                                    dir.clone(),
                                                                    progress,
                                                                    status,
                                                                ));
                                                            }
                                                        >
                                                            <Icon name="refresh"/>
                                                        </button>
                                                    }
                                                        .into_any()
                                                }
                                            }}
                                        </span>
                                    </li>
                                }
                            }
                        />
                    </ul>
                </div>
            </Show>
    }
}

/// Right-click actions for one file or folder.
#[component]
pub(crate) fn ContextMenu(
    menu: RwSignal<Option<(Entry, i32, i32)>>,
    on_open: Callback<Entry>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
    on_versions: Callback<Entry>,
    on_toggle_encryption: Callback<Entry>,
) -> impl IntoView {
    let context_menu = menu;
    view! {
            {move || {
                context_menu
                    .get()
                    .map(|(entry, x, y)| {
                        let is_dir = entry.kind == "dir";
                        let shared = entry.shared;
                        // Rename/Delete need ownership or a "write" share.
                        let ctx_edit = !shared
                            || entry.permission.as_deref() == Some("write");
                        let encrypted = entry.encrypted;
                        let open_e = entry.clone();
                        let download = entry.path.clone();
                        let copy_path = entry.path.clone();
                        let share_e = entry.clone();
                        let rename_e = entry.clone();
                        let delete_e = entry.clone();
                        let versions_e = entry.clone();
                        let encrypt_e = entry.clone();
                        // Only top-level folders own their flag; nested
                        // folders inherit their parent's policy.
                        let encrypt_toggle =
                            is_dir && !shared && entry.path.matches('/').count() == 1;
                        view! {
                            <div class="ctx-scrim" on:click=move |_| context_menu.set(None)></div>
                            <div
                                class="ctx-menu"
                                style:left=format!("{}px", x.max(0))
                                style:top=format!("{}px", y.max(0))
                            >
                                {is_dir
                                    .then(|| {
                                        view! {
                                            <button
                                                class="ctx-item"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    on_open.run(open_e.clone());
                                                }
                                            >
                                                <Icon name="folder"/>
                                                "Open"
                                            </button>
                                        }
                                    })}
                                {(!is_dir)
                                    .then(|| {
                                        if encrypted {
                                            view! {
                                                <button
                                                    class="ctx-item"
                                                    title="Download & decrypt"
                                                    on:click=move |_| {
                                                        context_menu.set(None);
                                                        on_decrypt.run(entry.clone());
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
                                                    class="ctx-item"
                                                    href=format!("/dav{}", encode_path(&download))
                                                    download
                                                    on:click=move |_| context_menu.set(None)
                                                >
                                                    <Icon name="download"/>
                                                    "Download"
                                                </a>
                                            }
                                                .into_any()
                                        }
                                    })}
                                <button
                                    class="ctx-item"
                                    on:click=move |_| {
                                        context_menu.set(None);
                                        let path = copy_path.clone();
                                        spawn_local(async move {
                                            crate::api::copy_to_clipboard(&path).await;
                                        });
                                    }
                                >
                                    <Icon name="link"/>
                                    "Copy path"
                                </button>
                                {ctx_edit
                                    .then(|| {
                                        view! {
                                            {(!shared)
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                on_share.run(share_e.clone());
                                                            }
                                                        >
                                                            <Icon name="share"/>
                                                            "Share"
                                                        </button>
                                                    }
                                                })}
                                            <button
                                                class="ctx-item"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    on_rename.run(rename_e.clone());
                                                }
                                            >
                                                <Icon name="edit"/>
                                                "Rename"
                                            </button>
                                            <button
                                                class="ctx-item danger"
                                                on:click=move |_| {
                                                    context_menu.set(None);
                                                    on_delete.run(delete_e.clone());
                                                }
                                            >
                                                <Icon name="trash"/>
                                                "Move to trash"
                                            </button>
                                            {(!is_dir && !shared)
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                on_versions.run(versions_e.clone());
                                                            }
                                                        >
                                                            <Icon name="history"/>
                                                            "Versions"
                                                        </button>
                                                    }
                                                })}
                                            {encrypt_toggle
                                                .then(|| {
                                                    view! {
                                                        <button
                                                            class="ctx-item"
                                                            on:click=move |_| {
                                                                context_menu.set(None);
                                                                on_toggle_encryption.run(encrypt_e.clone());
                                                            }
                                                        >
                                                            <Icon name="lock"/>
                                                            {if encrypted {
                                                                "Make this folder plaintext"
                                                            } else {
                                                                "Encrypt this folder"
                                                            }}
                                                        </button>
                                                    }
                                                })}
                                        }
                                    })}
                            </div>
                        }
                    })
            }}
    }
}

/// Full-screen image/text preview, including decryption on demand.
#[component]
pub(crate) fn Lightbox(
    open: RwSignal<Option<Entry>>,
    master: RwSignal<Option<MasterKey>>,
    error: RwSignal<String>,
    on_unlock: Callback<()>,
    on_decrypt: Callback<Entry>,
) -> impl IntoView {
    let lightbox = open;
    let lightbox_url = RwSignal::new(String::new());
    let lightbox_text = RwSignal::new(String::new());
    // Decrypts the lightbox file client-side when it is encrypted, fetches
    // text previews, and revokes the previous blob URL whenever the
    // lightbox changes.
    Effect::new(move |_| {
        let old = lightbox_url.get_untracked();
        if old.starts_with("blob:") {
            let _ = web_sys::Url::revoke_object_url(&old);
        }
        lightbox_url.set(String::new());
        lightbox_text.set(String::new());
        let current = lightbox.get();
        let master = master.get();
        let Some(entry) = current else {
            return;
        };
        let preview_text = is_text_name(&entry.name);
        if entry.encrypted {
            let Some(master) = master else {
                error.set("Unlock encryption first (Settings → Encryption).".to_string());
                on_unlock.run(());
                lightbox.set(None);
                return;
            };
            // Previews decrypt in memory: refuse absurd sizes instead of
            // OOMing the tab (the server preview caps at 20 MiB too).
            let cap = if preview_text {
                5 * 1024 * 1024
            } else {
                20 * 1024 * 1024
            };
            if entry.size > cap {
                error.set("This file is too large to preview — download it instead.".to_string());
                lightbox.set(None);
                return;
            }
            let path = entry.path.clone();
            let display_name = entry.name.clone();
            let shared = entry.shared;
            spawn_local(async move {
                let result = if shared {
                    crate::mls::decrypt_shared_or_legacy(&master, &path, &display_name).await
                } else {
                    crate::e2ee::decrypt_file(&master, &path).await
                };
                match result {
                    Ok((name, bytes)) => {
                        if preview_text {
                            lightbox_text.set(String::from_utf8_lossy(&bytes).into_owned());
                        } else {
                            lightbox_url.set(crate::e2ee::blob_url(&name, &bytes));
                        }
                    }
                    Err(e) => {
                        error.set(e);
                        lightbox.set(None);
                    }
                }
            });
        } else if preview_text {
            let path = entry.path.clone();
            spawn_local(async move {
                match api::get_text(&format!("/api/preview?path={}", encode(&path))).await {
                    Ok(text) => lightbox_text.set(text),
                    Err(e) => {
                        error.set(e);
                        lightbox.set(None);
                    }
                }
            });
        }
    });

    view! {
            {move || {
                lightbox
                    .get()
                    .map(|entry| {
                        let name = entry.name.clone();
                        let name2 = name.clone();
                        let name3 = name.clone();
                        let encrypted = entry.encrypted;
                        let preview_text = is_text_name(&entry.name);
                        let src = if encrypted {
                            lightbox_url.get()
                        } else {
                            format!("/api/preview?path={}&size=1024", encode(&entry.path))
                        };
                        let download = entry.path.clone();
                        let dl_entry = entry.clone();
                        view! {
                            <div class="lightbox" on:click=move |_| lightbox.set(None)>
                                {preview_text
                                    .then(|| {
                                        view! {
                                            <Show
                                                when=move || !lightbox_text.get().is_empty()
                                                fallback=|| view! { <p class="muted">"Loading preview…"</p> }
                                            >
                                                <pre class="lightbox-text">{move || lightbox_text.get()}</pre>
                                            </Show>
                                        }
                                    })}
                                {(!preview_text)
                                    .then(|| {
                                        view! {
                                            {encrypted
                                                .then(|| {
                                                    view! {
                                                        <Show
                                                            when=move || !lightbox_url.get().is_empty()
                                                            fallback=|| view! { <p class="muted">"Decrypting…"</p> }
                                                        >
                                                            <img src=move || lightbox_url.get() alt=name2.clone()/>
                                                        </Show>
                                                    }
                                                })}
                                            {(!encrypted)
                                                .then(|| {
                                                    view! { <img src=src alt=name3.clone()/> }
                                                })}
                                        }
                                    })}
                                <div
                                    class="lightbox-bar"
                                    on:click=move |ev: ev::MouseEvent| ev.stop_propagation()
                                >
                                    <span class="lightbox-name">{name.clone()}</span>
                                    {if encrypted {
                                        view! {
                                            <button
                                                class="icon-btn"
                                                title="Download & decrypt"
                                                on:click=move |_| {
                                                    lightbox.set(None);
                                                    on_decrypt.run(dl_entry.clone());
                                                }
                                            >
                                                <Icon name="download"/>
                                            </button>
                                        }
                                            .into_any()
                                    } else {
                                        view! {
                                            <a
                                                class="icon-btn"
                                                title="Download"
                                                href=format!("/dav{}", encode_path(&download))
                                                download
                                            >
                                                <Icon name="download"/>
                                            </a>
                                        }
                                            .into_any()
                                    }}
                                    <button
                                        class="icon-btn"
                                        aria-label="Close"
                                        on:click=move |_| lightbox.set(None)
                                    >
                                        <Icon name="x"/>
                                    </button>
                                </div>
                            </div>
                        }
                    })
            }}
    }
}
