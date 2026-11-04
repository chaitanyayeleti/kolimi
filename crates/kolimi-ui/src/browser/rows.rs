//! File, search and trash lists for the browser.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;

use super::types::{Entry, SearchHit, TrashItem, file_icon, is_image_name};
use crate::app::{encode, encode_path, human_size, relative_time};
use crate::components::{EmptyState, Icon};

/// Search results with navigation, download and clear actions.
#[component]
pub(crate) fn SearchResults(
    results: RwSignal<Vec<SearchHit>>,
    master: RwSignal<Option<MasterKey>>,
    shared_names: RwSignal<Vec<crate::e2ee::ShareDisplay>>,
    on_open: Callback<SearchHit>,
    on_decrypt: Callback<Entry>,
    on_clear: Callback<()>,
) -> impl IntoView {
    let e2ee_master = master;
    view! {
                    <div class="section-head">
                        <h2>"Search"</h2>
                        <button on:click=move |_| on_clear.run(())>"Clear"</button>
                    </div>
                    <Show when=move || results.get().is_empty()>
                        <EmptyState
                            icon="search"
                            title="No matches"
                            hint="Try a different name or clear the search."
                        />
                    </Show>
                    <ul class="files">
                        <For
                            each=move || results.get()
                            key=|hit| hit.path.clone()
                            children=move |hit| {
                                let hit_for_open = hit.clone();
                                let download_path = hit.path.clone();
                                let is_dir = hit.is_dir;
                                let name = hit.name.clone();
                                let snippet = hit.snippet.clone();
                                let path = hit.path.clone();
                                let encrypted = hit.encrypted;
                                let kind = if is_dir { "dir".to_string() } else { "file".to_string() };
                                view! {
                                    <li class="file">
                                        <button
                                            class="file-open"
                                            on:click=move |_| on_open.run(hit_for_open.clone())
                                        >
                                            <span class="file-icon">
                                                <Icon name=file_icon(&name, &kind)/>
                                            </span>
                                            <span class="file-body">
                                                <span class="file-name">{name.clone()}</span>
                                                <span class="file-meta">
                                                    {crate::e2ee::decode_display_path_with_shares(
                                                        e2ee_master.get_untracked().as_ref(),
                                                        &path,
                                                        &shared_names.get_untracked(),
                                                    )}
                                                    {(!snippet.is_empty())
                                                        .then(|| {
                                                            view! {
                                                                <span class="muted">" — " {snippet.clone()}</span>
                                                            }
                                                        })}
                                                </span>
                                            </span>
                                        </button>
                                        {(!is_dir)
                                            .then(|| {
                                                if encrypted {
                                                    let dl = Entry {
                                                        name: name.clone(),
                                                        path: download_path.clone(),
                                                        kind: kind.clone(),
                                                        size: 0,
                                                        modified_at: 0,
                                                        shared: false,
                                                        owner: None,
                                                        permission: None,
                                                        encrypted: true,
                                                    };
                                                    view! {
                                                        <span class="file-actions">
                                                            <button
                                                                class="icon-btn"
                                                                title="Download & decrypt"
                                                                on:click=move |_| on_decrypt.run(dl.clone())
                                                            >
                                                                <Icon name="download"/>
                                                            </button>
                                                        </span>
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <span class="file-actions">
                                                            <a
                                                                class="icon-btn"
                                                                title="Download"
                                                                href=format!("/dav{}", encode_path(&download_path))
                                                                download
                                                            >
                                                                <Icon name="download"/>
                                                            </a>
                                                        </span>
                                                    }
                                                        .into_any()
                                                }
                                            })}
                                    </li>
                                }
                            }
                        />
                    </ul>
    }
}

/// The files tab: breadcrumbs, loading, empty/locked states, list and grid.
#[component]
pub(crate) fn FileArea(
    parent: RwSignal<Option<String>>,
    loading: RwSignal<bool>,
    folder_encrypted: RwSignal<bool>,
    master: RwSignal<Option<MasterKey>>,
    entries: RwSignal<Vec<Entry>>,
    grid: RwSignal<bool>,
    selected: RwSignal<std::collections::HashSet<String>>,
    move_drag: RwSignal<Option<Entry>>,
    context_menu: RwSignal<Option<(Entry, i32, i32)>>,
    lightbox: RwSignal<Option<Entry>>,
    on_load: Callback<String>,
    on_open: Callback<Entry>,
    on_toggle_select: Callback<String>,
    on_move_into: Callback<(Entry, String)>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
    on_unlock: Callback<()>,
) -> impl IntoView {
    let e2ee_master = master;
    view! {
        {move || {
            parent
                .get()
                .map(|target| {
                    view! {
                        <button class="nav-item" on:click=move |_| on_load.run(target.clone())>
                            <Icon name="folder"/>
                            "Up one level"
                        </button>
                    }
                })
        }}
        {move || {
            if loading.get() {
                return view! {
                    <ul class="files skeleton-list">
                        {(0..6)
                            .map(|_| {
                                view! {
                                    <li class="file skeleton">
                                        <span class="sk sk-icon"></span>
                                        <span class="file-body">
                                            <span class="sk sk-line"></span>
                                            <span class="sk sk-line short"></span>
                                        </span>
                                    </li>
                                }
                            })
                            .collect_view()}
                    </ul>
                }
                    .into_any();
            }
            // A locked encrypted folder shows no names: the client hides
            // them until the key is available.
            if folder_encrypted.get() && e2ee_master.get().is_none() {
                return view! {
                    <EmptyState
                        icon="lock"
                        title="Vault is locked"
                        hint="Unlock encryption to see what's inside."
                        action_label="Unlock"
                        on_action=on_unlock
                    />
                }
                    .into_any();
            }
            if entries.get().is_empty() {
                return view! {
                    <EmptyState
                        icon="folder"
                        title="This folder is empty"
                        hint="Upload a file or create a folder to get started."
                    />
                }
                    .into_any();
            }
            if grid.get() {
                view! {
                    <div class="grid">
                        <For
                            each=move || entries.get()
                            key=|entry| entry.path.clone()
                            children=move |entry| {
                                view! {
                                    <FileTile
                                        entry=entry
                                        selected=selected
                                        move_drag=move_drag
                                        context_menu=context_menu
                                        lightbox=lightbox
                                        on_open=on_open
                                        on_toggle_select=on_toggle_select
                                        on_move_into=on_move_into
                                        on_decrypt=on_decrypt
                                        on_share=on_share
                                        on_rename=on_rename
                                        on_delete=on_delete
                                    />
                                }
                            }
                        />
                    </div>
                }
                    .into_any()
            } else {
                view! {
                    <ul class="files">
                        <For
                            each=move || entries.get()
                            key=|entry| entry.path.clone()
                            children=move |entry| {
                                view! {
                                    <FileRow
                                        entry=entry
                                        selected=selected
                                        move_drag=move_drag
                                        context_menu=context_menu
                                        on_open=on_open
                                        on_toggle_select=on_toggle_select
                                        on_move_into=on_move_into
                                        on_decrypt=on_decrypt
                                        on_share=on_share
                                        on_rename=on_rename
                                        on_delete=on_delete
                                    />
                                }
                            }
                        />
                    </ul>
                }
                    .into_any()
            }
        }}
    }
}

/// The trash tab with restore and permanent-delete actions.
#[component]
pub(crate) fn TrashArea(
    trash: RwSignal<Vec<TrashItem>>,
    on_restore: Callback<TrashItem>,
    on_purge: Callback<TrashItem>,
) -> impl IntoView {
    view! {
        {move || {
            if trash.get().is_empty() {
                return view! {
                    <EmptyState
                        icon="trash"
                        title="Trash is empty"
                        hint="Deleted files appear here for 30 days."
                    />
                }
                    .into_any();
            }
            view! {
                <ul class="files">
                    <For
                        each=move || trash.get()
                        key=|item| item.id
                        children=move |item| {
                            view! {
                                <TrashRow item=item on_restore=on_restore on_purge=on_purge/>
                            }
                        }
                    />
                </ul>
            }
                .into_any()
        }}
    }
}

#[component]
fn FileTile(
    entry: Entry,
    selected: RwSignal<std::collections::HashSet<String>>,
    move_drag: RwSignal<Option<Entry>>,
    context_menu: RwSignal<Option<(Entry, i32, i32)>>,
    lightbox: RwSignal<Option<Entry>>,
    on_open: Callback<Entry>,
    on_toggle_select: Callback<String>,
    on_move_into: Callback<(Entry, String)>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let is_img = !is_dir && !entry.encrypted && is_image_name(&entry.name);
    let name = entry.name.clone();
    let kind = entry.kind.clone();
    let meta = file_meta(&entry);
    let preview = entry.path.clone();
    let selected_path = entry.path.clone();
    let open_entry = entry.clone();
    let drag_copy = entry.clone();
    let ctx_copy = entry.clone();
    let drop_copy = entry.clone();
    let lightbox_copy = entry.clone();
    let select_path = entry.path.clone();
    let actions_entry = entry.clone();
    view! {
        <div
            class="tile"
            class:selected=move || selected.get().contains(&selected_path)
            draggable="true"
            on:dragstart=move |_| {
                move_drag.set(Some(drag_copy.clone()));
            }
            on:contextmenu=move |ev: ev::MouseEvent| {
                ev.prevent_default();
                context_menu
                    .set(Some((ctx_copy.clone(), ev.client_x(), ev.client_y())));
            }
            on:dragover=move |ev: ev::DragEvent| {
                if is_dir {
                    ev.prevent_default();
                }
            }
            on:drop=move |ev: ev::DragEvent| {
                if is_dir {
                    ev.prevent_default();
                    if let Some(src) = move_drag.get_untracked() {
                        on_move_into.run((src, drop_copy.path.clone()));
                        move_drag.set(None);
                    }
                }
            }
        >
            <button
                class="tile-open"
                on:click=move |ev: ev::MouseEvent| {
                    if ev.ctrl_key() || ev.meta_key() || ev.shift_key() {
                        on_toggle_select.run(select_path.clone());
                    } else {
                        on_open.run(open_entry.clone());
                    }
                }
            >
                <span class=format!(
                    "tile-thumb {}",
                    if is_dir { "folder" } else { "" },
                )>
                    {is_img
                        .then(|| {
                            view! {
                                <img
                                    loading="lazy"
                                    alt=""
                                    src=format!("/api/preview?path={}&size=256", encode(&preview))
                                    on:click=move |ev: ev::MouseEvent| {
                                        ev.stop_propagation();
                                        lightbox.set(Some(lightbox_copy.clone()));
                                    }
                                />
                            }
                        })}
                    {(!is_img)
                        .then(|| {
                            view! { <Icon name=file_icon(&name, &kind)/> }
                        })}
                </span>
                <span class="tile-name">{name.clone()}</span>
                <span class="tile-meta">{meta}</span>
            </button>
            <div class="tile-actions">
                <FileActions
                    entry=actions_entry
                    on_decrypt=on_decrypt
                    on_share=on_share
                    on_rename=on_rename
                    on_delete=on_delete
                />
            </div>
        </div>
    }
}

#[component]
fn FileRow(
    entry: Entry,
    selected: RwSignal<std::collections::HashSet<String>>,
    move_drag: RwSignal<Option<Entry>>,
    context_menu: RwSignal<Option<(Entry, i32, i32)>>,
    on_open: Callback<Entry>,
    on_toggle_select: Callback<String>,
    on_move_into: Callback<(Entry, String)>,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let is_img = !is_dir && !entry.encrypted && is_image_name(&entry.name);
    let shared = entry.shared;
    let owner = entry.owner.clone().unwrap_or_default();
    let permission = entry.permission.clone().unwrap_or_default();
    let name = entry.name.clone();
    let kind = entry.kind.clone();
    let meta = file_meta(&entry);
    let preview = entry.path.clone();
    let selected_path = entry.path.clone();
    let open_entry = entry.clone();
    let drag_copy = entry.clone();
    let ctx_copy = entry.clone();
    let drop_copy = entry.clone();
    let select_path = entry.path.clone();
    let actions_entry = entry.clone();
    view! {
        <li
            class="file"
            class:selected=move || selected.get().contains(&selected_path)
            draggable="true"
            on:dragstart=move |_| {
                move_drag.set(Some(drag_copy.clone()));
            }
            on:contextmenu=move |ev: ev::MouseEvent| {
                ev.prevent_default();
                context_menu
                    .set(Some((ctx_copy.clone(), ev.client_x(), ev.client_y())));
            }
            on:dragover=move |ev: ev::DragEvent| {
                if is_dir {
                    ev.prevent_default();
                }
            }
            on:drop=move |ev: ev::DragEvent| {
                if is_dir {
                    ev.prevent_default();
                    if let Some(src) = move_drag.get_untracked() {
                        on_move_into.run((src, drop_copy.path.clone()));
                        move_drag.set(None);
                    }
                }
            }
        >
            <button
                class="file-open"
                on:click=move |ev: ev::MouseEvent| {
                    if ev.ctrl_key() || ev.meta_key() || ev.shift_key() {
                        on_toggle_select.run(select_path.clone());
                    } else {
                        on_open.run(open_entry.clone());
                    }
                }
            >
                <span class=format!(
                    "file-icon {}",
                    if is_dir {
                        "folder"
                    } else if is_img {
                        "img"
                    } else {
                        ""
                    },
                )>
                    {is_img
                        .then(|| {
                            view! {
                                <img
                                    loading="lazy"
                                    alt=""
                                    src=format!("/api/preview?path={}&size=64", encode(&preview))
                                />
                            }
                        })}
                    {(!is_img)
                        .then(|| {
                            view! { <Icon name=file_icon(&name, &kind)/> }
                        })}
                </span>
                <span class="file-body">
                    <span class="file-name">{name.clone()}</span>
                    <span class="file-meta">
                        {meta}
                        {shared
                            .then(|| {
                                view! {
                                    <span class="badge">
                                        {format!("shared by {owner} ({permission})")}
                                    </span>
                                }
                            })}
                    </span>
                </span>
            </button>
            <span class="file-actions">
                <FileActions
                    entry=actions_entry
                    on_decrypt=on_decrypt
                    on_share=on_share
                    on_rename=on_rename
                    on_delete=on_delete
                />
            </span>
        </li>
    }
}

#[component]
fn FileActions(
    entry: Entry,
    on_decrypt: Callback<Entry>,
    on_share: Callback<Entry>,
    on_rename: Callback<Entry>,
    on_delete: Callback<Entry>,
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let shared = entry.shared;
    // Rename/Delete need ownership or a "write" share; Share stays owner-only.
    let can_edit = !shared || entry.permission.as_deref() == Some("write");
    let encrypted = entry.encrypted;
    let download = entry.path.clone();
    let decrypt_copy = entry.clone();
    let share_copy = entry.clone();
    let rename_copy = entry.clone();
    let delete_copy = entry.clone();
    view! {
        {(!is_dir)
            .then(|| {
                if encrypted {
                    view! {
                        <button
                            class="icon-btn"
                            title="Download & decrypt"
                            on:click=move |_| on_decrypt.run(decrypt_copy.clone())
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
                }
            })}
        {can_edit
            .then(|| {
                view! {
                    {(!shared)
                        .then(|| {
                            view! {
                                <button
                                    class="icon-btn"
                                    title="Share"
                                    on:click=move |_| on_share.run(share_copy.clone())
                                >
                                    <Icon name="share"/>
                                </button>
                            }
                        })}
                    <button
                        class="icon-btn"
                        title="Rename"
                        on:click=move |_| on_rename.run(rename_copy.clone())
                    >
                        <Icon name="edit"/>
                    </button>
                    <button
                        class="icon-btn"
                        title="Delete"
                        on:click=move |_| on_delete.run(delete_copy.clone())
                    >
                        <Icon name="trash"/>
                    </button>
                }
            })}
    }
}

#[component]
fn TrashRow(
    item: TrashItem,
    on_restore: Callback<TrashItem>,
    on_purge: Callback<TrashItem>,
) -> impl IntoView {
    let restore_copy = item.clone();
    let purge_copy = item.clone();
    let original = item.original_path.clone().unwrap_or_default();
    let size = human_size(item.size);
    view! {
        <li class="file">
            <div class="file-open">
                <span class="file-icon">
                    <Icon name="trash"/>
                </span>
                <span class="file-body">
                    <span class="file-name">{item.name.clone()}</span>
                    <span class="file-meta">
                        {size}
                        <span class="muted">{original}</span>
                    </span>
                </span>
            </div>
            <span class="file-actions">
                <button on:click=move |_| on_restore.run(restore_copy.clone())>
                    <Icon name="refresh"/>
                    "Restore"
                </button>
                <button
                    class="danger"
                    on:click=move |_| on_purge.run(purge_copy.clone())
                >
                    <Icon name="trash"/>
                    "Delete forever"
                </button>
            </span>
        </li>
    }
}

fn file_meta(entry: &Entry) -> String {
    if entry.kind == "dir" {
        if entry.encrypted {
            "Folder · Encrypted".to_string()
        } else {
            "Folder".to_string()
        }
    } else {
        let when = relative_time(entry.modified_at);
        let size = if entry.encrypted {
            "Encrypted".to_string()
        } else {
            human_size(entry.size)
        };
        if when.is_empty() {
            size
        } else {
            format!("{size} · {when}")
        }
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn entry(kind: &str, encrypted: bool, size: u64) -> Entry {
        Entry {
            name: "item".to_string(),
            path: "/item".to_string(),
            kind: kind.to_string(),
            size,
            modified_at: 0,
            shared: false,
            owner: None,
            permission: None,
            encrypted,
        }
    }

    #[wasm_bindgen_test]
    fn file_meta_labels_folders_and_encryption() {
        assert_eq!(file_meta(&entry("dir", false, 0)), "Folder");
        assert_eq!(file_meta(&entry("dir", true, 0)), "Folder · Encrypted");
        assert_eq!(file_meta(&entry("file", true, 1024)), "Encrypted");
        assert_eq!(file_meta(&entry("file", false, 512)), "512 B");
    }
}
