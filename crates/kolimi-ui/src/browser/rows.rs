//! File, search and trash lists for the browser.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use wasm_bindgen::JsCast;

use super::types::{
    Entry, FileFilter, FileSort, SearchHit, TrashItem, file_icon, is_image_name, view_entries,
};
use crate::app::{encode, encode_path, human_size, plural, relative_time};
use crate::components::{EmptyState, Icon};

/// Keeps a context menu inside the viewport. The menu is roughly 320px tall
/// and 240px wide; opening near the bottom edge must flip it upward enough to
/// remain clickable.
fn clamp_menu_position(x: i32, y: i32) -> (i32, i32) {
    let Some(window) = web_sys::window() else {
        return (x.max(8), y.max(8));
    };
    let width = window
        .inner_width()
        .ok()
        .and_then(|value| value.as_f64())
        .unwrap_or(1280.0) as i32;
    let height = window
        .inner_height()
        .ok()
        .and_then(|value| value.as_f64())
        .unwrap_or(800.0) as i32;
    (
        x.clamp(8, (width - 240).max(8)),
        y.clamp(8, (height - 340).max(8)),
    )
}

/// Opens the topbar's file picker from an empty-state action.
fn open_upload_picker() {
    let Some(input) = web_sys::window()
        .and_then(|window| window.document())
        .and_then(|document| document.get_element_by_id("topbar-upload"))
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
    else {
        return;
    };
    input.click();
}

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
                                let icon = file_icon(&name, &kind);
                                view! {
                                    <li class="file">
                                        <button
                                            class="file-open"
                                            on:click=move |_| on_open.run(hit_for_open.clone())
                                        >
                                            <span class=format!("file-icon {icon}")>
                                                <Icon name=icon/>
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
                                                                aria-label="Download and decrypt"
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
                                                                aria-label="Download"
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
    sort: RwSignal<FileSort>,
    sort_desc: RwSignal<bool>,
    filter: RwSignal<FileFilter>,
    selected: RwSignal<std::collections::HashSet<String>>,
    move_drag: RwSignal<Option<Entry>>,
    context_menu: RwSignal<Option<(Entry, i32, i32)>>,
    lightbox: RwSignal<Option<Entry>>,
    can_write: Signal<bool>,
    has_more: RwSignal<bool>,
    loading_more: RwSignal<bool>,
    on_load_more: Callback<()>,
    on_load: Callback<String>,
    on_mkdir: Callback<()>,
    on_open: Callback<Entry>,
    on_toggle_select: Callback<String>,
    on_move_into: Callback<(Entry, String)>,
    on_decrypt: Callback<Entry>,
    on_unlock: Callback<()>,
) -> impl IntoView {
    let e2ee_master = master;
    let visible =
        Memo::new(move |_| view_entries(&entries.get(), filter.get(), sort.get(), sort_desc.get()));
    let all_selected = Memo::new(move |_| {
        let paths = visible.get();
        !paths.is_empty()
            && paths
                .iter()
                .all(|entry| selected.get().contains(&entry.path))
    });
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
                if can_write.get() {
                    return view! {
                        <EmptyState
                            icon="folder"
                            title="This folder is empty"
                            hint="Upload a file or create a folder to get started."
                            action_label="Upload"
                            on_action=Callback::new(move |_| open_upload_picker())
                            secondary_action_label="New folder"
                            on_secondary_action=on_mkdir
                        />
                    }
                        .into_any();
                }
                return view! {
                    <EmptyState
                        icon="folder"
                        title="This folder is empty"
                        hint="Files shared with you will appear here."
                    />
                }
                    .into_any();
            }
            if visible.get().is_empty() {
                return view! {
                    <EmptyState
                        icon="search"
                        title="No files match this filter"
                        hint="Clear the filter to see everything in this folder."
                        action_label="Clear filter"
                        on_action=Callback::new(move |_| filter.set(FileFilter::All))
                    />
                }
                    .into_any();
            }

            let count_label = move || {
                let shown = visible.get().len();
                let total = entries.get().len();
                if has_more.get() {
                    if shown == total {
                        format!("{total}+ {}", if total == 1 { "item" } else { "items" })
                    } else {
                        format!(
                            "{shown} of {total}+ {}",
                            if total == 1 { "item" } else { "items" }
                        )
                    }
                } else if shown == total {
                    plural(shown, "item", "items")
                } else {
                    format!("{shown} of {}", plural(total, "item", "items"))
                }
            };
            view! {
                <div class="file-toolbar">
                    <span class="file-count">{count_label}</span>
                    <div class="file-toolbar-controls">
                        <select
                            aria-label="Filter files"
                            prop:value=move || match filter.get() {
                                FileFilter::All => "all",
                                FileFilter::Folders => "folders",
                                FileFilter::Files => "files",
                                FileFilter::Encrypted => "encrypted",
                                FileFilter::Shared => "shared",
                            }
                            on:change=move |ev| {
                                filter.set(match event_target_value(&ev).as_str() {
                                    "folders" => FileFilter::Folders,
                                    "files" => FileFilter::Files,
                                    "encrypted" => FileFilter::Encrypted,
                                    "shared" => FileFilter::Shared,
                                    _ => FileFilter::All,
                                });
                                selected.set(std::collections::HashSet::new());
                            }
                        >
                            <option value="all">"All items"</option>
                            <option value="folders">"Folders"</option>
                            <option value="files">"Files"</option>
                            <option value="encrypted">"Encrypted"</option>
                            <option value="shared">"Shared with me"</option>
                        </select>
                        <select
                            aria-label="Sort files"
                            prop:value=move || match sort.get() {
                                FileSort::Name => "name",
                                FileSort::Modified => "modified",
                                FileSort::Size => "size",
                                FileSort::Type => "type",
                            }
                            on:change=move |ev| {
                                sort.set(match event_target_value(&ev).as_str() {
                                    "modified" => FileSort::Modified,
                                    "size" => FileSort::Size,
                                    "type" => FileSort::Type,
                                    _ => FileSort::Name,
                                });
                            }
                        >
                            <option value="name">"Name"</option>
                            <option value="modified">"Modified"</option>
                            <option value="size">"Size"</option>
                            <option value="type">"Type"</option>
                        </select>
                        <button
                            class="icon-btn"
                            aria-label=move || {
                                if sort_desc.get() {
                                    "Sort ascending"
                                } else {
                                    "Sort descending"
                                }
                            }
                            title=move || {
                                if sort_desc.get() {
                                    "Sort ascending"
                                } else {
                                    "Sort descending"
                                }
                            }
                            on:click=move |_| sort_desc.update(|value| *value = !*value)
                        >
                            {move || if sort_desc.get() { "↓" } else { "↑" }}
                        </button>
                    </div>
                </div>

                {move || {
                    if grid.get() {
                        view! {
                            <div class="grid">
                                <For
                                    each=move || visible.get()
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
                                            />
                                        }
                                    }
                                />
                            </div>
                        }
                            .into_any()
                    } else {
                        view! {
                            <div class="file-list-head">
                                <input
                                    type="checkbox"
                                    class="file-check"
                                    aria-label="Select all"
                                    prop:checked=move || all_selected.get()
                                    on:change=move |_| {
                                        if all_selected.get_untracked() {
                                            selected.set(std::collections::HashSet::new());
                                        } else {
                                            selected.set(
                                                visible
                                                    .get_untracked()
                                                    .into_iter()
                                                    .map(|entry| entry.path)
                                                    .collect(),
                                            );
                                        }
                                    }
                                />
                                <span>"Name"</span>
                                <span class="col-size">"Size"</span>
                                <span class="col-time">"Modified"</span>
                                <span></span>
                            </div>
                            <ul class="files">
                                <For
                                    each=move || visible.get()
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
                                            />
                                        }
                                    }
                                />
                            </ul>
                        }
                            .into_any()
                    }
                }}

                <Show when=move || has_more.get()>
                    <div class="load-more">
                        <button
                            class="ghost"
                            disabled=move || loading_more.get()
                            on:click=move |_| on_load_more.run(())
                        >
                            {move || {
                                if loading_more.get() {
                                    "Loading…"
                                } else {
                                    "Load more"
                                }
                            }}
                        </button>
                    </div>
                </Show>
            }
                .into_any()
        }}
    }
}

/// The trash tab with restore and permanent-delete actions.
#[component]
pub(crate) fn TrashArea(
    trash: RwSignal<Vec<TrashItem>>,
    has_more: RwSignal<bool>,
    loading_more: RwSignal<bool>,
    on_load_more: Callback<()>,
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
                <Show when=move || has_more.get()>
                    <div class="load-more">
                        <button
                            class="ghost"
                            disabled=move || loading_more.get()
                            on:click=move |_| on_load_more.run(())
                        >
                            {move || {
                                if loading_more.get() {
                                    "Loading…"
                                } else {
                                    "Load more"
                                }
                            }}
                        </button>
                    </div>
                </Show>
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
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let is_img = !is_dir && !entry.encrypted && is_image_name(&entry.name);
    let name = entry.name.clone();
    let kind = entry.kind.clone();
    let icon = file_icon(&name, &kind);
    let meta = file_meta(&entry);
    let preview = entry.path.clone();
    let selected_path = entry.path.clone();
    let check_path = entry.path.clone();
    let check_path_for_checked = entry.path.clone();
    let select_label = format!("Select {name}");
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
                let (x, y) = clamp_menu_position(ev.client_x(), ev.client_y());
                context_menu.set(Some((ctx_copy.clone(), x, y)));
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
            <input
                type="checkbox"
                class="tile-check"
                aria-label=select_label
                prop:checked=move || selected.get().contains(&check_path_for_checked)
                on:change=move |_| on_toggle_select.run(check_path.clone())
            />
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
                    if is_dir {
                        "folder"
                    } else if is_img {
                        "img"
                    } else {
                        icon
                    },
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
                            view! { <Icon name=icon/> }
                        })}
                </span>
                <span class="tile-name">{name.clone()}</span>
                <span class="tile-meta">{meta}</span>
            </button>
            <div class="tile-actions">
                <FileActions
                    entry=actions_entry
                    context_menu=context_menu
                    on_decrypt=on_decrypt
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
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let is_img = !is_dir && !entry.encrypted && is_image_name(&entry.name);
    let shared = entry.shared;
    let owner = entry.owner.clone().unwrap_or_default();
    let permission = entry.permission.clone().unwrap_or_default();
    let name = entry.name.clone();
    let kind = entry.kind.clone();
    let icon = file_icon(&name, &kind);
    let meta = file_meta(&entry);
    let size_label = if is_dir {
        "—".to_string()
    } else if entry.encrypted {
        "Encrypted".to_string()
    } else {
        human_size(entry.size)
    };
    let time_label = {
        let label = relative_time(entry.modified_at);
        if label.is_empty() {
            "—".to_string()
        } else {
            label
        }
    };
    let preview = entry.path.clone();
    let selected_path = entry.path.clone();
    let check_path = entry.path.clone();
    let check_path_for_checked = entry.path.clone();
    let select_label = format!("Select {name}");
    let shared_title = format!("shared by {owner} ({permission})");
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
                let (x, y) = clamp_menu_position(ev.client_x(), ev.client_y());
                context_menu.set(Some((ctx_copy.clone(), x, y)));
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
            <input
                type="checkbox"
                class="file-check"
                aria-label=select_label
                prop:checked=move || selected.get().contains(&check_path_for_checked)
                on:change=move |_| on_toggle_select.run(check_path.clone())
            />
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
                        icon
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
                            view! { <Icon name=icon/> }
                        })}
                </span>
                <span class="file-body">
                    <span class="file-name">{name.clone()}</span>
                    <span class="file-badges">
                        {entry
                            .encrypted
                            .then(|| view! { <span class="badge">"encrypted"</span> })}
                        {shared
                            .then(|| {
                                view! {
                                    <span class="badge" title=shared_title.clone()>
                                        "shared"
                                    </span>
                                }
                            })}
                    </span>
                    <span class="file-meta file-meta-mobile">{meta}</span>
                </span>
            </button>
            <span class="file-size">{size_label}</span>
            <span class="file-time">{time_label}</span>
            <span class="file-actions">
                <FileActions
                    entry=actions_entry
                    context_menu=context_menu
                    on_decrypt=on_decrypt
                />
            </span>
        </li>
    }
}

#[component]
fn FileActions(
    entry: Entry,
    context_menu: RwSignal<Option<(Entry, i32, i32)>>,
    on_decrypt: Callback<Entry>,
) -> impl IntoView {
    let is_dir = entry.kind == "dir";
    let encrypted = entry.encrypted;
    let download = entry.path.clone();
    let decrypt_copy = entry.clone();
    let menu_entry = entry.clone();
    view! {
        {(!is_dir)
            .then(|| {
                if encrypted {
                    view! {
                        <button
                            class="icon-btn"
                            title="Download & decrypt"
                            aria-label="Download and decrypt"
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
                            aria-label="Download"
                            href=format!("/dav{}", encode_path(&download))
                            download
                        >
                            <Icon name="download"/>
                        </a>
                    }
                        .into_any()
                }
            })}
        <button
            class="icon-btn"
            title="Actions"
            aria-label="Actions"
            on:click=move |ev: ev::MouseEvent| {
                ev.stop_propagation();
                let (x, y) = ev
                    .current_target()
                    .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
                    .map(|element| {
                        let rect = element.get_bounding_client_rect();
                        (rect.right() as i32, rect.bottom() as i32)
                    })
                    .unwrap_or_else(|| (ev.client_x(), ev.client_y()));
                let (x, y) = clamp_menu_position(x, y);
                context_menu.set(Some((menu_entry.clone(), x, y)));
            }
        >
            <Icon name="dots"/>
        </button>
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
        <li class="file simple">
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
