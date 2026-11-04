//! The browser shell: sidebar navigation and the top bar.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use serde_json::Value;

use super::types::{Entry, Tab};
use crate::app::{Logo, human_size};
use crate::components::Icon;

/// Sidebar navigation, storage usage and account actions.
#[component]
pub(crate) fn Sidebar(
    tab: RwSignal<Tab>,
    search_active: RwSignal<bool>,
    is_admin: RwSignal<bool>,
    usage: RwSignal<Value>,
    username: RwSignal<String>,
    on_files: Callback<()>,
    on_trash: Callback<()>,
    on_passkeys: Callback<()>,
    on_settings: Callback<()>,
    on_admin: Callback<()>,
    on_theme: Callback<()>,
    on_sign_out: Callback<()>,
) -> impl IntoView {
    view! {
            <aside class="sidebar">
                <a class="side-brand" href="/app/">
                    <Logo/>
                    "Kolimi"
                </a>
                <nav class="nav">
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Files && !search_active.get()
                        on:click=move |_| on_files.run(())
                    >
                        <Icon name="folder"/>
                        "Files"
                    </button>
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Trash
                        on:click=move |_| on_trash.run(())
                    >
                        <Icon name="trash"/>
                        "Trash"
                    </button>
                    <div class="nav-sep"></div>
                    <button class="nav-item" on:click=move |_| on_passkeys.run(())>
                        <Icon name="key"/>
                        "Passkeys"
                    </button>
                    <button class="nav-item" on:click=move |_| on_settings.run(())>
                        <Icon name="settings"/>
                        "Settings"
                    </button>
                    {move || {
                        is_admin
                            .get()
                            .then(|| {
                                view! {
                                    <button
                                        class="nav-item"
                                        on:click=move |_| on_admin.run(())
                                    >
                                        <Icon name="users"/>
                                        "Admin"
                                    </button>
                                }
                            })
                    }}
                </nav>
                <div class="side-foot">
                    <div class="storage">
                        {move || {
                            let data = usage.get();
                            let used = data["used_bytes"].as_u64().unwrap_or(0);
                            let quota = data["effective_quota_bytes"].as_u64().unwrap_or(0);
                            let pct = if quota == 0 {
                                0.0
                            } else {
                                (used as f64 / quota as f64).clamp(0.0, 1.0)
                            };
                            let dash = format!("{:.2} {:.2}", pct * 100.0, 100.0 - pct * 100.0);
                            let label = if quota == 0 {
                                format!("{} used", human_size(used))
                            } else {
                                format!("{} of {}", human_size(used), human_size(quota))
                            };
                            view! {
                                <div class="storage-ring">
                                    <svg viewBox="0 0 36 36" role="img" aria-label="Storage used">
                                        <circle class="ring-bg" cx="18" cy="18" r="15.9155"></circle>
                                        <circle
                                            class="ring-fg"
                                            cx="18"
                                            cy="18"
                                            r="15.9155"
                                            stroke-dasharray=dash
                                        ></circle>
                                    </svg>
                                    <div class="storage-info">
                                        <b>{format!("{:.0}%", pct * 100.0)}</b>
                                        <small class="muted">{label}</small>
                                    </div>
                                </div>
                            }
                        }}
                    </div>
                    <div class="account">
                        <span class="avatar">
                            {move || {
                                username
                                    .get()
                                    .chars()
                                    .next()
                                    .map(|c| c.to_uppercase().to_string())
                                    .unwrap_or_else(|| "?".to_string())
                            }}
                        </span>
                        <div class="who">
                            <b>
                                {move || {
                                    if username.get().is_empty() {
                                        "Signed in".to_string()
                                    } else {
                                        username.get()
                                    }
                                }}
                            </b>
                            <small>"Account"</small>
                        </div>
                    </div>
                    <button class="nav-item" on:click=move |_| on_theme.run(())>
                        <Icon name="sun"/>
                        "Theme"
                    </button>
                    <button class="nav-item" on:click=move |_| on_sign_out.run(())>
                        <Icon name="logout"/>
                        "Sign out"
                    </button>
                </div>
            </aside>
    }
}

/// Breadcrumbs, search, upload/new-folder and list/grid controls.
#[component]
pub(crate) fn Topbar(
    path: RwSignal<String>,
    tab: RwSignal<Tab>,
    search_active: RwSignal<bool>,
    master: RwSignal<Option<MasterKey>>,
    shared_names: RwSignal<Vec<crate::e2ee::ShareDisplay>>,
    query: RwSignal<String>,
    grid: RwSignal<bool>,
    upload_label: RwSignal<String>,
    can_write: Signal<bool>,
    move_drag: RwSignal<Option<Entry>>,
    on_menu: Callback<()>,
    on_load: Callback<String>,
    on_move_into: Callback<(Entry, String)>,
    on_search_submit: Callback<ev::SubmitEvent>,
    on_upload: Callback<ev::Event>,
    on_mkdir: Callback<()>,
) -> impl IntoView {
    let e2ee_master = master;
    view! {
                <header class="topbar">
                    <button
                        class="icon-btn menu-btn"
                        aria-label="Menu"
                        on:click=move |_| on_menu.run(())
                    >
                        <Icon name="menu"/>
                    </button>
                    <div class="crumbs">
                        {move || {
                            if search_active.get() {
                                return vec![
                                    view! { <span class="crumb current">"Search"</span> }
                                        .into_any(),
                                ];
                            }
                            if tab.get() == Tab::Trash {
                                return vec![
                                    view! { <span class="crumb current">"Trash"</span> }
                                        .into_any(),
                                ];
                            }
                            let current = path.get();
                            let segments: Vec<&str> = current
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .collect();
                            let decoded_path = crate::e2ee::decode_display_path_with_shares(
                                e2ee_master.get_untracked().as_ref(),
                                &current,
                                &shared_names.get_untracked(),
                            );
                            let labels: Vec<String> = decoded_path
                                .split('/')
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect();

                            let mut crumbs = vec![
                                view! {
                                    <button
                                        class="crumb"
                                        on:click=move |_| on_load.run("/".to_string())
                                        on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                        on:drop=move |ev: ev::DragEvent| {
                                            ev.prevent_default();
                                            if let Some(src) = move_drag.get_untracked() {
                                                on_move_into.run((src, "/".to_string()));
                                                move_drag.set(None);
                                            }
                                        }
                                    >
                                        <Icon name="cloud"/>
                                    </button>
                                }
                                    .into_any(),
                            ];
                            let mut accumulated = String::new();
                            for (label_index, segment) in segments.into_iter().enumerate() {
                                accumulated.push('/');
                                accumulated.push_str(segment);
                                let target = accumulated.clone();
                                let drop_target = accumulated.clone();
                                let label = labels
                                    .get(label_index)
                                    .cloned()
                                    .unwrap_or_else(|| segment.to_string());
                                crumbs.push(
                                    view! {
                                        <span class="sep">"/"</span>
                                        <button
                                            class="crumb"
                                            on:click=move |_| on_load.run(target.clone())
                                            on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                            on:drop=move |ev: ev::DragEvent| {
                                                ev.prevent_default();
                                                if let Some(src) = move_drag.get_untracked() {
                                                    on_move_into.run((src, drop_target.clone()));
                                                    move_drag.set(None);
                                                }
                                            }
                                        >
                                            {label}
                                        </button>
                                    }
                                        .into_any(),
                                );
                            }
                            crumbs
                        }}
                    </div>
                    <div class="topbar-spacer"></div>
                    <div class="topbar-actions">
                        <form class="search" on:submit=move |ev| on_search_submit.run(ev)>
                            <Icon name="search"/>
                            <input
                                type="search"
                                placeholder="Search files…"
                                prop:value=move || query.get()
                                on:input=move |ev| query.set(event_target_value(&ev))
                            />
                        </form>
                        <Show when=move || can_write.get()>
                            <label class="button primary" title="Upload files">
                                <Icon name="upload"/>
                                <span>{move || upload_label.get()}</span>
                                <input type="file" class="hidden" multiple on:change=move |ev| on_upload.run(ev)/>
                            </label>
                            <button on:click=move |_| on_mkdir.run(()) title="New folder">
                                <Icon name="folder-plus"/>
                                <span class="hide-sm">"New folder"</span>
                            </button>
                        </Show>
                        <div class="segmented" role="group" aria-label="View">
                            <button
                                class="icon-btn"
                                class:active=move || !grid.get()
                                on:click=move |_| grid.set(false)
                                aria-label="List view"
                            >
                                <Icon name="list"/>
                            </button>
                            <button
                                class="icon-btn"
                                class:active=move || grid.get()
                                on:click=move |_| grid.set(true)
                                aria-label="Grid view"
                            >
                                <Icon name="grid"/>
                            </button>
                        </div>
                    </div>
                </header>
    }
}
