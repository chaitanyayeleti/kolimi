//! The authenticated file browser.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, closure::Closure};

use self::actions::FilesContext;
use self::dialogs::BrowserDialogs;
use self::overlays::{ContextMenu, Lightbox, Toasts, UploadTray};
use self::rows::{FileArea, SearchResults, TrashArea};
use self::search::{encrypted_name_hits, received_mounts};
use self::sharing::SharingContext;
use self::shell::{Sidebar, Topbar};
use self::types::{
    Entry, SearchHit, Tab, TrashItem, UploadItem, is_image_name, is_text_name, parent_of,
    parse_entries, parse_results, parse_trash,
};
use self::uploads::UploadContext;
use crate::api;
use crate::app::{View as AppView, encode, encode_path, mark_session_expired, toggle_theme};
use crate::components::Icon;
use crate::dialogs::SettingsTab;

mod actions;
mod dialogs;
mod overlays;
mod rows;
mod search;
mod sharing;
mod shell;
mod types;
mod uploads;

#[component]
pub(crate) fn Browser(view: RwSignal<AppView>) -> impl IntoView {
    let path = RwSignal::new("/".to_string());
    let entries = RwSignal::new(Vec::<Entry>::new());
    let parent = RwSignal::new(Option::<String>::None);
    let error = RwSignal::new(String::new());
    let notice = RwSignal::new(String::new());
    let tab = RwSignal::new(Tab::Files);
    let trash = RwSignal::new(Vec::<TrashItem>::new());
    let share_target = RwSignal::new(Option::<Entry>::None);
    let versions_for = RwSignal::new(Option::<Entry>::None);
    let vault_setup = RwSignal::new(false);
    let upload_label = RwSignal::new("Upload".to_string());
    let query = RwSignal::new(String::new());
    let results = RwSignal::new(Vec::<SearchHit>::new());
    let search_active = RwSignal::new(false);
    let settings_tab = RwSignal::new(SettingsTab::Encryption);
    let admin_open = RwSignal::new(false);
    let is_admin = RwSignal::new(false);
    let username = RwSignal::new(String::new());
    let nav_open = RwSignal::new(false);
    let grid = RwSignal::new(false);
    let dragging = RwSignal::new(false);
    let e2ee_master = RwSignal::new(Option::<MasterKey>::None);
    let e2ee_open = RwSignal::new(false);
    let open_settings = Callback::new(move |tab: SettingsTab| {
        settings_tab.set(tab);
        e2ee_open.set(true);
    });
    let open_encryption = Callback::new(move |_: ()| {
        open_settings.run(SettingsTab::Encryption);
    });
    let quota_warn = RwSignal::new(Option::<u8>::None);
    let usage = RwSignal::new(Value::Null);
    let loading = RwSignal::new(false);
    // Whether the folder being shown is encrypted (so it can be hidden while
    // locked). Comes from the browse response, which inherits the folder flag.
    let folder_encrypted = RwSignal::new(false);
    let context_menu = RwSignal::new(Option::<(Entry, i32, i32)>::None);
    let lightbox = RwSignal::new(Option::<Entry>::None);
    let move_drag = RwSignal::new(Option::<Entry>::None);
    // A reload in the same tab keeps the unlock: the master key lives in
    // sessionStorage until the tab closes, Lock, or sign out.
    if e2ee_master.get_untracked().is_none()
        && let Some(recalled) = crate::e2ee::recalled_master()
    {
        e2ee_master.set(Some(recalled));
    }
    // A web recipient must publish an MLS key package before anyone can
    // share an encrypted folder with them. This is idempotent per device.
    Effect::new(move |_| {
        if let Some(master) = e2ee_master.get() {
            spawn_local(async move {
                if crate::mls::publish_key_package(&master).await.is_ok() {
                    let _ = crate::mls::refresh_owned_groups(&master).await;
                }
            });
        }
    });
    let undo = RwSignal::new(Option::<(String, i64)>::None);
    let uploads = RwSignal::new(Vec::<UploadItem>::new());
    let upload_seq = RwSignal::new(0u32);
    let selected = RwSignal::new(std::collections::HashSet::<String>::new());
    // Administrators get the user-management panel.
    spawn_local(async move {
        if let Ok(r) = api::get("/api/me").await
            && r.status == 200
        {
            is_admin.set(r.body["is_admin"].as_bool().unwrap_or(false));
            username.set(r.body["username"].as_str().unwrap_or_default().to_string());
        }
        if let Ok(r) = api::get("/api/me/usage").await
            && r.status == 200
        {
            usage.set(r.body);
        }
    });

    // First login: offer to create the Vault passphrase. Dismissal is
    // remembered, and Vault prompts again the first time it is used, so
    // nobody is forced through it before they need encryption.
    Effect::new(move |_| {
        if e2ee_master.get_untracked().is_some() || vault_setup.get_untracked() {
            return;
        }
        let dismissed = web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item("kolimi.vault.dismissed").ok().flatten())
            .is_some();
        if dismissed {
            return;
        }
        spawn_local(async move {
            if crate::e2ee::keyring_exists().await == Ok(false) {
                vault_setup.set(true);
            }
        });
    });

    // Detect session expiry while the app stays open: poll and fall back to
    // the login view instead of leaving a dead Browser view.
    {
        let check = Closure::<dyn FnMut()>::new(move || {
            spawn_local(async move {
                if let Ok(r) = api::get("/api/me").await
                    && r.status == 401
                {
                    view.set(AppView::Login);
                }
            });
        });
        if let Some(window) = web_sys::window() {
            let _ = window.set_interval_with_callback_and_timeout_and_arguments_0(
                check.as_ref().unchecked_ref(),
                60_000,
            );
        }
        check.forget();
    }

    // Navigation is a signal: setting `nav` loads it, so a missing folder can
    // fall back to the root without recursive closures.
    let nav = RwSignal::new("/".to_string());
    let load = move |next: String| nav.set(next);
    let undo_trash = Callback::new(move |_: ()| {
        if let Some((_, id)) = undo.get_untracked() {
            spawn_local(async move {
                let _ =
                    api::send_json("POST", &format!("/api/trash/{id}/restore"), &json!({})).await;
                undo.set(None);
                load(path.get_untracked());
            });
        }
    });
    let load_seq = RwSignal::new(0u32);
    // Mounts received from others, with their permissions: gates Upload /
    // New folder inside read-only shared folders. `shared_names` carries the
    // unwrapped display name (and, for folders, the name key) per mount.
    let received = RwSignal::new(Vec::<Value>::new());
    let shared_names = RwSignal::new(Vec::<crate::e2ee::ShareDisplay>::new());
    // Whether the current folder accepts writes: the own tree always does;
    // a received mount only with "write" permission.
    let can_write_here = move |current: &str| {
        let current = current.trim_end_matches('/');
        if current.is_empty() || current == "/Shared with me" {
            return current.is_empty();
        }
        if let Some(rest) = current.strip_prefix("/Shared with me/") {
            let mount = format!("/Shared with me/{}", rest.split('/').next().unwrap_or(""));
            return received.get_untracked().iter().any(|m| {
                m["mount"].as_str() == Some(mount.as_str()) && m["permission"] == "write"
            });
        }
        true
    };
    let refresh_usage = move || {
        spawn_local(async move {
            if let Ok(r) = api::get("/api/me/usage").await
                && r.status == 200
            {
                usage.set(r.body);
            }
        });
    };
    Effect::new(move |_| {
        let requested = nav.get();
        // Navigating leaves any multi-select behind.
        selected.set(std::collections::HashSet::new());
        loading.set(true);
        let seq = load_seq.get_untracked().wrapping_add(1);
        load_seq.set(seq);
        spawn_local(async move {
            let master = e2ee_master.get_untracked();
            let (mounts, names) = received_mounts(master.as_ref()).await;
            received.set(mounts);
            shared_names.set(names);
            let shares = shared_names.get_untracked();
            let url = format!("/api/browse?path={}", encode(&requested));
            let result = api::get(&url).await;
            // A newer navigation supersedes this response: don't apply it or
            // clear the loading state.
            if load_seq.get_untracked() != seq {
                return;
            }
            match result {
                Ok(r) if r.status == 200 => {
                    folder_encrypted.set(r.body["encrypted"].as_bool().unwrap_or(false));
                    entries.set(parse_entries(&r.body, master.as_ref(), &shares));
                    parent.set(
                        r.body
                            .get("parent")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    );
                    path.set(
                        r.body
                            .get("path")
                            .and_then(Value::as_str)
                            .unwrap_or(&requested)
                            .to_string(),
                    );
                    error.set(String::new());
                }
                Ok(r) if r.status == 401 => {
                    crate::e2ee::forget_master();
                    mark_session_expired();
                    view.set(AppView::Login);
                }
                Ok(r) if r.status == 404 && requested != "/" => {
                    // Renamed or removed: show the files instead of an error
                    // the user cannot act on.
                    error.set("That folder no longer exists — showing your files.".to_string());
                    nav.set("/".to_string());
                }
                Ok(r) if r.status == 403 => {
                    error.set("You don't have access to that folder.".to_string());
                }
                Ok(r) => error.set(format!(
                    "Couldn't load this folder (HTTP {}). Please try again.",
                    r.status
                )),
                Err(_) => error.set(
                    "Couldn't reach the server. Check your connection and try again.".to_string(),
                ),
            }
            loading.set(false);
        });
    });

    let load_trash = move || {
        spawn_local(async move {
            match api::get("/api/trash").await {
                Ok(r) if r.status == 200 => trash.set(parse_trash(
                    &r.body,
                    e2ee_master.get_untracked().as_ref(),
                    &shared_names.get_untracked(),
                )),
                Ok(r) => error.set(r.error().unwrap_or("Could not load trash").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    // Toasts fade themselves out. A timer only clears the toast if it still
    // shows the message it was scheduled for, so a stale timer cannot wipe a
    // newer one.
    Effect::new(move |_| {
        let current = error.get();
        if !current.is_empty() {
            let clear = Closure::once_into_js(move || {
                if error.get_untracked() == current {
                    error.set(String::new());
                }
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    6000,
                );
            }
        }
    });
    Effect::new(move |_| {
        let current = notice.get();
        if !current.is_empty() {
            let clear = Closure::once_into_js(move || {
                if notice.get_untracked() == current {
                    notice.set(String::new());
                }
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    4000,
                );
            }
        }
    });
    // Undo and quota toasts dismiss themselves too, so they never cover
    // the screen until clicked.
    Effect::new(move |_| {
        if undo.get().is_some() {
            let clear = Closure::once_into_js(move || {
                undo.set(None);
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    15000,
                );
            }
        }
    });
    Effect::new(move |_| {
        if quota_warn.get().is_some() {
            let clear = Closure::once_into_js(move || {
                quota_warn.set(None);
            });
            if let Some(window) = web_sys::window() {
                let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                    clear.unchecked_ref::<js_sys::Function>(),
                    15000,
                );
            }
        }
    });

    let sign_out = move |_| {
        // Full navigation, not a fetch: the server deletes the session row,
        // clears the cookies and redirects to the app. No SPA state, cache
        // entry or stale cookie can bring the session back on refresh.
        crate::e2ee::forget_master();
        if let Some(window) = web_sys::window() {
            let _ = window.location().assign("/logout");
        }
    };

    let open = move |entry: Entry| {
        if entry.kind == "dir" {
            load(entry.path);
        } else if is_image_name(&entry.name) || is_text_name(&entry.name) {
            lightbox.set(Some(entry));
        }
    };

    let mkdir = move |_| {
        let Some(name) = api::prompt("New folder name", "") else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let current = path.get_untracked();
        spawn_local(async move {
            let encrypted = crate::e2ee::file_info(&current)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            let writable_share = match e2ee_master.get_untracked() {
                Some(master) => crate::mls::encode_shared_name(&master, &current, &name).await,
                None => Ok(None),
            };
            let folder_name = match writable_share {
                Ok(Some(encoded)) => encoded,
                Ok(None) => {
                    if encrypted {
                        let Some(master) = e2ee_master.get_untracked() else {
                            error.set(
                                "Unlock encryption first (Settings → Encryption).".to_string(),
                            );
                            open_settings.run(SettingsTab::Encryption);
                            return;
                        };
                        let parent_plaintext =
                            crate::e2ee::decode_display_path(Some(&master), &current);
                        match crate::e2ee::encode_component(&master, &parent_plaintext, &name) {
                            Ok(encoded) => encoded,
                            Err(e) => {
                                error.set(e);
                                return;
                            }
                        }
                    } else {
                        name
                    }
                }
                Err(e) => {
                    error.set(e);
                    return;
                }
            };
            let url = format!(
                "/dav{}",
                encode_path(&format!(
                    "{}/{}",
                    current.trim_end_matches('/'),
                    folder_name
                ))
            );
            match api::dav("MKCOL", &url, None, &[]).await {
                Ok(r) if r.status == 201 => load(current),
                Ok(r) => error.set(format!("Could not create folder (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    let ctx_open = Callback::new(move |entry: Entry| open(entry));
    let file_load = Callback::new(move |next: String| load(next));
    let load_trash_cb = Callback::new(move |_: ()| load_trash());
    let files_ctx = FilesContext {
        path,
        entries,
        selected,
        master: e2ee_master,
        error,
        notice,
        undo,
        load: file_load,
        load_trash: load_trash_cb,
        refresh_usage: Callback::new(move |_: ()| refresh_usage()),
        open_encryption,
    };
    let file_actions = actions::actions(files_ctx);
    let ctx_decrypt = file_actions.decrypt;
    let ctx_rename = file_actions.rename;
    let ctx_delete = file_actions.delete;
    let ctx_versions = Callback::new(move |entry: Entry| versions_for.set(Some(entry)));
    let file_toggle_select = file_actions.toggle_select;
    let file_move_into = file_actions.move_into;
    let sharing_ctx = SharingContext {
        master: e2ee_master,
        error,
        notice,
        share_target,
        encrypting: RwSignal::new(false),
        load: file_load,
        open_encryption,
    };
    let ctx_share = Callback::new(move |entry: Entry| sharing::share_entry(sharing_ctx, entry));
    let ctx_toggle_encryption =
        Callback::new(move |entry: Entry| sharing::toggle_encryption(sharing_ctx, entry));
    let upload_ctx = UploadContext {
        uploads,
        upload_seq,
        path,
        master: e2ee_master,
        quota_warn,
        notice,
        error,
        vault_setup,
        dragging,
        load: file_load,
        refresh_usage: Callback::new(move |_: ()| refresh_usage()),
        open_encryption,
    };
    let upload = move |ev: ev::Event| uploads::upload_event(upload_ctx, ev);
    let drop_files = move |ev: ev::DragEvent| uploads::drop_files(upload_ctx, ev);
    let retry_upload = Callback::new(move |args| uploads::retry_upload(upload_ctx, args));

    let search_open = Callback::new(move |hit: SearchHit| {
        search_active.set(false);
        if hit.is_dir {
            load(hit.path);
        } else {
            load(parent_of(&hit.path));
        }
    });
    let trash_restore = file_actions.restore;
    let trash_purge = file_actions.purge;
    let bulk_download = move |_| file_actions.bulk_download.run(());
    let bulk_move = move |_| file_actions.bulk_move.run(());
    let bulk_trash = move |_| file_actions.bulk_trash.run(());

    let search_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let text = query.get_untracked();
        if text.trim().is_empty() {
            search_active.set(false);
            return;
        }
        spawn_local(async move {
            let url = format!("/api/search?q={}&limit=50", encode(&text));
            match api::get(&url).await {
                Ok(r) if r.status == 200 => {
                    let master = e2ee_master.get_untracked();
                    let shares = shared_names.get_untracked();
                    let mut hits = parse_results(&r.body, master.as_ref(), &shares);
                    // The server cannot search ciphertext names; supplement
                    // with a client-side name search while unlocked.
                    if let Some(master) = &master {
                        let known: std::collections::HashSet<String> =
                            hits.iter().map(|hit| hit.path.clone()).collect();
                        for hit in encrypted_name_hits(master, &text, &shares).await {
                            if !known.contains(&hit.path) {
                                hits.push(hit);
                            }
                        }
                    }
                    results.set(hits);
                    search_active.set(true);
                    error.set(String::new());
                }
                Ok(r) => error.set(r.error().unwrap_or("Search failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };
    let clear_search = Callback::new(move |_: ()| {
        search_active.set(false);
        results.set(Vec::new());
        query.set(String::new());
    });

    let nav_files = Callback::new(move |_: ()| {
        search_active.set(false);
        tab.set(Tab::Files);
        load(path.get_untracked());
        nav_open.set(false);
    });
    let nav_trash = Callback::new(move |_: ()| {
        search_active.set(false);
        tab.set(Tab::Trash);
        load_trash();
        nav_open.set(false);
    });
    let nav_passkeys = Callback::new(move |_: ()| {
        open_settings.run(SettingsTab::Passkeys);
    });
    let nav_settings = Callback::new(move |_: ()| {
        open_settings.run(SettingsTab::Encryption);
    });
    let nav_admin = Callback::new(move |_: ()| admin_open.set(true));
    let nav_theme = Callback::new(move |_: ()| toggle_theme());
    let nav_sign_out = Callback::new(move |_: ()| sign_out(()));
    let top_menu = Callback::new(move |_: ()| nav_open.set(!nav_open.get_untracked()));
    let top_search = Callback::new(move |ev: ev::SubmitEvent| search_submit(ev));
    let top_upload = Callback::new(move |ev: ev::Event| upload(ev));
    let top_mkdir = Callback::new(move |_: ()| mkdir(()));
    let can_write = Signal::derive(move || can_write_here(&path.get()));

    view! {
        <div
            class="shell"
            class:nav-open=move || nav_open.get()
            on:dragover=move |ev| {
                ev.prevent_default();
                dragging.set(true);
            }
            on:dragleave=move |_| dragging.set(false)
            on:drop=drop_files
        >
            <div class="nav-scrim" on:click=move |_| nav_open.set(false)></div>
            <div class="dropzone" class:active=move || dragging.get()>
                <div class="dropzone-inner">
                    <Icon name="upload"/>
                    <p>"Drop files to upload"</p>
                </div>
            </div>
            <Sidebar
                tab=tab
                search_active=search_active
                is_admin=is_admin
                usage=usage
                username=username
                on_files=nav_files
                on_trash=nav_trash
                on_passkeys=nav_passkeys
                on_settings=nav_settings
                on_admin=nav_admin
                on_theme=nav_theme
                on_sign_out=nav_sign_out
            />

            <div class="main">
                <Topbar
                    path=path
                    tab=tab
                    search_active=search_active
                    master=e2ee_master
                    shared_names=shared_names
                    query=query
                    grid=grid
                    upload_label=upload_label
                    can_write=can_write
                    move_drag=move_drag
                    on_menu=top_menu
                    on_load=file_load
                    on_move_into=file_move_into
                    on_search_submit=top_search
                    on_upload=top_upload
                    on_mkdir=top_mkdir
                />
                <main class="content">
                    <Show when=move || !selected.get().is_empty()>
                        <div class="bulk-bar">
                            <span class="bulk-count">
                                {move || format!("{} selected", selected.get().len())}
                            </span>
                            <button on:click=bulk_download>"Download"</button>
                            <button on:click=bulk_move>"Move to…"</button>
                            <button class="danger" on:click=bulk_trash>"Trash"</button>
                            <button
                                on:click=move |_| selected.set(std::collections::HashSet::new())
                            >
                                "Clear"
                            </button>
                        </div>
                    </Show>

        {move || {
            if search_active.get() {
                return view! {
                    <SearchResults
                        results=results
                        master=e2ee_master
                        shared_names=shared_names
                        on_open=search_open
                        on_decrypt=ctx_decrypt
                        on_clear=clear_search
                    />
                }
                    .into_any();
            }
            match tab.get() {
                Tab::Files => {
                    view! {
                        <FileArea
                            parent=parent
                            loading=loading
                            folder_encrypted=folder_encrypted
                            master=e2ee_master
                            entries=entries
                            grid=grid
                            selected=selected
                            move_drag=move_drag
                            context_menu=context_menu
                            lightbox=lightbox
                            on_load=file_load
                            on_open=ctx_open
                            on_toggle_select=file_toggle_select
                            on_move_into=file_move_into
                            on_decrypt=ctx_decrypt
                            on_share=ctx_share
                            on_rename=ctx_rename
                            on_delete=ctx_delete
                            on_unlock=open_encryption
                        />
                    }
                        .into_any()
                }
                Tab::Trash => {
                    view! {
                        <TrashArea
                            trash=trash
                            on_restore=trash_restore
                            on_purge=trash_purge
                        />
                    }
                        .into_any()
                }
            }
        }}
                </main>
            </div>

            <Toasts
                error=error
                notice=notice
                quota_warn=quota_warn
                undo=undo
                on_undo=undo_trash
            />
            <UploadTray uploads=uploads on_retry=retry_upload/>
            <ContextMenu
                menu=context_menu
                on_open=ctx_open
                on_decrypt=ctx_decrypt
                on_share=ctx_share
                on_rename=ctx_rename
                on_delete=ctx_delete
                on_versions=ctx_versions
                on_toggle_encryption=ctx_toggle_encryption
            />
            <Lightbox
                open=lightbox
                master=e2ee_master
                error=error
                on_unlock=open_encryption
                on_decrypt=ctx_decrypt
            />


            <BrowserDialogs
                vault_setup=vault_setup
                share_target=share_target
                versions_for=versions_for
                admin_open=admin_open
                e2ee_open=e2ee_open
                master_signal=e2ee_master
                settings_tab=settings_tab
                current_path=path
                notice=notice
                on_load=file_load
            />
        </div>
    }
}
