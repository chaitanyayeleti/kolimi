//! The authenticated file browser.

use kolimi_crypto::MasterKey;
use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, closure::Closure};

use self::overlays::{ContextMenu, Lightbox, Toasts, UploadTray};
use self::rows::{FileArea, SearchResults, TrashArea};
use self::search::{encrypted_name_hits, received_mounts};
use self::types::{
    Entry, SearchHit, Tab, TrashItem, UploadItem, UploadStatus, is_image_name, is_text_name,
    parent_of, parse_entries, parse_results, parse_trash,
};
use crate::api;
use crate::app::{
    Logo, View as AppView, encode, encode_path, human_size, mark_session_expired, toggle_theme,
};
use crate::components::Icon;
use crate::dialogs::{
    AdminDialog, SettingsDialog, SettingsTab, ShareDialog, VaultSetupDialog, VersionsDialog,
};

mod overlays;
mod rows;
mod search;
mod types;

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

    // Uploads one file, tracking it in the tray via its own signals.
    // Encrypted destinations are encrypted client-side first (chunks +
    // manifest + wrapped key, like the sync client); plaintext uploads
    // stream the Blob straight from disk with no WASM-side copy.
    let start_upload = move |file: web_sys::File,
                             dir: String,
                             progress: RwSignal<u8>,
                             status: RwSignal<UploadStatus>| {
        let plain_name = file.name();
        let tray = uploads;
        spawn_local(async move {
            // Shared helper: mark this row done/failed and refresh when the
            // tray has no in-flight uploads left.
            let finish = move |ok: bool, warning: Option<u8>| {
                if let Some(percent) = warning {
                    quota_warn.set(Some(percent));
                }
                status.set(if ok {
                    UploadStatus::Done
                } else {
                    UploadStatus::Failed
                });
                if !tray
                    .get_untracked()
                    .iter()
                    .any(|item| item.status.get_untracked() == UploadStatus::Uploading)
                {
                    let snapshot = tray.get_untracked();
                    let done = snapshot
                        .iter()
                        .filter(|item| item.status.get_untracked() == UploadStatus::Done)
                        .count();
                    let failed = snapshot
                        .iter()
                        .filter(|item| item.status.get_untracked() == UploadStatus::Failed)
                        .count();
                    if failed == 0 {
                        notice.set(format!(
                            "Uploaded {done} file{}",
                            if done == 1 { "" } else { "s" }
                        ));
                    } else {
                        error.set(format!("Uploaded {done}, {failed} failed"));
                    }
                    tray.update(|list| {
                        list.retain(|item| item.status.get_untracked() != UploadStatus::Done);
                    });
                    load(path.get_untracked());
                    refresh_usage();
                }
            };
            let encrypted = crate::e2ee::file_info(&dir)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            // A writable received share is encrypted with the owner's name
            // key and MLS keyring, not this account's Vault keys.
            if crate::mls::is_writable_shared(&dir).await {
                let Some(master) = e2ee_master.get_untracked() else {
                    finish(false, None);
                    error.set("Unlock encryption to write to this shared folder.".to_string());
                    open_settings.run(SettingsTab::Encryption);
                    return;
                };
                let bytes = match api::read_file(&file).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                        return;
                    }
                };
                progress.set(50);
                match crate::mls::upload_shared(&master, &dir, &plain_name, &bytes).await {
                    Ok(()) => {
                        progress.set(100);
                        finish(true, None);
                    }
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                    }
                }
                return;
            }
            if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    finish(false, None);
                    // First use of an encrypted folder: create the Vault
                    // passphrase if none exists, otherwise unlock it.
                    if crate::e2ee::keyring_exists().await == Ok(false) {
                        vault_setup.set(true);
                    } else {
                        error.set(
                            "This folder is encrypted — unlock it to upload (Encryption in the sidebar)."
                                .to_string(),
                        );
                        open_settings.run(SettingsTab::Encryption);
                    }
                    return;
                };
                let bytes = match api::read_file(&file).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                        return;
                    }
                };
                // The server must not learn the name: encode it as one
                // opaque path segment inside the encrypted folder.
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dir);
                let target =
                    match crate::e2ee::encode_component(&master, &parent_plaintext, &plain_name) {
                        Ok(encoded) => format!("{}/{}", dir.trim_end_matches('/'), encoded),
                        Err(e) => {
                            finish(false, None);
                            error.set(e);
                            return;
                        }
                    };
                progress.set(50);
                match crate::e2ee::upload_encrypted(&master, &target, &bytes).await {
                    Ok(()) => {
                        progress.set(100);
                        finish(true, None);
                    }
                    Err(e) => {
                        finish(false, None);
                        error.set(e);
                    }
                }
                return;
            }
            let target = format!("{}/{}", dir.trim_end_matches('/'), plain_name);
            let url = format!("/dav{}", encode_path(&target));
            let file_name = plain_name;
            let blob = web_sys::Blob::from(file);
            api::upload_blob(
                &url,
                &blob,
                move |pct| progress.set(pct),
                move |result| {
                    let (ok, warning) = match result {
                        Ok((code, warning)) => {
                            if !matches!(code, 201 | 204) {
                                error.set(format!(
                                    "Upload of “{}” failed (HTTP {code}){}.{}",
                                    file_name,
                                    if code == 403 {
                                        " — the session or CSRF token was rejected"
                                    } else if code == 413 {
                                        " — file too large"
                                    } else {
                                        ""
                                    },
                                    if code == 403 {
                                        " Try signing out and in again."
                                    } else {
                                        ""
                                    },
                                ));
                            }
                            (matches!(code, 201 | 204), warning)
                        }
                        Err(e) => {
                            error.set(format!("Upload of “{}” failed: {e}", file_name));
                            (false, None)
                        }
                    };
                    finish(ok, warning);
                },
            );
        });
    };

    let upload_files = move |files: Vec<web_sys::File>| {
        if files.is_empty() {
            return;
        }
        let dir = path.get_untracked();
        for file in files {
            let id = upload_seq.get_untracked() + 1;
            upload_seq.set(id);
            let progress = RwSignal::new(0u8);
            let status = RwSignal::new(UploadStatus::Uploading);
            uploads.update(|list| {
                list.push(UploadItem {
                    id,
                    name: file.name(),
                    dir: dir.clone(),
                    progress,
                    status,
                    file: file.clone(),
                });
            });
            start_upload(file, dir.clone(), progress, status);
        }
    };

    let collect_files = move |files: web_sys::FileList| {
        let mut selected = Vec::new();
        for index in 0..files.length() {
            if let Some(file) = files.get(index) {
                selected.push(file);
            }
        }
        selected
    };

    let retry_upload = Callback::new(
        move |(file, dir, progress, status): (
            web_sys::File,
            String,
            RwSignal<u8>,
            RwSignal<UploadStatus>,
        )| {
            progress.set(0);
            status.set(UploadStatus::Uploading);
            start_upload(file, dir, progress, status);
        },
    );

    let upload = move |ev: ev::Event| {
        let Some(input) = ev
            .target()
            .and_then(|target| target.dyn_into::<web_sys::HtmlInputElement>().ok())
        else {
            return;
        };
        let Some(files) = input.files() else {
            return;
        };
        let selected = collect_files(files);
        // Reset so the same files can be chosen again later.
        input.set_value("");
        upload_files(selected);
    };

    let drop_files = move |ev: ev::DragEvent| {
        ev.prevent_default();
        dragging.set(false);
        let Some(transfer) = ev.data_transfer() else {
            return;
        };
        if let Some(files) = transfer.files() {
            let selected = collect_files(files);
            if selected.is_empty() {
                // A folder (not files) was dropped: browsers only expose
                // files here, so say so instead of failing silently.
                let types = transfer.types();
                if (0..types.length())
                    .filter_map(|i| types.get(i).as_string())
                    .any(|kind| kind == "Files")
                {
                    error.set(
                        "That looks like a folder — drag-and-drop takes files only. Create the folder first, then drop the files inside.".to_string(),
                    );
                }
                return;
            }
            upload_files(selected);
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

    // Encrypted content must be unlocked before it can be shared, renamed,
    // moved, or deleted: while locked, Vault is read-only. (The server
    // cannot verify key possession, so this guard is client-side — but it
    // stops the accidental "I deleted my Vault while it was locked".)
    let require_unlock = move |entry: &Entry| -> bool {
        if !entry.encrypted || e2ee_master.get_untracked().is_some() {
            return true;
        }
        error.set("Vault is locked — unlock encryption first (Settings → Encryption).".to_string());
        open_settings.run(SettingsTab::Encryption);
        false
    };

    let delete_entry = move |entry: Entry| {
        if !require_unlock(&entry) {
            return;
        }
        if !api::confirm(&format!("Move “{}” to trash?", entry.name)) {
            return;
        }
        let current = path.get_untracked();
        let entry_path = entry.path.clone();
        let entry_name = entry.name.clone();
        spawn_local(async move {
            let url = format!("/dav{}", encode_path(&entry_path));
            match api::dav("DELETE", &url, None, &[]).await {
                Ok(r) if r.status == 204 => {
                    // Find the trashed node so the move can be undone.
                    if let Ok(tr) = api::get("/api/trash").await
                        && tr.status == 200
                        && let Some(items) = tr.body.as_array()
                        && let Some(id) = items
                            .iter()
                            .find(|item| {
                                item["original_path"].as_str() == Some(entry_path.as_str())
                            })
                            .and_then(|item| item["id"].as_i64())
                    {
                        undo.set(Some((entry_name.clone(), id)));
                    }
                    if let Some(master) = e2ee_master.get_untracked() {
                        let _ = crate::mls::remove_path_prefix(&master, &entry_path).await;
                    }
                    load(current);
                    refresh_usage();
                }
                Ok(r) => error.set(format!("Delete failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    let rename_entry = move |entry: Entry| {
        if !require_unlock(&entry) {
            return;
        }
        let Some(name) = api::prompt("New name", &entry.name) else {
            return;
        };
        if name.is_empty() || name == entry.name {
            return;
        }
        let current = path.get_untracked();
        let encrypted = entry.encrypted && !entry.shared;
        let shared = entry.shared;
        let source = entry.path.clone();
        spawn_local(async move {
            if shared {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Unlock encryption first (Settings → Encryption).".to_string());
                    open_settings.run(SettingsTab::Encryption);
                    return;
                };
                match crate::mls::encode_shared_name(&master, &current, &name).await {
                    Ok(Some(encoded)) => {
                        let destination = format!("{}/{}", current.trim_end_matches('/'), encoded);
                        let url = format!("/dav{}", encode_path(&source));
                        let dest_dav = format!("/dav{}", encode_path(&destination));
                        match api::dav("MOVE", &url, None, &[("destination", &dest_dav)]).await {
                            Ok(r) if matches!(r.status, 201 | 204) => {
                                let _ =
                                    crate::mls::rename_path_prefix(&master, &source, &destination)
                                        .await;
                                load(current);
                            }
                            Ok(r) => error.set(format!("Rename failed (HTTP {})", r.status)),
                            Err(e) => error.set(e),
                        }
                    }
                    Ok(None) => error.set(
                        "This shared folder is read-only — ask the owner for write access."
                            .to_string(),
                    ),
                    Err(e) => error.set(e),
                }
                return;
            }
            if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_settings.run(SettingsTab::Encryption);
                    return;
                };
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &current);
                let encoded = match crate::e2ee::encode_component(&master, &parent_plaintext, &name)
                {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        error.set(e);
                        return;
                    }
                };
                // Metadata-only server move: works on ciphertext.
                let destination = format!("{}/{}", current.trim_end_matches('/'), encoded);
                match crate::e2ee::move_file(&source, &destination).await {
                    Ok(()) => {
                        let _ =
                            crate::mls::rename_path_prefix(&master, &source, &destination).await;
                        load(current);
                    }
                    Err(e) => error.set(e),
                }
                return;
            }
            let destination = format!(
                "/dav{}",
                encode_path(&format!("{}/{}", current.trim_end_matches('/'), name))
            );
            let url = format!("/dav{}", encode_path(&source));
            match api::dav("MOVE", &url, None, &[("destination", &destination)]).await {
                Ok(r) if matches!(r.status, 201 | 204) => load(current),
                Ok(r) => error.set(format!("Rename failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    // Moves `entry` into `dest_dir` (drag-to-move onto a folder or crumb).
    // Crossing the encryption boundary is refused: plaintext must never land
    // in an encrypted tree, and ciphertext must not become unreadable in a
    // plaintext one.
    let move_into = move |entry: Entry, dest_dir: String| {
        if !require_unlock(&entry) {
            return;
        }
        let source = entry.path.clone();
        let encrypted = entry.encrypted && !entry.shared;
        let name = entry.name.clone();
        spawn_local(async move {
            let dest_encrypted = crate::e2ee::file_info(&dest_dir)
                .await
                .map(|info| info["encrypted"].as_bool().unwrap_or(false))
                .unwrap_or(false);
            if !encrypted && dest_encrypted {
                error.set(format!(
                    "“{name}” is not encrypted — upload it into the Vault so it is encrypted on your device."
                ));
                return;
            }
            if encrypted && !dest_encrypted {
                error.set(
                    "This item is encrypted — it can only move between encrypted folders."
                        .to_string(),
                );
                return;
            }
            let destination = if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_settings.run(SettingsTab::Encryption);
                    return;
                };
                let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dest_dir);
                let encoded = match crate::e2ee::encode_component(&master, &parent_plaintext, &name)
                {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        error.set(e);
                        return;
                    }
                };
                format!("{}/{}", dest_dir.trim_end_matches('/'), encoded)
            } else {
                format!("{}/{}", dest_dir.trim_end_matches('/'), name)
            };
            if destination == source {
                return;
            }
            if encrypted {
                let Some(master) = e2ee_master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_settings.run(SettingsTab::Encryption);
                    return;
                };
                match crate::e2ee::move_file(&source, &destination).await {
                    Ok(()) => {
                        let _ =
                            crate::mls::rename_path_prefix(&master, &source, &destination).await;
                        notice.set(format!("Moved {name}"));
                        load(path.get_untracked());
                    }
                    Err(e) => error.set(e),
                }
                return;
            }
            let dav_source = format!("/dav{}", encode_path(&source));
            let dav_dest = format!("/dav{}", encode_path(&destination));
            match api::dav("MOVE", &dav_source, None, &[("destination", &dav_dest)]).await {
                Ok(r) if matches!(r.status, 201 | 204) => {
                    notice.set(format!("Moved {name}"));
                    load(path.get_untracked());
                }
                Ok(r) => error.set(format!("Move failed (HTTP {})", r.status)),
                Err(e) => error.set(e),
            }
        });
    };

    // ---- Multi-select + bulk actions ----
    let toggle_select = move |target: String| {
        selected.update(|set| {
            if !set.insert(target.clone()) {
                set.remove(&target);
            }
        });
    };

    let bulk_trash = move |_| {
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        // Encrypted selections need an unlock, exactly like single delete.
        let encrypted_selected = entries
            .get_untracked()
            .into_iter()
            .any(|entry| entry.encrypted && paths.contains(&entry.path));
        if encrypted_selected && e2ee_master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            open_settings.run(SettingsTab::Encryption);
            return;
        }
        let current = path.get_untracked();
        let count = paths.len();
        spawn_local(async move {
            let mut failed = 0usize;
            for target in &paths {
                let url = format!("/dav{}", encode_path(target));
                match api::dav("DELETE", &url, None, &[]).await {
                    Ok(r) if (200..300).contains(&r.status) => {
                        if let Some(master) = e2ee_master.get_untracked() {
                            let _ = crate::mls::remove_path_prefix(&master, target).await;
                        }
                    }
                    Ok(r) => {
                        failed += 1;
                        error.set(format!("Delete failed (HTTP {})", r.status));
                    }
                    Err(e) => {
                        failed += 1;
                        error.set(e);
                    }
                }
            }
            selected.set(std::collections::HashSet::new());
            if failed == 0 {
                notice.set(format!("Moved {count} item(s) to trash"));
            }
            load(current);
            refresh_usage();
        });
    };

    let bulk_move = move |_| {
        let Some(dest) = api::prompt("Move selected to (folder path)", "/") else {
            return;
        };
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        // Encrypted entries go through the metadata-only API move; the
        // rest keep using WebDAV.
        let encrypted: std::collections::HashSet<String> = entries
            .get_untracked()
            .into_iter()
            .filter(|e| e.encrypted && !e.shared)
            .map(|e| e.path)
            .collect();
        if encrypted.iter().any(|path| paths.contains(path))
            && e2ee_master.get_untracked().is_none()
        {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            open_settings.run(SettingsTab::Encryption);
            return;
        }
        let count = paths.len();
        spawn_local(async move {
            let mut failed = 0usize;
            for target in &paths {
                let name = target.rsplit('/').next().unwrap_or("file");
                let destination = format!("{}/{}", dest.trim_end_matches('/'), name);
                if encrypted.contains(target) {
                    match crate::e2ee::move_file(target, &destination).await {
                        Ok(()) => {}
                        Err(e) => {
                            failed += 1;
                            error.set(e);
                        }
                    }
                    continue;
                }
                let source = format!("/dav{}", encode_path(target));
                let dav_dest = format!("/dav{}", encode_path(&destination));
                match api::dav("MOVE", &source, None, &[("destination", &dav_dest)]).await {
                    Ok(r) if (200..300).contains(&r.status) => {}
                    Ok(r) => {
                        failed += 1;
                        error.set(format!("Move failed (HTTP {})", r.status));
                    }
                    Err(e) => {
                        failed += 1;
                        error.set(e);
                    }
                }
            }
            selected.set(std::collections::HashSet::new());
            if failed == 0 {
                notice.set(format!("Moved {count} item(s)"));
            }
            load(path.get_untracked());
        });
    };

    let decrypt_entry = move |entry: Entry| {
        let Some(master) = e2ee_master.get_untracked() else {
            error.set("Unlock encryption first (Settings → Encryption).".to_string());
            open_settings.run(SettingsTab::Encryption);
            return;
        };
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
                    crate::e2ee::save_bytes(&name, &bytes);
                    notice.set(format!("Decrypted {name}"));
                }
                Err(e) => error.set(e),
            }
        });
    };

    let bulk_download = move |_| {
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        let known: std::collections::HashMap<String, Entry> = entries
            .get_untracked()
            .into_iter()
            .map(|entry| (entry.path.clone(), entry))
            .collect();
        for target in paths {
            // Encrypted files cannot be fetched as-is: decrypt client-side.
            if let Some(entry) = known.get(&target).filter(|entry| entry.encrypted) {
                decrypt_entry(entry.clone());
                continue;
            }
            let url = format!("/dav{}", encode_path(&target));
            if let Some(document) = web_sys::window().and_then(|window| window.document())
                && let Ok(element) = document.create_element("a")
                && let Ok(anchor) = element.dyn_into::<web_sys::HtmlAnchorElement>()
            {
                anchor.set_href(&url);
                anchor.set_download("");
                anchor.click();
            }
        }
        selected.set(std::collections::HashSet::new());
    };

    let restore = move |item: TrashItem| {
        spawn_local(async move {
            match api::send_json(
                "POST",
                &format!("/api/trash/{}/restore", item.id),
                &json!({}),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(format!("Restored {}", item.name));
                    load_trash();
                    refresh_usage();
                }
                Ok(r) => error.set(r.error().unwrap_or("Restore failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let purge = move |item: TrashItem| {
        if !api::confirm(&format!("Permanently delete “{}”?", item.name)) {
            return;
        }
        spawn_local(async move {
            match api::delete(&format!("/api/trash/{}", item.id)).await {
                Ok(r) if r.status == 204 => {
                    load_trash();
                    refresh_usage();
                }
                Ok(r) => error.set(r.error().unwrap_or("Delete failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    let share_entry = move |entry: Entry| {
        if entry.encrypted && e2ee_master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption before sharing, or the recipient gets no key."
                    .to_string(),
            );
            open_settings.run(SettingsTab::Encryption);
            return;
        }
        share_target.set(Some(entry));
    };

    // Declares a folder encrypted (or plaintext). The server flag is what
    // every client reads, so this is the only switch that matters. Making a
    // non-empty folder encrypted first re-uploads every plaintext file
    // encrypted, then flips the flag: the server refuses a mixed folder, and
    // leaving plaintext behind would break the "anything inside is encrypted"
    // promise. Already-encrypted files are skipped, so an interrupted run can
    // simply be retried.
    let encrypting = RwSignal::new(false);
    let toggle_encryption = move |entry: Entry| {
        if encrypting.get_untracked() {
            return;
        }
        let path = entry.path.clone();
        let parent = path
            .rsplit_once('/')
            .map(|(dir, _)| {
                if dir.is_empty() {
                    "/".to_string()
                } else {
                    dir.to_string()
                }
            })
            .unwrap_or_else(|| "/".to_string());
        if entry.encrypted {
            spawn_local(async move {
                match api::send_json(
                    "POST",
                    "/api/files/encrypt",
                    &json!({ "path": path, "encrypted": false }),
                )
                .await
                {
                    Ok(r) if r.status == 200 => {
                        notice.set("Folder is now plaintext".to_string());
                        load(parent);
                    }
                    Ok(r) => error.set(
                        r.error()
                            .unwrap_or("Could not change encryption")
                            .to_string(),
                    ),
                    Err(e) => error.set(e),
                }
            });
            return;
        }
        let Some(master) = e2ee_master.get_untracked() else {
            error.set("Unlock encryption first (Settings → Encryption).".to_string());
            open_settings.run(SettingsTab::Encryption);
            return;
        };
        encrypting.set(true);
        spawn_local(async move {
            let files = match crate::e2ee::plaintext_files_under(&path).await {
                Ok(files) => files,
                Err(e) => {
                    error.set(e);
                    encrypting.set(false);
                    return;
                }
            };
            if !files.is_empty() {
                let message = format!(
                    "Encrypt {} existing file{} in this folder now? They will be re-uploaded encrypted — keep this tab open until it finishes.",
                    files.len(),
                    if files.len() == 1 { "" } else { "s" }
                );
                let confirmed = web_sys::window()
                    .and_then(|window| window.confirm_with_message(&message).ok())
                    .unwrap_or(false);
                if !confirmed {
                    encrypting.set(false);
                    return;
                }
            }
            let total = files.len();
            for (index, file) in files.iter().enumerate() {
                let name = file.path.rsplit('/').next().unwrap_or(&file.path);
                notice.set(format!("Encrypting {} of {}: {name}", index + 1, total));
                let bytes = match api::get_bytes(&format!("/dav{}", encode_path(&file.path))).await
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error.set(format!("Could not read “{}”: {e}", file.path));
                        load(parent.clone());
                        encrypting.set(false);
                        return;
                    }
                };
                // Also encrypt the name. A legacy plaintext name is first
                // moved to its encoded form (metadata-only), then the content
                // is encrypted in place. Names that are already encoded
                // (an interrupted earlier run) are left alone.
                let (dir, name) = file
                    .path
                    .rsplit_once('/')
                    .map(|(dir, name)| (dir.to_string(), name.to_string()))
                    .unwrap_or_else(|| ("/".to_string(), file.path.clone()));
                let target = if kolimi_crypto::is_encoded_name(&name) {
                    file.path.clone()
                } else {
                    let parent_plaintext = crate::e2ee::decode_display_path(Some(&master), &dir);
                    let encoded =
                        match crate::e2ee::encode_component(&master, &parent_plaintext, &name) {
                            Ok(encoded) => encoded,
                            Err(e) => {
                                error.set(e);
                                encrypting.set(false);
                                return;
                            }
                        };
                    let target = format!("{dir}/{encoded}");
                    if let Err(e) = crate::e2ee::move_file(&file.path, &target).await {
                        error.set(format!("Renaming “{name}” for encryption failed: {e}"));
                        load(parent.clone());
                        encrypting.set(false);
                        return;
                    }
                    target
                };
                if let Err(e) = crate::e2ee::upload_encrypted_versioned(
                    &master,
                    &target,
                    &bytes,
                    file.content_id.as_deref(),
                )
                .await
                {
                    error.set(format!("Encrypting “{}” failed: {e}", file.path));
                    load(parent.clone());
                    encrypting.set(false);
                    return;
                }
            }
            match api::send_json(
                "POST",
                "/api/files/encrypt",
                &json!({ "path": path, "encrypted": true }),
            )
            .await
            {
                Ok(r) if r.status == 200 => {
                    notice.set(if total == 0 {
                        "Folder encrypted — new files are encrypted on your device".to_string()
                    } else {
                        format!(
                            "Folder encrypted — {total} file{} encrypted on your device",
                            if total == 1 { "" } else { "s" }
                        )
                    });
                    load(parent);
                }
                Ok(r) => error.set(
                    r.error()
                        .unwrap_or("Could not change encryption")
                        .to_string(),
                ),
                Err(e) => error.set(e),
            }
            encrypting.set(false);
        });
    };

    let ctx_open = Callback::new(move |entry: Entry| open(entry));
    let ctx_decrypt = Callback::new(move |entry: Entry| decrypt_entry(entry));
    let ctx_share = Callback::new(move |entry: Entry| share_entry(entry));
    let ctx_rename = Callback::new(move |entry: Entry| rename_entry(entry));
    let ctx_delete = Callback::new(move |entry: Entry| delete_entry(entry));
    let ctx_versions = Callback::new(move |entry: Entry| versions_for.set(Some(entry)));
    let ctx_toggle_encryption = Callback::new(move |entry: Entry| toggle_encryption(entry));
    let file_load = Callback::new(move |next: String| load(next));
    let file_toggle_select = Callback::new(move |target: String| toggle_select(target));
    let file_move_into =
        Callback::new(move |(entry, dest): (Entry, String)| move_into(entry, dest));
    let search_open = Callback::new(move |hit: SearchHit| {
        search_active.set(false);
        if hit.is_dir {
            load(hit.path);
        } else {
            load(parent_of(&hit.path));
        }
    });
    let trash_restore = Callback::new(move |item: TrashItem| restore(item));
    let trash_purge = Callback::new(move |item: TrashItem| purge(item));

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
            <aside class="sidebar">
                <a class="side-brand" href="/app/">
                    <Logo/>
                    "Kolimi"
                </a>
                <nav class="nav">
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Files && !search_active.get()
                        on:click=move |_| {
                            search_active.set(false);
                            tab.set(Tab::Files);
                            load(path.get_untracked());
                            nav_open.set(false);
                        }
                    >
                        <Icon name="folder"/>
                        "Files"
                    </button>
                    <button
                        class="nav-item"
                        class:active=move || tab.get() == Tab::Trash
                        on:click=move |_| {
                            search_active.set(false);
                            tab.set(Tab::Trash);
                            load_trash();
                            nav_open.set(false);
                        }
                    >
                        <Icon name="trash"/>
                        "Trash"
                    </button>
                    <div class="nav-sep"></div>
                    <button class="nav-item" on:click=move |_| open_settings.run(SettingsTab::Passkeys)>
                        <Icon name="key"/>
                        "Passkeys"
                    </button>
                    <button class="nav-item" on:click=move |_| open_settings.run(SettingsTab::Encryption)>
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
                                        on:click=move |_| admin_open.set(true)
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
                    <button class="nav-item" on:click=move |_| toggle_theme()>
                        <Icon name="sun"/>
                        "Theme"
                    </button>
                    <button class="nav-item" on:click=sign_out>
                        <Icon name="logout"/>
                        "Sign out"
                    </button>
                </div>
            </aside>

            <div class="main">
                <header class="topbar">
                    <button
                        class="icon-btn menu-btn"
                        aria-label="Menu"
                        on:click=move |_| nav_open.set(!nav_open.get_untracked())
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
                                        on:click=move |_| load("/".to_string())
                                        on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                        on:drop=move |ev: ev::DragEvent| {
                                            ev.prevent_default();
                                            if let Some(src) = move_drag.get_untracked() {
                                                move_into(src, "/".to_string());
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
                                            on:click=move |_| load(target.clone())
                                            on:dragover=move |ev: ev::DragEvent| ev.prevent_default()
                                            on:drop=move |ev: ev::DragEvent| {
                                                ev.prevent_default();
                                                if let Some(src) = move_drag.get_untracked() {
                                                    move_into(src, drop_target.clone());
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
                        <form class="search" on:submit=search_submit>
                            <Icon name="search"/>
                            <input
                                type="search"
                                placeholder="Search files…"
                                prop:value=move || query.get()
                                on:input=move |ev| query.set(event_target_value(&ev))
                            />
                        </form>
                        <Show when=move || can_write_here(&path.get())>
                            <label class="button primary" title="Upload files">
                                <Icon name="upload"/>
                                <span>{move || upload_label.get()}</span>
                                <input type="file" class="hidden" multiple on:change=upload/>
                            </label>
                            <button on:click=mkdir title="New folder">
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
                                e2ee_master.set(Some(master));
                                vault_setup.set(false);
                                notice.set("Vault ready — anything you put inside it is encrypted".to_string());
                                load(path.get_untracked());
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
                            master=e2ee_master.get()
                            on_close=Callback::new(move |_| share_target.set(None))
                        />
                    }
                })
        }}

            {move || {
                versions_for
                .get()
                .map(|entry| {
                    let current = path.get();
                    view! {
                        <VersionsDialog
                            path=entry.path.clone()
                            name=entry.name.clone()
                            on_close=Callback::new(move |_| versions_for.set(None))
                            on_restored=Callback::new(move |_| load(current.clone()))
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
                            master=e2ee_master
                            tab=settings_tab
                            on_close=Callback::new(move |_| e2ee_open.set(false))
                        />
                    }
                })
        }}
        </div>
    }
}
