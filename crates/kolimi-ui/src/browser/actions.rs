//! File, bulk and trash actions for the browser.

use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::json;
use wasm_bindgen::JsCast;

use super::types::{Entry, TrashItem};
use crate::api;
use crate::app::encode_path;

/// Signals and callbacks shared by the file actions.
#[derive(Clone, Copy)]
pub(super) struct FilesContext {
    pub path: RwSignal<String>,
    pub entries: RwSignal<Vec<Entry>>,
    pub selected: RwSignal<std::collections::HashSet<String>>,
    pub master: RwSignal<Option<kolimi_crypto::MasterKey>>,
    pub error: RwSignal<String>,
    pub notice: RwSignal<String>,
    pub undo: RwSignal<Option<(String, i64)>>,
    pub load: Callback<String>,
    pub load_trash: Callback<()>,
    pub refresh_usage: Callback<()>,
    pub open_encryption: Callback<()>,
}

/// Actions the browser view can invoke on files, selections and trash.
#[derive(Clone, Copy)]
pub(super) struct FileActions {
    pub delete: Callback<Entry>,
    pub rename: Callback<Entry>,
    pub move_into: Callback<(Entry, String)>,
    pub toggle_select: Callback<String>,
    pub bulk_trash: Callback<()>,
    pub bulk_move: Callback<()>,
    pub decrypt: Callback<Entry>,
    pub bulk_download: Callback<()>,
    pub restore: Callback<TrashItem>,
    pub purge: Callback<TrashItem>,
}

pub(super) fn actions(ctx: FilesContext) -> FileActions {
    let FilesContext {
        path,
        entries,
        selected,
        master,
        error,
        notice,
        undo,
        load,
        load_trash,
        refresh_usage,
        open_encryption,
    } = ctx;

    // Encrypted content must be unlocked before it can be shared, renamed,
    // moved, or deleted: while locked, Vault is read-only. (The server
    // cannot verify key possession, so this guard is client-side — but it
    // stops the accidental "I deleted my Vault while it was locked".)
    let require_unlock = move |entry: &Entry| -> bool {
        if !entry.encrypted || master.get_untracked().is_some() {
            return true;
        }
        error.set("Vault is locked — unlock encryption first (Settings → Encryption).".to_string());
        open_encryption.run(());
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
                    if let Some(master) = master.get_untracked() {
                        let _ = crate::mls::remove_path_prefix(&master, &entry_path).await;
                    }
                    load.run(current);
                    refresh_usage.run(());
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
                let Some(master) = master.get_untracked() else {
                    error.set("Unlock encryption first (Settings → Encryption).".to_string());
                    open_encryption.run(());
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
                                load.run(current);
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
                let Some(master) = master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_encryption.run(());
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
                        load.run(current);
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
                Ok(r) if matches!(r.status, 201 | 204) => load.run(current),
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
                let Some(master) = master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_encryption.run(());
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
                let Some(master) = master.get_untracked() else {
                    error.set("Vault is locked — unlock encryption first.".to_string());
                    open_encryption.run(());
                    return;
                };
                match crate::e2ee::move_file(&source, &destination).await {
                    Ok(()) => {
                        let _ =
                            crate::mls::rename_path_prefix(&master, &source, &destination).await;
                        notice.set(format!("Moved {name}"));
                        load.run(path.get_untracked());
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
                    load.run(path.get_untracked());
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

    let bulk_trash = move |_: ()| {
        let paths: Vec<String> = selected.get_untracked().into_iter().collect();
        // Encrypted selections need an unlock, exactly like single delete.
        let encrypted_selected = entries
            .get_untracked()
            .into_iter()
            .any(|entry| entry.encrypted && paths.contains(&entry.path));
        if encrypted_selected && master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            open_encryption.run(());
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
                        if let Some(master) = master.get_untracked() {
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
            load.run(current);
            refresh_usage.run(());
        });
    };

    let bulk_move = move |_: ()| {
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
        if encrypted.iter().any(|path| paths.contains(path)) && master.get_untracked().is_none() {
            error.set(
                "Vault is locked — unlock encryption first (Settings → Encryption).".to_string(),
            );
            open_encryption.run(());
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
            load.run(path.get_untracked());
        });
    };

    let decrypt_entry = move |entry: Entry| {
        let Some(master) = master.get_untracked() else {
            error.set("Unlock encryption first (Settings → Encryption).".to_string());
            open_encryption.run(());
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

    let bulk_download = move |_: ()| {
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
                    load_trash.run(());
                    refresh_usage.run(());
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
                    load_trash.run(());
                    refresh_usage.run(());
                }
                Ok(r) => error.set(r.error().unwrap_or("Delete failed").to_string()),
                Err(e) => error.set(e),
            }
        });
    };

    FileActions {
        delete: Callback::new(delete_entry),
        rename: Callback::new(rename_entry),
        move_into: Callback::new(move |(entry, dest): (Entry, String)| move_into(entry, dest)),
        toggle_select: Callback::new(toggle_select),
        bulk_trash: Callback::new(bulk_trash),
        bulk_move: Callback::new(bulk_move),
        decrypt: Callback::new(decrypt_entry),
        bulk_download: Callback::new(bulk_download),
        restore: Callback::new(restore),
        purge: Callback::new(purge),
    }
}
