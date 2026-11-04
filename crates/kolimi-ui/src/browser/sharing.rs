//! Sharing and folder-encryption actions.

use kolimi_crypto::MasterKey;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::json;

use super::types::Entry;
use crate::api;
use crate::app::encode_path;

/// Signals and callbacks shared by the sharing actions.
#[derive(Clone, Copy)]
pub(super) struct SharingContext {
    pub master: RwSignal<Option<MasterKey>>,
    pub error: RwSignal<String>,
    pub notice: RwSignal<String>,
    pub share_target: RwSignal<Option<Entry>>,
    pub encrypting: RwSignal<bool>,
    pub load: Callback<String>,
    pub open_encryption: Callback<()>,
}

pub(super) fn share_entry(ctx: SharingContext, entry: Entry) {
    let SharingContext {
        master,
        error,
        share_target,
        open_encryption,
        ..
    } = ctx;

    if entry.encrypted && master.get_untracked().is_none() {
        error.set(
            "Vault is locked — unlock encryption before sharing, or the recipient gets no key."
                .to_string(),
        );
        open_encryption.run(());
        return;
    }
    share_target.set(Some(entry));
}

pub(super) fn toggle_encryption(ctx: SharingContext, entry: Entry) {
    let SharingContext {
        master,
        error,
        notice,
        encrypting,
        load,
        open_encryption,
        ..
    } = ctx;

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
                    load.run(parent);
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
    let Some(master) = master.get_untracked() else {
        error.set("Unlock encryption first (Settings → Encryption).".to_string());
        open_encryption.run(());
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
            let bytes = match api::get_bytes(&format!("/dav{}", encode_path(&file.path))).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    error.set(format!("Could not read “{}”: {e}", file.path));
                    load.run(parent.clone());
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
                let encoded = match crate::e2ee::encode_component(&master, &parent_plaintext, &name)
                {
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
                    load.run(parent.clone());
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
                load.run(parent.clone());
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
                load.run(parent);
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
}
