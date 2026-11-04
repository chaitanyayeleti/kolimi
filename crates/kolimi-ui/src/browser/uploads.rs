//! File uploads: the tray, drag-and-drop and retry.

use leptos::ev;
use leptos::prelude::*;
use leptos::task::spawn_local;
use wasm_bindgen::JsCast;

use super::types::{UploadItem, UploadStatus};
use crate::api;
use crate::app::encode_path;

/// Signals and callbacks shared by the upload actions.
#[derive(Clone, Copy)]
pub(super) struct UploadContext {
    pub uploads: RwSignal<Vec<UploadItem>>,
    pub upload_seq: RwSignal<u32>,
    pub path: RwSignal<String>,
    pub master: RwSignal<Option<kolimi_crypto::MasterKey>>,
    pub quota_warn: RwSignal<Option<u8>>,
    pub notice: RwSignal<String>,
    pub error: RwSignal<String>,
    pub vault_setup: RwSignal<bool>,
    pub dragging: RwSignal<bool>,
    pub load: Callback<String>,
    pub refresh_usage: Callback<()>,
    pub open_encryption: Callback<()>,
}

pub(super) fn start_upload(
    ctx: UploadContext,
    file: web_sys::File,
    dir: String,
    progress: RwSignal<u8>,
    status: RwSignal<UploadStatus>,
) {
    let UploadContext {
        uploads,
        path,
        master: e2ee_master,
        quota_warn,
        notice,
        error,
        vault_setup,
        load,
        refresh_usage,
        open_encryption,
        ..
    } = ctx;
    // Uploads one file, tracking it in the tray via its own signals.
    // Encrypted destinations are encrypted client-side first (chunks +
    // manifest + wrapped key, like the sync client); plaintext uploads
    // stream the Blob straight from disk with no WASM-side copy.
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
                load.run(path.get_untracked());
                refresh_usage.run(());
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
                open_encryption.run(());
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
                    open_encryption.run(());
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
}

pub(super) fn upload_files(ctx: UploadContext, files: Vec<web_sys::File>) {
    if files.is_empty() {
        return;
    }
    let dir = ctx.path.get_untracked();
    for file in files {
        let id = ctx.upload_seq.get_untracked() + 1;
        ctx.upload_seq.set(id);
        let progress = RwSignal::new(0u8);
        let status = RwSignal::new(UploadStatus::Uploading);
        ctx.uploads.update(|list| {
            list.push(UploadItem {
                id,
                name: file.name(),
                dir: dir.clone(),
                progress,
                status,
                file: file.clone(),
            });
        });
        start_upload(ctx, file, dir.clone(), progress, status);
    }
}

fn collect_files(files: web_sys::FileList) -> Vec<web_sys::File> {
    let mut selected = Vec::new();
    for index in 0..files.length() {
        if let Some(file) = files.get(index) {
            selected.push(file);
        }
    }
    selected
}

pub(super) fn retry_upload(
    ctx: UploadContext,
    (file, dir, progress, status): (web_sys::File, String, RwSignal<u8>, RwSignal<UploadStatus>),
) {
    progress.set(0);
    status.set(UploadStatus::Uploading);
    start_upload(ctx, file, dir, progress, status);
}

pub(super) fn upload_event(ctx: UploadContext, ev: ev::Event) {
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
    upload_files(ctx, selected);
}

pub(super) fn drop_files(ctx: UploadContext, ev: ev::DragEvent) {
    ev.prevent_default();
    ctx.dragging.set(false);
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
                ctx.error.set(
                    "That looks like a folder — drag-and-drop takes files only. Create the folder first, then drop the files inside.".to_string(),
                );
            }
            return;
        }
        upload_files(ctx, selected);
    }
}
