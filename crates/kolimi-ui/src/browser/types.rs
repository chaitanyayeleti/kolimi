//! Types and pure parsers for the authenticated browser.

use kolimi_crypto::MasterKey;
use leptos::prelude::RwSignal;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Tab {
    Files,
    Trash,
}

#[derive(Clone, PartialEq)]
pub(super) struct Entry {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) kind: String,
    pub(super) size: u64,
    pub(super) modified_at: i64,
    pub(super) shared: bool,
    pub(super) owner: Option<String>,
    pub(super) permission: Option<String>,
    pub(super) encrypted: bool,
}

#[derive(Clone, PartialEq)]
pub(super) struct TrashItem {
    pub(super) id: i64,
    pub(super) name: String,
    pub(super) original_path: Option<String>,
    pub(super) size: u64,
}

#[derive(Clone, PartialEq)]
pub(super) struct SearchHit {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) is_dir: bool,
    pub(super) size: u64,
    pub(super) modified_at: i64,
    pub(super) snippet: String,
    pub(super) encrypted: bool,
}

/// Upload-tray status for one file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UploadStatus {
    Uploading,
    Done,
    Failed,
}

/// One file in the upload tray.
///
/// Progress and status are their own signals so a row reads them in O(1)
/// instead of scanning the whole tray on every update.
#[derive(Clone)]
pub(super) struct UploadItem {
    pub(super) id: u32,
    pub(super) name: String,
    pub(super) dir: String,
    pub(super) progress: RwSignal<u8>,
    pub(super) status: RwSignal<UploadStatus>,
    pub(super) file: web_sys::File,
}

pub(super) fn parse_results(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<SearchHit> {
    body.get("results")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let path = item["path"].as_str().unwrap_or_default().to_string();
                    SearchHit {
                        name: crate::e2ee::display_name_with_shares(master, &path, shares),
                        path,
                        is_dir: item["is_dir"].as_bool().unwrap_or(false),
                        size: item["size"].as_u64().unwrap_or(0),
                        modified_at: item["modified_at"].as_i64().unwrap_or(0),
                        snippet: item["snippet"].as_str().unwrap_or_default().to_string(),
                        encrypted: item["encrypted"].as_bool().unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parent_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        _ => "/".to_string(),
    }
}

pub(super) fn is_image_name(name: &str) -> bool {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(extension.as_str(), "png" | "jpg" | "jpeg" | "gif" | "bmp")
}

pub(super) fn is_text_name(name: &str) -> bool {
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        extension.as_str(),
        "txt"
            | "md"
            | "markdown"
            | "log"
            | "json"
            | "xml"
            | "html"
            | "htm"
            | "css"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "rs"
            | "py"
            | "sh"
            | "toml"
            | "yaml"
            | "yml"
            | "csv"
            | "ini"
            | "conf"
            | "c"
            | "h"
            | "go"
            | "java"
    )
}

pub(super) fn parse_entries(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<Entry> {
    body.get("entries")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let path = item["path"].as_str().unwrap_or_default().to_string();
                    Entry {
                        name: crate::e2ee::display_name_with_shares(master, &path, shares),
                        path,
                        kind: item["kind"].as_str().unwrap_or("file").to_string(),
                        size: item["size"].as_u64().unwrap_or(0),
                        modified_at: item["modified_at"].as_i64().unwrap_or(0),
                        shared: item["shared"].as_bool().unwrap_or(false),
                        owner: item["owner"].as_str().map(str::to_string),
                        permission: item["permission"].as_str().map(str::to_string),
                        encrypted: item["encrypted"].as_bool().unwrap_or(false),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn parse_trash(
    body: &Value,
    master: Option<&MasterKey>,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<TrashItem> {
    body.as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let original = item["original_path"].as_str();
                    let display_path = original.map(|path| {
                        crate::e2ee::decode_display_path_with_shares(master, path, shares)
                    });
                    TrashItem {
                        id: item["id"].as_i64().unwrap_or(0),
                        name: display_path
                            .as_deref()
                            .and_then(|path| path.rsplit('/').next())
                            .filter(|name| !name.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| {
                                crate::e2ee::decode_display_name(
                                    master,
                                    item["name"].as_str().unwrap_or_default(),
                                )
                            }),
                        original_path: display_path,
                        size: item["size"].as_u64().unwrap_or(0),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The icon used for a file-list entry.
pub(super) fn file_icon(name: &str, kind: &str) -> &'static str {
    if kind == "dir" {
        return "folder";
    }
    if is_image_name(name) {
        return "image";
    }
    "file"
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn parent_of_handles_roots_and_nested_paths() {
        assert_eq!(parent_of("/a/b.txt"), "/a");
        assert_eq!(parent_of("/a"), "/");
        assert_eq!(parent_of("/"), "/");
        assert_eq!(parent_of(""), "/");
    }

    #[wasm_bindgen_test]
    fn image_and_text_extensions_are_case_insensitive() {
        assert!(is_image_name("Photo.JPG"));
        assert!(is_image_name("diagram.png"));
        assert!(!is_image_name("notes.txt"));
        assert!(is_text_name("README.MD"));
        assert!(is_text_name("script.rs"));
        assert!(!is_text_name("archive.zip"));
    }
}
