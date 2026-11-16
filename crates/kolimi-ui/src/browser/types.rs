//! Types and pure parsers for the authenticated browser.

use kolimi_crypto::MasterKey;
use leptos::prelude::RwSignal;
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Tab {
    Files,
    Trash,
    Settings,
    Admin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileSort {
    Name,
    Modified,
    Size,
    Type,
}

impl FileSort {
    pub(super) fn key(self) -> &'static str {
        match self {
            FileSort::Name => "name",
            FileSort::Modified => "modified",
            FileSort::Size => "size",
            FileSort::Type => "type",
        }
    }

    pub(super) fn parse(value: &str) -> Self {
        match value {
            "modified" => FileSort::Modified,
            "size" => FileSort::Size,
            "type" => FileSort::Type,
            _ => FileSort::Name,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileFilter {
    All,
    Folders,
    Files,
    Encrypted,
    Shared,
}

impl FileFilter {
    pub(super) fn key(self) -> &'static str {
        match self {
            FileFilter::All => "all",
            FileFilter::Folders => "folders",
            FileFilter::Files => "files",
            FileFilter::Encrypted => "encrypted",
            FileFilter::Shared => "shared",
        }
    }

    pub(super) fn parse(value: &str) -> Self {
        match value {
            "folders" => FileFilter::Folders,
            "files" => FileFilter::Files,
            "encrypted" => FileFilter::Encrypted,
            "shared" => FileFilter::Shared,
            _ => FileFilter::All,
        }
    }
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

fn extension(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

fn matches_filter(entry: &Entry, filter: FileFilter) -> bool {
    match filter {
        FileFilter::All => true,
        FileFilter::Folders => entry.kind == "dir",
        FileFilter::Files => entry.kind != "dir",
        FileFilter::Encrypted => entry.encrypted,
        FileFilter::Shared => entry.shared,
    }
}

/// Applies the list filter and sort. Folders always stay above files; the
/// direction only reverses the order within each group.
pub(super) fn view_entries(
    entries: &[Entry],
    filter: FileFilter,
    sort: FileSort,
    descending: bool,
) -> Vec<Entry> {
    let mut visible: Vec<Entry> = entries
        .iter()
        .filter(|entry| matches_filter(entry, filter))
        .cloned()
        .collect();
    visible.sort_by(|a, b| {
        let a_dir = a.kind == "dir";
        let b_dir = b.kind == "dir";
        if a_dir != b_dir {
            return b_dir.cmp(&a_dir);
        }
        let order = match sort {
            FileSort::Name => a
                .name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.name.cmp(&b.name)),
            FileSort::Modified => a
                .modified_at
                .cmp(&b.modified_at)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
            FileSort::Size => a
                .size
                .cmp(&b.size)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
            FileSort::Type => extension(&a.name)
                .cmp(&extension(&b.name))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        };
        if descending { order.reverse() } else { order }
    });
    visible
}

/// The icon used for a file-list entry.
pub(super) fn file_icon(name: &str, kind: &str) -> &'static str {
    if kind == "dir" {
        return "folder";
    }
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "svg" | "avif" | "heic" => "image",
        "pdf" => "pdf",
        "doc" | "docx" | "odt" | "rtf" | "pages" | "epub" => "doc",
        "xls" | "xlsx" | "ods" | "csv" | "tsv" | "numbers" => "sheet",
        "ppt" | "pptx" | "odp" | "key" => "slides",
        "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "7z" | "rar" | "zst" => "archive",
        "mp3" | "flac" | "wav" | "ogg" | "m4a" | "aac" | "opus" => "audio",
        "mp4" | "mkv" | "webm" | "mov" | "avi" | "m4v" => "video",
        "rs" | "py" | "js" | "ts" | "jsx" | "tsx" | "go" | "java" | "c" | "h" | "cpp" | "hpp"
        | "css" | "html" | "htm" | "json" | "xml" | "toml" | "yaml" | "yml" | "sh" | "bash"
        | "zsh" | "sql" | "kt" | "swift" | "rb" | "php" => "code",
        "txt" | "md" | "markdown" | "log" => "text",
        _ => "file",
    }
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
    fn view_preferences_round_trip() {
        for sort in [
            FileSort::Name,
            FileSort::Modified,
            FileSort::Size,
            FileSort::Type,
        ] {
            assert_eq!(FileSort::parse(sort.key()), sort);
        }
        assert_eq!(FileSort::parse("unknown"), FileSort::Name);

        for filter in [
            FileFilter::All,
            FileFilter::Folders,
            FileFilter::Files,
            FileFilter::Encrypted,
            FileFilter::Shared,
        ] {
            assert_eq!(FileFilter::parse(filter.key()), filter);
        }
        assert_eq!(FileFilter::parse("unknown"), FileFilter::All);
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

    #[wasm_bindgen_test]
    fn file_icons_cover_documents_media_and_archives() {
        assert_eq!(file_icon("notes.txt", "file"), "text");
        assert_eq!(file_icon("report.PDF", "file"), "pdf");
        assert_eq!(file_icon("budget.xlsx", "file"), "sheet");
        assert_eq!(file_icon("deck.pptx", "file"), "slides");
        assert_eq!(file_icon("backup.tar.gz", "file"), "archive");
        assert_eq!(file_icon("song.flac", "file"), "audio");
        assert_eq!(file_icon("clip.webm", "file"), "video");
        assert_eq!(file_icon("lib.rs", "file"), "code");
        assert_eq!(file_icon("photo.JPG", "file"), "image");
        assert_eq!(file_icon("unknown.bin", "file"), "file");
        assert_eq!(file_icon("anything.bin", "dir"), "folder");
    }

    fn view_entry(
        name: &str,
        kind: &str,
        size: u64,
        modified_at: i64,
        encrypted: bool,
        shared: bool,
    ) -> Entry {
        Entry {
            name: name.to_string(),
            path: format!("/{name}"),
            kind: kind.to_string(),
            size,
            modified_at,
            shared,
            owner: None,
            permission: None,
            encrypted,
        }
    }

    #[wasm_bindgen_test]
    fn view_entries_filters_and_keeps_folders_first() {
        let entries = vec![
            view_entry("b.txt", "file", 20, 2, false, false),
            view_entry("zeta", "dir", 0, 1, false, false),
            view_entry("a.txt", "file", 10, 3, false, true),
            view_entry("alpha", "dir", 0, 1, true, false),
        ];

        assert_eq!(
            view_entries(&entries, FileFilter::All, FileSort::Name, false)
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta", "a.txt", "b.txt"]
        );

        assert_eq!(
            view_entries(&entries, FileFilter::Folders, FileSort::Name, false)
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zeta"]
        );

        assert_eq!(
            view_entries(&entries, FileFilter::Encrypted, FileSort::Name, false)
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["alpha"]
        );

        assert_eq!(
            view_entries(&entries, FileFilter::Shared, FileSort::Size, true)
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["a.txt"]
        );
    }

    #[wasm_bindgen_test]
    fn view_entries_reverses_only_within_folder_and_file_groups() {
        let entries = vec![
            view_entry("small.txt", "file", 1, 1, false, false),
            view_entry("large.txt", "file", 99, 1, false, false),
            view_entry("alpha", "dir", 0, 1, false, false),
            view_entry("zeta", "dir", 0, 1, false, false),
        ];
        assert_eq!(
            view_entries(&entries, FileFilter::All, FileSort::Size, true)
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["zeta", "alpha", "large.txt", "small.txt"]
        );
    }
}
