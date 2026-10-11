//! Preview generation: classification, the sandboxed worker bridge, and
//! the `/api/preview` endpoint.

use std::path::PathBuf;
use std::time::Duration;

use axum::{
    Extension,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::CurrentUser;
use serde::Deserialize;

use crate::AppState;

/// Maximum input size handed to the worker.
pub const MAX_PREVIEW_INPUT: u64 = 20 * 1024 * 1024;
/// Wall-clock budget for one worker run.
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent workers (bounded so previews cannot exhaust the host).
pub const MAX_CONCURRENT_WORKERS: usize = 4;
/// Text preview size.
pub const MAX_TEXT_PREVIEW: usize = 64 * 1024;

/// What kind of preview a file supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    /// Raster image thumbnail.
    Image,
    /// Plain-text head.
    Text,
}

/// Classifies a file name for preview support.
pub fn classify(name: &str) -> Option<PreviewKind> {
    let mime = mime_guess::from_path(name).first()?;
    if mime.type_() == mime_guess::mime::IMAGE {
        return Some(PreviewKind::Image);
    }
    if mime.type_() == mime_guess::mime::TEXT || looks_textual(name) {
        return Some(PreviewKind::Text);
    }
    None
}

/// Whether a file name looks like source/text worth indexing or previewing.
pub fn looks_textual(name: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        "txt",
        "md",
        "markdown",
        "rst",
        "log",
        "csv",
        "tsv",
        "json",
        "jsonl",
        "xml",
        "yaml",
        "yml",
        "toml",
        "ini",
        "conf",
        "cfg",
        "sh",
        "bash",
        "zsh",
        "fish",
        "py",
        "rs",
        "js",
        "mjs",
        "ts",
        "tsx",
        "jsx",
        "css",
        "scss",
        "html",
        "htm",
        "sql",
        "go",
        "java",
        "kt",
        "c",
        "h",
        "cpp",
        "hpp",
        "cc",
        "rb",
        "php",
        "pl",
        "lua",
        "org",
        "tex",
        "bib",
        "srt",
        "vtt",
        "diff",
        "patch",
        "nix",
        "desktop",
        "service",
        "gitignore",
        "env",
    ];
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    EXTENSIONS.contains(&extension.as_str())
}

/// UTF-8 (lossy) text when the bytes look textual.
pub fn extract_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    if bytes.iter().take(8192).any(|&byte| byte == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Query parameters for `/api/preview`.
#[derive(Deserialize)]
pub struct PreviewQuery {
    path: String,
    #[serde(default = "default_size")]
    size: u32,
}

fn default_size() -> u32 {
    256
}

/// `GET /api/preview?path=&size=` — a thumbnail or text head.
pub async fn handler(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PreviewQuery>,
) -> Response {
    let access = match state.vfs.stat_access(user.user_id, &query.path).await {
        Ok(Some(access)) => access,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if access.node.is_dir() {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if state.db.is_encrypted(access.node.id).await.unwrap_or(false) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let Some(kind) = classify(&access.node.name) else {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    };
    let size = query.size.clamp(32, 1024);

    match kind {
        PreviewKind::Text => {
            let (_, bytes) = match state
                .vfs
                .read_access_head(user.user_id, &query.path, MAX_TEXT_PREVIEW)
                .await
            {
                Ok(result) => result,
                Err(kolimi_vfs::VfsError::Forbidden) => {
                    return StatusCode::FORBIDDEN.into_response();
                }
                Err(_) => return StatusCode::NOT_FOUND.into_response(),
            };
            let mut response = Response::new(axum::body::Body::from(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }
        PreviewKind::Image => {
            if access.node.size > MAX_PREVIEW_INPUT {
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
            let data = match state.vfs.read_access(user.user_id, &query.path).await {
                Ok((_, data)) => data,
                Err(kolimi_vfs::VfsError::Forbidden) => {
                    return StatusCode::FORBIDDEN.into_response();
                }
                Err(_) => return StatusCode::NOT_FOUND.into_response(),
            };
            match run_worker(&state, "image", &data, size).await {
                Ok(png) => {
                    let mut response = Response::new(axum::body::Body::from(png));
                    response
                        .headers_mut()
                        .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
                    response
                }
                Err(WorkerError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
                Err(WorkerError::Failed(_)) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "preview failed").into_response()
                }
            }
        }
    }
}

/// Why a worker run failed.
#[derive(Debug)]
pub enum WorkerError {
    /// The payload was rejected before or by the worker.
    TooLarge,
    /// The worker crashed, timed out, or produced no output.
    Failed(String),
}

/// Writes `data` to a scratch file and runs the sandboxed worker on it.
async fn run_worker(
    state: &AppState,
    kind: &str,
    data: &[u8],
    max_dim: u32,
) -> Result<Vec<u8>, WorkerError> {
    let _permit = state
        .preview_permits
        .acquire()
        .await
        .map_err(|_| WorkerError::Failed("preview queue closed".to_string()))?;

    let name = kolimi_auth::token::new_session_token()
        .map_err(|error| WorkerError::Failed(error.to_string()))?;
    let scratch = state
        .data_dir
        .join("tmp")
        .join(format!("preview-{name}.bin"));
    tokio::fs::write(&scratch, data)
        .await
        .map_err(|error| WorkerError::Failed(error.to_string()))?;

    let result = run_worker_inner(state, kind, &scratch, max_dim).await;
    let _ = tokio::fs::remove_file(&scratch).await;
    result
}

async fn run_worker_inner(
    state: &AppState,
    kind: &str,
    scratch: &std::path::Path,
    max_dim: u32,
) -> Result<Vec<u8>, WorkerError> {
    let child = tokio::process::Command::new(&state.preview_worker)
        .arg("preview-worker")
        .arg(kind)
        .arg(scratch)
        .arg(max_dim.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| WorkerError::Failed(error.to_string()))?;

    let output = match tokio::time::timeout(WORKER_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(WorkerError::Failed(error.to_string())),
        Err(_) => return Err(WorkerError::Failed("worker timed out".to_string())),
    };
    if !output.status.success() || output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WorkerError::Failed(format!(
            "status {:?}: {}",
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(output.stdout)
}

/// A path to a scratch file (kept for tests).
pub fn scratch_dir(state: &AppState) -> PathBuf {
    state.data_dir.join("tmp")
}
