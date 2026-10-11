//! E2EE endpoints (RFC 0007): the keyring and per-file wrapped keys.
//!
//! The server stores these blobs verbatim and can do nothing with them.
//! Keys are owner-only: shares of encrypted files are out of scope for
//! the v1 design, so no share path may read them.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::CurrentUser;
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, api, audit};

/// Maximum keyring body size.
const MAX_KEYRING_BODY: usize = kolimi_db::MAX_KEYRING_BYTES;
/// Maximum wrapped-key body size.
const MAX_KEY_BODY: usize = kolimi_db::MAX_WRAPPED_KEY_BYTES;

/// Query for per-file key requests.
#[derive(Deserialize)]
pub struct KeyQuery {
    path: String,
}

/// `GET /api/e2ee/keyring` — the caller's keyring.
pub async fn get_keyring(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.keyring(user.user_id).await {
        Ok(Some(keyring)) => Json(json!({ "keyring": keyring })).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no keyring configured" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `PUT /api/e2ee/keyring` — store the caller's keyring (opaque JSON).
pub async fn put_keyring(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    body: Body,
) -> Response {
    let bytes = match read_body(body, MAX_KEYRING_BODY).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    let Ok(keyring) = String::from_utf8(bytes) else {
        return api::bad_request("keyring must be UTF-8 JSON");
    };
    if serde_json::from_str::<serde_json::Value>(&keyring).is_err() {
        return api::bad_request("keyring must be valid JSON");
    }
    match state.db.set_keyring(user.user_id, &keyring).await {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.keyring_set",
                &user.username,
                json!({ "bytes": keyring.len() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/files/key?path=` — the wrapped key of an encrypted file.
pub async fn get_file_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<KeyQuery>,
) -> Response {
    let node = match owned_file(&state, &user, &query.path).await {
        Ok(node) => node,
        Err(response) => return response,
    };
    match state.db.file_key(node.id).await {
        Ok(Some(wrapped)) => {
            Json(json!({ "wrapped_key": STANDARD.encode(&wrapped) })).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "file is not encrypted" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `PUT /api/files/key?path=` — store the wrapped key of an encrypted file.
///
/// The client calls this once per file (before or after the first
/// encrypted commit); later commits reuse the same key.
pub async fn put_file_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<KeyQuery>,
    body: Body,
) -> Response {
    let node = match owned_file(&state, &user, &query.path).await {
        Ok(node) => node,
        Err(response) => return response,
    };
    let wrapped = match read_body(body, MAX_KEY_BODY).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    if wrapped.is_empty() {
        return api::bad_request("wrapped key must not be empty");
    }
    match state.db.set_file_key(user.user_id, node.id, &wrapped).await {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.key_set",
                &query.path,
                json!({ "bytes": wrapped.len() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => api::internal_error(),
    }
}

async fn owned_file(
    state: &AppState,
    user: &CurrentUser,
    path: &str,
) -> Result<kolimi_vfs::Node, Response> {
    let access = match state.vfs.resolve_access(user.user_id, path).await {
        Ok(access) => access,
        Err(kolimi_vfs::VfsError::NotFound) => return Err(api::not_found()),
        Err(_) => return Err(api::internal_error()),
    };
    if access.owner_id != user.user_id || access.is_mount_root {
        return Err(api::forbidden("only the owner can manage file keys"));
    }
    if access.node.is_dir() {
        return Err(api::bad_request("not a file"));
    }
    Ok(access.node)
}

async fn read_body(body: Body, limit: usize) -> Result<Vec<u8>, Response> {
    match to_bytes(body, limit).await {
        Ok(bytes) => Ok(bytes.to_vec()),
        Err(_) => Err(StatusCode::PAYLOAD_TOO_LARGE.into_response()),
    }
}
