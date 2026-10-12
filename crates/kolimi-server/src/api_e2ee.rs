//! E2EE endpoints (RFC 0007): the keyring and per-file wrapped keys.
//!
//! The server stores these blobs verbatim and can do nothing with them.
//! Keys are owner-only: shares of encrypted files are out of scope for
//! the v1 design, so no share path may read them.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{Path, Query, State},
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

/// `GET /api/e2ee/identity` — the caller's identity (private key wrapped).
pub async fn get_identity(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.identity(user.user_id).await {
        Ok(Some((public_key, wrapped_private))) => Json(json!({
            "public_key": STANDARD.encode(&public_key),
            "wrapped_private": STANDARD.encode(&wrapped_private),
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no E2EE identity" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}

#[derive(Deserialize)]
pub struct IdentityRequest {
    public_key: String,
    wrapped_private: String,
}

/// `PUT /api/e2ee/identity` — publish an identity (opaque private key).
pub async fn put_identity(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<IdentityRequest>,
) -> Response {
    let (Ok(public_key), Ok(wrapped_private)) = (
        STANDARD.decode(&req.public_key),
        STANDARD.decode(&req.wrapped_private),
    ) else {
        return api::bad_request("keys must be base64");
    };
    if public_key.len() != 32 {
        return api::bad_request("public key must be 32 bytes");
    }
    match state
        .db
        .set_identity(user.user_id, &public_key, &wrapped_private)
        .await
    {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.identity_set",
                &user.username,
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/e2ee/identity/{username}` — a user's published public key.
pub async fn public_identity(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Response {
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return api::not_found();
    };
    match state.db.public_key(target.id).await {
        Ok(Some(public_key)) => {
            Json(json!({ "public_key": STANDARD.encode(&public_key) })).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "user has no E2EE identity" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}

/// Query for share-key requests.
#[derive(Deserialize)]
pub struct ShareKeyQuery {
    path: String,
    #[serde(default)]
    recipient: Option<String>,
}

/// `GET /api/e2ee/share-key?path=` — the caller's wrapped key for a
/// shared encrypted file (any access level; only the recipient has one).
pub async fn get_share_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<ShareKeyQuery>,
) -> Response {
    let access = match state.vfs.resolve_access(user.user_id, &query.path).await {
        Ok(access) => access,
        Err(kolimi_vfs::VfsError::NotFound) => return api::not_found(),
        Err(_) => return api::internal_error(),
    };
    match state.db.share_key(access.node.id, user.user_id).await {
        Ok(Some(wrapped)) => {
            Json(json!({ "wrapped_key": STANDARD.encode(&wrapped) })).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no share key for this file" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `PUT /api/e2ee/share-key?path=&recipient=` — the owner wraps a file
/// key for a recipient (ECIES; the server stores it opaquely).
pub async fn put_share_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<ShareKeyQuery>,
    body: Body,
) -> Response {
    let Some(recipient) = query.recipient.as_deref() else {
        return api::bad_request("recipient is required");
    };
    let node = match owned_file(&state, &user, &query.path).await {
        Ok(node) => node,
        Err(response) => return response,
    };
    let Some(target) = state.db.find_user(recipient).await.ok().flatten() else {
        return api::bad_request("no such user");
    };
    if state
        .db
        .public_key(target.id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return api::bad_request("recipient has no E2EE identity");
    }
    let wrapped = match read_body(body, MAX_KEY_BODY).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };
    match state.db.set_share_key(node.id, target.id, &wrapped).await {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.share_key_set",
                &query.path,
                json!({ "recipient": recipient }),
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

/// Body for creating an enrollment (RFC 0008).
#[derive(Deserialize)]
pub struct CreateEnrollment {
    /// Operator-visible label for the new device.
    device_name: String,
    /// The new device's X25519 public key (base64).
    device_public_key: String,
}

/// Body for approving an enrollment.
#[derive(Deserialize)]
pub struct ApproveEnrollment {
    /// The master key wrapped for the new device (base64).
    wrapped_master_key: String,
}

/// `GET /api/e2ee/enrollments` — pending enrollments awaiting approval.
pub async fn list_enrollments(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.pending_enrollments(user.user_id).await {
        Ok(items) => {
            let list: Vec<_> = items
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "device_name": e.device_name,
                        "device_public_key": STANDARD.encode(&e.device_public_key),
                        "created_at": e.created_at,
                        "expires_at": e.expires_at,
                    })
                })
                .collect();
            Json(json!({ "enrollments": list })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `POST /api/e2ee/enrollments` — a new device requests enrollment.
pub async fn create_enrollment(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<CreateEnrollment>,
) -> Response {
    let Ok(public_key) = STANDARD.decode(req.device_public_key.as_bytes()) else {
        return api::bad_request("device_public_key must be base64");
    };
    let name = req.device_name.trim();
    if name.is_empty() || name.len() > 64 {
        return api::bad_request("device_name must be 1..=64 characters");
    }
    match state
        .db
        .create_enrollment(user.user_id, name, &public_key)
        .await
    {
        Ok(id) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.enrollment_created",
                &user.username,
                json!({ "device_name": name, "enrollment": id }),
            )
            .await;
            Json(json!({ "id": id })).into_response()
        }
        Err(kolimi_db::DbError::Conflict(_)) => api::bad_request("too many pending enrollments"),
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/e2ee/enrollments/{id}` — poll one enrollment.
pub async fn get_enrollment(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.enrollment(user.user_id, id).await {
        Ok(Some(e)) => Json(json!({
            "id": e.id,
            "device_name": e.device_name,
            "device_public_key": STANDARD.encode(&e.device_public_key),
            "approved": e.approved_at.is_some(),
            "wrapped_master_key": e.wrapped_master_key.as_ref().map(|k| STANDARD.encode(k)),
        }))
        .into_response(),
        Ok(None) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// `POST /api/e2ee/enrollments/{id}/approve` — an unlocked device uploads the
/// master key wrapped for the new device.
pub async fn approve_enrollment(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
    Json(req): Json<ApproveEnrollment>,
) -> Response {
    let Ok(wrapped) = STANDARD.decode(req.wrapped_master_key.as_bytes()) else {
        return api::bad_request("wrapped_master_key must be base64");
    };
    let Some(enrollment) = state.db.enrollment(user.user_id, id).await.ok().flatten() else {
        return api::not_found();
    };
    match state
        .db
        .approve_enrollment(user.user_id, id, &wrapped)
        .await
    {
        Ok(true) => {
            let _ = state
                .db
                .register_device(
                    user.user_id,
                    &enrollment.device_name,
                    &enrollment.device_public_key,
                )
                .await;
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.enrollment_approved",
                &user.username,
                json!({ "device_name": enrollment.device_name, "enrollment": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::bad_request("enrollment is not pending"),
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/e2ee/enrollments/{id}` — discard an enrollment.
pub async fn delete_enrollment(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.delete_enrollment(user.user_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/e2ee/devices` — the account's registered devices.
pub async fn list_devices(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.devices(user.user_id).await {
        Ok(items) => {
            let list: Vec<_> = items
                .iter()
                .map(|d| {
                    json!({
                        "id": d.id,
                        "name": d.name,
                        "public_key": STANDARD.encode(&d.public_key),
                        "created_at": d.created_at,
                        "last_seen_at": d.last_seen_at,
                    })
                })
                .collect();
            Json(json!({ "devices": list })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/e2ee/devices/{id}` — remove a device record (advisory: the
/// device keeps any master key it already holds; see RFC 0008).
pub async fn delete_device(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.db.delete_device(user.user_id, id).await {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "e2ee.device_removed",
                &user.username,
                json!({ "device": id }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}
