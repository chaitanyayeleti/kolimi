//! MLS group state for encrypted shares (RFC 9420).
//!
//! The server is a dumb, ordered store: it validates ACLs, epochs and
//! sizes, then keeps opaque key packages, protocol messages and the
//! encrypted share keyring. It cannot read any of them.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, api, audit};
use kolimi_auth::CurrentUser;
use kolimi_vfs::{Perm, VfsError};

const MAX_KEY_PACKAGE: usize = 64 * 1024;
const MAX_MESSAGE: usize = 256 * 1024;
const MAX_KEYRING: usize = 1024 * 1024;

#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

#[derive(Deserialize)]
pub struct PageQuery {
    path: String,
    #[serde(default)]
    after: i64,
    #[serde(default)]
    limit: i64,
}

#[derive(Deserialize)]
pub struct KeyringQuery {
    path: String,
    if_epoch: i64,
    /// Optimistic revision from the last GET; `0` means "no keyring yet".
    #[serde(default)]
    if_revision: Option<i64>,
}

#[derive(Deserialize)]
pub struct KeyPackageRequest {
    device_id: String,
    /// Base64-encoded opaque key package.
    payload: String,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct InitGroupRequest {
    /// Base64-encoded random MLS group id.
    group_id: String,
}

#[derive(Deserialize)]
pub struct ConsumeKeyPackagesRequest {
    ids: Vec<i64>,
}

#[derive(Deserialize)]
pub struct MessageRequest {
    epoch: i64,
    kind: String,
    /// Base64-encoded opaque MLS message.
    payload: String,
}

async fn access(
    state: &AppState,
    user: &CurrentUser,
    path: &str,
) -> Result<kolimi_vfs::Access, Response> {
    match state.vfs.resolve_access(user.user_id, path).await {
        Ok(access) => Ok(access),
        Err(VfsError::NotFound) => Err(api::not_found()),
        Err(VfsError::Forbidden) => Err(api::forbidden("no access")),
        Err(VfsError::SharedRoot) => Err(api::bad_request("not a share root")),
        Err(_) => Err(api::internal_error()),
    }
}

/// `PUT /api/mls/key-packages` — publish this device's key package.
pub async fn put_key_package(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<KeyPackageRequest>,
) -> Response {
    if req.device_id.trim().is_empty() || req.device_id.len() > 64 {
        return api::bad_request("device_id must be 1–64 bytes");
    }
    let Ok(payload) = STANDARD.decode(req.payload.as_bytes()) else {
        return api::bad_request("payload must be base64");
    };
    if payload.is_empty() || payload.len() > MAX_KEY_PACKAGE {
        return api::bad_request("key package size");
    }
    match state
        .db
        .set_mls_key_package(user.user_id, req.device_id.trim(), &payload, req.expires_at)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/mls/key-packages/{username}` — public packages for adding a
/// user's devices to a group.
pub async fn get_key_packages(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    Path(username): Path<String>,
) -> Response {
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return api::not_found();
    };
    match state.db.mls_key_packages(target.id).await {
        Ok(packages) => {
            let packages: Vec<_> = packages
                .into_iter()
                .map(|package| {
                    json!({
                        "id": package.id,
                        "device_id": package.device_id,
                        "payload": STANDARD.encode(&package.payload),
                        "created_at": package.created_at,
                        "expires_at": package.expires_at,
                    })
                })
                .collect();
            Json(json!({ "user": target.username, "packages": packages })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/mls/key-packages` — this caller's own packages (pool status).
pub async fn get_own_key_packages(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.mls_key_packages(user.user_id).await {
        Ok(packages) => {
            let packages: Vec<_> = packages
                .into_iter()
                .map(|package| {
                    json!({
                        "id": package.id,
                        "device_id": package.device_id,
                        "payload": STANDARD.encode(&package.payload),
                        "created_at": package.created_at,
                        "expires_at": package.expires_at,
                    })
                })
                .collect();
            Json(json!({ "packages": packages })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `POST /api/mls/key-packages/consume` — mark packages as used.
///
/// Key packages are single-use in MLS. The adding client consumes the
/// packages it actually put into a commit so no other group reuses them.
pub async fn consume_key_packages(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    Json(req): Json<ConsumeKeyPackagesRequest>,
) -> Response {
    if req.ids.is_empty() || req.ids.len() > 64 {
        return api::bad_request("ids must contain 1–64 entries");
    }
    match state.db.consume_mls_key_packages(&req.ids).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `PUT /api/mls/group?path=` — initialize the node's MLS group.
pub async fn init_group(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<InitGroupRequest>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.owner_id != user.user_id || access.is_mount_root {
        return api::forbidden("only the owner can initialize the group");
    }
    // Groups are node-scoped. A file node is valid for a single-file share.
    let Ok(group_id) = STANDARD.decode(req.group_id.as_bytes()) else {
        return api::bad_request("group_id must be base64");
    };
    if group_id.len() < 16 || group_id.len() > 64 {
        return api::bad_request("group_id must be 16–64 bytes");
    }
    match state.db.init_mls_group(access.node.id, &group_id).await {
        Ok(group) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.group_init",
                &query.path,
                json!({ "epoch": group.epoch }),
            )
            .await;
            Json(json!({
                "group_id": STANDARD.encode(&group.mls_group_id),
                "epoch": group.epoch,
            }))
            .into_response()
        }
        Err(kolimi_db::DbError::Conflict(message)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/mls/group?path=&after=&limit=` — group state, messages and the
/// current encrypted share keyring.
pub async fn get_group(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PageQuery>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    let group = match state.db.mls_group(access.node.id).await {
        Ok(Some(group)) => group,
        Ok(None) => return api::not_found(),
        Err(_) => return api::internal_error(),
    };
    // `limit` defaults to 0 from query decoding; return a useful page
    // rather than clamping it to a single message.
    let limit = if query.limit <= 0 { 100 } else { query.limit };
    let messages = match state
        .db
        .mls_messages(access.node.id, query.after.max(0), limit)
        .await
    {
        Ok(messages) => messages,
        Err(_) => return api::internal_error(),
    };
    let keyring = state.db.mls_keyring(access.node.id).await.ok().flatten();
    let messages: Vec<_> = messages
        .into_iter()
        .map(|message| {
            json!({
                "seq": message.seq,
                "epoch": message.epoch,
                "kind": message.kind,
                "payload": STANDARD.encode(&message.payload),
                "sender_id": message.sender_id,
                "created_at": message.created_at,
            })
        })
        .collect();
    Json(json!({
        "group_id": STANDARD.encode(&group.mls_group_id),
        "epoch": group.epoch,
        "messages": messages,
        "keyring": keyring.map(|keyring| json!({
            "epoch": keyring.epoch,
            "payload": STANDARD.encode(&keyring.payload),
            "updated_by": keyring.updated_by,
            "updated_at": keyring.updated_at,
            "revision": keyring.revision,
        })),
    }))
    .into_response()
}

/// `POST /api/mls/messages?path=` — append a proposal/commit/welcome.
pub async fn post_message(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<MessageRequest>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.perm != Perm::Write {
        return api::forbidden("write access is required to send MLS messages");
    }
    if req.epoch < 0 {
        return api::bad_request("epoch must be non-negative");
    }
    let Ok(payload) = STANDARD.decode(req.payload.as_bytes()) else {
        return api::bad_request("payload must be base64");
    };
    if payload.is_empty() || payload.len() > MAX_MESSAGE {
        return api::bad_request("message size");
    }
    match state
        .db
        .append_mls_message(access.node.id, req.epoch, &req.kind, &payload, user.user_id)
        .await
    {
        Ok(seq) => Json(json!({ "seq": seq })).into_response(),
        Err(kolimi_db::DbError::Conflict(message)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
        Err(kolimi_db::DbError::NotFound(_)) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// `PUT /api/mls/keyring?path=&if_epoch=` — store the current epoch's
/// encrypted share keyring (raw bytes).
pub async fn put_keyring(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<KeyringQuery>,
    body: Body,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.perm != Perm::Write {
        return api::forbidden("write access is required to update the keyring");
    }
    let payload = match to_bytes(body, MAX_KEYRING).await {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => return api::bad_request("empty keyring"),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    match state
        .db
        .set_mls_keyring(
            access.node.id,
            query.if_epoch,
            &payload,
            user.user_id,
            query.if_epoch,
            query.if_revision,
        )
        .await
    {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.keyring_set",
                &query.path,
                json!({ "epoch": query.if_epoch }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "epoch changed; fetch the group and retry" })),
        )
            .into_response(),
        Err(kolimi_db::DbError::NotFound(_)) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}
