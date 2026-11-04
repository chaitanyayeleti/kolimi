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
/// Unused key packages expire so abandoned devices cannot accumulate.
const MLS_KEY_PACKAGE_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Distinct MLS devices allowed per account. Generous for desktop/web/CLI
/// plus replacements, while bounding automated device-id churn.
const MAX_MLS_DEVICES_PER_USER: i64 = 16;
/// Client pools are four; leave room for retries before rejecting.
const MAX_MLS_KEY_PACKAGES_PER_DEVICE: i64 = 8;

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
    /// Operator-visible label for the device (optional, best effort).
    #[serde(default)]
    device_name: String,
    /// Base64-encoded public MLS signature key from the key package. Used
    /// only to map a device to its group leaf during revocation.
    #[serde(default)]
    signature_key: Option<String>,
    /// Base64-encoded opaque key package.
    payload: String,
    #[serde(default)]
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct DeviceQuery {
    device_id: String,
}

#[derive(Deserialize)]
pub struct RevocationRequest {
    /// Base64-encoded public MLS signature key of the removed leaf.
    signature_key: String,
    #[serde(default)]
    device_id: String,
}

#[derive(Deserialize)]
pub struct RevocationQuery {
    path: String,
    signature_key: String,
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

#[derive(Deserialize)]
pub struct CommitRequest {
    epoch: i64,
    /// Base64-encoded opaque MLS commit.
    commit: String,
    /// Base64-encoded Welcome produced by the same commit, if any.
    #[serde(default)]
    welcome: Option<String>,
}

#[derive(Deserialize)]
pub struct EpochRequest {
    device_id: String,
    epoch: i64,
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
    let device_name = req.device_name.trim();
    if device_name.len() > 128 {
        return api::bad_request("device_name must be at most 128 bytes");
    }
    let signature_key = match req.signature_key {
        Some(encoded) => {
            let Ok(key) = STANDARD.decode(encoded.as_bytes()) else {
                return api::bad_request("signature_key must be base64");
            };
            if key.is_empty() || key.len() > 256 {
                return api::bad_request("signature_key size");
            }
            Some(key)
        }
        None => None,
    };
    let expires_at = req
        .expires_at
        .or_else(|| Some(kolimi_db::now_millis() + MLS_KEY_PACKAGE_TTL_MILLIS));
    match state
        .db
        .set_mls_key_package(
            user.user_id,
            req.device_id.trim(),
            device_name,
            signature_key.as_deref(),
            &payload,
            expires_at,
            MAX_MLS_DEVICES_PER_USER,
            MAX_MLS_KEY_PACKAGES_PER_DEVICE,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(kolimi_db::DbError::Conflict(message)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
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

/// `GET /api/mls/devices` — this account's MLS device roster.
///
/// Signature keys are public material. The roster is bookkeeping for caps
/// and revocation; it is not proof that a device is still a group member.
pub async fn get_devices(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.list_mls_devices(user.user_id).await {
        Ok(devices) => {
            let devices: Vec<_> = devices
                .into_iter()
                .map(|device| {
                    json!({
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "signature_key": device
                            .signature_key
                            .as_deref()
                            .map(|key| STANDARD.encode(key)),
                        "created_at": device.created_at,
                        "last_seen_at": device.last_seen_at,
                    })
                })
                .collect();
            Json(json!({ "devices": devices })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/mls/devices/{username}` — another account's public MLS device
/// roster (id, name and signature key only), for a share owner who must
/// remove a recipient's device from a group.
pub async fn get_user_devices(
    State(state): State<AppState>,
    Extension(_user): Extension<CurrentUser>,
    Path(username): Path<String>,
) -> Response {
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return api::not_found();
    };
    match state.db.list_mls_devices(target.id).await {
        Ok(devices) => {
            let devices: Vec<_> = devices
                .into_iter()
                .map(|device| {
                    json!({
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "signature_key": device
                            .signature_key
                            .as_deref()
                            .map(|key| STANDARD.encode(key)),
                    })
                })
                .collect();
            Json(json!({ "user": target.username, "devices": devices })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/mls/devices?device_id=` — remove one device from the
/// roster after the client removed its MLS leaves.
///
/// The server cannot verify an MLS removal, so this endpoint only clears
/// bookkeeping: the roster row, unpublished packages and stale epoch
/// reports. Clients must post the actual remove commit(s) first.
pub async fn delete_device(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<DeviceQuery>,
) -> Response {
    let device_id = query.device_id.trim();
    if device_id.is_empty() || device_id.len() > 64 {
        return api::bad_request("device_id must be 1–64 bytes");
    }
    match state.db.delete_mls_device(user.user_id, device_id).await {
        Ok(removed) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.device_forget",
                device_id,
                json!({ "removed": removed }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
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
    let revocations = state
        .db
        .mls_group_revocations(access.node.id)
        .await
        .unwrap_or_default();
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
        "revocations": revocations
            .into_iter()
            .map(|revocation| json!({
                "signature_key": STANDARD.encode(&revocation.signature_key),
                "device_id": revocation.device_id,
                "revoked_at": revocation.revoked_at,
            }))
            .collect::<Vec<_>>(),
    }))
    .into_response()
}

/// `POST /api/mls/revocations?path=` — remember a removed device signature so
/// automatic re-add skips its leftover key packages. A client asserts this
/// after it posts the remove commit; the server cannot verify the removal.
pub async fn post_revocation(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<RevocationRequest>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.perm != Perm::Write {
        return api::forbidden("write access is required to record an MLS revocation");
    }
    let Ok(signature_key) = STANDARD.decode(req.signature_key.as_bytes()) else {
        return api::bad_request("signature_key must be base64");
    };
    if signature_key.is_empty() || signature_key.len() > 256 {
        return api::bad_request("signature_key size");
    }
    if req.device_id.len() > 64 {
        return api::bad_request("device_id must be at most 64 bytes");
    }
    match state
        .db
        .revoke_mls_device(
            access.node.id,
            &signature_key,
            req.device_id.trim(),
            user.user_id,
        )
        .await
    {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.device_revoke",
                &query.path,
                json!({ "device_id": req.device_id.trim() }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/mls/revocations?path=&signature_key=` — clear a revocation
/// when an explicit re-share intentionally adds the device again.
pub async fn delete_revocation(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<RevocationQuery>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.perm != Perm::Write {
        return api::forbidden("write access is required to clear an MLS revocation");
    }
    let Ok(signature_key) = STANDARD.decode(query.signature_key.as_bytes()) else {
        return api::bad_request("signature_key must be base64");
    };
    match state
        .db
        .clear_mls_device_revocation(access.node.id, &signature_key)
        .await
    {
        Ok(_) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.device_unrevoke",
                &query.path,
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => api::internal_error(),
    }
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

/// `POST /api/mls/commit?path=` — atomically append a commit and optional
/// Welcome, advancing the epoch only if the commit wins.
pub async fn post_commit(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<CommitRequest>,
) -> Response {
    let access = match access(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if access.perm != Perm::Write {
        return api::forbidden("write access is required to send an MLS commit");
    }
    if req.epoch < 0 {
        return api::bad_request("epoch must be non-negative");
    }
    let Ok(commit) = STANDARD.decode(req.commit.as_bytes()) else {
        return api::bad_request("commit must be base64");
    };
    if commit.is_empty() || commit.len() > MAX_MESSAGE {
        return api::bad_request("commit size");
    }
    let welcome = match req.welcome {
        Some(encoded) => {
            let Ok(welcome) = STANDARD.decode(encoded.as_bytes()) else {
                return api::bad_request("welcome must be base64");
            };
            if welcome.is_empty() || welcome.len() > MAX_MESSAGE {
                return api::bad_request("welcome size");
            }
            Some(welcome)
        }
        None => None,
    };
    match state
        .db
        .append_mls_commit(
            access.node.id,
            req.epoch,
            &commit,
            welcome.as_deref(),
            user.user_id,
        )
        .await
    {
        Ok((seq, welcome_seq)) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "mls.commit",
                &query.path,
                json!({ "epoch": req.epoch, "welcome": welcome_seq.is_some() }),
            )
            .await;
            Json(json!({ "seq": seq, "welcome_seq": welcome_seq })).into_response()
        }
        Err(kolimi_db::DbError::Conflict(message)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
        Err(kolimi_db::DbError::NotFound(_)) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// Finds the nearest ancestor (or the node itself) that owns an MLS group.
///
/// Reports arrive for a file inside a shared folder as well as for the
/// share root, so a plain `access.node.id` is not enough.
async fn group_node(
    state: &AppState,
    user: &CurrentUser,
    path: &str,
) -> Result<kolimi_vfs::Access, Response> {
    let mut current = path.trim_end_matches('/').to_string();
    loop {
        let access = access(state, user, &current).await?;
        if state
            .db
            .mls_group(access.node.id)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            return Ok(access);
        }
        let Some((parent, _)) = current.rsplit_once('/') else {
            return Err(api::not_found());
        };
        if parent.is_empty() {
            return Err(api::not_found());
        }
        current = parent.to_string();
    }
}

/// `POST /api/mls/epoch?path=` — record this device's last processed epoch.
///
/// The janitor uses the minimum fresh report to decide which protocol
/// messages are still needed; reporting is advisory and never changes the
/// group state.
pub async fn post_epoch(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
    Json(req): Json<EpochRequest>,
) -> Response {
    let access = match group_node(&state, &user, &query.path).await {
        Ok(access) => access,
        Err(response) => return response,
    };
    if req.device_id.trim().is_empty() || req.device_id.len() > 64 {
        return api::bad_request("device_id must be 1–64 bytes");
    }
    if req.epoch < 0 {
        return api::bad_request("epoch must be non-negative");
    }
    match state
        .db
        .report_mls_epoch(
            access.node.id,
            user.user_id,
            req.device_id.trim(),
            req.epoch,
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
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
