//! Sharing API: user/group shares, public links, and the anonymous
//! `/public/{token}` surface.
//!
//! All permission decisions are delegated to the VFS permission engine;
//! this module only orchestrates storage and HTTP semantics.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::TryStreamExt;
use kolimi_auth::{CurrentUser, password, token};
use kolimi_db::{DbError, ShareRow};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::cookie_value;
use crate::{AppState, api, api_browse::root_path, audit};

/// Default lifetime of a public link (30 days).
pub const DEFAULT_LINK_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Lifetime of an unlock session for a password-protected link (12 hours).
pub const LINK_SESSION_TTL_MILLIS: i64 = 12 * 60 * 60 * 1000;

// ---- authenticated share management -----------------------------------

/// `POST /api/shares` — create a user, group, or link share.
#[derive(Deserialize)]
pub struct CreateShareRequest {
    path: String,
    kind: String,
    recipient: Option<String>,
    permission: Option<String>,
    /// Link password: omitted = generate one, `""` = none, else use it.
    password: Option<String>,
    /// Link lifetime: omitted = 30 days, `0` = never, else seconds.
    expires_in_secs: Option<i64>,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<CreateShareRequest>,
) -> Response {
    let permission = req.permission.as_deref().unwrap_or("read");
    if !matches!(permission, "read" | "write") {
        return api::bad_request("permission must be \"read\" or \"write\"");
    }
    let access = match state.vfs.resolve_access(user.user_id, &req.path).await {
        Ok(access) => access,
        Err(kolimi_vfs::VfsError::NotFound) => return api::not_found(),
        Err(_) => return api::not_found(),
    };
    if access.owner_id != user.user_id || access.is_mount_root {
        return api::forbidden("you can only share your own files");
    }
    if access.node.parent_id.is_none() {
        return api::bad_request("the root cannot be shared");
    }
    // Encrypted content can be shared with named users and groups (the
    // owner's client wraps file keys per member, RFC 0007 v2). Public links
    // to encrypted files are allowed too: the file key travels in the URL
    // **fragment** (`#k=…`), which the browser never sends to the server, so
    // the server stays blind (RFC 0007 open question 3).

    let (result, generated): (Result<ShareRow, DbError>, Option<String>) = match req.kind.as_str() {
        "user" => {
            let Some(recipient) = req.recipient.as_deref() else {
                return api::bad_request("recipient is required for user shares");
            };
            let Some(target) = state.db.find_user(recipient).await.ok().flatten() else {
                return api::bad_request("no such user");
            };
            if target.id == user.user_id {
                return api::bad_request("cannot share with yourself");
            }
            (
                state
                    .db
                    .create_share(
                        user.user_id,
                        access.node.id,
                        "user",
                        Some(target.id),
                        None,
                        permission,
                        None,
                        None,
                        None,
                    )
                    .await,
                None,
            )
        }
        "group" => {
            let Some(recipient) = req.recipient.as_deref() else {
                return api::bad_request("recipient is required for group shares");
            };
            let Some(group) = state.db.group_by_name(recipient).await.ok().flatten() else {
                return api::bad_request("no such group");
            };
            (
                state
                    .db
                    .create_share(
                        user.user_id,
                        access.node.id,
                        "group",
                        None,
                        Some(group.id),
                        permission,
                        None,
                        None,
                        None,
                    )
                    .await,
                None,
            )
        }
        "link" => {
            if permission != "read" {
                return api::bad_request("public write links are not supported yet");
            }
            let Ok(token) = token::new_csrf_token() else {
                return api::internal_error();
            };
            let (password_hash, generated) = match req.password.as_deref() {
                None => {
                    let Ok(generated) = random_password() else {
                        return api::internal_error();
                    };
                    match hash_password(&generated).await {
                        Ok(hash) => (Some(hash), Some(generated)),
                        Err(response) => return response,
                    }
                }
                Some("") => (None, None),
                Some(given) => match hash_password(given).await {
                    Ok(hash) => (Some(hash), None),
                    Err(response) => return response,
                },
            };
            let expires_at = match req.expires_in_secs {
                None => Some(kolimi_db::now_millis() + DEFAULT_LINK_TTL_MILLIS),
                Some(0) => None,
                Some(secs) if secs > 0 => Some(kolimi_db::now_millis() + secs * 1000),
                Some(_) => return api::bad_request("expires_in_secs must be >= 0"),
            };
            (
                state
                    .db
                    .create_share(
                        user.user_id,
                        access.node.id,
                        "link",
                        None,
                        None,
                        "read",
                        Some(&token),
                        password_hash.as_deref(),
                        expires_at,
                    )
                    .await,
                generated,
            )
        }
        _ => return api::bad_request("kind must be \"user\", \"group\", or \"link\""),
    };

    match result {
        Ok(share) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "share.create",
                &share.id.to_string(),
                json!({
                    "kind": share.kind,
                    "path": req.path,
                    "recipient": req.recipient,
                }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(share_json(&state, &share, generated.as_deref()).await),
            )
                .into_response()
        }
        Err(DbError::Conflict(_)) => conflict("already shared with that recipient"),
        Err(_) => api::internal_error(),
    }
}

/// `GET /api/shares?path=` — shares created for one of the caller's nodes.
pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    let access = match state.vfs.resolve_access(user.user_id, &query.path).await {
        Ok(access) => access,
        Err(_) => return api::not_found(),
    };
    if access.owner_id != user.user_id {
        return api::forbidden("not your file");
    }
    let shares = match state.db.shares_for_node(user.user_id, access.node.id).await {
        Ok(shares) => shares,
        Err(_) => return api::internal_error(),
    };
    let mut items = Vec::with_capacity(shares.len());
    for share in &shares {
        items.push(share_json(&state, share, None).await);
    }
    Json(json!({ "path": query.path, "shares": items })).into_response()
}

/// `GET /api/shares/owned` — every share the caller created.
pub async fn owned(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let shares = match state.db.shares_owned(user.user_id).await {
        Ok(shares) => shares,
        Err(_) => return api::internal_error(),
    };
    let mut items = Vec::with_capacity(shares.len());
    for share in &shares {
        items.push(share_json(&state, share, None).await);
    }
    Json(json!({ "shares": items })).into_response()
}

/// `GET /api/shares/received` — the caller's received shares as mounts.
pub async fn received(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let mounts = match state.vfs.received_mounts(user.user_id).await {
        Ok(mounts) => mounts,
        Err(_) => return api::internal_error(),
    };
    let items: Vec<Value> = mounts
        .iter()
        .map(|mount| {
            json!({
                "share_id": mount.share_id,
                "owner": mount.owner_username,
                "name": mount.name,
                "mount": format!("/{}/{}", kolimi_vfs::SHARED_MOUNT, mount.name),
                "kind": if mount.kind == kolimi_vfs::NodeKind::Dir { "dir" } else { "file" },
                "permission": mount.permission.as_str(),
                "size": mount.size,
                "modified_at": mount.modified_at,
            })
        })
        .collect();
    Json(json!({ "mounts": items })).into_response()
}

/// `GET /api/groups/{name}/members` — member usernames of a group.
///
/// Needed by the owner's client to wrap file keys per member.
pub async fn group_members(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    let Some(group) = state.db.group_by_name(&name).await.ok().flatten() else {
        return api::not_found();
    };
    let members = match state.db.group_members(group.id).await {
        Ok(members) => members,
        Err(_) => return api::internal_error(),
    };
    // Rosters are only for the group's own members and administrators.
    if !user.is_admin && !members.iter().any(|member| member.id == user.user_id) {
        return api::forbidden("not a member of this group");
    }
    let names: Vec<&str> = members
        .iter()
        .map(|member| member.username.as_str())
        .collect();
    Json(json!({ "group": group.name, "members": names })).into_response()
}

/// `GET /api/shareable` — users and groups a share can target.
pub async fn shareable(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let users: Vec<String> = match state.db.list_users().await {
        Ok(users) => users
            .into_iter()
            .filter(|u| u.id != user.user_id && !u.disabled)
            .map(|u| u.username)
            .collect(),
        Err(_) => return api::internal_error(),
    };
    let groups: Vec<String> = match state.db.list_groups().await {
        Ok(groups) => groups.into_iter().map(|g| g.name).collect(),
        Err(_) => return api::internal_error(),
    };
    Json(json!({ "users": users, "groups": groups })).into_response()
}

/// `PATCH /api/shares/{id}` — update permission, password, or expiry.
#[derive(Deserialize)]
pub struct UpdateShareRequest {
    permission: Option<String>,
    /// `None` = unchanged, `""` = clear, else set (links only).
    password: Option<String>,
    /// `None` = unchanged, `0` = never, else seconds (links only).
    expires_in_secs: Option<i64>,
}

pub async fn update(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(share_id): Path<i64>,
    Json(req): Json<UpdateShareRequest>,
) -> Response {
    let Some(share) = state.db.share_by_id(share_id).await.ok().flatten() else {
        return api::not_found();
    };
    if share.owner_id != user.user_id {
        return api::forbidden("only the owner can modify a share");
    }

    if let Some(permission) = req.permission.as_deref() {
        if !matches!(permission, "read" | "write") {
            return api::bad_request("permission must be \"read\" or \"write\"");
        }
        if share.kind == "link" && permission != "read" {
            return api::bad_request("public write links are not supported yet");
        }
        if state
            .db
            .update_share_permission(share.id, permission)
            .await
            .is_err()
        {
            return api::internal_error();
        }
    }
    if let Some(password) = req.password.as_deref() {
        if share.kind != "link" {
            return api::bad_request("passwords only apply to public links");
        }
        let hash = if password.is_empty() {
            None
        } else {
            match hash_password(password).await {
                Ok(hash) => Some(hash),
                Err(response) => return response,
            }
        };
        if state
            .db
            .update_share_password(share.id, hash.as_deref())
            .await
            .is_err()
        {
            return api::internal_error();
        }
    }
    if let Some(secs) = req.expires_in_secs {
        if share.kind != "link" {
            return api::bad_request("expiry only applies to public links");
        }
        let expires_at = match secs {
            0 => None,
            secs if secs > 0 => Some(kolimi_db::now_millis() + secs * 1000),
            _ => return api::bad_request("expires_in_secs must be >= 0"),
        };
        if state
            .db
            .update_share_expiry(share.id, expires_at)
            .await
            .is_err()
        {
            return api::internal_error();
        }
    }

    let Some(share) = state.db.share_by_id(share_id).await.ok().flatten() else {
        return api::not_found();
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "share.update",
        &share_id.to_string(),
        json!({}),
    )
    .await;
    let body = share_json(&state, &share, None).await;
    if body.get("missing").and_then(Value::as_bool) == Some(true) {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "the shared item no longer exists" })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// `DELETE /api/shares/{id}` — revoke a share.
///
/// The owner can revoke any share. A recipient can only remove a user share
/// addressed to them (leaving the group). Group shares can only be revoked
/// by the owner: allowing any member to delete the row would revoke access
/// for the whole group.
pub async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(share_id): Path<i64>,
) -> Response {
    let Some(share) = state.db.share_by_id(share_id).await.ok().flatten() else {
        return api::not_found();
    };
    // Group members can leave the share (removing themselves from the group)
    // without revoking it for everyone else. This is handled before the
    // owner-only check below.
    if share.owner_id != user.user_id && share.kind == "group" {
        if let Some(group_id) = share.recipient_group_id {
            let members = state.db.group_members(group_id).await.unwrap_or_default();
            if members.iter().any(|m| m.id == user.user_id) {
                // Leave: drop membership and this member's wrapped keys only.
                let _ = state.db.remove_group_member(group_id, user.user_id).await;
                let _ = state
                    .db
                    .delete_share_keys(share.node_id, user.user_id)
                    .await;
                audit(
                    &state,
                    Some(user.user_id),
                    Some(&user.username),
                    "share.leave",
                    &share_id.to_string(),
                    json!({}),
                )
                .await;
                return StatusCode::NO_CONTENT.into_response();
            }
        }
        return api::forbidden("not allowed to revoke this share");
    }
    let mut allowed = share.owner_id == user.user_id;
    if !allowed {
        allowed = match share.kind.as_str() {
            "user" => share.recipient_user_id == Some(user.user_id),
            // Group members leave via the path above, not by deleting the
            // share row for everyone.
            _ => false,
        };
    }
    if !allowed {
        return api::forbidden("not allowed to revoke this share");
    }
    match state.db.delete_share(share_id).await {
        Ok(true) => {
            if share.kind == "user"
                && let Some(recipient) = share.recipient_user_id
            {
                let _ = state.db.delete_share_keys(share.node_id, recipient).await;
            }
            if share.kind == "group"
                && let Some(group_id) = share.recipient_group_id
            {
                // Only drop wrapped keys for members of this group who no
                // longer have any share covering the node (direct or via
                // another group). Never wipe keys for unrelated recipients.
                let _ =
                    remove_group_share_keys(&state, share.owner_id, share.node_id, group_id).await;
            }
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "share.delete",
                &share_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

// ---- public link surface ----------------------------------------------

/// `GET /public/{token}` — metadata (and directory listing) for a link.
pub async fn public_meta(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (share, node) = match load_link(&state, &token).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if let Err(response) = require_unlocked(&state, &share, &headers).await {
        return response;
    }
    let mut body = json!({
        "name": node.name,
        "kind": if node.is_dir() { "dir" } else { "file" },
        "size": node.size,
        "modified_at": node.modified_at,
    });
    if node.is_dir()
        && let Ok(children) = state.vfs.list_node(share.owner_id, &node).await
    {
        body["entries"] = json!(entries_json(&children));
    }
    Json(body).into_response()
}

/// `GET /public/{token}/list` and `/list/{*path}` — browse a link folder.
pub async fn public_list(
    State(state): State<AppState>,
    Path((token, sub)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    public_list_inner(&state, &token, &sub, &headers).await
}

pub async fn public_list_root(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    public_list_inner(&state, &token, "", &headers).await
}

async fn public_list_inner(
    state: &AppState,
    token: &str,
    sub: &str,
    headers: &HeaderMap,
) -> Response {
    let (share, _) = match load_link(state, token).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if let Err(response) = require_unlocked(state, &share, headers).await {
        return response;
    }
    let node = match state
        .vfs
        .link_node(share.owner_id, share.node_id, sub)
        .await
    {
        Ok(node) => node,
        Err(kolimi_vfs::VfsError::NotFound) => return api::not_found(),
        Err(_) => return api::not_found(),
    };
    if !node.is_dir() {
        return api::bad_request("not a directory");
    }
    match state.vfs.list_node(share.owner_id, &node).await {
        Ok(children) => Json(json!({
            "path": format!("/{sub}"),
            "entries": entries_json(&children),
        }))
        .into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `GET /public/{token}/download` and `/download/{*path}` — file bytes.
pub async fn public_download(
    State(state): State<AppState>,
    Path((token, sub)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    public_download_inner(&state, &token, &sub, &headers).await
}

pub async fn public_download_root(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    public_download_inner(&state, &token, "", &headers).await
}

async fn public_download_inner(
    state: &AppState,
    token: &str,
    sub: &str,
    headers: &HeaderMap,
) -> Response {
    let (share, _) = match load_link(state, token).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if let Err(response) = require_unlocked(state, &share, headers).await {
        return response;
    }
    let node = match state
        .vfs
        .link_node(share.owner_id, share.node_id, sub)
        .await
    {
        Ok(node) => node,
        Err(_) => return api::not_found(),
    };
    if node.is_dir() {
        return api::bad_request("not a file");
    }
    let Some(content_id) = node.content_id else {
        return api::not_found();
    };
    let manifest = match state.vfs.manifest(share.owner_id, &content_id).await {
        Ok(manifest) => std::sync::Arc::new(manifest),
        Err(_) => return api::internal_error(),
    };
    // Stream chunk-by-chunk: public links must not buffer multi-gigabyte
    // files in RAM (WebDAV GET already streams this way).
    let stream = state.vfs.store().content_stream(share.owner_id, manifest);
    audit(
        state,
        None,
        Some("link"),
        "link.download",
        &share.id.to_string(),
        json!({ "file": node.name }),
    )
    .await;
    let content_type = mime_guess::from_path(&node.name)
        .first_or_octet_stream()
        .to_string();
    let disposition = format!(
        "attachment; filename*=UTF-8''{}",
        percent_encoding::utf8_percent_encode(&node.name, percent_encoding::NON_ALPHANUMERIC)
    );
    let mut response = Response::new(axum::body::Body::from_stream(
        stream.map_err(|_| axum::Error::new("chunk read failed")),
    ));
    let headers_out = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        headers_out.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        headers_out.insert(header::CONTENT_DISPOSITION, value);
    }
    if let Ok(value) = HeaderValue::from_str(&node.size.to_string()) {
        headers_out.insert(header::CONTENT_LENGTH, value);
    }
    response
}

/// `POST /public/{token}/unlock` — exchange a password for a session cookie.
#[derive(Deserialize)]
pub struct UnlockRequest {
    password: String,
}

pub async fn public_unlock(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Path(token): Path<String>,
    Json(req): Json<UnlockRequest>,
) -> Response {
    let (share, _) = match load_link(&state, &token).await {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let Some(password_hash) = share.password_hash.clone() else {
        return StatusCode::NO_CONTENT.into_response();
    };
    // Key the lockout on (link, source) so a flood cannot lock the link
    // out for everyone who legitimately holds it.
    let lockout_key = format!("link:{}:{}", share.id, ip);
    if state.lockout.check(&lockout_key).is_some() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many failed attempts, try again later" })),
        )
            .into_response();
    }
    let candidate = req.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        password::verify_password(&password_hash, &candidate).unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !verified {
        state.lockout.record_failure(&lockout_key);
        audit(
            &state,
            None,
            Some("link"),
            "link.unlock_failed",
            &share.id.to_string(),
            json!({}),
        )
        .await;
        return api::unauthorized("wrong password");
    }
    state.lockout.record_success(&lockout_key);
    audit(
        &state,
        None,
        Some("link"),
        "link.unlock",
        &share.id.to_string(),
        json!({}),
    )
    .await;

    let Ok(session_token) = token::new_session_token() else {
        return api::internal_error();
    };
    let hash = token::hash_token(&session_token);
    let expires_at = kolimi_db::now_millis() + LINK_SESSION_TTL_MILLIS;
    if state
        .db
        .create_link_session(share.id, &hash, expires_at)
        .await
        .is_err()
    {
        return api::internal_error();
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    let cookie = format!(
        "{}=%s; Path=/; Max-Age={}; SameSite=Lax; HttpOnly{}",
        link_cookie_name(share.id),
        LINK_SESSION_TTL_MILLIS / 1000,
        if state.secure_cookies { "; Secure" } else { "" },
    )
    .replace("%s", &session_token);
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

// ---- helpers -----------------------------------------------------------

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default = "root_path")]
    path: String,
}

fn link_cookie_name(share_id: i64) -> String {
    format!("kolimi_link_{share_id}")
}

async fn hash_password(password: &str) -> Result<String, Response> {
    let candidate = password.to_string();
    match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await {
        Ok(Ok(hash)) => Ok(hash),
        _ => Err(api::internal_error()),
    }
}

fn random_password() -> Result<String, ()> {
    let raw = token::new_csrf_token().map_err(|_| ())?;
    Ok(raw.chars().take(12).collect())
}

async fn load_link(
    state: &AppState,
    token: &str,
) -> Result<(ShareRow, kolimi_vfs::Node), Response> {
    let Some(share) = state.db.share_by_token(token).await.ok().flatten() else {
        return Err(api::not_found());
    };
    if share
        .expires_at
        .is_some_and(|at| at <= kolimi_db::now_millis())
    {
        return Err((
            StatusCode::GONE,
            Json(json!({ "error": "this link has expired" })),
        )
            .into_response());
    }
    let node = match state.vfs.link_node(share.owner_id, share.node_id, "").await {
        Ok(node) => node,
        Err(_) => return Err(api::not_found()),
    };
    Ok((share, node))
}

async fn require_unlocked(
    state: &AppState,
    share: &ShareRow,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if share.password_hash.is_none() {
        return Ok(());
    }
    let cookie_name = link_cookie_name(share.id);
    let Some(value) = cookie_value(headers, &cookie_name) else {
        return Err(password_required());
    };
    let hash = token::hash_token(&value);
    match state.db.find_link_session(&hash).await {
        Ok(Some(session)) if session.share_id == share.id => Ok(()),
        _ => Err(password_required()),
    }
}

fn password_required() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "password required", "password_required": true })),
    )
        .into_response()
}

/// Drops wrapped E2EE keys for members of a revoked group share, but only for
/// members who no longer have any share covering the node (direct user share
/// or another group). Recipients with independent access keep their keys.
async fn remove_group_share_keys(state: &AppState, owner_id: i64, node_id: i64, group_id: i64) {
    let remaining = state
        .db
        .shares_for_node(owner_id, node_id)
        .await
        .unwrap_or_default();
    let mut still_authorized = std::collections::HashSet::new();
    for share in &remaining {
        if share.kind == "user"
            && let Some(recipient) = share.recipient_user_id
        {
            still_authorized.insert(recipient);
        }
        if share.kind == "group"
            && let Some(gid) = share.recipient_group_id
            && let Ok(members) = state.db.group_members(gid).await
        {
            for member in members {
                still_authorized.insert(member.id);
            }
        }
    }
    if let Ok(members) = state.db.group_members(group_id).await {
        for member in members {
            if !still_authorized.contains(&member.id) {
                let _ = state.db.delete_share_keys(node_id, member.id).await;
            }
        }
    }
}

fn entries_json(nodes: &[kolimi_vfs::Node]) -> Vec<Value> {
    nodes
        .iter()
        .map(|node| {
            json!({
                "name": node.name,
                "kind": if node.is_dir() { "dir" } else { "file" },
                "size": node.size,
                "modified_at": node.modified_at,
            })
        })
        .collect()
}

async fn share_json(state: &AppState, share: &ShareRow, generated_password: Option<&str>) -> Value {
    // Node details are best-effort; a deleted node leaves a stale share row
    // that is simply skipped at mount time. Surface it as `missing` so callers
    // can answer 410 Gone instead of returning a blank path/name.
    let path = state
        .db
        .node_path(share.owner_id, share.node_id)
        .await
        .ok()
        .flatten();
    let missing = path.is_none();
    let path = path.unwrap_or_default();
    let name = path.rsplit('/').next().unwrap_or_default().to_string();
    let recipient = if let Some(user_id) = share.recipient_user_id {
        state
            .db
            .get_user(user_id)
            .await
            .ok()
            .flatten()
            .map(|user| user.username)
    } else if let Some(group_id) = share.recipient_group_id {
        state
            .db
            .group_by_id(group_id)
            .await
            .ok()
            .flatten()
            .map(|group| group.name)
    } else {
        None
    };
    json!({
        "id": share.id,
        "kind": share.kind,
        "permission": share.permission,
        "recipient": recipient,
        "path": path,
        "name": name,
        "token": share.token,
        "url": share.token.as_ref().map(|token| format!("/s/{token}")),
        "password": generated_password,
        "expires_at": share.expires_at,
        "created_at": share.created_at,
        "missing": missing,
    })
}

fn conflict(message: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
}
