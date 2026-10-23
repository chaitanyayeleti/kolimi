//! JSON directory browsing for the web UI.
//!
//! Merges the caller's own tree with received-share mounts; every entry
//! carries the permission the caller has on it.

use axum::{
    Extension, Json,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use kolimi_auth::CurrentUser;
use kolimi_vfs::{Node, SHARED_MOUNT, VfsError, path};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, api, audit};

/// Query parameters for `/api/browse`.
#[derive(Deserialize)]
pub struct BrowseQuery {
    #[serde(default = "root_path")]
    path: String,
}

pub(crate) fn root_path() -> String {
    "/".to_string()
}

/// `GET /api/browse?path=` — one directory level as JSON.
pub async fn browse(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<BrowseQuery>,
) -> Response {
    let segments = match path::parse(&query.path) {
        Ok(segments) => segments,
        Err(_) => return api::bad_request("invalid path"),
    };
    let parent = parent_of(&segments);

    // The virtual root of received shares.
    if segments.first().map(String::as_str) == Some(SHARED_MOUNT) && segments.len() == 1 {
        let entries = match mount_entries(&state, user.user_id).await {
            Ok(entries) => entries,
            Err(_) => return api::internal_error(),
        };
        return Json(json!({
            "path": format!("/{SHARED_MOUNT}"),
            "encrypted": false,
            "parent": "/",
            "entries": entries,
        }))
        .into_response();
    }

    // The caller's own root also shows mounts.
    if segments.is_empty() {
        let mut entries = Vec::new();
        let encrypted: std::collections::HashSet<i64> =
            match state.db.encrypted_node_ids(user.user_id).await {
                Ok(ids) => ids.into_iter().collect(),
                Err(_) => return api::internal_error(),
            };
        match state.vfs.list_access(user.user_id, "/").await {
            Ok((_, children)) => {
                for child in children {
                    entries.push(node_entry(
                        &child,
                        "",
                        false,
                        None,
                        None,
                        encrypted.contains(&child.id) || child.encrypted,
                    ));
                }
            }
            Err(e) => return vfs_error(e),
        }
        match mount_entries(&state, user.user_id).await {
            Ok(mounts) => entries.extend(mounts),
            Err(_) => return api::internal_error(),
        }
        return Json(json!({
            "path": "/",
            "encrypted": false,
            "parent": Value::Null,
            "entries": entries,
        }))
        .into_response();
    }

    match state.vfs.list_access(user.user_id, &query.path).await {
        Ok((access, children)) => {
            let shared = access.owner_id != user.user_id;
            let owner = if shared {
                state
                    .db
                    .get_user(access.owner_id)
                    .await
                    .ok()
                    .flatten()
                    .map(|user| user.username)
            } else {
                None
            };
            let permission = shared.then(|| access.perm.as_str().to_string());
            let encrypted: std::collections::HashSet<i64> =
                match state.db.encrypted_node_ids(access.owner_id).await {
                    Ok(ids) => ids.into_iter().collect(),
                    Err(_) => return api::internal_error(),
                };
            // Everything inside an encrypted folder is encrypted, even when
            // the child folder carries no flag of its own.
            let inherited = state
                .vfs
                .path_is_encrypted(user.user_id, &query.path)
                .await
                .unwrap_or(true);
            let entries: Vec<Value> = children
                .iter()
                .map(|child| {
                    node_entry(
                        child,
                        &normalized_path(&segments),
                        shared,
                        owner.clone(),
                        permission.clone(),
                        inherited || encrypted.contains(&child.id) || child.encrypted,
                    )
                })
                .collect();
            Json(json!({
                "path": normalized_path(&segments),
                "encrypted": inherited,
                "parent": parent,
                "entries": entries,
            }))
            .into_response()
        }
        Err(VfsError::NotFound) => (axum::http::StatusCode::NOT_FOUND).into_response(),
        Err(VfsError::Forbidden) => (axum::http::StatusCode::FORBIDDEN).into_response(),
        Err(e) => vfs_error(e),
    }
}

async fn mount_entries(state: &AppState, user_id: i64) -> Result<Vec<Value>, kolimi_vfs::VfsError> {
    let mounts = state.vfs.received_mounts(user_id).await?;
    // Encrypted flags are per owner tree; mounts are few, so one lookup
    // per distinct owner.
    let mut encrypted_by_owner: std::collections::HashMap<i64, std::collections::HashSet<i64>> =
        std::collections::HashMap::new();
    let mut out = Vec::with_capacity(mounts.len());
    for mount in &mounts {
        let set = match encrypted_by_owner.get(&mount.owner_id) {
            Some(set) => set.clone(),
            None => {
                let ids: std::collections::HashSet<i64> = state
                    .db
                    .encrypted_node_ids(mount.owner_id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                encrypted_by_owner.insert(mount.owner_id, ids.clone());
                ids
            }
        };
        out.push(json!({
            "name": mount.name,
            "path": format!("/{SHARED_MOUNT}/{}", mount.name),
            "kind": if mount.kind == kolimi_vfs::NodeKind::Dir { "dir" } else { "file" },
            "size": mount.size,
            "modified_at": mount.modified_at,
            "etag": mount.to_node().etag(),
            "shared": true,
            "owner": mount.owner_username,
            "permission": mount.permission.as_str(),
            "encrypted": set.contains(&mount.node_id),
        }));
    }
    Ok(out)
}

fn node_entry(
    node: &Node,
    base: &str,
    shared: bool,
    owner: Option<String>,
    permission: Option<String>,
    encrypted: bool,
) -> Value {
    let path = if base.is_empty() || base == "/" {
        format!("/{}", node.name)
    } else {
        format!("{base}/{}", node.name)
    };
    json!({
        "name": node.name,
        "path": path,
        "kind": if node.is_dir() { "dir" } else { "file" },
        "size": node.size,
        "modified_at": node.modified_at,
        "etag": node.etag(),
        "shared": shared,
        "owner": owner,
        "permission": permission,
        "encrypted": encrypted,
    })
}

fn parent_of(segments: &[String]) -> Value {
    if segments.is_empty() {
        return Value::Null;
    }
    if segments.len() == 1 {
        return json!("/");
    }
    json!(normalized_path(&segments[..segments.len() - 1]))
}

fn normalized_path(segments: &[String]) -> String {
    format!("/{}", segments.join("/"))
}

fn vfs_error(e: VfsError) -> Response {
    match e {
        VfsError::NotFound => axum::http::StatusCode::NOT_FOUND.into_response(),
        VfsError::Forbidden => axum::http::StatusCode::FORBIDDEN.into_response(),
        _ => api::internal_error(),
    }
}

/// Query parameters for `/api/files/info`.
#[derive(Deserialize)]
pub struct InfoQuery {
    #[serde(default = "root_path")]
    path: String,
}

/// `GET /api/files/info?path=` — metadata for one node, including whether it
/// is encrypted. Used by the web UI to decide how to handle a path (e.g.
/// whether an upload target needs client-side encryption).
pub async fn info(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<InfoQuery>,
) -> Response {
    let access = match state.vfs.resolve_access(user.user_id, &query.path).await {
        Ok(access) => access,
        Err(VfsError::NotFound) => return api::not_found(),
        Err(VfsError::Forbidden) => return api::forbidden("no access"),
        Err(_) => return api::internal_error(),
    };
    // `encrypted` means "everything at this path is client-side encrypted".
    // It follows the folder hierarchy: any ancestor folder (including this
    // one) that is declared encrypted makes the path encrypted. No guessing
    // from the contents — an empty Vault is still a Vault, and a subfolder
    // created inside Vault is encrypted too. This is the exact check the
    // uploader uses before deciding to encrypt.
    let inherited = state
        .vfs
        .path_is_encrypted(user.user_id, &query.path)
        .await
        .unwrap_or(true);
    let encrypted = inherited
        || access.node.encrypted
        || (!access.node.is_dir() && state.db.is_encrypted(access.node.id).await.unwrap_or(true));
    Json(json!({
        "path": query.path,
        "kind": if access.node.is_dir() { "dir" } else { "file" },
        "size": access.node.size,
        "modified_at": access.node.modified_at,
        "etag": access.node.etag(),
        "encrypted": encrypted,
    }))
    .into_response()
}

/// Request body for `/api/files/encrypt`.
#[derive(Deserialize)]
pub struct EncryptRequest {
    path: String,
    encrypted: bool,
}

/// `POST /api/files/encrypt` — declare a folder encrypted (or plaintext).
///
/// The flag is what every client reads to decide whether uploads must be
/// encrypted, so it can be set on an empty folder. Two safety rules:
/// enabling is refused while plaintext files exist inside (they would be
/// indistinguishable from ciphertext to other clients), and disabling is
/// refused while encrypted files exist (it would expose them as plaintext).
pub async fn set_encryption(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<EncryptRequest>,
) -> Response {
    let access = match state.vfs.resolve_access(user.user_id, &req.path).await {
        Ok(access) => access,
        Err(VfsError::NotFound) => return api::not_found(),
        Err(VfsError::Forbidden) => return api::forbidden("no access"),
        Err(_) => return api::internal_error(),
    };
    if !access.node.is_dir() {
        return api::bad_request("only folders can be encrypted");
    }
    if access.node.parent_id.is_none() {
        return api::bad_request("the account root cannot be encrypted");
    }
    if !access.perm.allows(kolimi_vfs::Perm::Write) {
        return api::forbidden("write access is required");
    }
    // Mixed folders would let a plaintext client masquerade as ciphertext
    // (or the reverse), so refuse until the subtree is uniform.
    let mut stack = vec![access.node.clone()];
    let mut plaintext = 0usize;
    let mut encrypted = 0usize;
    while let Some(dir) = stack.pop() {
        let children = match state.vfs.list_node(access.owner_id, &dir).await {
            Ok(children) => children,
            Err(_) => return api::internal_error(),
        };
        for child in children {
            if child.is_dir() {
                stack.push(child);
            } else if state.db.is_encrypted(child.id).await.unwrap_or(true) {
                encrypted += 1;
            } else {
                plaintext += 1;
            }
        }
    }
    if req.encrypted && plaintext > 0 {
        return api::bad_request(
            "this folder still holds unencrypted files — move them out or delete them first",
        );
    }
    if !req.encrypted && encrypted > 0 {
        return api::bad_request(
            "this folder still holds encrypted files — remove them before making it plaintext",
        );
    }
    match state
        .db
        .set_folder_encrypted(access.owner_id, access.node.id, req.encrypted)
        .await
    {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "folder.encryption",
                &req.path,
                json!({ "encrypted": req.encrypted }),
            )
            .await;
            Json(json!({ "path": req.path, "encrypted": req.encrypted })).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// Request body for `/api/files/move`.
#[derive(Deserialize)]
pub struct MoveRequest {
    from: String,
    to: String,
}

/// `POST /api/files/move` — rename or move a node (metadata-only).
///
/// Unlike WebDAV `MOVE` (plaintext-only surface per the E2EE boundary), this
/// works for encrypted nodes too: moving ciphertext pointers never exposes
/// plaintext to the server. Write permission on both ends is enforced by the
/// VFS.
pub async fn move_node(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<MoveRequest>,
) -> Response {
    if req.from.is_empty() || req.to.is_empty() {
        return api::bad_request("from and to are required");
    }
    // Metadata moves must not cross the encryption boundary: a plaintext
    // file would land inside an encrypted folder, or a ciphertext file would
    // be exposed in a plaintext one. On a DB error, assume encrypted (the
    // safe direction) so a broken lookup cannot leak plaintext.
    let from_encrypted = state
        .vfs
        .path_is_encrypted(user.user_id, &req.from)
        .await
        .unwrap_or(true);
    let to_encrypted = state
        .vfs
        .path_is_encrypted(user.user_id, &req.to)
        .await
        .unwrap_or(true);
    if from_encrypted != to_encrypted {
        return api::bad_request(
            "cannot move items across the encryption boundary — upload them into the target folder instead",
        );
    }
    match state
        .vfs
        .move_node(user.user_id, &req.from, &req.to, false)
        .await
    {
        Ok(_) => Json(json!({ "from": req.from, "to": req.to })).into_response(),
        Err(VfsError::NotFound) => api::not_found(),
        Err(VfsError::Forbidden) => api::forbidden("no access"),
        Err(VfsError::AlreadyExists) => (
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "error": "destination already exists" })),
        )
            .into_response(),
        Err(_) => api::internal_error(),
    }
}
