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

use crate::{AppState, api};

/// Query parameters for `/api/browse`.
#[derive(Deserialize)]
pub struct BrowseQuery {
    #[serde(default = "root_path")]
    path: String,
}

fn root_path() -> String {
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
            "parent": "/",
            "entries": entries,
        }))
        .into_response();
    }

    // The caller's own root also shows mounts.
    if segments.is_empty() {
        let mut entries = Vec::new();
        match state.vfs.list_access(user.user_id, "/").await {
            Ok((_, children)) => {
                for child in children {
                    entries.push(node_entry(&child, "", false, None, None));
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
            let entries: Vec<Value> = children
                .iter()
                .map(|child| {
                    node_entry(
                        child,
                        &normalized_path(&segments),
                        shared,
                        owner.clone(),
                        permission.clone(),
                    )
                })
                .collect();
            Json(json!({
                "path": normalized_path(&segments),
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
    Ok(mounts
        .iter()
        .map(|mount| {
            json!({
                "name": mount.name,
                "path": format!("/{SHARED_MOUNT}/{}", mount.name),
                "kind": if mount.kind == kolimi_vfs::NodeKind::Dir { "dir" } else { "file" },
                "size": mount.size,
                "modified_at": mount.modified_at,
                "etag": mount.to_node().etag(),
                "shared": true,
                "owner": mount.owner_username,
                "permission": mount.permission.as_str(),
            })
        })
        .collect())
}

fn node_entry(
    node: &Node,
    base: &str,
    shared: bool,
    owner: Option<String>,
    permission: Option<String>,
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
