//! Native sync API (RFC 0002): change feed, manifests, chunks, trash, and
//! version history. WebDAV remains the compatibility surface; this API gives
//! first-party clients delta transfers and live notifications.

use std::{collections::HashMap, convert::Infallible, time::Duration};

use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::StreamExt;
use kolimi_auth::CurrentUser;
use kolimi_chunk::{Hash, Manifest};
use kolimi_vfs::VfsError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::api::{bad_request, forbidden, internal_error, not_found, quota_warning_percent};
use crate::audit;

const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMMIT_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_PAGE: i64 = 500;
const MAX_PAGE: i64 = 2000;

fn page_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
}

/// Pagination/query parameters for sync endpoints.
#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    since: Option<i64>,
    #[serde(default)]
    after_id: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

/// `path=` query parameter.
#[derive(Deserialize)]
pub struct PathQuery {
    path: String,
}

fn vfs_error_response(e: VfsError) -> Response {
    let status = match &e {
        VfsError::NotFound | VfsError::Store(kolimi_store::StoreError::NotFound(_)) => {
            StatusCode::NOT_FOUND
        }
        VfsError::IsCollection
        | VfsError::Root
        | VfsError::InvalidPath(_)
        | VfsError::ParentNotCollection => StatusCode::BAD_REQUEST,
        VfsError::AlreadyExists | VfsError::Conflict(_) => StatusCode::CONFLICT,
        VfsError::MissingChunk(_) => StatusCode::CONFLICT,
        VfsError::Store(kolimi_store::StoreError::TooLarge { .. })
        | VfsError::Store(kolimi_store::StoreError::QuotaExceeded { .. }) => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": e.to_string() }))).into_response()
}

fn json_response(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

/// `GET /api/sync/changes?since=&limit=` — per-user change feed.
pub async fn changes(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PageQuery>,
) -> Response {
    let since = query.since.unwrap_or(0).max(0);
    let limit = page_limit(query.limit);
    let mut rows = match state.db.changes_since(user.user_id, since, limit + 1).await {
        Ok(rows) => rows,
        Err(_) => return internal_error(),
    };
    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let next_seq = rows.last().map(|row| row.seq).unwrap_or(since);

    let changes: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "seq": row.seq,
                "path": row.path,
                "from_path": row.from_path,
                "op": row.op,
                "content_id": row.content_id.as_deref().and_then(bytes_to_hash_hex),
                "size": row.size,
                "modified_at": row.modified_at,
            })
        })
        .collect();
    json_response(
        StatusCode::OK,
        json!({ "changes": changes, "next_seq": next_seq, "has_more": has_more }),
    )
}

fn bytes_to_hash_hex(bytes: &[u8]) -> Option<String> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash::from_bytes(arr).to_hex())
}

/// `GET /api/sync/tree?after_id=&limit=` — paginated namespace snapshot.
pub async fn tree(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PageQuery>,
) -> Response {
    let after_id = query.after_id.unwrap_or(0).max(0);
    let limit = page_limit(query.limit);
    let nodes = match state.db.all_live_nodes(user.user_id).await {
        Ok(nodes) => nodes,
        Err(_) => return internal_error(),
    };
    let encrypted: std::collections::HashSet<i64> =
        match state.db.encrypted_node_ids(user.user_id).await {
            Ok(ids) => ids.into_iter().collect(),
            // Never report ciphertext as plaintext on a DB error.
            Err(_) => return internal_error(),
        };

    let mut info: HashMap<i64, (Option<i64>, String)> = HashMap::new();
    for node in &nodes {
        info.insert(node.id, (node.parent_id, node.name.clone()));
    }
    let mut memo: HashMap<i64, String> = HashMap::new();

    let mut entries = Vec::new();
    let mut last_id = after_id;
    for node in nodes.iter().filter(|node| node.id > after_id) {
        if entries.len() as i64 >= limit {
            break;
        }
        let path = path_for(node.id, &info, &mut memo);
        entries.push(json!({
            "id": node.id,
            "path": path,
            "kind": node.kind,
            "size": node.size,
            "content_id": node.content_id.as_deref().and_then(bytes_to_hash_hex),
            "etag": etag_for(node),
            "modified_at": node.modified_at,
            "encrypted": encrypted.contains(&node.id),
        }));
        last_id = node.id;
    }
    let has_more = nodes.iter().any(|node| node.id > last_id);
    json_response(
        StatusCode::OK,
        json!({ "entries": entries, "last_id": last_id, "has_more": has_more }),
    )
}

fn etag_for(node: &kolimi_db::Node) -> String {
    match node.content_id.as_deref().and_then(bytes_to_hash_hex) {
        Some(hex) => format!("\"{hex}\""),
        None => format!("\"d{}\"", node.modified_at),
    }
}

fn path_for(
    id: i64,
    info: &HashMap<i64, (Option<i64>, String)>,
    memo: &mut HashMap<i64, String>,
) -> String {
    if let Some(path) = memo.get(&id) {
        return path.clone();
    }
    let Some((parent, name)) = info.get(&id) else {
        return String::new();
    };
    let base = match parent {
        Some(parent) => path_for(*parent, info, memo),
        None => String::new(),
    };
    let path = if name.is_empty() {
        "/".to_string()
    } else if base.is_empty() || base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    };
    memo.insert(id, path.clone());
    path
}

/// `GET /api/sync/shared-tree` — files shared with the caller.
///
/// Paths are presented under `/Shared with me/<name>/…`, mirroring the
/// browse mount. Encrypted files carry `encrypted: true` and their keys
/// are fetched separately (`/api/e2ee/share-key`).
pub async fn shared_tree(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let shares = match state.db.received_shares(user.user_id).await {
        Ok(shares) => shares,
        Err(_) => return internal_error(),
    };

    let mut entries = Vec::new();
    let mut seen: std::collections::HashSet<(i64, i64)> = std::collections::HashSet::new();
    let mut nodes_cache: HashMap<i64, Vec<kolimi_db::Node>> = HashMap::new();
    let mut encrypted_cache: HashMap<i64, std::collections::HashSet<i64>> = HashMap::new();

    for share in shares {
        if !seen.insert((share.owner_id, share.node_id)) {
            continue;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = nodes_cache.entry(share.owner_id)
        {
            let nodes = match state.db.all_live_nodes(share.owner_id).await {
                Ok(nodes) => nodes,
                Err(_) => return internal_error(),
            };
            entry.insert(nodes);
        }
        if let std::collections::hash_map::Entry::Vacant(entry) =
            encrypted_cache.entry(share.owner_id)
        {
            let ids = match state.db.encrypted_node_ids(share.owner_id).await {
                Ok(ids) => ids.into_iter().collect(),
                Err(_) => return internal_error(),
            };
            entry.insert(ids);
        }
        let nodes = &nodes_cache[&share.owner_id];
        let encrypted = &encrypted_cache[&share.owner_id];

        let mut info: HashMap<i64, (Option<i64>, String)> = HashMap::new();
        for node in nodes {
            info.insert(node.id, (node.parent_id, node.name.clone()));
        }

        for node in nodes {
            if node.kind != "file" {
                continue;
            }
            // The node itself, or a descendant of the shared directory.
            let mut current = Some(node.id);
            let mut relative = Vec::new();
            let mut belongs = false;
            while let Some(id) = current {
                if id == share.node_id {
                    belongs = true;
                    break;
                }
                let Some((parent, name)) = info.get(&id) else {
                    break;
                };
                relative.push(name.clone());
                current = *parent;
            }
            if !belongs {
                continue;
            }
            relative.reverse();
            let suffix = relative.join("/");
            let path = if suffix.is_empty() {
                format!("/Shared with me/{}", share.name)
            } else {
                format!("/Shared with me/{}/{}", share.name, suffix)
            };
            entries.push(json!({
                "path": path,
                "content_id": node.content_id.as_deref().and_then(bytes_to_hash_hex),
                "size": node.size,
                "modified_at": node.modified_at,
                "encrypted": encrypted.contains(&node.id),
                "owner": share.owner_username,
                "shared": true,
                "etag": etag_for(node),
            }));
        }
    }
    json_response(StatusCode::OK, json!({ "entries": entries }))
}

/// `GET /api/manifests/{content_id}` — manifest by content id.
pub async fn manifest_by_id(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(content_id): Path<String>,
) -> Response {
    let Ok(hash) = content_id.parse::<Hash>() else {
        return bad_request("invalid content id");
    };
    match state.vfs.manifest(user.user_id, &hash).await {
        Ok(manifest) => Json(manifest).into_response(),
        Err(e) => vfs_error_response(e),
    }
}

/// `GET /api/files/manifest?path=` — current manifest of a file.
pub async fn file_manifest(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    match state.vfs.manifest_of(user.user_id, &query.path).await {
        Ok(manifest) => Json(manifest).into_response(),
        Err(e) => vfs_error_response(e),
    }
}

/// `GET /api/chunks/{hash}` — download one chunk.
#[derive(Deserialize)]
pub struct ChunkQuery {
    /// Optional file path; when present the chunk is read from that
    /// file's owner store (shared files) and must belong to the file.
    #[serde(default)]
    path: Option<String>,
}

pub async fn get_chunk(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(hash): Path<String>,
    Query(query): Query<ChunkQuery>,
) -> Response {
    let Ok(hash) = hash.parse::<Hash>() else {
        return bad_request("invalid chunk hash");
    };
    let mut owner_id = user.user_id;
    if let Some(path) = query.path.as_deref() {
        let access = match state.vfs.resolve_access(user.user_id, path).await {
            Ok(access) => access,
            Err(VfsError::NotFound) => return not_found(),
            Err(_) => return internal_error(),
        };
        if access.node.is_dir() {
            return bad_request("path must be a file");
        }
        let Some(content_id) = access.node.content_id else {
            return not_found();
        };
        let Ok(manifest) = state.vfs.manifest(access.owner_id, &content_id).await else {
            return not_found();
        };
        if !manifest.chunks.iter().any(|chunk| chunk.hash == hash) {
            return forbidden("chunk does not belong to this file");
        }
        owner_id = access.owner_id;
    }
    match state.vfs.read_chunk(owner_id, &hash).await {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            response
        }
        Err(e) => vfs_error_response(e),
    }
}

/// `PUT /api/chunks/{hash}` — idempotent chunk upload (also completes
/// interrupted uploads: already-present chunks return 204).
pub async fn put_chunk(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(hash): Path<String>,
    body: Body,
) -> Response {
    let Ok(hash) = hash.parse::<Hash>() else {
        return bad_request("invalid chunk hash");
    };
    let bytes = match to_bytes(body, MAX_CHUNK_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    if bytes.is_empty() {
        return bad_request("empty chunk");
    }
    let existed = state.vfs.read_chunk(user.user_id, &hash).await.is_ok();
    match state.vfs.write_chunk(user.user_id, &hash, &bytes).await {
        Ok(()) if existed => StatusCode::NO_CONTENT.into_response(),
        Ok(()) => StatusCode::CREATED.into_response(),
        Err(VfsError::Store(kolimi_store::StoreError::Mismatch { .. })) => {
            bad_request("chunk hash does not match its content")
        }
        Err(e) => vfs_error_response(e),
    }
}

/// `path=` and optional `if_content_id=` for manifest commits.
#[derive(Deserialize)]
pub struct CommitQuery {
    path: String,
    #[serde(default)]
    if_content_id: Option<String>,
}

/// `PUT /api/files?path=&if_content_id=` — commit a client-built manifest.
pub async fn commit_file(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<CommitQuery>,
    body: Body,
) -> Response {
    let bytes = match to_bytes(body, MAX_COMMIT_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let manifest: Manifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(_) => return bad_request("invalid manifest"),
    };
    if manifest.version != Manifest::VERSION {
        return bad_request("unsupported manifest version");
    }
    let declared: u64 = manifest
        .chunks
        .iter()
        .map(|chunk| u64::from(chunk.len))
        .sum();
    if declared != manifest.size {
        return bad_request("manifest size does not match chunk lengths");
    }

    let usage_before = state.vfs.quota_state(user.user_id).await.ok();
    match state
        .vfs
        .commit_manifest(
            user.user_id,
            &query.path,
            &manifest,
            query.if_content_id.as_deref(),
        )
        .await
    {
        Ok(Some(node)) => {
            state.metrics.upload();
            let mut response = json_response(
                StatusCode::OK,
                json!({
                    "content_id": node.content_id.map(|hash| hash.to_hex()),
                    "size": node.size,
                    "etag": node.etag(),
                }),
            );
            // Near-quota notification: warn (and audit once per crossing)
            // when a commit pushes the user to/over 90% of their quota.
            if let Ok((quota, used)) = state.vfs.quota_state(user.user_id).await
                && let Some(percent) = quota_warning_percent(used, quota)
            {
                let crossed = usage_before
                    .map(|(_, before)| quota_warning_percent(before, quota).is_none())
                    .unwrap_or(true);
                if crossed {
                    audit(
                        &state,
                        Some(user.user_id),
                        Some(&user.username),
                        "quota.warn",
                        &query.path,
                        json!({ "used_bytes": used, "quota_bytes": quota, "percent": percent }),
                    )
                    .await;
                }
                if let Ok(value) = HeaderValue::from_str(&percent.to_string()) {
                    response
                        .headers_mut()
                        .insert("x-kolimi-quota-warning", value);
                }
            }
            response
        }
        Ok(None) => {
            let current = state
                .vfs
                .stat(user.user_id, &query.path)
                .await
                .ok()
                .flatten()
                .and_then(|node| node.content_id.map(|hash| hash.to_hex()));
            json_response(
                StatusCode::CONFLICT,
                json!({ "error": "content changed under the client", "current_content_id": current }),
            )
        }
        Err(VfsError::MissingChunk(hash)) => json_response(
            StatusCode::CONFLICT,
            json!({ "error": "missing chunk", "chunk": hash.to_hex() }),
        ),
        Err(e) => vfs_error_response(e),
    }
}

/// `GET /api/trash` — list recoverable deletions.
pub async fn list_trash(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.vfs.trash(user.user_id).await {
        Ok(nodes) => {
            let entries: Vec<Value> = nodes
                .iter()
                .map(|node| {
                    json!({
                        "id": node.id,
                        "name": node.name,
                        "original_path": node.original_path,
                        "kind": if node.is_dir() { "dir" } else { "file" },
                        "size": node.size,
                    })
                })
                .collect();
            json_response(StatusCode::OK, json!(entries))
        }
        Err(e) => vfs_error_response(e),
    }
}

/// `POST /api/trash/{id}/restore` — restore a trashed node.
pub async fn restore_trash(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.vfs.restore_from_trash(user.user_id, id).await {
        Ok(node) => json_response(StatusCode::OK, json!({ "id": node.id, "name": node.name })),
        Err(e) => vfs_error_response(e),
    }
}

/// `DELETE /api/trash/{id}` — permanently delete a trashed node.
pub async fn delete_trash(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    match state.vfs.purge_from_trash(user.user_id, id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => vfs_error_response(e),
    }
}

/// `GET /api/versions?path=` — version history of a file.
pub async fn list_versions(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PathQuery>,
) -> Response {
    match state.vfs.versions(user.user_id, &query.path).await {
        Ok(versions) => {
            let entries: Vec<Value> = versions
                .iter()
                .map(|version| {
                    json!({
                        "id": version.id,
                        "size": version.size,
                        "created_at": version.created_at,
                        "content_id": bytes_to_hash_hex(&version.content_id),
                    })
                })
                .collect();
            json_response(StatusCode::OK, json!(entries))
        }
        Err(e) => vfs_error_response(e),
    }
}

/// Body for restoring a version.
#[derive(Deserialize)]
pub struct RestoreVersion {
    path: String,
}

/// `POST /api/versions/{id}/restore` — make a version current again.
pub async fn restore_version(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(version_id): Path<i64>,
    Json(body): Json<RestoreVersion>,
) -> Response {
    match state
        .vfs
        .restore_version(user.user_id, &body.path, version_id)
        .await
    {
        Ok(node) => json_response(
            StatusCode::OK,
            json!({ "content_id": node.content_id.map(|hash| hash.to_hex()), "size": node.size }),
        ),
        Err(e) => vfs_error_response(e),
    }
}

/// `GET /api/sync/events?since=` — SSE wake-up channel.
///
/// Emits `{"seq": N}` whenever the user's change feed advances; clients
/// then fetch `/api/sync/changes?since=`. This keeps the stream tiny and
/// makes reconnects safe (`Last-Event-ID` / `since` resume).
pub async fn events(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<PageQuery>,
) -> Response {
    // Bound the number of live streams and their lifetime so a client
    // cannot exhaust tasks/DB polling with many open connections.
    let Ok(permit) = state.sse_permits.clone().try_acquire_owned() else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "too many event streams\n",
        )
            .into_response();
    };
    let start_seq = query.since.unwrap_or(0).max(0);
    let current = state
        .db
        .latest_change_seq(user.user_id)
        .await
        .unwrap_or(start_seq);
    let initial = Event::default()
        .event("change")
        .data(json!({ "seq": current }).to_string());
    let deadline = tokio::time::Instant::now() + crate::SSE_MAX_LIFETIME;

    let updates = futures_util::stream::unfold(
        (state, user.user_id, current, deadline, permit),
        |(state, user_id, last, deadline, permit)| async move {
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                match state.db.latest_change_seq(user_id).await {
                    Ok(seq) if seq > last => {
                        let event = Event::default()
                            .event("change")
                            .data(json!({ "seq": seq }).to_string());
                        return Some((
                            Ok::<Event, Infallible>(event),
                            (state, user_id, seq, deadline, permit),
                        ));
                    }
                    _ => continue,
                }
            }
        },
    );

    let stream =
        futures_util::stream::once(async move { Ok::<Event, Infallible>(initial) }).chain(updates);
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
