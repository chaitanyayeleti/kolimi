//! WebDAV surface (RFC 4918 subset) for Kolimi.
//!
//! Implements OPTIONS, GET/HEAD (with byte ranges), PUT, DELETE, MKCOL,
//! PROPFIND, PROPPATCH, COPY, MOVE, LOCK/UNLOCK, and REPORT over the VFS.
//! Advertises DAV compliance classes 1 and 2.
//!
//! The router is stateless: `Vfs` and `CurrentUser` are injected via
//! request extensions by the server crate.

mod caldav;
mod cond;
mod davpath;
mod ical;
mod lock;
mod range;
mod report;
mod vcard;
mod xml;

pub use lock::LockManager;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Extension,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use kolimi_auth::CurrentUser;
use kolimi_store::StoreError;
use kolimi_vfs::{Node, NodeKind, SHARED_MOUNT, Vfs, VfsError};

use crate::report::{Report, ReportProps, parse_report};

const ALLOW: &str =
    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, COPY, MOVE, MKCOL, LOCK, UNLOCK, REPORT";
const MAX_PROPFIND_BODY: usize = 1024 * 1024;
const MAX_UPLOAD_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SYNC_CHANGES: i64 = 10_000;

/// Routes served under `/dav`, generic over the app state.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/dav", any(handle))
        .route("/dav/", any(handle))
        .route("/dav/{*path}", any(handle))
}

async fn handle(
    Extension(vfs): Extension<Arc<Vfs>>,
    Extension(user): Extension<CurrentUser>,
    Extension(locks): Extension<Arc<LockManager>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let path = uri.path();
    let Some(raw) = path.strip_prefix("/dav") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let segments = match davpath::to_segments(raw) {
        Ok(segments) => segments,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // CalDAV/CardDAV namespaces.
    if matches!(
        segments.first().map(String::as_str),
        Some("principals" | "calendars" | "addressbooks")
    ) {
        return caldav::handle(&vfs, &user, &segments, &method, &headers, body).await;
    }

    let vfs_path = kolimi_vfs::path::join(&segments);
    let user_id = user.user_id;

    match method.as_str() {
        "OPTIONS" => options(),
        "GET" => get(&vfs, user_id, &vfs_path, &headers, false).await,
        "HEAD" => get(&vfs, user_id, &vfs_path, &headers, true).await,
        "PUT" => put(&vfs, &locks, user_id, &vfs_path, &headers, body).await,
        "DELETE" => delete(&vfs, &locks, user_id, &vfs_path, &headers).await,
        "MKCOL" => mkcol(&vfs, &locks, user_id, &vfs_path, &headers, body).await,
        "PROPFIND" => propfind(&vfs, &locks, &user, &segments, &vfs_path, &headers, body).await,
        "PROPPATCH" => proppatch(&vfs, &locks, user_id, &segments, &vfs_path, &headers, body).await,
        "COPY" => copy_move(&vfs, &locks, user_id, &vfs_path, &headers, false).await,
        "MOVE" => copy_move(&vfs, &locks, user_id, &vfs_path, &headers, true).await,
        "LOCK" => lock_node(&vfs, &locks, &user, &segments, &vfs_path, &headers, body).await,
        "UNLOCK" => unlock_node(&locks, user_id, &vfs_path, &headers),
        "REPORT" => report_file_tree(&vfs, &user, &vfs_path, body).await,
        _ => method_not_allowed(),
    }
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(header::ALLOW, HeaderValue::from_static(ALLOW));
    headers.insert(
        axum::http::HeaderName::from_static("dav"),
        HeaderValue::from_static("1, 2, sync-collection"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("ms-author-via"),
        HeaderValue::from_static("DAV"),
    );
    response
}

fn method_not_allowed() -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(ALLOW));
    response
}

/// Whether `node_id` is an end-to-end encrypted file. The server holds no
/// keys, so DAV must never serve ciphertext as a file, nor let plaintext
/// overwrite one (RFC 0010, option A: plaintext-only DAV surface). A DB
/// error fails **closed** (treat as encrypted) to avoid leaking ciphertext.
async fn is_encrypted(vfs: &Vfs, node_id: i64) -> bool {
    vfs.db().is_encrypted(node_id).await.unwrap_or(true)
}

/// `403 Forbidden` for any DAV access to an encrypted node.
fn encrypted_forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

async fn get(vfs: &Vfs, user_id: i64, path: &str, headers: &HeaderMap, head: bool) -> Response {
    let (access, manifest) = match vfs.read_manifest_access(user_id, path).await {
        Ok(result) => result,
        Err(VfsError::IsCollection | VfsError::SharedRoot) => return method_not_allowed(),
        Err(e) => return vfs_error(e),
    };
    let node = access.node;
    let owner_id = access.owner_id;
    if is_encrypted(vfs, node.id).await {
        return encrypted_forbidden();
    }
    let size = manifest.size;

    let etag = node.etag();
    if let Some(value) = header_str(headers, header::IF_NONE_MATCH)
        && cond::matches_etag(value, &etag, true)
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        let headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&etag) {
            headers.insert(header::ETAG, value);
        }
        if let Ok(value) = HeaderValue::from_str(&cond::http_date(node.modified_at)) {
            headers.insert(header::LAST_MODIFIED, value);
        }
        return response;
    }

    let content_type = mime_guess::from_path(&node.name)
        .first_or_octet_stream()
        .to_string();

    // Range handling, subject to `If-Range` (serve the whole entity when the
    // validator does not match the current one).
    let mut wanted = header_str(headers, header::RANGE)
        .map(|value| range::parse(value, size))
        .unwrap_or(range::RangeOutcome::Full);
    if matches!(wanted, range::RangeOutcome::Satisfiable { .. })
        && let Some(if_range) = header_str(headers, header::IF_RANGE)
        && if_range.trim() != etag
        && if_range.trim() != cond::http_date(node.modified_at)
    {
        wanted = range::RangeOutcome::Full;
    }

    let manifest = std::sync::Arc::new(manifest);
    let base = || {
        Response::builder()
            .header(header::CONTENT_TYPE, content_type.clone())
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::ETAG, etag.clone())
            .header(header::LAST_MODIFIED, cond::http_date(node.modified_at))
    };

    match wanted {
        range::RangeOutcome::Unsatisfiable => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let out = response.headers_mut();
            out.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            if let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}")) {
                out.insert(header::CONTENT_RANGE, value);
            }
            response
        }
        range::RangeOutcome::Satisfiable { start, end } => {
            let length = end - start;
            let stream = vfs
                .store()
                .content_window_stream(owner_id, manifest, start, end);
            let body = if head {
                Body::empty()
            } else {
                Body::from_stream(stream)
            };
            let response = base()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_LENGTH, length)
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{}/{size}", end - 1),
                )
                .body(body);
            response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        range::RangeOutcome::Full => {
            let stream = vfs.store().content_stream(owner_id, manifest);
            let body = if head {
                Body::empty()
            } else {
                Body::from_stream(stream)
            };
            let response = base()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, size)
                .body(body);
            response.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

async fn put(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = lock_check(vfs, locks, user_id, path, headers).await {
        return response;
    }

    let existing = match vfs.stat_access(user_id, path).await {
        Ok(existing) => existing.map(|access| access.node),
        Err(e) => return vfs_error(e),
    };

    if let Some(node) = &existing
        && is_encrypted(vfs, node.id).await
    {
        return encrypted_forbidden();
    }

    if let Some(value) = header_str(headers, header::IF_NONE_MATCH)
        && value.trim() == "*"
        && existing.is_some()
    {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }
    if let Some(value) = header_str(headers, header::IF_MATCH) {
        match &existing {
            None => return StatusCode::PRECONDITION_FAILED.into_response(),
            Some(node) => {
                if !cond::matches_etag(value, &node.etag(), false) {
                    return StatusCode::PRECONDITION_FAILED.into_response();
                }
            }
        }
    }

    let stream = Box::pin(body.into_data_stream());
    match vfs
        .put_stream_access(user_id, path, stream, MAX_UPLOAD_BYTES)
        .await
    {
        Ok(node) => {
            let status = if existing.is_some() {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::CREATED
            };
            let mut response = status.into_response();
            if let Ok(value) = HeaderValue::from_str(&node.etag()) {
                response.headers_mut().insert(header::ETAG, value);
            }
            response
        }
        Err(e) => vfs_error(e),
    }
}

async fn delete(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    if let Some(response) = lock_check(vfs, locks, user_id, path, headers).await {
        return response;
    }
    match vfs.delete_access(user_id, path).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VfsError::Root) => StatusCode::FORBIDDEN.into_response(),
        Err(e) => vfs_error(e),
    }
}

async fn mkcol(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = lock_check(vfs, locks, user_id, path, headers).await {
        return response;
    }
    match to_bytes(body, 1).await {
        Ok(bytes) if bytes.is_empty() => {}
        _ => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
    match vfs.mkdir_access(user_id, path).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(VfsError::AlreadyExists) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        Err(e) => vfs_error(e),
    }
}

async fn propfind(
    vfs: &Vfs,
    locks: &LockManager,
    user: &CurrentUser,
    segments: &[String],
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let user_id = user.user_id;
    let principal = principal_href(user);
    let depth = header_str(headers, "depth")
        .unwrap_or("1")
        .trim()
        .to_ascii_lowercase();
    if depth == "infinity" {
        return StatusCode::FORBIDDEN.into_response();
    }
    if depth != "0" && depth != "1" {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let body = match to_bytes(body, MAX_PROPFIND_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let requested = match xml::parse_propfind(&body) {
        Ok(requested) => requested,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut entries = Vec::new();
    if segments.first().map(String::as_str) == Some(SHARED_MOUNT) && segments.len() == 1 {
        // The virtual root of received shares.
        let mut root_entry = xml::PropEntry::new(segments, &shared_root_node());
        root_entry.principal_href = Some(principal.clone());
        entries.push(root_entry);
        if depth == "1"
            && let Ok(mounts) = vfs.received_mounts(user_id).await
        {
            for mount in mounts {
                let mut child_segments = segments.to_vec();
                child_segments.push(mount.name.clone());
                let mut entry = xml::PropEntry::new(&child_segments, &mount.to_node());
                entry.principal_href = Some(principal.clone());
                entries.push(entry);
            }
        }
    } else {
        let access = match vfs.resolve_access(user_id, path).await {
            Ok(access) => access,
            Err(e) => return vfs_error(e),
        };
        let node = access.node;
        let mut entry = xml::PropEntry::new(segments, &node);
        entry.principal_href = Some(principal.clone());
        entries.push(entry);
        if let Ok(dead) = vfs.dead_props_access(user_id, path).await
            && let Some(first) = entries.first_mut()
        {
            first.dead_props = dead
                .into_iter()
                .map(|p| (p.namespace, p.name, p.value))
                .collect();
        }
        if node.is_dir() && depth == "1" {
            match vfs.list_access(user_id, path).await {
                Ok((_, children)) => {
                    for child in children {
                        let mut child_segments = segments.to_vec();
                        child_segments.push(child.name.clone());
                        let mut entry = xml::PropEntry::new(&child_segments, &child);
                        entry.principal_href = Some(principal.clone());
                        entries.push(entry);
                    }
                }
                Err(e) => return vfs_error(e),
            }
        }
    }

    if !entries.is_empty() {
        let (used, available) = quota_props(vfs, user_id).await;
        for entry in &mut entries {
            if entry.is_dir {
                entry.quota_used = used;
                entry.quota_available = available;
            }
        }
    }
    if let Some(first) = entries.first_mut() {
        first.locks = locks.discover(user_id, path);
    }

    match xml::multistatus(&entries, &requested) {
        Ok(xml) => {
            let mut response = Response::new(Body::from(xml));
            *response.status_mut() = StatusCode::from_u16(207).unwrap_or(StatusCode::MULTI_STATUS);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The caller's RFC 4331 quota values: `(used, available)` bytes, both
/// optional. `available` is `None` when the account is unlimited.
async fn quota_props(vfs: &Vfs, user_id: i64) -> (Option<u64>, Option<u64>) {
    let Ok(Some(user)) = vfs.db().get_user(user_id).await else {
        return (None, None);
    };
    let used = u64::try_from(user.used_bytes).unwrap_or(0);
    let cap = match user.quota_bytes {
        Some(quota) if quota > 0 => Some(quota as u64),
        Some(_) => None,
        None => match vfs.store().default_quota() {
            0 => None,
            default => Some(default),
        },
    };
    (Some(used), cap.map(|cap| cap.saturating_sub(used)))
}

async fn proppatch(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    segments: &[String],
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = lock_check(vfs, locks, user_id, path, headers).await {
        return response;
    }
    let body = match to_bytes(body, MAX_PROPFIND_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let ops = match xml::parse_proppatch(&body) {
        Ok(ops) if !ops.is_empty() => ops,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(e) = vfs.resolve_access(user_id, path).await {
        return vfs_error(e);
    }

    let mut db_ops = Vec::new();
    let mut results = Vec::new();
    for op in &ops {
        let namespace = op.namespace().to_string();
        let name = op.name().to_string();
        if namespace == "DAV:" {
            results.push(xml::PatchResult {
                namespace,
                name,
                status: 403,
            });
            continue;
        }
        results.push(xml::PatchResult {
            namespace: namespace.clone(),
            name: name.clone(),
            status: 200,
        });
        db_ops.push(match op {
            xml::PatchOp::Set {
                namespace,
                name,
                value,
            } => kolimi_vfs::DeadPropOp::Set {
                namespace: namespace.clone(),
                name: name.clone(),
                value: value.clone(),
            },
            xml::PatchOp::Remove { namespace, name } => kolimi_vfs::DeadPropOp::Remove {
                namespace: namespace.clone(),
                name: name.clone(),
            },
        });
    }

    if !db_ops.is_empty()
        && let Err(e) = vfs.apply_proppatch_access(user_id, path, &db_ops).await
    {
        return vfs_error(e);
    }

    match xml::proppatch_response(&davpath::encode_href(segments), &results) {
        Ok(xml) => {
            let mut response = Response::new(Body::from(xml));
            *response.status_mut() = StatusCode::from_u16(207).unwrap_or(StatusCode::MULTI_STATUS);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn copy_move(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    source: &str,
    headers: &HeaderMap,
    is_move: bool,
) -> Response {
    let Some(destination_header) = header_str(headers, "destination") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(destination) = davpath::destination_to_vfs_path(destination_header) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if source == destination {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Never copy or move encrypted content over DAV: reading the source or
    // overwriting the destination would cross the plaintext boundary.
    if let Ok(Some(access)) = vfs.stat_access(user_id, source).await
        && is_encrypted(vfs, access.node.id).await
    {
        return encrypted_forbidden();
    }
    if let Ok(Some(access)) = vfs.stat_access(user_id, &destination).await
        && is_encrypted(vfs, access.node.id).await
    {
        return encrypted_forbidden();
    }
    // Moving writes to the destination (and removes the source); copying only
    // writes to the destination.
    if let Some(response) = lock_check(vfs, locks, user_id, &destination, headers).await {
        return response;
    }
    if is_move && let Some(response) = lock_check(vfs, locks, user_id, source, headers).await {
        return response;
    }
    let overwrite = match header_str(headers, "overwrite") {
        None => true,
        Some(value) => match value.trim().to_ascii_uppercase().as_str() {
            "T" => true,
            "F" => false,
            _ => return StatusCode::BAD_REQUEST.into_response(),
        },
    };

    let result = if is_move {
        vfs.transfer_access(user_id, source, &destination, overwrite, false)
            .await
    } else {
        vfs.transfer_access(user_id, source, &destination, overwrite, true)
            .await
    };

    match result {
        Ok(created) => {
            if created {
                StatusCode::CREATED.into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
        Err(VfsError::AlreadyExists) => StatusCode::PRECONDITION_FAILED.into_response(),
        Err(e) => vfs_error(e),
    }
}

fn header_str(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Enforces locks on a write to `path`: `Some(response)` when the request
/// must be rejected (`423 Locked` or `412 Precondition Failed`).
async fn lock_check(
    vfs: &Vfs,
    locks: &LockManager,
    user_id: i64,
    path: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let covering = locks.covering_tokens(user_id, path);
    let if_header = header_str(headers, "if");
    let supplied = if_header.map(lock::if_tokens).unwrap_or_default();
    // A governing lock requires its token, whatever else the `If` says.
    if !covering.is_empty() && !covering.iter().any(|token| supplied.contains(token)) {
        return Some(StatusCode::LOCKED.into_response());
    }
    let header = if_header?;
    let etag = vfs
        .stat_access(user_id, path)
        .await
        .ok()
        .flatten()
        .map(|access| access.node.etag());
    if lock::evaluate_if(header, etag.as_deref(), &covering) {
        None
    } else {
        Some(StatusCode::PRECONDITION_FAILED.into_response())
    }
}

/// `LOCK` (RFC 4918 §9.10): create a lock, or refresh one when the body is
/// empty and the `If` header carries the token.
async fn lock_node(
    vfs: &Vfs,
    locks: &LockManager,
    user: &CurrentUser,
    segments: &[String],
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    let user_id = user.user_id;
    let timeout = header_str(headers, "timeout")
        .map(lock::parse_timeout)
        .unwrap_or(0);
    let depth_infinity = !matches!(
        header_str(headers, "depth")
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0")
    );

    let bytes = match to_bytes(body, MAX_PROPFIND_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if bytes.is_empty() {
        // Refresh: the token must arrive via the `If` header.
        let tokens = header_str(headers, "if")
            .map(lock::if_tokens)
            .unwrap_or_default();
        for token in tokens {
            if let Ok(held) = locks.refresh(user_id, path, &token, timeout) {
                return lock_response(StatusCode::OK, segments, &held);
            }
        }
        return StatusCode::PRECONDITION_FAILED.into_response();
    }

    let info = match xml::parse_lockinfo(&bytes) {
        Ok(info) => info,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
    match locks.lock(
        user_id,
        path,
        info.scope,
        info.owner,
        depth_infinity,
        timeout,
    ) {
        Ok(held) => {
            let exists = vfs
                .stat_access(user_id, path)
                .await
                .ok()
                .flatten()
                .is_some();
            let status = if exists {
                StatusCode::OK
            } else {
                // A lock on an unmapped URL creates a lock-null resource.
                StatusCode::CREATED
            };
            lock_response(status, segments, &held)
        }
        Err(lock::LockError::Conflict) => StatusCode::LOCKED.into_response(),
        Err(lock::LockError::NotFound) => StatusCode::PRECONDITION_FAILED.into_response(),
    }
}

/// `UNLOCK` (RFC 4918 §9.11).
fn unlock_node(locks: &LockManager, user_id: i64, path: &str, headers: &HeaderMap) -> Response {
    let Some(value) = header_str(headers, "lock-token") else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let token = lock::lock_token_value(value);
    match locks.unlock(user_id, path, &token) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

/// Builds a `LOCK` response: the `Lock-Token` header plus a `lockdiscovery`
/// body.
fn lock_response(status: StatusCode, segments: &[String], held: &lock::Lock) -> Response {
    let href = davpath::encode_href(segments);
    let xml = xml::lockdiscovery_body(&href, std::slice::from_ref(held));
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!("<{}>", held.token)) {
        response
            .headers_mut()
            .insert(axum::http::HeaderName::from_static("lock-token"), value);
    }
    response
}

/// `REPORT` on the file tree: RFC 6578 `sync-collection` over the user's
/// change feed. Reports are scoped to the addressed directory (changes
/// outside it are filtered out).
async fn report_file_tree(vfs: &Vfs, user: &CurrentUser, path: &str, body: Body) -> Response {
    let body = match to_bytes(body, MAX_PROPFIND_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let report = match parse_report(&body) {
        Ok(report) => report,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Report::SyncCollection {
        sync_token,
        level,
        props,
    } = report
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if level != 1 {
        return StatusCode::FORBIDDEN.into_response();
    }
    let since = match sync_token {
        None => 0,
        Some(token) => match parse_user_sync_token(&token, user.user_id) {
            Some(seq) => seq,
            None => return caldav::invalid_sync_token(),
        },
    };

    let db = vfs.db();
    let changes = match db
        .changes_since(user.user_id, since, MAX_SYNC_CHANGES)
        .await
    {
        Ok(changes) => changes,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let latest = db.latest_change_seq(user.user_id).await.unwrap_or(since);

    let prefix = if path == "/" {
        "/".to_string()
    } else {
        format!("{path}/")
    };
    let within =
        |candidate: &str| path == "/" || candidate == path || candidate.starts_with(&prefix);

    let principal = principal_href(user);
    let mut entries: Vec<xml::PropEntry> = Vec::new();
    let mut deleted: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for change in changes {
        if change.op == "move" {
            if let Some(from) = change.from_path.as_deref()
                && within(from)
            {
                deleted.push(href_for(from));
            }
        } else if change.op == "delete" {
            if within(&change.path) {
                deleted.push(href_for(&change.path));
            }
            continue;
        }
        if !within(&change.path) || !seen.insert(change.path.clone()) {
            continue;
        }
        let Ok(path_segments) = kolimi_vfs::path::parse(&change.path) else {
            continue;
        };
        match vfs.resolve(user.user_id, &change.path).await {
            Ok(node) => {
                let mut entry = xml::PropEntry::new(&path_segments, &node);
                entry.principal_href = Some(principal.clone());
                if let Ok(dead) = vfs.dead_props(user.user_id, &change.path).await {
                    entry.dead_props = dead
                        .into_iter()
                        .map(|prop| (prop.namespace, prop.name, prop.value))
                        .collect();
                }
                entries.push(entry);
            }
            Err(_) => deleted.push(href_for(&change.path)),
        }
    }

    let requested = match props {
        ReportProps::Only(list) => xml::RequestedProps::Only(list),
        _ => xml::RequestedProps::All,
    };
    let token = format!("urn:kolimi:sync:user:{}:{}", user.user_id, latest);
    match xml::multistatus_sync(&entries, &deleted, &requested, &token) {
        Ok(xml) => {
            let mut response = Response::new(Body::from(xml));
            *response.status_mut() = StatusCode::from_u16(207).unwrap_or(StatusCode::MULTI_STATUS);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            );
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn href_for(path: &str) -> String {
    kolimi_vfs::path::parse(path)
        .map(|segments| davpath::encode_href(&segments))
        .unwrap_or_else(|_| "/dav/".to_string())
}

fn parse_user_sync_token(token: &str, user_id: i64) -> Option<i64> {
    let rest = token.strip_prefix("urn:kolimi:sync:user:")?;
    let (id, seq) = rest.split_once(':')?;
    if id.parse::<i64>().ok()? != user_id {
        return None;
    }
    seq.parse().ok()
}

fn principal_href(user: &CurrentUser) -> String {
    format!("/dav/principals/{}/", user.username)
}

fn shared_root_node() -> Node {
    Node {
        id: -1,
        parent_id: None,
        name: SHARED_MOUNT.to_string(),
        kind: NodeKind::Dir,
        content_id: None,
        size: 0,
        created_at: 0,
        modified_at: 0,
        trashed: false,
        original_path: None,
    }
}

fn vfs_error(e: VfsError) -> Response {
    let status = match &e {
        VfsError::NotFound => StatusCode::NOT_FOUND,
        VfsError::AlreadyExists | VfsError::ParentNotCollection | VfsError::Conflict(_) => {
            StatusCode::CONFLICT
        }
        VfsError::IsCollection | VfsError::SharedRoot => StatusCode::METHOD_NOT_ALLOWED,
        VfsError::InvalidPath(_) => StatusCode::BAD_REQUEST,
        VfsError::Root | VfsError::Forbidden => StatusCode::FORBIDDEN,
        VfsError::MissingChunk(_) => StatusCode::CONFLICT,
        VfsError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        VfsError::Store(store) => match store {
            StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            StoreError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            StoreError::Mismatch { .. } => StatusCode::BAD_REQUEST,
            StoreError::Corrupt(_)
            | StoreError::Io(_)
            | StoreError::Stream(_)
            | StoreError::Chunking(_)
            | StoreError::Random(_)
            | StoreError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        },
    };
    status.into_response()
}
