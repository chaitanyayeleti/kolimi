//! WebDAV surface (RFC 4918 subset) for Kolimi.
//!
//! Implements OPTIONS, GET/HEAD, PUT, DELETE, MKCOL, PROPFIND, COPY, and
//! MOVE over the VFS. LOCK/UNLOCK and streaming range requests are not
//! implemented yet (see ROADMAP M1/M2).
//!
//! The router is stateless: `Vfs` and `CurrentUser` are injected via
//! request extensions by the server crate.

mod cond;
mod davpath;
mod xml;

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
use kolimi_vfs::{Vfs, VfsError};

const ALLOW: &str = "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, COPY, MOVE, MKCOL";
const MAX_PROPFIND_BODY: usize = 1024 * 1024;
const MAX_UPLOAD_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
    let vfs_path = kolimi_vfs::path::join(&segments);
    let user_id = user.user_id;

    match method.as_str() {
        "OPTIONS" => options(),
        "GET" => get(&vfs, user_id, &vfs_path, &headers, false).await,
        "HEAD" => get(&vfs, user_id, &vfs_path, &headers, true).await,
        "PUT" => put(&vfs, user_id, &vfs_path, &headers, body).await,
        "DELETE" => delete(&vfs, user_id, &vfs_path).await,
        "MKCOL" => mkcol(&vfs, user_id, &vfs_path, body).await,
        "PROPFIND" => propfind(&vfs, user_id, &segments, &vfs_path, &headers, body).await,
        "PROPPATCH" => proppatch(&vfs, user_id, &segments, &vfs_path, body).await,
        "COPY" => copy_move(&vfs, user_id, &vfs_path, &headers, false).await,
        "MOVE" => copy_move(&vfs, user_id, &vfs_path, &headers, true).await,
        _ => method_not_allowed(),
    }
}

fn options() -> Response {
    let mut response = StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.insert(header::ALLOW, HeaderValue::from_static(ALLOW));
    headers.insert(
        axum::http::HeaderName::from_static("dav"),
        HeaderValue::from_static("1"),
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

async fn get(vfs: &Vfs, user_id: i64, path: &str, headers: &HeaderMap, head: bool) -> Response {
    let (node, data) = match vfs.read(user_id, path).await {
        Ok(result) => result,
        Err(VfsError::IsCollection) => return method_not_allowed(),
        Err(e) => return vfs_error(e),
    };

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
    let length = data.len();
    let body = if head {
        Body::empty()
    } else {
        Body::from(data)
    };

    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, length)
        .header(header::ETAG, etag)
        .header(header::LAST_MODIFIED, cond::http_date(node.modified_at));
    match builder.body(body) {
        Ok(response) => response,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn put(vfs: &Vfs, user_id: i64, path: &str, headers: &HeaderMap, body: Body) -> Response {
    let existing = match vfs.stat(user_id, path).await {
        Ok(existing) => existing,
        Err(e) => return vfs_error(e),
    };

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
        .put_stream(user_id, path, stream, MAX_UPLOAD_BYTES)
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

async fn delete(vfs: &Vfs, user_id: i64, path: &str) -> Response {
    match vfs.delete(user_id, path).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(VfsError::Root) => StatusCode::FORBIDDEN.into_response(),
        Err(e) => vfs_error(e),
    }
}

async fn mkcol(vfs: &Vfs, user_id: i64, path: &str, body: Body) -> Response {
    match to_bytes(body, 1).await {
        Ok(bytes) if bytes.is_empty() => {}
        _ => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }
    match vfs.mkdir(user_id, path).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(VfsError::AlreadyExists) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        Err(e) => vfs_error(e),
    }
}

async fn propfind(
    vfs: &Vfs,
    user_id: i64,
    segments: &[String],
    path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
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

    let node = match vfs.resolve(user_id, path).await {
        Ok(node) => node,
        Err(e) => return vfs_error(e),
    };

    let mut entries = vec![xml::PropEntry::new(segments, &node)];
    if let Ok(dead) = vfs.dead_props(user_id, path).await
        && let Some(first) = entries.first_mut()
    {
        first.dead_props = dead
            .into_iter()
            .map(|p| (p.namespace, p.name, p.value))
            .collect();
    }
    if node.is_dir() && depth == "1" {
        match vfs.list(user_id, path).await {
            Ok(children) => {
                for child in children {
                    let mut child_segments = segments.to_vec();
                    child_segments.push(child.name.clone());
                    entries.push(xml::PropEntry::new(&child_segments, &child));
                }
            }
            Err(e) => return vfs_error(e),
        }
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

async fn proppatch(
    vfs: &Vfs,
    user_id: i64,
    segments: &[String],
    path: &str,
    body: Body,
) -> Response {
    let body = match to_bytes(body, MAX_PROPFIND_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let ops = match xml::parse_proppatch(&body) {
        Ok(ops) if !ops.is_empty() => ops,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Err(e) = vfs.resolve(user_id, path).await {
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
        && let Err(e) = vfs.apply_proppatch(user_id, path, &db_ops).await
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
    let overwrite = match header_str(headers, "overwrite") {
        None => true,
        Some(value) => match value.trim().to_ascii_uppercase().as_str() {
            "T" => true,
            "F" => false,
            _ => return StatusCode::BAD_REQUEST.into_response(),
        },
    };

    let result = if is_move {
        vfs.move_node(user_id, source, &destination, overwrite)
            .await
    } else {
        vfs.copy_node(user_id, source, &destination, overwrite)
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

fn vfs_error(e: VfsError) -> Response {
    let status = match &e {
        VfsError::NotFound => StatusCode::NOT_FOUND,
        VfsError::AlreadyExists | VfsError::ParentNotCollection | VfsError::Conflict(_) => {
            StatusCode::CONFLICT
        }
        VfsError::IsCollection => StatusCode::METHOD_NOT_ALLOWED,
        VfsError::InvalidPath(_) => StatusCode::BAD_REQUEST,
        VfsError::Root => StatusCode::FORBIDDEN,
        VfsError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        VfsError::Store(store) => match store {
            StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            StoreError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            StoreError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
            StoreError::Io(_) | StoreError::Stream(_) | StoreError::Random(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        },
    };
    status.into_response()
}
