//! Static serving of the embedded Leptos web UI.
//!
//! Assets live in `assets/ui/` and are staged there by
//! `scripts/build-ui.sh`. In debug builds `rust-embed` reads them from disk
//! (so a rebuilt UI is picked up without recompiling the server); release
//! builds embed them into the binary.

use axum::{
    extract::Path,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

/// Embedded UI assets.
#[derive(RustEmbed)]
#[folder = "assets/ui"]
struct Assets;

const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self'; img-src 'self' data:; connect-src 'self'; \
     object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

/// `GET /` — redirect to the app.
pub async fn root() -> Response {
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/app/"));
    response
}

/// `GET /.well-known/caldav|carddav` — DAV service discovery (RFC 6764):
/// clients are sent to the WebDAV root, where `current-user-principal`
/// leads them to the calendar/address-book homes.
pub async fn well_known() -> Response {
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/dav/"));
    response
}

/// `GET /app` and `/app/` — the application shell.
pub async fn index() -> Response {
    shell()
}

/// `GET /app/{*path}` — an asset, or the shell for client-side routes.
pub async fn asset(Path(path): Path<String>) -> Response {
    if let Some(response) = serve(&path) {
        return response;
    }
    // Paths that look like files must 404 rather than fall back to HTML.
    if path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.'))
    {
        return not_found();
    }
    shell()
}

/// `GET /s/{token}` — the public-link page (client-side routed).
pub async fn public_page() -> Response {
    shell()
}

/// The application shell: the built `index.html`, or the committed
/// placeholder when the UI has not been staged yet.
fn shell() -> Response {
    serve("index.html")
        .or_else(|| serve("not-built.html"))
        .unwrap_or_else(not_found)
}

fn serve(path: &str) -> Option<Response> {
    let asset = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = Response::new(axum::body::Body::from(asset.data.into_owned()));
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(value) = HeaderValue::from_str(CSP) {
        headers.insert("content-security-policy", value);
    }
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Some(response)
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}
