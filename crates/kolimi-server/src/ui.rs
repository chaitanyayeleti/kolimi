//! Static serving of the embedded Leptos web UI.
//!
//! Assets live in `assets/ui/` and are staged there by
//! `scripts/build-ui.sh`. In debug builds `rust-embed` reads them from disk
//! (so a rebuilt UI is picked up without recompiling the server); release
//! builds embed them into the binary.

use axum::{
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode, header},
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
pub async fn index(headers: HeaderMap) -> Response {
    shell(Some(&headers))
}

/// `GET /app/{*path}` — an asset, or the shell for client-side routes.
pub async fn asset(Path(path): Path<String>, headers: HeaderMap) -> Response {
    if let Some(response) = serve(&path, Some(&headers)) {
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
    shell(Some(&headers))
}

/// `GET /s/{token}` — the public-link page (client-side routed).
pub async fn public_page() -> Response {
    shell(None)
}

/// `GET /invite` — the invite-acceptance page.
///
/// The token lives in the URL fragment, so the server only ever sees this
/// bare path. Keep the shell out of caches.
pub async fn invite_page() -> Response {
    let mut response = shell(None);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The application shell: the built `index.html`, or the committed
/// placeholder when the UI has not been staged yet.
fn shell(headers: Option<&HeaderMap>) -> Response {
    serve("index.html", headers)
        .or_else(|| serve("not-built.html", headers))
        .unwrap_or_else(not_found)
}

fn serve(path: &str, headers: Option<&HeaderMap>) -> Option<Response> {
    let mut asset = Assets::get(path)?;
    let mut encoding = None;
    if let Some(coding) = preferred_encoding(headers) {
        let alternate = match coding {
            "br" => Assets::get(&format!("{path}.br")),
            _ => Assets::get(&format!("{path}.gz")),
        };
        if let Some(compressed) = alternate {
            asset = compressed;
            encoding = Some(coding);
        }
    }

    let etag = format!("\"{}\"", hex::encode(asset.metadata.sha256_hash()));
    if if_none_match(headers, &etag) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        let response_headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&etag) {
            response_headers.insert(header::ETAG, value);
        }
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        response_headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        if let Some(coding) = encoding {
            response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
        }
        return Some(response);
    }

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let mut response = Response::new(axum::body::Body::from(asset.data.into_owned()));
    let response_headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        response_headers.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response_headers.insert(header::ETAG, value);
    }
    response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response_headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    if let Some(coding) = encoding {
        response_headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
    }
    if let Ok(value) = HeaderValue::from_str(CSP) {
        response_headers.insert("content-security-policy", value);
    }
    response_headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Some(response)
}

/// Picks the best representation the client advertises. Brotli wins ties;
/// an unknown or absent coding falls back to the raw asset.
fn preferred_encoding(headers: Option<&HeaderMap>) -> Option<&'static str> {
    let value = headers?.get(header::ACCEPT_ENCODING)?.to_str().ok()?;
    let mut best: Option<(&'static str, f32)> = None;
    for coding in ["br", "gzip"] {
        let Some(quality) = encoding_quality(value, coding) else {
            continue;
        };
        if quality <= 0.0 {
            continue;
        }
        if best.is_none_or(|(_, best_quality)| quality > best_quality) {
            best = Some((coding, quality));
        }
    }
    best.map(|(coding, _)| coding)
}

fn encoding_quality(header: &str, coding: &str) -> Option<f32> {
    let mut wildcard = None;
    for entry in header.split(',') {
        let mut parts = entry.trim().split(';');
        let name = parts.next().unwrap_or("").trim();
        let quality = parts
            .find_map(|parameter| {
                let parameter = parameter.trim();
                parameter
                    .strip_prefix("q=")
                    .or_else(|| parameter.strip_prefix("Q="))
                    .and_then(|value| value.parse::<f32>().ok())
            })
            .unwrap_or(1.0);
        if name.eq_ignore_ascii_case(coding) {
            return Some(quality);
        }
        if name == "*" {
            wildcard = Some(quality);
        }
    }
    wildcard
}

fn if_none_match(headers: Option<&HeaderMap>, etag: &str) -> bool {
    let Some(value) = headers
        .and_then(|headers| headers.get(header::IF_NONE_MATCH))
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*"
            || candidate == etag
            || candidate
                .strip_prefix("W/")
                .is_some_and(|weak| weak == etag)
    })
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_negotiation_prefers_brotli_and_honours_q_values() {
        assert_eq!(preferred_encoding(None), None);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        assert_eq!(preferred_encoding(Some(&headers)), Some("br"));

        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br;q=0, gzip;q=1"),
        );
        assert_eq!(preferred_encoding(Some(&headers)), Some("gzip"));

        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("br;q=0.5, gzip;q=1"),
        );
        assert_eq!(preferred_encoding(Some(&headers)), Some("gzip"));

        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip;q=0.5, br;q=0.5"),
        );
        assert_eq!(preferred_encoding(Some(&headers)), Some("br"));

        headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("*;q=1"));
        assert_eq!(preferred_encoding(Some(&headers)), Some("br"));
    }

    #[test]
    fn if_none_match_accepts_strong_weak_and_listed_etags() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"abc\", \"def\""),
        );
        assert!(if_none_match(Some(&headers), "\"abc\""));
        assert!(if_none_match(Some(&headers), "\"def\""));
        assert!(!if_none_match(Some(&headers), "\"other\""));

        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(if_none_match(Some(&headers), "\"anything\""));
        assert!(!if_none_match(None, "\"anything\""));
    }
}
