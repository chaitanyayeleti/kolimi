//! Request hardening: per-client rate limiting for sensitive endpoints
//! and baseline security response headers.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Login and passkey ceremonies allowed per window, per client.
pub const AUTH_LIMIT: u32 = 20;
/// Window for [`AUTH_LIMIT`].
pub const AUTH_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Public-link unlock attempts allowed per window, per client.
pub const LINK_LIMIT: u32 = 30;
/// Window for [`LINK_LIMIT`].
pub const LINK_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Preview requests allowed per window, per client.
pub const PREVIEW_LIMIT: u32 = 120;
/// Window for [`PREVIEW_LIMIT`].
pub const PREVIEW_WINDOW: Duration = Duration::from_secs(60);
/// TOTP enable/disable attempts allowed per window, per client.
pub const TOTP_LIMIT: u32 = 10;
/// Window for [`TOTP_LIMIT`].
pub const TOTP_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Cap on tracked keys before stale entries are swept.
const MAX_KEYS: usize = 10_000;

struct Bucket {
    count: u32,
    start: Instant,
}

/// A bounded, per-key fixed-window rate limiter.
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    /// Creates an empty limiter.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Records a hit for `key` and reports whether it stays within `max`
    /// requests per `window`. Recovers from a poisoned lock.
    pub fn allow(&self, key: &str, max: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > MAX_KEYS {
            map.retain(|_, bucket| now.duration_since(bucket.start) < window);
        }
        // Hard cap: a flood of unique keys (e.g. spoofed X-Forwarded-For) must
        // not grow the map without bound. Evict arbitrary entries until under
        // the limit.
        while map.len() > MAX_KEYS {
            let Some(evict) = map.keys().next().cloned() else {
                break;
            };
            map.remove(&evict);
        }
        let bucket = map.entry(key.to_string()).or_insert(Bucket {
            count: 0,
            start: now,
        });
        if now.duration_since(bucket.start) >= window {
            bucket.count = 0;
            bucket.start = now;
        }
        bucket.count += 1;
        bucket.count <= max
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves the client address: the direct peer by default, or the last
/// `X-Forwarded-For` entry when the server trusts a front proxy (the last
/// entry is the one appended by the trusted proxy, so client-supplied
/// values cannot spoof it).
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trust_proxy: bool) -> String {
    if trust_proxy
        && let Some(value) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        && let Some(last) = value
            .split(',')
            .map(str::trim)
            .rfind(|entry| !entry.is_empty())
    {
        return last.to_string();
    }
    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extracts the caller's address for lockout/rate-limit keying. Always
/// succeeds: the address is the peer, or `X-Forwarded-For` when a proxy
/// is trusted, falling back to `"unknown"`.
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        Ok(ClientIp(client_ip(&parts.headers, peer, state.trust_proxy)))
    }
}

/// Middleware: rate-limits login, passkey, public-unlock, and preview
/// requests by client address; everything else passes straight through.
pub async fn limit(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    let method = req.method();
    let is_auth = (method == Method::POST && path == "/api/session")
        || path.starts_with("/api/passkeys/login/");
    let is_totp = method == Method::POST && path.starts_with("/api/totp/");
    let (class, max, window) = if is_auth {
        ("auth", AUTH_LIMIT, AUTH_WINDOW)
    } else if is_totp {
        ("totp", TOTP_LIMIT, TOTP_WINDOW)
    } else if method == Method::POST && path.starts_with("/public/") && path.ends_with("/unlock") {
        ("link", LINK_LIMIT, LINK_WINDOW)
    } else if path == "/api/preview" {
        ("preview", PREVIEW_LIMIT, PREVIEW_WINDOW)
    } else {
        return next.run(req).await;
    };

    let ip = client_ip(
        req.headers(),
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0),
        state.trust_proxy,
    );
    if !state
        .rate_limiter
        .allow(&format!("{class}:{ip}"), max, window)
    {
        let mut response = (StatusCode::TOO_MANY_REQUESTS, "too many requests\n").into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        return response;
    }
    next.run(req).await
}

const HSTS: HeaderName = HeaderName::from_static("strict-transport-security");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");

/// Middleware: adds baseline security headers to every response.
///
/// `Strict-Transport-Security` is only sent when cookies are marked
/// secure (i.e. the deployment is expected to sit behind TLS).
pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    // API and session responses must never be cached: a cached `/api/me`
    // after logout makes a signed-out browser look signed in, and a cached
    // browse listing hides changes.
    let is_api = req.uri().path().starts_with("/api/");
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    if is_api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    if state.secure_cookies {
        headers.entry(HSTS).or_insert(HeaderValue::from_static(
            "max-age=31536000; includeSubDomains",
        ));
    }
    response
}

/// Middleware: log rejected requests at INFO.
///
/// Without this a failed upload or a refused WebDAV write leaves no trace at
/// the default log level — the client sees a toast and the server admin sees
/// nothing. Path only, never the query string, which can carry share tokens.
pub async fn log_rejected(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let response = next.run(req).await;
    let status = response.status();
    // An unauthenticated visit to the app probes `/api/me` before showing
    // the login form; that 401 is expected and would just be noise.
    let expected_probe =
        status == StatusCode::UNAUTHORIZED && (path == "/api/me" || path == "/api/session");
    if (status.is_client_error() || status.is_server_error()) && !expected_probe {
        tracing::info!(%method, %path, %status, "request rejected");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_allows_up_to_max_then_blocks() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.allow("k", 3, Duration::from_secs(60)));
        }
        assert!(!limiter.allow("k", 3, Duration::from_secs(60)));
        // A different key is unaffected.
        assert!(limiter.allow("other", 3, Duration::from_secs(60)));
    }

    #[test]
    fn window_resets() {
        let limiter = RateLimiter::new();
        assert!(limiter.allow("k", 1, Duration::from_millis(20)));
        assert!(!limiter.allow("k", 1, Duration::from_millis(20)));
        std::thread::sleep(Duration::from_millis(40));
        assert!(limiter.allow("k", 1, Duration::from_millis(20)));
    }

    #[test]
    fn client_ip_prefers_peer_unless_trusting_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let peer: Option<SocketAddr> = "10.0.0.5:1234".parse().ok();
        assert_eq!(client_ip(&headers, peer, false), "10.0.0.5");
        // Trusting the proxy, the last entry (added by the proxy) wins.
        assert_eq!(client_ip(&headers, peer, true), "10.0.0.1");
        assert_eq!(client_ip(&HeaderMap::new(), peer, true), "10.0.0.5");
    }
}
