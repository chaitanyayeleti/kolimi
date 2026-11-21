#![allow(clippy::result_large_err)]

use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::{CurrentUser, cache::credential_cache_key, password, token};
use subtle::ConstantTimeEq;

use crate::{
    AppState, CSRF_COOKIE, SESSION_COOKIE, app_scope::AppPasswordAuth, app_scope::authorize_scope,
    hardening,
};

/// How often a successful request refreshes `last_seen_at` / `last_used_at`.
/// Throttling this write avoids a SQLite write transaction on every WebDAV,
/// sync, or browse request; credential revocation still reads the row on
/// every request and therefore stays immediate.
const AUTH_TOUCH_INTERVAL_MILLIS: i64 = 60_000;

/// Authentication middleware: resolves the caller from Basic credentials,
/// a bearer token, or a session cookie, and attaches the [`CurrentUser`].
///
/// Cookie-authenticated mutating API requests additionally require a
/// double-submit CSRF token (`X-CSRF-Token` matching the `kolimi_csrf`
/// cookie).
pub async fn require_auth(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, Response> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    // A read-only metrics token is accepted only by /metrics. It never
    // authenticates any other route and does not create a session.
    if path == "/metrics" && metrics_token_ok(&state, &headers) {
        req.extensions_mut().insert(CurrentUser {
            user_id: 0,
            username: "metrics".to_string(),
            is_admin: true,
            must_change_password: false,
            must_setup_mfa: false,
            session_hash: None,
        });
        return Ok(next.run(req).await);
    }

    let ip = hardening::client_ip(
        &headers,
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0),
        state.trust_proxy,
    );

    let (user, via_cookie, app_password) = match authenticate(&state, &headers, &ip, &path).await {
        Ok(authenticated) => authenticated,
        Err(mut response) => {
            // Only WebDAV surfaces may ask the client for HTTP Basic
            // credentials. Challenging `/api/*` makes browsers cache the
            // password for the whole origin and silently authenticate with
            // it: no session cookie is ever created, sign-out has nothing
            // to revoke, and stale credentials shadow real sessions.
            if !path.starts_with("/dav") {
                response.headers_mut().remove(header::WWW_AUTHENTICATE);
            }
            return Err(response);
        }
    };

    // A forced password rotation blocks every surface except the probe and
    // the two calls needed to replace the password. This includes WebDAV,
    // Basic-auth scripts, and the sync client: a temporary password cannot
    // be used to move data.
    if user.must_change_password && !forced_password_change_allowed(&method, &path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "password change required",
                "must_change_password": true,
            })),
        )
            .into_response());
    }

    if user.must_setup_mfa && !forced_mfa_setup_allowed(&method, &path) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "two-factor or passkey setup required",
                "must_setup_mfa": true,
            })),
        )
            .into_response());
    }

    // App passwords are least-privilege. The check runs after authentication
    // and the forced-setup gates, before any handler or CSRF work. A failed
    // scope check never falls back to the session cookie: the credential that
    // authenticated this request is the one that must be authorized.
    if let Some(app) = &app_password
        && !authorize_scope(&method, &path, &app.scopes)
    {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "this app password does not have the required scope",
                "insufficient_scope": true,
            })),
        )
            .into_response());
    }

    // Cookie-authenticated state-changing requests must carry the
    // double-submit CSRF token on every surface (API, WebDAV, plugins), not
    // just `/api/*`. Covers WebDAV mutating methods too.
    let is_mutating = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) || matches!(
        method.as_str(),
        "MKCOL" | "MKCALENDAR" | "MOVE" | "COPY" | "PROPPATCH" | "LOCK" | "UNLOCK"
    );
    // Signing out is exempt: the worst case without CSRF is that someone
    // logs you out (no data access), and requiring the token made a
    // missing/stale cookie turn "log out" into a dead end.
    let is_logout = method == Method::DELETE && req.uri().path() == "/api/session";
    if via_cookie
        && is_mutating
        && !is_logout
        && !csrf_ok(&state, &headers, user.session_hash.as_ref()).await
    {
        return Err(StatusCode::FORBIDDEN.into_response());
    }

    req.extensions_mut().insert(user);
    if let Some(app) = app_password {
        req.extensions_mut().insert(app);
    }
    Ok(next.run(req).await)
}

/// Spends the same Argon2id work as a real password verification, so that
/// login timing does not reveal whether a username exists (or is
/// disabled / passkey-only). See the user-enumeration issue.
pub(crate) async fn burn_password_time(state: &AppState, candidate: &str) {
    let hash = state.dummy_password_hash.clone();
    let candidate = candidate.to_owned();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = password::verify_password(&hash, &candidate);
    })
    .await;
}

enum Credentials {
    Basic { username: String, password: String },
    Bearer(String),
    Cookie(String),
}

fn extract_credentials(headers: &HeaderMap, path: &str) -> Option<Credentials> {
    // The session cookie always wins. Browsers attach cached HTTP Basic
    // credentials to every same-origin request once challenged, and if the
    // `Authorization` header were preferred those stale credentials would
    // shadow a real session — so `DELETE /api/session` would revoke a
    // session nobody was using while the browser stayed signed in through
    // Basic. A cookie that no longer exists must therefore yield 401, never
    // a silent Basic re-authentication.
    if let Some(raw) = cookie_value(headers, SESSION_COOKIE) {
        return Some(Credentials::Cookie(raw));
    }
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let (scheme, rest) = value.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") {
            return Some(Credentials::Bearer(rest.trim().to_string()));
        }
        if scheme.eq_ignore_ascii_case("basic") && basic_allowed(path) {
            let (username, password) = decode_basic(rest.trim())?;
            return Some(Credentials::Basic { username, password });
        }
        return None;
    }
    None
}

/// Whether HTTP Basic may authenticate this path.
///
/// Basic stays a first-class credential for WebDAV, `curl -u` scripts, the
/// sync client and the desktop app. The one exception is `/api/me`: it is
/// the web UI's session probe, and accepting Basic there lets a browser's
/// cached credentials skip the login form entirely and survive sign-out.
fn basic_allowed(path: &str) -> bool {
    path != "/api/me"
}

/// Endpoints a user with `must_change_password` may still call: enough to
/// discover the state, re-authenticate, replace the password, and sign out.
fn forced_password_change_allowed(method: &Method, path: &str) -> bool {
    (method == Method::GET && path == "/api/me")
        || (method == Method::POST && matches!(path, "/api/me/password" | "/api/reauth"))
        || (method == Method::DELETE && path == "/api/session")
}

/// Endpoints a user with `must_setup_mfa` may still call: enough to enroll
/// TOTP or a passkey, confirm presence, and sign out.
fn forced_mfa_setup_allowed(method: &Method, path: &str) -> bool {
    (method == Method::GET && matches!(path, "/api/me" | "/api/totp" | "/api/passkeys"))
        || (method == Method::POST
            && matches!(
                path,
                "/api/totp/begin"
                    | "/api/totp/enable"
                    | "/api/passkeys/register/begin"
                    | "/api/passkeys/register/finish"
                    | "/api/reauth"
                    | "/api/me/password"
            ))
        || (method == Method::DELETE && path == "/api/session")
}

/// Whether a request carries the optional read-only metrics token.
///
/// `X-Kolimi-Metrics-Token` or `Authorization: Bearer …` is accepted. The
/// token is only consulted on `/metrics`; it cannot authenticate any other
/// route.
fn metrics_token_ok(state: &AppState, headers: &HeaderMap) -> bool {
    metrics_token_matches(state.metrics_token.as_deref(), headers)
}

fn metrics_token_matches(expected: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let provided = headers
        .get("x-kolimi-metrics-token")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
            let (scheme, rest) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(rest.trim())
        });
    provided.is_some_and(|provided| expected.as_bytes().ct_eq(provided.as_bytes()).into())
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    ip: &str,
    path: &str,
) -> Result<(CurrentUser, bool, Option<AppPasswordAuth>), Response> {
    match extract_credentials(headers, path) {
        Some(Credentials::Basic { username, password }) => {
            let (user, app) = authenticate_basic(state, &username, &password, ip).await?;
            Ok((user, false, app))
        }
        Some(Credentials::Bearer(raw)) => authenticate_token(state, &raw)
            .await
            .map(|user| (user, false, None)),
        Some(Credentials::Cookie(raw)) => authenticate_token(state, &raw)
            .await
            .map(|user| (user, true, None)),
        None => Err(unauthorized()),
    }
}

async fn authenticate_basic(
    state: &AppState,
    username: &str,
    password: &str,
    ip: &str,
) -> Result<(CurrentUser, Option<AppPasswordAuth>), Response> {
    // App passwords are high-entropy device credentials. They are checked
    // before the account password and intentionally bypass TOTP: the token
    // already represents a second, revocable credential for one device.
    let app_hash = token::hash_token(password);
    if let Ok(Some(app)) = state.db.find_app_password(username, &app_hash).await {
        let now = kolimi_db::now_millis();
        if app.expires_at.is_some_and(|at| at <= now) {
            return Err(unauthorized());
        }
        let Ok(Some(user)) = state.db.get_user(app.user_id).await else {
            return Err(unauthorized());
        };
        if user.disabled {
            return Err(unauthorized());
        }
        // A malformed scope row fails closed rather than becoming full
        // access. Existing rows were migrated to `*`.
        let Ok(scopes) = crate::app_scope::ScopeSet::parse(&app.scopes) else {
            return Err(unauthorized());
        };
        if app
            .last_used_at
            .is_none_or(|last| now.saturating_sub(last) >= AUTH_TOUCH_INTERVAL_MILLIS)
        {
            let _ = state.db.touch_app_password(app.id, now).await;
        }
        return Ok((
            CurrentUser {
                user_id: user.id,
                username: user.username,
                is_admin: user.is_admin,
                must_change_password: user.must_change_password,
                must_setup_mfa: user.must_setup_mfa,
                session_hash: None,
            },
            Some(AppPasswordAuth { id: app.id, scopes }),
        ));
    }

    // Keying the lockout on (account, source) means a flood from one
    // client cannot lock the account out for everyone else.
    // Lowercase the account: SQLite matches usernames `COLLATE NOCASE`,
    // so `Alice` and `alice` are the same account and must share lockout.
    let lockout_key = format!("basic:{}:{ip}", username.to_lowercase());
    if state.lockout.check(&lockout_key).is_some() {
        return Err(StatusCode::TOO_MANY_REQUESTS.into_response());
    }

    let key = credential_cache_key(username, password);
    // A cache hit is only trusted while the account's credentials are
    // unchanged: a password reset (even from the CLI) bumps the version, so
    // the old password stops authenticating immediately.
    let cached = match state.cred_cache.get(&key) {
        Some((user_id, version)) => match state.db.get_user(user_id).await.ok().flatten() {
            Some(user) if !user.disabled && user.credentials_version == version => Some(user),
            _ => None,
        },
        None => None,
    };
    let user = if let Some(user) = cached {
        Some(user)
    } else {
        match state.db.find_user(username).await.ok().flatten() {
            Some(user) if !user.disabled => {
                let hash = user.password_hash.clone();
                let password = password.to_owned();
                let verified = tokio::task::spawn_blocking(move || {
                    password::verify_password(&hash, &password).unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                if verified {
                    state.lockout.record_success(&lockout_key);
                    state
                        .cred_cache
                        .insert(key, user.id, user.credentials_version);
                    Some(user)
                } else {
                    state.lockout.record_failure(&lockout_key);
                    None
                }
            }
            _ => {
                burn_password_time(state, password).await;
                state.lockout.record_failure(&lockout_key);
                None
            }
        }
    };

    match user {
        Some(user) if !user.disabled => {
            // Basic auth carries only a password, so it can never satisfy a
            // second factor. Reject it outright when TOTP is enrolled; use a
            // session (which enforces TOTP) or a scoped token instead.
            // A DB error fails closed: never downgrade to password-only.
            match state.db.totp_secret(user.id).await {
                Ok(Some(_)) => Err(unauthorized()),
                Ok(None) => Ok((
                    CurrentUser {
                        user_id: user.id,
                        username: user.username,
                        is_admin: user.is_admin,
                        must_change_password: user.must_change_password,
                        must_setup_mfa: user.must_setup_mfa,
                        session_hash: None,
                    },
                    None,
                )),
                Err(_) => Err(unauthorized()),
            }
        }
        _ => Err(unauthorized()),
    }
}

async fn authenticate_token(state: &AppState, raw_token: &str) -> Result<CurrentUser, Response> {
    let hash = token::hash_token(raw_token);
    let now = kolimi_db::now_millis();

    let Some(session) = state.db.find_session(&hash).await.ok().flatten() else {
        return Err(unauthorized());
    };
    if session.expires_at <= now {
        let _ = state.db.delete_session(&hash).await;
        return Err(unauthorized());
    }
    let Some(user) = state.db.get_user(session.user_id).await.ok().flatten() else {
        return Err(unauthorized());
    };
    if user.disabled {
        return Err(unauthorized());
    }
    if now.saturating_sub(session.last_seen_at) >= AUTH_TOUCH_INTERVAL_MILLIS {
        let _ = state.db.touch_session(session.id, now).await;
    }

    Ok(CurrentUser {
        user_id: user.id,
        username: user.username,
        is_admin: user.is_admin,
        must_change_password: user.must_change_password,
        must_setup_mfa: user.must_setup_mfa,
        session_hash: Some(hash),
    })
}

fn decode_basic(encoded: &str) -> Option<(String, String)> {
    let bytes = STANDARD.decode(encoded).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (username, password) = text.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=')
                && key == name
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Double-submit check: the `X-CSRF-Token` header must be present, non-empty,
/// and equal to the `kolimi_csrf` cookie. Returns the token when it passes.
fn csrf_double_submit(headers: &HeaderMap) -> Option<String> {
    let header_token = headers.get("x-csrf-token").and_then(|v| v.to_str().ok())?;
    let cookie_token = cookie_value(headers, CSRF_COOKIE)?;
    (header_token == cookie_token && !header_token.is_empty()).then(|| header_token.to_string())
}

/// Full CSRF check for a cookie-authenticated request: the double-submit token
/// must also match the hash bound to the session, so a forged or planted
/// cookie value alone cannot pass.
async fn csrf_ok(state: &AppState, headers: &HeaderMap, session_hash: Option<&[u8; 32]>) -> bool {
    let Some(token) = csrf_double_submit(headers) else {
        return false;
    };
    let Some(session_hash) = session_hash else {
        return false;
    };
    match state.db.session_csrf_hash(session_hash).await {
        Ok(Some(expected)) => token::hash_token(&token).as_slice() == expected.as_slice(),
        // Session created before CSRF was bound (e.g. just after a server
        // upgrade): accept the double-submit token and bind it now, so the
        // session is strictly bound from this request on.
        Ok(None) => {
            let _ = state
                .db
                .set_session_csrf_hash(session_hash, &token::hash_token(&token))
                .await;
            true
        }
        Err(_) => false,
    }
}

fn unauthorized() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Basic realm=\"kolimi\", charset=\"UTF-8\""),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn decodes_basic_credentials() {
        let encoded = STANDARD.encode("alice:pass:with:colons");
        let (username, password) = decode_basic(&encoded).unwrap();
        assert_eq!(username, "alice");
        assert_eq!(password, "pass:with:colons");
    }

    #[test]
    fn rejects_malformed_basic_credentials() {
        assert!(decode_basic("not base64!").is_none());
        assert!(decode_basic(&STANDARD.encode("no-colon")).is_none());
    }

    #[test]
    fn extracts_cookie_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; kolimi_session=abc123; kolimi_csrf=xyz"),
        );
        assert_eq!(cookie_value(&headers, "kolimi_session").unwrap(), "abc123");
        assert_eq!(cookie_value(&headers, "kolimi_csrf").unwrap(), "xyz");
        assert!(cookie_value(&headers, "missing").is_none());
    }

    #[test]
    fn metrics_token_accepts_header_or_bearer_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-kolimi-metrics-token",
            HeaderValue::from_static("metrics-secret"),
        );
        assert!(metrics_token_matches(Some("metrics-secret"), &headers));
        assert!(!metrics_token_matches(Some("other"), &headers));
        assert!(!metrics_token_matches(None, &headers));

        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer metrics-secret"),
        );
        assert!(metrics_token_matches(Some("metrics-secret"), &bearer));

        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic bWV0cmljczpzZWNyZXQ="),
        );
        assert!(!metrics_token_matches(Some("metrics-secret"), &basic));
    }

    #[test]
    fn csrf_requires_matching_nonempty_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("kolimi_csrf=token123"),
        );
        headers.insert("x-csrf-token", HeaderValue::from_static("token123"));
        assert_eq!(csrf_double_submit(&headers).as_deref(), Some("token123"));

        headers.insert("x-csrf-token", HeaderValue::from_static("different"));
        assert!(csrf_double_submit(&headers).is_none());

        headers.insert("x-csrf-token", HeaderValue::from_static(""));
        assert!(csrf_double_submit(&headers).is_none());

        let mut empty = HeaderMap::new();
        empty.insert(header::COOKIE, HeaderValue::from_static("kolimi_csrf="));
        empty.insert("x-csrf-token", HeaderValue::from_static(""));
        assert!(csrf_double_submit(&empty).is_none());
    }
}
