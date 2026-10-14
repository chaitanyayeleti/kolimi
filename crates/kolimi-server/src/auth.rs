#![allow(clippy::result_large_err)]

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::{CurrentUser, cache::credential_cache_key, password, token};

use crate::{AppState, CSRF_COOKIE, SESSION_COOKIE, hardening};

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
    let headers = req.headers().clone();
    let ip = hardening::client_ip(
        &headers,
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0),
        state.trust_proxy,
    );

    let (user, via_cookie) = authenticate(&state, &headers, &ip).await?;

    // Cookie-authenticated state-changing requests must carry the
    // double-submit CSRF token on every surface (API, WebDAV, plugins), not
    // just `/api/*`.
    if via_cookie
        && matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        )
        && !csrf_ok(&state, &headers, user.session_hash.as_ref()).await
    {
        return Err(StatusCode::FORBIDDEN.into_response());
    }

    req.extensions_mut().insert(user);
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

fn extract_credentials(headers: &HeaderMap) -> Option<Credentials> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        let (scheme, rest) = value.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("basic") {
            let (username, password) = decode_basic(rest.trim())?;
            return Some(Credentials::Basic { username, password });
        }
        if scheme.eq_ignore_ascii_case("bearer") {
            return Some(Credentials::Bearer(rest.trim().to_string()));
        }
        return None;
    }
    cookie_value(headers, SESSION_COOKIE).map(Credentials::Cookie)
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    ip: &str,
) -> Result<(CurrentUser, bool), Response> {
    match extract_credentials(headers) {
        Some(Credentials::Basic { username, password }) => {
            authenticate_basic(state, &username, &password, ip)
                .await
                .map(|user| (user, false))
        }
        Some(Credentials::Bearer(raw)) => authenticate_token(state, &raw)
            .await
            .map(|user| (user, false)),
        Some(Credentials::Cookie(raw)) => authenticate_token(state, &raw)
            .await
            .map(|user| (user, true)),
        None => Err(unauthorized()),
    }
}

async fn authenticate_basic(
    state: &AppState,
    username: &str,
    password: &str,
    ip: &str,
) -> Result<CurrentUser, Response> {
    // Keying the lockout on (account, source) means a flood from one
    // client cannot lock the account out for everyone else.
    let lockout_key = format!("basic:{username}:{ip}");
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
        Some(user) if !user.disabled => Ok(CurrentUser {
            user_id: user.id,
            username: user.username,
            is_admin: user.is_admin,
            session_hash: None,
        }),
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
    let _ = state.db.touch_session(session.id, now).await;

    Ok(CurrentUser {
        user_id: user.id,
        username: user.username,
        is_admin: user.is_admin,
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
