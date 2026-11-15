//! Per-device app passwords for background sync, WebDAV/CalDAV, and clients
//! that cannot perform an interactive TOTP or passkey login.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::{CurrentUser, token};
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, api, audit};

/// A freshly authenticated session may create its first app password without
/// a second confirmation. This is what lets passkey-only desktop clients link
/// a web session; older sessions must re-authenticate.
const FRESH_SESSION_MILLIS: i64 = 5 * 60 * 1000;

#[derive(Deserialize)]
pub struct CreateRequest {
    name: String,
}

fn valid_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && trimmed.chars().count() <= 64 && !trimmed.chars().any(char::is_control)
}

/// Accepts either a valid re-authentication token or a session created within
/// the freshness window.
async fn require_fresh_or_reauth(
    state: &AppState,
    user: &CurrentUser,
    headers: &HeaderMap,
) -> Result<(), Response> {
    if let Some(hash) = user.session_hash
        && let Ok(Some(session)) = state.db.find_session(&hash).await
        && kolimi_db::now_millis() - session.created_at <= FRESH_SESSION_MILLIS
    {
        return Ok(());
    }
    crate::reauth::require(state, user.user_id, headers)
}

/// `GET /api/me/app-passwords` — list app passwords (never the tokens).
pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.list_app_passwords(user.user_id).await {
        Ok(passwords) => Json(json!({ "app_passwords": passwords })).into_response(),
        Err(_) => api::internal_error(),
    }
}

/// `POST /api/me/app-passwords` — create a token, shown once.
pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Json(req): Json<CreateRequest>,
) -> Response {
    if let Err(response) = require_fresh_or_reauth(&state, &user, &headers).await {
        return response;
    }
    let name = req.name.trim();
    if !valid_name(name) {
        return api::bad_request("name must be 1-64 printable characters");
    }
    let plaintext = match token::new_session_token() {
        Ok(token) => token,
        Err(_) => return api::internal_error(),
    };
    let hash = token::hash_token(&plaintext);
    match state
        .db
        .create_app_password(user.user_id, name, &hash)
        .await
    {
        Ok(password) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "app_password.add",
                name,
                json!({ "id": password.id }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": password.id,
                    "name": password.name,
                    "created_at": password.created_at,
                    "token": plaintext,
                })),
            )
                .into_response()
        }
        Err(kolimi_db::DbError::Conflict(message)) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/me/app-passwords/{id}` — revoke one token.
pub async fn revoke(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(response) = require_fresh_or_reauth(&state, &user, &headers).await {
        return response;
    }
    match state.db.delete_app_password(user.user_id, id).await {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "app_password.revoke",
                &id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(kolimi_db::DbError::NotFound(_)) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// `DELETE /api/me/app-passwords/current` — a device revokes the token it
/// authenticated with. This is the desktop sign-out path and needs no
/// separate re-authentication because possession of the token is the proof.
pub async fn revoke_current(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
) -> Response {
    let Some((username, password)) = basic_credentials(&headers) else {
        return api::bad_request("app-password revocation requires HTTP Basic auth");
    };
    if !username.eq_ignore_ascii_case(&user.username) {
        return api::unauthorized("invalid credentials");
    }
    let hash = token::hash_token(&password);
    match state.db.delete_app_password_hash(user.user_id, &hash).await {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "app_password.revoke",
                "current",
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = STANDARD.decode(rest.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}
