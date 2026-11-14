//! Admin invite management and the unauthenticated invite-acceptance API.
//!
//! Tokens are 256-bit random values. Only their BLAKE3 digest is stored, and
//! the plaintext appears once in the generated link. Admin UI links place
//! the token in the URL **fragment** (`/invite#token=…`) so browsers and
//! reverse proxies never receive it in a request line or access log; the
//! acceptance page sends it in JSON request bodies instead.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::{CurrentUser, password, token};
use kolimi_db::{DbError, Invite, NewInvite, validate_username};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, api, audit};

/// Invite lifetime when the caller does not choose one.
pub const DEFAULT_INVITE_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Shortest accepted invite lifetime.
pub const MIN_INVITE_TTL_SECS: i64 = 60 * 60;
/// Longest accepted invite lifetime.
pub const MAX_INVITE_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Trims and validates optional profile fields.
pub(crate) fn clean_profile(
    display_name: Option<&str>,
    email: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    let display_name = display_name
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if display_name
        .is_some_and(|value| value.chars().count() > 80 || value.chars().any(char::is_control))
    {
        return Err("display name must be at most 80 characters".to_string());
    }
    let email = email.map(str::trim).filter(|value| !value.is_empty());
    if email.is_some_and(|value| {
        value.chars().count() > 254
            || value.chars().any(char::is_whitespace)
            || !value.contains('@')
    }) {
        return Err("enter a valid email address".to_string());
    }
    Ok((display_name.map(str::to_string), email.map(str::to_string)))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn forbidden() -> Response {
    api::forbidden("administrator access required")
}

/// Parses the 64-hex-character token before hashing, so malformed input
/// fails without touching the database.
fn token_hash(input: &str) -> Option<[u8; 32]> {
    let token = input.trim();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(token::hash_token(token))
}

fn invite_json(invite: &Invite, now: i64) -> Value {
    json!({
        "id": invite.id,
        "username": invite.username,
        "display_name": invite.display_name,
        "email": invite.email,
        "created_at": invite.created_at,
        "expires_at": invite.expires_at,
        "expired": invite.expires_at <= now,
        "used": invite.used_at.is_some(),
    })
}

/// New-invite payload.
#[derive(Deserialize)]
pub struct NewInviteRequest {
    username: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    expires_in_secs: Option<i64>,
}

/// `POST /api/invites` — create a one-time onboarding link.
pub async fn create_invite(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<NewInviteRequest>,
) -> Response {
    if !user.is_admin {
        return forbidden();
    }
    let username = req.username.trim();
    if let Err(error) = validate_username(username) {
        return api::bad_request(&error.to_string());
    }
    let (display_name, email) =
        match clean_profile(req.display_name.as_deref(), req.email.as_deref()) {
            Ok(profile) => profile,
            Err(message) => return api::bad_request(&message),
        };
    let ttl = req
        .expires_in_secs
        .unwrap_or(DEFAULT_INVITE_TTL_SECS)
        .clamp(MIN_INVITE_TTL_SECS, MAX_INVITE_TTL_SECS);
    let plaintext = match token::new_session_token() {
        Ok(token) => token,
        Err(_) => return api::internal_error(),
    };
    let hash = token::hash_token(&plaintext);
    let invite = match state
        .db
        .create_invite(NewInvite {
            username,
            token_hash: &hash,
            created_by: Some(user.user_id),
            expires_at: kolimi_db::now_millis() + ttl * 1000,
            display_name: display_name.as_deref(),
            email: email.as_deref(),
        })
        .await
    {
        Ok(invite) => invite,
        Err(DbError::Conflict(message)) => {
            return (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response();
        }
        Err(DbError::InvalidUsername(_)) => return api::bad_request("invalid username"),
        Err(_) => return api::internal_error(),
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "invite.create",
        &invite.username,
        json!({ "id": invite.id, "expires_at": invite.expires_at, "by": "api" }),
    )
    .await;
    no_store(
        (
            StatusCode::CREATED,
            Json(json!({
                "id": invite.id,
                "username": invite.username,
                "display_name": invite.display_name,
                "email": invite.email,
                "created_at": invite.created_at,
                "expires_at": invite.expires_at,
                "url": format!("/invite#token={plaintext}"),
            })),
        )
            .into_response(),
    )
}

/// `GET /api/invites` — pending invite overview (never includes tokens).
pub async fn list_invites(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if !user.is_admin {
        return forbidden();
    }
    let invites = match state.db.list_pending_invites().await {
        Ok(invites) => invites,
        Err(_) => return api::internal_error(),
    };
    let now = kolimi_db::now_millis();
    let invites: Vec<Value> = invites
        .iter()
        .map(|invite| invite_json(invite, now))
        .collect();
    no_store(Json(json!({ "invites": invites })).into_response())
}

/// `DELETE /api/invites/{id}` — revoke a pending invite.
pub async fn revoke_invite(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Response {
    if !user.is_admin {
        return forbidden();
    }
    let invite = match state.db.invite_by_id(id).await {
        Ok(Some(invite)) => invite,
        Ok(None) => return api::not_found(),
        Err(_) => return api::internal_error(),
    };
    match state.db.revoke_invite(id).await {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "invite.revoke",
                &invite.username,
                json!({ "id": id, "by": "api" }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// Token-only payload for the public lookup call.
#[derive(Deserialize)]
pub struct InviteTokenRequest {
    token: String,
}

/// `POST /api/invites/lookup` — validate a token and return display hints.
///
/// POST rather than GET keeps the token out of request lines, browser
/// history, and proxy logs. The endpoint is rate-limited with the other
/// invite calls.
pub async fn lookup_invite(
    State(state): State<AppState>,
    Json(req): Json<InviteTokenRequest>,
) -> Response {
    let Some(hash) = token_hash(&req.token) else {
        return api::not_found();
    };
    let invite = match state.db.find_valid_invite(&hash).await {
        Ok(Some(invite)) => invite,
        Ok(None) => return api::not_found(),
        Err(_) => return api::internal_error(),
    };
    no_store(
        Json(json!({
            "username": invite.username,
            "display_name": invite.display_name,
            "email": invite.email,
            "expires_at": invite.expires_at,
        }))
        .into_response(),
    )
}

/// Accept-invite payload.
#[derive(Deserialize)]
pub struct AcceptInviteRequest {
    token: String,
    password: String,
}

/// `POST /api/invites/accept` — set the password and create the account.
pub async fn accept_invite(
    State(state): State<AppState>,
    Json(req): Json<AcceptInviteRequest>,
) -> Response {
    if req.password.chars().count() < password::MIN_PASSWORD_LEN {
        return api::bad_request(&format!(
            "password must be at least {} characters",
            password::MIN_PASSWORD_LEN
        ));
    }
    let Some(hash) = token_hash(&req.token) else {
        return api::not_found();
    };
    // Validate before spending Argon2 work so random tokens cannot be used
    // as a cheap CPU sink.
    match state.db.find_valid_invite(&hash).await {
        Ok(Some(_)) => {}
        Ok(None) => return api::not_found(),
        Err(_) => return api::internal_error(),
    }
    let candidate = req.password;
    let password_hash =
        match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await {
            Ok(Ok(hash)) => hash,
            Ok(Err(error)) => return api::bad_request(&error.to_string()),
            Err(_) => return api::internal_error(),
        };
    let user = match state.db.consume_invite(&hash, &password_hash).await {
        Ok(user) => user,
        Err(DbError::NotFound(_)) => return api::not_found(),
        Err(DbError::Conflict(message)) => {
            return (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response();
        }
        Err(DbError::InvalidUsername(_)) => return api::bad_request("invalid username"),
        Err(_) => return api::internal_error(),
    };
    audit(
        &state,
        None,
        None,
        "invite.accept",
        &user.username,
        json!({ "display_name_set": user.display_name.is_some() }),
    )
    .await;
    no_store(
        (
            StatusCode::CREATED,
            Json(json!({
                "username": user.username,
                "display_name": user.display_name,
            })),
        )
            .into_response(),
    )
}
