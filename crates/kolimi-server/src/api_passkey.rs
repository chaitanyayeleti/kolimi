//! Passkey (WebAuthn) endpoints: registration, management, and login.

#![allow(clippy::result_large_err)]

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use kolimi_auth::{
    CurrentUser,
    passkey::{CredentialID, Passkey, PublicKeyCredential, RegisterPublicKeyCredential},
};
use kolimi_db::DbError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::api::{bad_request, internal_error, start_session, unauthorized};
use crate::audit;

const MAX_PASSKEYS_PER_USER: i64 = 20;
const MAX_PASSKEY_NAME_LEN: usize = 64;

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_PASSKEY_NAME_LEN && !name.chars().any(char::is_control)
}

fn parse_passkeys(rows: &[kolimi_db::PasskeyRow]) -> Vec<(i64, Passkey)> {
    rows.iter()
        .filter_map(|row| {
            serde_json::from_str::<Passkey>(&row.credential)
                .ok()
                .map(|passkey| (row.id, passkey))
        })
        .collect()
}

fn too_many() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({ "error": "too many failed attempts, try again later" })),
    )
        .into_response()
}

fn no_passkeys() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "no passkeys registered for this user" })),
    )
        .into_response()
}

/// `POST /api/passkeys/register/begin` — start registering a new passkey.
pub async fn register_begin(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.count_passkeys(user.user_id).await {
        Ok(count) if count >= MAX_PASSKEYS_PER_USER => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "passkey limit reached" })),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(_) => return internal_error(),
    }

    let rows = match state.db.list_passkeys(user.user_id).await {
        Ok(rows) => rows,
        Err(_) => return internal_error(),
    };
    let exclude: Vec<CredentialID> = parse_passkeys(&rows)
        .into_iter()
        .map(|(_, passkey)| passkey.cred_id().clone())
        .collect();

    match state
        .passkeys
        .begin_registration(user.user_id, &user.username, exclude)
    {
        Ok((challenge_id, options)) => {
            Json(json!({ "challenge_id": challenge_id, "options": options })).into_response()
        }
        Err(error) => {
            tracing::warn!(error = %error, "passkey registration begin failed");
            internal_error()
        }
    }
}

/// Body for finishing registration.
#[derive(Deserialize)]
pub struct RegisterFinish {
    challenge_id: String,
    name: String,
    credential: Value,
}

/// `POST /api/passkeys/register/finish` — verify and store the new passkey.
pub async fn register_finish(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Json(req): Json<RegisterFinish>,
) -> Response {
    // A session alone must not add a credential that survives password
    // changes and bypasses TOTP at login (RT-18).
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    if !valid_name(&req.name) {
        return bad_request("passkey name must be 1-64 printable characters");
    }
    let Ok(credential) = serde_json::from_value::<RegisterPublicKeyCredential>(req.credential)
    else {
        return bad_request("invalid credential");
    };

    let passkey =
        match state
            .passkeys
            .finish_registration(&req.challenge_id, user.user_id, &credential)
        {
            Ok(passkey) => passkey,
            Err(error) => {
                tracing::debug!(error = %error, "passkey registration verification failed");
                return bad_request("passkey registration failed");
            }
        };

    let Ok(serialized) = serde_json::to_string(&passkey) else {
        return internal_error();
    };
    match state
        .db
        .add_passkey(
            user.user_id,
            &req.name,
            &serialized,
            kolimi_db::now_millis(),
        )
        .await
    {
        Ok(row) => {
            let _ = state.db.set_must_setup_mfa(user.user_id, false).await;
            // A passkey is a new long-lived credential. Drop sessions that
            // predate it so a session attacker cannot keep one alive after
            // the owner adds a stronger factor.
            let sessions_revoked = match user.session_hash {
                Some(hash) => state
                    .db
                    .delete_user_sessions_except(user.user_id, hash.as_slice())
                    .await
                    .unwrap_or(0),
                None => state
                    .db
                    .delete_user_sessions(user.user_id)
                    .await
                    .unwrap_or(0),
            };
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "passkey.add",
                &row.name,
                json!({ "sessions_revoked": sessions_revoked }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({ "id": row.id, "name": row.name })),
            )
                .into_response()
        }
        Err(DbError::Conflict(_)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "a passkey with that name already exists" })),
        )
            .into_response(),
        Err(_) => internal_error(),
    }
}

/// `GET /api/passkeys` — list the caller's passkeys.
pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.list_passkeys(user.user_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(_) => internal_error(),
    }
}

/// `DELETE /api/passkeys/{id}` — remove one of the caller's passkeys.
pub async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(passkey_id): Path<i64>,
) -> Response {
    // Removing a credential is equally sensitive: it can lock the owner out
    // or erase the only strong factor they have left.
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    // A passkey-only account that removes its last credential locks itself
    // out (recovery then needs an administrator). Refuse the self-lockout.
    let account = match state.db.get_user(user.user_id).await {
        Ok(Some(account)) => account,
        Ok(None) => return unauthorized("invalid credentials"),
        Err(_) => return internal_error(),
    };
    if account.password_hash.is_empty() {
        let count = match state.db.count_passkeys(user.user_id).await {
            Ok(count) => count,
            Err(_) => return internal_error(),
        };
        if count <= 1 {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "cannot remove the last passkey on a passwordless account"
                })),
            )
                .into_response();
        }
    }
    match state.db.delete_passkey(user.user_id, passkey_id).await {
        Ok(()) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "passkey.remove",
                &passkey_id.to_string(),
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(DbError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => internal_error(),
    }
}

/// Verifies a passkey assertion and persists the incremented sign counter.
///
/// Shared by login and re-authentication. A failure is deliberately generic
/// so the caller can apply its own audit/lockout policy.
async fn complete_assertion(
    state: &AppState,
    user_id: i64,
    challenge_id: &str,
    credential: &PublicKeyCredential,
) -> Result<(), Response> {
    let rows = match state.db.list_passkeys(user_id).await {
        Ok(rows) => rows,
        Err(_) => return Err(internal_error()),
    };
    let stored = parse_passkeys(&rows);
    if stored.is_empty() {
        return Err(unauthorized("invalid credentials"));
    }
    let result = match state
        .passkeys
        .finish_authentication(challenge_id, user_id, credential)
    {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(error = %error, "passkey authentication failed");
            return Err(unauthorized("invalid credentials"));
        }
    };
    let Some((passkey_id, mut passkey)) = stored
        .into_iter()
        .find(|(_, passkey)| passkey.cred_id() == result.cred_id())
    else {
        return Err(unauthorized("invalid credentials"));
    };
    passkey.update_credential(&result);
    // Fail closed: if the incremented counter cannot be stored, do not
    // authenticate (a stale counter weakens replay protection).
    let serialized = match serde_json::to_string(&passkey) {
        Ok(serialized) => serialized,
        Err(error) => {
            tracing::error!(%error, "failed to serialize passkey");
            return Err(internal_error());
        }
    };
    if let Err(error) = state
        .db
        .update_passkey(user_id, passkey_id, &serialized, kolimi_db::now_millis())
        .await
    {
        tracing::error!(%error, "failed to persist passkey sign counter");
        return Err(internal_error());
    }
    Ok(())
}

/// Body for starting a passkey login.
#[derive(Deserialize)]
pub struct LoginBegin {
    username: String,
}

/// `POST /api/passkeys/login/begin` — start a passkey login.
///
/// Returns 404 for unknown users and for users without passkeys alike,
/// so the endpoint does not reveal which accounts exist.
pub async fn login_begin(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Json(req): Json<LoginBegin>,
) -> Response {
    // Key the lockout on (account, source) so one client cannot lock an
    // account out for everyone.
    let lockout_key = format!("passkey:{}:{}", req.username, ip);
    if state.lockout.check(&lockout_key).is_some() {
        return too_many();
    }
    let Some(user) = state.db.find_user(&req.username).await.ok().flatten() else {
        return no_passkeys();
    };
    if user.disabled {
        return no_passkeys();
    }
    let rows = state.db.list_passkeys(user.id).await.unwrap_or_default();
    let credentials: Vec<Passkey> = parse_passkeys(&rows).into_iter().map(|(_, p)| p).collect();
    if credentials.is_empty() {
        return no_passkeys();
    }

    match state.passkeys.begin_authentication(user.id, &credentials) {
        Ok((challenge_id, options)) => {
            Json(json!({ "challenge_id": challenge_id, "options": options })).into_response()
        }
        Err(error) => {
            tracing::warn!(error = %error, "passkey authentication begin failed");
            internal_error()
        }
    }
}

/// Body for finishing a passkey login.
#[derive(Deserialize)]
pub struct LoginFinish {
    username: String,
    challenge_id: String,
    credential: Value,
}

/// `POST /api/passkeys/login/finish` — verify the assertion and start a session.
pub async fn login_finish(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    headers: HeaderMap,
    Json(req): Json<LoginFinish>,
) -> Response {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let lockout_key = format!("passkey:{}:{}", req.username, ip);
    if state.lockout.check(&lockout_key).is_some() {
        return too_many();
    }
    let Some(user) = state.db.find_user(&req.username).await.ok().flatten() else {
        return unauthorized("invalid credentials");
    };
    if user.disabled {
        return unauthorized("invalid credentials");
    }

    let Ok(credential) = serde_json::from_value::<PublicKeyCredential>(req.credential) else {
        return bad_request("invalid credential");
    };
    if let Err(response) = complete_assertion(&state, user.id, &req.challenge_id, &credential).await
    {
        state.lockout.record_failure(&lockout_key);
        state.metrics.login_failure();
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "bad_passkey" }),
        )
        .await;
        return response;
    }

    state.lockout.record_success(&lockout_key);
    state.metrics.login("passkey");
    audit(
        &state,
        Some(user.id),
        Some(&user.username),
        "auth.login",
        &user.username,
        json!({ "method": "passkey" }),
    )
    .await;
    start_session(&state, &user, &ip, user_agent.as_deref()).await
}

/// `POST /api/reauth/passkey/begin` — start a fresh assertion for an
/// already-signed-in user. Required for passkey-only accounts, which have
/// no password to re-enter.
pub async fn reauth_begin(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let lockout_key = format!("passkey-reauth:{}:{ip}", user.user_id);
    if state.lockout.check(&lockout_key).is_some() {
        return too_many();
    }
    let rows = match state.db.list_passkeys(user.user_id).await {
        Ok(rows) => rows,
        Err(_) => return internal_error(),
    };
    let credentials: Vec<Passkey> = parse_passkeys(&rows).into_iter().map(|(_, p)| p).collect();
    if credentials.is_empty() {
        return no_passkeys();
    }
    match state
        .passkeys
        .begin_authentication(user.user_id, &credentials)
    {
        Ok((challenge_id, options)) => {
            Json(json!({ "challenge_id": challenge_id, "options": options })).into_response()
        }
        Err(error) => {
            tracing::warn!(error = %error, "passkey re-auth begin failed");
            internal_error()
        }
    }
}

/// Body for finishing a passkey re-authentication.
#[derive(Deserialize)]
pub struct ReauthFinish {
    challenge_id: String,
    credential: Value,
}

/// `POST /api/reauth/passkey/finish` — verify a fresh assertion and issue
/// a single-use re-authentication token.
pub async fn reauth_finish(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<ReauthFinish>,
) -> Response {
    let lockout_key = format!("passkey-reauth:{}:{ip}", user.user_id);
    if state.lockout.check(&lockout_key).is_some() {
        return too_many();
    }
    let Ok(credential) = serde_json::from_value::<PublicKeyCredential>(req.credential) else {
        return bad_request("invalid credential");
    };
    if let Err(response) =
        complete_assertion(&state, user.user_id, &req.challenge_id, &credential).await
    {
        state.lockout.record_failure(&lockout_key);
        audit(
            &state,
            Some(user.user_id),
            Some(&user.username),
            "auth.reauth_failed",
            &user.username,
            json!({ "reason": "bad_passkey" }),
        )
        .await;
        return response;
    }
    state.lockout.record_success(&lockout_key);
    let Some(token) = state.reauth.issue(user.user_id) else {
        return internal_error();
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "auth.reauth",
        &user.username,
        json!({ "method": "passkey" }),
    )
    .await;
    Json(json!({
        "token": token,
        "expires_in_secs": crate::reauth::REAUTH_TTL.as_secs(),
    }))
    .into_response()
}
