//! Passkey (WebAuthn) endpoints: registration, management, and login.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
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
    Json(req): Json<RegisterFinish>,
) -> Response {
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
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "passkey.add",
                &row.name,
                json!({}),
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
    Path(passkey_id): Path<i64>,
) -> Response {
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

/// Body for starting a passkey login.
#[derive(Deserialize)]
pub struct LoginBegin {
    username: String,
}

/// `POST /api/passkeys/login/begin` — start a passkey login.
///
/// Returns 404 for unknown users and for users without passkeys alike,
/// so the endpoint does not reveal which accounts exist.
pub async fn login_begin(State(state): State<AppState>, Json(req): Json<LoginBegin>) -> Response {
    if state.lockout.check(&req.username).is_some() {
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
pub async fn login_finish(State(state): State<AppState>, Json(req): Json<LoginFinish>) -> Response {
    if state.lockout.check(&req.username).is_some() {
        return too_many();
    }
    let Some(user) = state.db.find_user(&req.username).await.ok().flatten() else {
        return unauthorized("invalid credentials");
    };
    if user.disabled {
        return unauthorized("invalid credentials");
    }

    let rows = state.db.list_passkeys(user.id).await.unwrap_or_default();
    let stored = parse_passkeys(&rows);
    if stored.is_empty() {
        return unauthorized("invalid credentials");
    }
    let Ok(credential) = serde_json::from_value::<PublicKeyCredential>(req.credential) else {
        return bad_request("invalid credential");
    };

    let result = match state
        .passkeys
        .finish_authentication(&req.challenge_id, user.id, &credential)
    {
        Ok(result) => result,
        Err(error) => {
            tracing::debug!(error = %error, "passkey authentication failed");
            state.lockout.record_failure(&req.username);
            audit(
                &state,
                None,
                None,
                "auth.login_failed",
                &req.username,
                json!({ "reason": "bad_passkey" }),
            )
            .await;
            return unauthorized("invalid credentials");
        }
    };

    let Some((passkey_id, mut passkey)) = stored
        .into_iter()
        .find(|(_, passkey)| passkey.cred_id() == result.cred_id())
    else {
        state.lockout.record_failure(&req.username);
        return unauthorized("invalid credentials");
    };

    passkey.update_credential(&result);
    if let Ok(serialized) = serde_json::to_string(&passkey) {
        let _ = state
            .db
            .update_passkey(user.id, passkey_id, &serialized, kolimi_db::now_millis())
            .await;
    }

    state.lockout.record_success(&req.username);
    audit(
        &state,
        Some(user.id),
        Some(&user.username),
        "auth.login",
        &user.username,
        json!({ "method": "passkey" }),
    )
    .await;
    start_session(&state, &user).await
}
