use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::{CurrentUser, password, token};
use kolimi_db::DbError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, CSRF_COOKIE, SESSION_COOKIE, SESSION_TTL_MILLIS, audit};

/// Liveness probe.
pub async fn healthz() -> &'static str {
    "ok"
}

/// Version information.
pub async fn version() -> Json<Value> {
    Json(json!({
        "name": "kolimi-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Credentials for session login.
#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
    /// TOTP or recovery code, when two-factor is enrolled.
    #[serde(default)]
    code: Option<String>,
}

/// `POST /api/session` — exchanges credentials for a session cookie.
pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    if req.username.is_empty() || req.password.is_empty() {
        return bad_request("username and password are required");
    }
    if state.lockout.check(&req.username).is_some() {
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "locked_out" }),
        )
        .await;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many failed attempts, try again later" })),
        )
            .into_response();
    }

    let Some(user) = state.db.find_user(&req.username).await.ok().flatten() else {
        crate::auth::burn_password_time(&state, &req.password).await;
        state.lockout.record_failure(&req.username);
        state.metrics.login_failure();
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "unknown_user" }),
        )
        .await;
        return unauthorized("invalid credentials");
    };
    if user.disabled {
        crate::auth::burn_password_time(&state, &req.password).await;
        state.lockout.record_failure(&req.username);
        state.metrics.login_failure();
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "disabled" }),
        )
        .await;
        return unauthorized("invalid credentials");
    }
    if user.password_hash.is_empty() {
        crate::auth::burn_password_time(&state, &req.password).await;
        state.lockout.record_failure(&req.username);
        state.metrics.login_failure();
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "passkey_only" }),
        )
        .await;
        return unauthorized("invalid credentials");
    }

    let hash = user.password_hash.clone();
    let candidate = req.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        password::verify_password(&hash, &candidate).unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if !verified {
        state.lockout.record_failure(&req.username);
        state.metrics.login_failure();
        audit(
            &state,
            None,
            None,
            "auth.login_failed",
            &req.username,
            json!({ "reason": "bad_password" }),
        )
        .await;
        return unauthorized("invalid credentials");
    }
    // Second factor, when enrolled.
    if let Some((secret_b32, last_step)) = state.db.totp_secret(user.id).await.ok().flatten() {
        let Some(code) = req.code.as_deref() else {
            audit(
                &state,
                Some(user.id),
                Some(&user.username),
                "auth.totp_required",
                &user.username,
                json!({}),
            )
            .await;
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "two-factor code required", "totp_required": true })),
            )
                .into_response();
        };
        let Ok(secret) = kolimi_auth::totp::TotpSecret::from_base32(&secret_b32) else {
            return internal_error();
        };
        let now_secs = (kolimi_db::now_millis() / 1000) as u64;
        let matched =
            kolimi_auth::totp::verify(&secret, code, now_secs, last_step.map(|s| s as u64));
        let method = if let Some(step) = matched {
            if !state
                .db
                .consume_totp_step(user.id, step)
                .await
                .unwrap_or(false)
            {
                state.lockout.record_failure(&req.username);
                state.metrics.login_failure();
                audit(
                    &state,
                    None,
                    None,
                    "auth.login_failed",
                    &req.username,
                    json!({ "reason": "totp_replayed" }),
                )
                .await;
                return unauthorized("invalid credentials");
            }
            "password+totp"
        } else if state
            .db
            .consume_recovery_code(user.id, &kolimi_auth::totp::hash_recovery_code(code))
            .await
            .unwrap_or(false)
        {
            "recovery_code"
        } else {
            state.lockout.record_failure(&req.username);
            state.metrics.login_failure();
            audit(
                &state,
                None,
                None,
                "auth.login_failed",
                &req.username,
                json!({ "reason": "bad_totp" }),
            )
            .await;
            return unauthorized("invalid credentials");
        };
        state.lockout.record_success(&req.username);
        audit(
            &state,
            Some(user.id),
            Some(&user.username),
            "auth.login",
            &user.username,
            json!({ "method": method }),
        )
        .await;
        return start_session(&state, &user).await;
    }

    state.lockout.record_success(&req.username);
    audit(
        &state,
        Some(user.id),
        Some(&user.username),
        "auth.login",
        &user.username,
        json!({ "method": "password" }),
    )
    .await;

    start_session(&state, &user).await
}

/// Creates a session for `user` and returns the login response with cookies.
pub(crate) async fn start_session(state: &AppState, user: &kolimi_db::User) -> Response {
    let (Ok(session_token), Ok(csrf_token)) = (token::new_session_token(), token::new_csrf_token())
    else {
        return internal_error();
    };
    let expires_at = kolimi_db::now_millis() + SESSION_TTL_MILLIS;
    if state
        .db
        .create_session(user.id, &token::hash_token(&session_token), expires_at)
        .await
        .is_err()
    {
        return internal_error();
    }
    let _ = state
        .db
        .delete_expired_sessions(kolimi_db::now_millis())
        .await;

    let mut response = Json(json!({
        "username": user.username,
        "is_admin": user.is_admin,
        "expires_at": expires_at,
    }))
    .into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(
            SESSION_COOKIE,
            &session_token,
            30 * 24 * 60 * 60,
            true,
            state.secure_cookies,
        ),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(
            CSRF_COOKIE,
            &csrf_token,
            30 * 24 * 60 * 60,
            false,
            state.secure_cookies,
        ),
    );
    response
}

/// `DELETE /api/session` — revokes the current session.
pub async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if let Some(hash) = user.session_hash {
        let _ = state.db.delete_session(&hash).await;
    }
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "auth.logout",
        &user.username,
        json!({}),
    )
    .await;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(SESSION_COOKIE, "", 0, true, state.secure_cookies),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie(CSRF_COOKIE, "", 0, false, state.secure_cookies),
    );
    response
}

/// `GET /api/me` — information about the authenticated user.
pub async fn me(Extension(user): Extension<CurrentUser>) -> Json<Value> {
    Json(json!({
        "username": user.username,
        "is_admin": user.is_admin,
    }))
}

/// Query parameters for `/api/search`.
#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
    #[serde(default = "search_limit")]
    limit: usize,
}

fn search_limit() -> usize {
    50
}

/// `GET /api/search?q=&limit=` — full-text search over the caller's files.
pub async fn search(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let search = state.search.clone();
    let user_id = user.user_id;
    let text = query.q.clone();
    let limit = query.limit.clamp(1, 100);
    let result = tokio::task::spawn_blocking(move || search.search(user_id, &text, limit)).await;
    match result {
        Ok(Ok(hits)) => Json(json!({ "query": query.q, "results": hits })).into_response(),
        Ok(Err(kolimi_search::SearchError::Query(message))) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid query: {message}") })),
        )
            .into_response(),
        _ => internal_error(),
    }
}

/// New user creation payload.
#[derive(Deserialize)]
pub struct NewUserRequest {
    username: String,
    password: String,
}

/// `POST /api/users` — admin-only user creation.
pub async fn create_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<NewUserRequest>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let candidate = req.password.clone();
    let hash = match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await
    {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => return bad_request(&e.to_string()),
        Err(_) => return internal_error(),
    };
    match state.db.create_user(&req.username, &hash).await {
        Ok(created) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "user.add",
                &created.username,
                json!({ "by": "api" }),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": created.id,
                    "username": created.username,
                    "is_admin": created.is_admin,
                })),
            )
                .into_response()
        }
        Err(DbError::Conflict(_)) => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "username already exists" })),
        )
            .into_response(),
        Err(DbError::InvalidUsername(_)) => bad_request("invalid username"),
        Err(_) => internal_error(),
    }
}

/// `GET /api/users` — admin-only list of accounts.
pub async fn list_users(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.db.list_users().await {
        Ok(users) => Json(json!({ "users": users })).into_response(),
        Err(_) => internal_error(),
    }
}

/// Payload for `PATCH /api/users/{username}`.
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    /// Enable or disable the account.
    #[serde(default)]
    disabled: Option<bool>,
    /// Grant or revoke administrator rights.
    #[serde(default)]
    admin: Option<bool>,
}

/// `PATCH /api/users/{username}` — admin-only account changes.
pub async fn update_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.disabled.is_none() && req.admin.is_none() {
        return bad_request("nothing to update");
    }
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    if let Some(disabled) = req.disabled {
        if disabled && target.id == user.user_id {
            return bad_request("cannot disable your own account");
        }
        if let Err(error) = state.db.set_disabled(&username, disabled).await {
            return db_error(error);
        }
        let action = if disabled {
            "user.disable"
        } else {
            "user.enable"
        };
        audit(
            &state,
            Some(user.user_id),
            Some(&user.username),
            action,
            &target.username,
            json!({}),
        )
        .await;
    }
    if let Some(admin) = req.admin {
        if !admin && target.id == user.user_id {
            return bad_request("cannot revoke your own administrator rights");
        }
        if let Err(error) = state.db.set_admin(target.id, admin).await {
            return db_error(error);
        }
        let action = if admin {
            "user.grant_admin"
        } else {
            "user.revoke_admin"
        };
        audit(
            &state,
            Some(user.user_id),
            Some(&user.username),
            action,
            &target.username,
            json!({}),
        )
        .await;
    }
    match state.db.find_user(&username).await {
        Ok(Some(updated)) => Json(json!(updated)).into_response(),
        _ => internal_error(),
    }
}

/// `DELETE /api/users/{username}` — admin-only account deletion.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(username): Path<String>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    if target.id == user.user_id {
        return bad_request("cannot delete your own account");
    }
    match state.db.delete_user(&username).await {
        Ok(()) => {
            // The row and its cascades are gone; drop the per-user blob
            // directory too, since the janitor only visits existing users.
            if let Err(error) = state.vfs.remove_user_data(target.id).await {
                tracing::error!(%error, user_id = target.id, "could not remove deleted user's blobs");
                audit(
                    &state,
                    Some(user.user_id),
                    Some(&user.username),
                    "user.delete_orphan_blobs",
                    &target.username,
                    json!({ "error": error.to_string() }),
                )
                .await;
            }
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "user.delete",
                &target.username,
                json!({}),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => db_error(error),
    }
}

/// Maps a database error onto an HTTP response.
fn db_error(error: DbError) -> Response {
    match error {
        DbError::NotFound(_) => not_found(),
        DbError::Conflict(message) => {
            (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response()
        }
        DbError::InvalidUsername(_) => bad_request("invalid username"),
        DbError::Sqlx(_) | DbError::Migrate(_) => internal_error(),
    }
}

fn cookie(
    name: &str,
    value: &str,
    max_age_secs: i64,
    http_only: bool,
    secure: bool,
) -> HeaderValue {
    let mut cookie = format!("{name}={value}; Path=/; Max-Age={max_age_secs}; SameSite=Strict");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).unwrap_or(HeaderValue::from_static(""))
}

pub(crate) fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": message }))).into_response()
}

pub(crate) fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

pub(crate) fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "internal server error" })),
    )
        .into_response()
}

pub(crate) fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
}

pub(crate) fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Json(json!({ "error": message }))).into_response()
}
