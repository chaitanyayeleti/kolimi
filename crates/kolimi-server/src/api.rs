use axum::{
    Extension, Json,
    extract::{Query, State},
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
        state.lockout.record_failure(&req.username);
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
        state.lockout.record_failure(&req.username);
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
        state.lockout.record_failure(&req.username);
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
