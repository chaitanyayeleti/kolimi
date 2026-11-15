use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use kolimi_auth::{CurrentUser, password, token};
use kolimi_db::{DbError, SortOrder, UserFilter, UserSort};
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
pub async fn login(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    let user_agent = user_agent(&headers);
    if req.username.is_empty() || req.password.is_empty() {
        return bad_request("username and password are required");
    }
    // Key the lockout on (account, source) so one client cannot lock an
    // account out for everyone. Lowercase the account: SQLite matches
    // usernames `COLLATE NOCASE`.
    let lockout_key = format!("login:{}:{ip}", req.username.to_lowercase());
    if state.lockout.check(&lockout_key).is_some() {
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
        state.lockout.record_failure(&lockout_key);
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
        state.lockout.record_failure(&lockout_key);
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
        state.lockout.record_failure(&lockout_key);
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
        state.lockout.record_failure(&lockout_key);
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
    // Second factor, when enrolled. A DB error here must not silently
    // downgrade the login to password-only.
    let totp = match state.db.totp_secret(user.id).await {
        Ok(totp) => totp,
        Err(_) => return internal_error(),
    };
    if let Some((secret_b32, last_step)) = totp {
        let Some(code) = req.code.as_deref() else {
            state.metrics.login("totp_required");
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
                state.lockout.record_failure(&lockout_key);
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
            state.lockout.record_failure(&lockout_key);
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
        state.lockout.record_success(&lockout_key);
        state.metrics.login(if method == "recovery_code" {
            "recovery"
        } else {
            "totp"
        });
        audit(
            &state,
            Some(user.id),
            Some(&user.username),
            "auth.login",
            &user.username,
            json!({ "method": method }),
        )
        .await;
        return start_session(&state, &user, &ip, user_agent.as_deref()).await;
    }

    state.lockout.record_success(&lockout_key);
    state.metrics.login("password");
    audit(
        &state,
        Some(user.id),
        Some(&user.username),
        "auth.login",
        &user.username,
        json!({ "method": "password" }),
    )
    .await;

    start_session(&state, &user, &ip, user_agent.as_deref()).await
}

/// Creates a session for `user` and returns the login response with cookies.
pub(crate) async fn start_session(
    state: &AppState,
    user: &kolimi_db::User,
    ip: &str,
    user_agent: Option<&str>,
) -> Response {
    let (Ok(session_token), Ok(csrf_token)) = (token::new_session_token(), token::new_csrf_token())
    else {
        return internal_error();
    };
    let expires_at = kolimi_db::now_millis() + SESSION_TTL_MILLIS;
    let token_hash = token::hash_token(&session_token);
    let csrf_hash = token::hash_token(&csrf_token);
    if state
        .db
        .create_session(
            user.id,
            &token_hash,
            &csrf_hash,
            expires_at,
            Some(ip),
            user_agent,
        )
        .await
        .is_err()
    {
        return internal_error();
    }
    let now = kolimi_db::now_millis();
    let _ = state.db.set_last_login(user.id, now).await;
    let _ = state.db.delete_expired_sessions(now).await;

    let mut response = no_store(
        Json(json!({
            "username": user.username,
            "is_admin": user.is_admin,
            "display_name": user.display_name,
            "email": user.email,
            "must_change_password": user.must_change_password,
            "must_setup_mfa": user.must_setup_mfa,
            "expires_at": expires_at,
        }))
        .into_response(),
    );
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
    if let Some(hash) = user.session_hash
        && let Err(error) = state.db.delete_session(&hash).await
    {
        // The session must not survive a "logout"; surface the failure.
        tracing::error!(%error, "failed to revoke session on logout");
        return internal_error();
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
    clear_session_cookies(&state)
}

/// Expires both session cookies, leaving a 204 response.
fn clear_session_cookies(state: &AppState) -> Response {
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

/// Returns the request's `User-Agent`, if it is valid UTF-8.
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// `GET|POST /logout` — end the session and navigate to the login page.
///
/// A real navigation, not a fetch: the server deletes the session row,
/// clears both cookies, and redirects. There is no client state left to get
/// out of sync, so a refresh can never resurrect the session.
pub async fn logout_navigate(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(raw) = crate::auth::cookie_value(&headers, SESSION_COOKIE) else {
        // No cookie at all: just go to the app, which shows the login form.
        tracing::info!("logout: no session cookie on the request");
        return redirect_to_app(&state);
    };
    let hash = token::hash_token(&raw);
    match state.db.find_session(&hash).await {
        Ok(Some(session)) => {
            if let Err(error) = state.db.delete_session(&hash).await {
                tracing::error!(%error, "logout: failed to delete session");
            } else {
                tracing::info!(user_id = session.user_id, "logout: session revoked");
                if let Ok(Some(user)) = state.db.get_user(session.user_id).await {
                    audit(
                        &state,
                        Some(user.id),
                        Some(&user.username),
                        "auth.logout",
                        &user.username,
                        json!({ "via": "logout" }),
                    )
                    .await;
                }
            }
        }
        Ok(None) => tracing::info!("logout: cookie did not match a live session"),
        Err(error) => tracing::error!(%error, "logout: session lookup failed"),
    }
    redirect_to_app(&state)
}

fn redirect_to_app(state: &AppState) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    if let Ok(location) = HeaderValue::from_str("/app/") {
        response.headers_mut().insert(header::LOCATION, location);
    }
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
pub async fn me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.get_user(user.user_id).await {
        Ok(Some(account)) => Json(json!({
            "username": account.username,
            "display_name": account.display_name,
            "email": account.email,
            "is_admin": account.is_admin,
            "created_at": account.created_at,
            "password_login": !account.password_hash.is_empty(),
            "must_change_password": account.must_change_password,
            "must_setup_mfa": account.must_setup_mfa,
        }))
        .into_response(),
        Ok(None) => unauthorized("invalid credentials"),
        Err(_) => internal_error(),
    }
}

/// Profile fields the caller may edit about themselves. An omitted field
/// keeps its current value; `null` or an empty string clears it.
#[derive(Deserialize, Default)]
pub struct UpdateMeRequest {
    #[serde(default)]
    display_name: Option<Option<String>>,
    #[serde(default)]
    email: Option<Option<String>>,
}

/// `PATCH /api/me` — update the caller's optional profile fields.
///
/// Email is informational only; Kolimi does not send mail.
pub async fn update_me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<UpdateMeRequest>,
) -> Response {
    let Some(account) = state.db.get_user(user.user_id).await.ok().flatten() else {
        return unauthorized("invalid credentials");
    };
    let display_name = match req.display_name {
        None => account.display_name,
        Some(value) => match crate::api_invites::clean_profile(value.as_deref(), None) {
            Ok((display_name, _)) => display_name,
            Err(message) => return bad_request(&message),
        },
    };
    let email = match req.email {
        None => account.email,
        Some(value) => match crate::api_invites::clean_profile(None, value.as_deref()) {
            Ok((_, email)) => email,
            Err(message) => return bad_request(&message),
        },
    };
    if state
        .db
        .set_profile(user.user_id, display_name.as_deref(), email.as_deref())
        .await
        .is_err()
    {
        return internal_error();
    }
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "user.profile_update",
        &user.username,
        json!({
            "display_name": display_name.is_some(),
            "email": email.is_some(),
        }),
    )
    .await;
    Json(json!({
        "display_name": display_name,
        "email": email,
    }))
    .into_response()
}

/// `GET /api/me/sessions` — the caller's live sessions.
pub async fn my_sessions(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    match state.db.list_user_sessions(user.user_id).await {
        Ok(sessions) => {
            let current = user.session_hash.as_ref();
            let sessions: Vec<Value> = sessions
                .iter()
                .map(|session| session_json(session, current))
                .collect();
            no_store(Json(json!({ "sessions": sessions })).into_response())
        }
        Err(_) => internal_error(),
    }
}

/// Body for [`set_my_session_label`].
#[derive(Deserialize, Default)]
pub struct SessionLabelRequest {
    /// New label; empty or omitted clears it.
    #[serde(default)]
    label: Option<String>,
}

/// `PATCH /api/me/sessions/{id}` — label one of the caller's sessions.
pub async fn set_my_session_label(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(session_id): Path<i64>,
    Json(req): Json<SessionLabelRequest>,
) -> Response {
    let label = req.label.map(|value| value.trim().to_string());
    if label
        .as_deref()
        .is_some_and(|value| value.chars().count() > 80 || value.chars().any(char::is_control))
    {
        return bad_request("session label must be at most 80 characters");
    }
    let label = label.filter(|value| !value.is_empty());
    match state
        .db
        .set_session_label(user.user_id, session_id, label.as_deref())
        .await
    {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "session.label",
                &user.username,
                json!({ "session_id": session_id, "labeled": label.is_some() }),
            )
            .await;
            no_store(Json(json!({ "label": label })).into_response())
        }
        Ok(false) => not_found(),
        Err(_) => internal_error(),
    }
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn session_json(session: &kolimi_db::Session, current: Option<&[u8; 32]>) -> Value {
    json!({
        "id": session.id,
        "current": current.is_some_and(|hash| session.token_hash.as_slice() == hash.as_slice()),
        "created_at": session.created_at,
        "last_seen_at": session.last_seen_at,
        "expires_at": session.expires_at,
        "ip": session.ip.clone(),
        "user_agent": session.user_agent.clone(),
        "label": session.label.clone(),
    })
}

/// Query for [`revoke_my_sessions`].
#[derive(Deserialize, Default)]
pub struct SessionRevokeQuery {
    /// Keep the session that issued this request.
    #[serde(default)]
    keep_current: bool,
}

/// `DELETE /api/me/sessions/{id}` — revoke one of the caller's sessions.
pub async fn revoke_my_session(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(session_id): Path<i64>,
) -> Response {
    let sessions = match state.db.list_user_sessions(user.user_id).await {
        Ok(sessions) => sessions,
        Err(_) => return internal_error(),
    };
    let Some(target) = sessions.iter().find(|session| session.id == session_id) else {
        return not_found();
    };
    let current = user
        .session_hash
        .as_ref()
        .is_some_and(|hash| target.token_hash.as_slice() == hash.as_slice());
    match state.db.delete_user_session(user.user_id, session_id).await {
        Ok(true) => {}
        Ok(false) => return not_found(),
        Err(_) => return internal_error(),
    }
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "session.revoke",
        &user.username,
        json!({ "session_id": session_id, "current": current }),
    )
    .await;
    if current {
        clear_session_cookies(&state)
    } else {
        StatusCode::NO_CONTENT.into_response()
    }
}

/// `DELETE /api/me/sessions` — revoke all sessions, optionally keeping the
/// current one.
pub async fn revoke_my_sessions(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<SessionRevokeQuery>,
) -> Response {
    let keep_current = query.keep_current && user.session_hash.is_some();
    let result = if keep_current {
        match user.session_hash.as_ref() {
            Some(hash) => {
                state
                    .db
                    .delete_user_sessions_except(user.user_id, hash)
                    .await
            }
            None => state.db.delete_user_sessions(user.user_id).await,
        }
    } else {
        state.db.delete_user_sessions(user.user_id).await
    };
    let revoked = match result {
        Ok(count) => count,
        Err(_) => return internal_error(),
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "session.revoke_all",
        &user.username,
        json!({ "revoked": revoked, "kept_current": keep_current }),
    )
    .await;
    if keep_current {
        StatusCode::NO_CONTENT.into_response()
    } else {
        clear_session_cookies(&state)
    }
}

/// Body for [`change_password`].
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    new_password: String,
}

/// `POST /api/me/password` — change the caller's login password.
///
/// Requires a fresh re-authentication token. Other sessions are revoked;
/// the session that made the change stays valid.
pub async fn change_password(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    let Some(account) = state.db.get_user(user.user_id).await.ok().flatten() else {
        return unauthorized("invalid credentials");
    };
    if account.password_hash.is_empty() {
        return bad_request("this account is passkey-only; manage passkeys instead");
    }
    // Cheap validation happens before the re-auth token is consumed. The
    // expensive Argon2 hash runs only after fresh proof of presence, so a
    // stolen session cannot burn CPU by posting new passwords.
    if req.new_password.chars().count() < password::MIN_PASSWORD_LEN {
        return bad_request(&format!(
            "password must be at least {} characters",
            password::MIN_PASSWORD_LEN
        ));
    }
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    let candidate = req.new_password;
    let hash = match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await
    {
        Ok(Ok(hash)) => hash,
        Ok(Err(error)) => return bad_request(&error.to_string()),
        Err(_) => return internal_error(),
    };
    if state
        .db
        .set_password(&account.username, &hash)
        .await
        .is_err()
    {
        return internal_error();
    }
    let revoked = match user.session_hash.as_ref() {
        Some(hash) => {
            state
                .db
                .delete_user_sessions_except(user.user_id, hash)
                .await
        }
        None => state.db.delete_user_sessions(user.user_id).await,
    };
    let revoked = match revoked {
        Ok(count) => count,
        Err(_) => return internal_error(),
    };
    state.cred_cache.clear();
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "user.password_change",
        &user.username,
        json!({ "sessions_revoked": revoked }),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /api/me/usage` — the caller's own storage usage (for the sidebar).
pub async fn self_usage(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let Some(account) = state.db.find_user(&user.username).await.ok().flatten() else {
        return not_found();
    };
    let used = match state.vfs.reconcile_usage(account.id).await {
        Ok(bytes) => bytes,
        Err(_) => account.used_bytes.max(0) as u64,
    };
    let quota = effective_quota(&state, account.quota_bytes);
    Json(json!({
        "used_bytes": used,
        "quota_bytes": account.quota_bytes,
        "effective_quota_bytes": quota,
        "used_percent": quota_percent(used, quota),
    }))
    .into_response()
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
    /// Grant administrator rights at creation time.
    #[serde(default)]
    admin: bool,
    /// Optional per-user quota in bytes (`0` = unlimited).
    #[serde(default)]
    quota_bytes: Option<i64>,
    /// Optional human-readable name.
    #[serde(default)]
    display_name: Option<String>,
    /// Optional contact address (informational).
    #[serde(default)]
    email: Option<String>,
    /// Require the user to replace the initial password at next sign-in.
    #[serde(default)]
    must_change_password: bool,
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
    if req.quota_bytes.is_some_and(|quota| quota < 0) {
        return bad_request("quota_bytes must be >= 0");
    }
    let (display_name, email) = match crate::api_invites::clean_profile(
        req.display_name.as_deref(),
        req.email.as_deref(),
    ) {
        Ok(profile) => profile,
        Err(message) => return bad_request(&message),
    };
    let candidate = req.password.clone();
    let hash = match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await
    {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => return bad_request(&e.to_string()),
        Err(_) => return internal_error(),
    };
    match state.db.create_user(&req.username, &hash).await {
        Ok(created) => {
            if req.admin
                && let Err(error) = state.db.set_admin(created.id, true).await
            {
                return db_error(error);
            }
            if let Some(quota) = req.quota_bytes
                && let Err(error) = state.db.set_quota_bytes(created.id, Some(quota)).await
            {
                return db_error(error);
            }
            if (display_name.is_some() || email.is_some())
                && let Err(error) = state
                    .db
                    .set_profile(created.id, display_name.as_deref(), email.as_deref())
                    .await
            {
                return db_error(error);
            }
            if req.must_change_password
                && let Err(error) = state.db.set_must_change_password(created.id, true).await
            {
                return db_error(error);
            }
            if let Err(error) = state.db.set_must_setup_mfa(created.id, true).await {
                return db_error(error);
            }
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "user.add",
                &created.username,
                json!({
                    "by": "api",
                    "admin": req.admin,
                    "quota_bytes": req.quota_bytes,
                    "must_change_password": req.must_change_password,
                    "must_setup_mfa": true,
                }),
            )
            .await;
            match state.db.get_user(created.id).await {
                Ok(Some(updated)) => (StatusCode::CREATED, Json(json!(updated))).into_response(),
                _ => internal_error(),
            }
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

/// Query for `GET /api/users`.
#[derive(Deserialize)]
pub struct UsersQuery {
    /// Keyset cursor: return users with a larger id (default order only).
    #[serde(default)]
    cursor: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
    /// Sort key: `id` (default), `username`, `used_bytes`, `quota_bytes`.
    #[serde(default)]
    sort: Option<String>,
    /// Sort direction: `asc` (default) or `desc`.
    #[serde(default)]
    order: Option<String>,
    /// Filter: `over_quota`, `disabled`, or `admin`.
    #[serde(default)]
    filter: Option<String>,
    /// Case-insensitive username substring search.
    #[serde(default)]
    q: Option<String>,
}

/// `GET /api/users?cursor=&limit=&sort=&order=&filter=` — admin-only list.
///
/// Reads the cached `quota_bytes`/`used_bytes` columns only, so listing
/// never walks the blob store (safe with thousands of users). Use
/// `GET /api/users/{username}/usage` for a freshly measured number.
/// Keyset pagination applies to the default `id` order; `sort=used_bytes&
/// order=desc` finds the heaviest users, `filter=over_quota` the ones at
/// or above their quota.
pub async fn list_users(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<UsersQuery>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let sort = match query.sort.as_deref() {
        None | Some("id") => UserSort::Id,
        Some("username") => UserSort::Username,
        Some("used_bytes" | "usage") => UserSort::UsedBytes,
        Some("quota_bytes" | "quota") => UserSort::QuotaBytes,
        Some(other) => return bad_request(&format!("unknown sort: {other}")),
    };
    // The keyset cursor only makes sense for the id order; reject it rather
    // than silently returning page 1 forever.
    if query.cursor.is_some() && sort != UserSort::Id {
        return bad_request("cursor pagination is only supported for sort=id");
    }
    let order = match query.order.as_deref() {
        None | Some("asc") => SortOrder::Asc,
        Some("desc") => SortOrder::Desc,
        Some(other) => return bad_request(&format!("unknown order: {other}")),
    };
    // Descending id pages use `id < cursor`; the first page therefore starts
    // at the top of the range, not at zero.
    let after = match query.cursor {
        Some(cursor) => cursor.max(0),
        None if order == SortOrder::Desc => i64::MAX,
        None => 0,
    };
    let filter = match query.filter.as_deref() {
        None => UserFilter::None,
        Some("over_quota") => UserFilter::OverQuota,
        Some("disabled") => UserFilter::Disabled,
        Some("admin") => UserFilter::Admin,
        Some(other) => return bad_request(&format!("unknown filter: {other}")),
    };
    let search = query.q.as_deref().map(str::trim).filter(|q| !q.is_empty());
    if search.is_some_and(|q| q.chars().count() > 64) {
        return bad_request("search query must be at most 64 characters");
    }
    let default_quota = state.vfs.store().default_quota();
    match state
        .db
        .users_page_sorted(kolimi_db::UserPageQuery {
            after_id: after,
            limit: limit + 1,
            sort,
            order,
            filter,
            default_quota,
            search,
        })
        .await
    {
        Ok(mut users) => {
            let has_more = users.len() as i64 > limit;
            if has_more {
                users.pop();
            }
            let next_cursor = if has_more && sort == UserSort::Id {
                users.last().map(|account| account.id)
            } else {
                None
            };
            Json(json!({ "users": users, "next_cursor": next_cursor, "has_more": has_more }))
                .into_response()
        }
        Err(_) => internal_error(),
    }
}

/// `GET /api/users/{username}` — admin-only account detail.
pub async fn user_detail(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(username): Path<String>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(account) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    let passkeys = match state.db.count_passkeys(account.id).await {
        Ok(count) => count,
        Err(_) => return internal_error(),
    };
    let totp = match state.db.totp_secret(account.id).await {
        Ok(secret) => secret.is_some(),
        Err(_) => return internal_error(),
    };
    let sessions = match state.db.list_user_sessions(account.id).await {
        Ok(sessions) => sessions.len(),
        Err(_) => return internal_error(),
    };
    let groups = match state.db.user_groups(account.id).await {
        Ok(groups) => groups
            .into_iter()
            .map(|group| group.name)
            .collect::<Vec<_>>(),
        Err(_) => return internal_error(),
    };
    let owned_shares = match state.db.shares_owned(account.id).await {
        Ok(shares) => shares.len(),
        Err(_) => return internal_error(),
    };
    let received_shares = match state.db.received_shares(account.id).await {
        Ok(shares) => shares.len(),
        Err(_) => return internal_error(),
    };
    let e2ee_keyring = match state.db.keyring(account.id).await {
        Ok(keyring) => keyring.is_some(),
        Err(_) => return internal_error(),
    };
    Json(json!({
        "id": account.id,
        "username": account.username,
        "display_name": account.display_name,
        "email": account.email,
        "is_admin": account.is_admin,
        "disabled": account.disabled,
        "must_change_password": account.must_change_password,
        "created_at": account.created_at,
        "last_login_at": account.last_login_at,
        "quota_bytes": account.quota_bytes,
        "used_bytes": account.used_bytes,
        "usage_updated_at": account.usage_updated_at,
        "password_login": !account.password_hash.is_empty(),
        "passkey_count": passkeys,
        "totp_enabled": totp,
        "session_count": sessions,
        "groups": groups,
        "owned_shares": owned_shares,
        "received_shares": received_shares,
        "e2ee_keyring": e2ee_keyring,
    }))
    .into_response()
}

/// Payload for admin account recovery.
#[derive(Deserialize, Default)]
pub struct RecoverUserRequest {
    /// Optional new password. When omitted, a generated password is returned
    /// once in the response.
    #[serde(default)]
    password: Option<String>,
    /// Keep the current TOTP secret.
    #[serde(default)]
    keep_totp: bool,
    /// Keep registered passkeys.
    #[serde(default)]
    keep_passkeys: bool,
}

/// `POST /api/users/{username}/recover` — admin account recovery.
///
/// Requires a fresh re-authentication token. By default this drops every
/// session, clears TOTP, and removes every passkey.
pub async fn recover_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<RecoverUserRequest>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    if req
        .password
        .as_deref()
        .filter(|password| !password.is_empty())
        .is_some_and(|password| password.chars().count() < password::MIN_PASSWORD_LEN)
    {
        return bad_request(&format!(
            "password must be at least {} characters",
            password::MIN_PASSWORD_LEN
        ));
    }
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    let generated = req
        .password
        .as_deref()
        .filter(|value| !value.is_empty())
        .is_none();
    let password = match req.password.filter(|value| !value.is_empty()) {
        Some(password) => password,
        None => match token::new_session_token() {
            Ok(password) => password,
            Err(_) => return internal_error(),
        },
    };
    let candidate = password.clone();
    let hash = match tokio::task::spawn_blocking(move || password::hash_password(&candidate)).await
    {
        Ok(Ok(hash)) => hash,
        Ok(Err(error)) => return bad_request(&error.to_string()),
        Err(_) => return internal_error(),
    };
    let report = match crate::admin::recover_user_by(
        &state.db,
        &target.username,
        &hash,
        req.keep_totp,
        !req.keep_passkeys,
        Some(user.user_id),
        Some(&user.username),
    )
    .await
    {
        Ok(report) => report,
        Err(DbError::NotFound(_)) => return not_found(),
        Err(_) => return internal_error(),
    };
    let mut response = Json(json!({
        "username": target.username,
        "password": generated.then_some(password),
        "sessions_dropped": report.sessions_dropped,
        "passkeys_removed": report.passkeys_removed,
        "app_passwords_revoked": report.app_passwords_revoked,
        "totp_disabled": report.totp_disabled,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `POST /api/users/{username}/logout` — revoke every session of a user.
pub async fn admin_logout_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    let revoked = match state.db.delete_user_sessions(target.id).await {
        Ok(count) => count,
        Err(_) => return internal_error(),
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "session.revoke_all",
        &target.username,
        json!({ "revoked": revoked, "by": "admin" }),
    )
    .await;
    Json(json!({ "sessions_revoked": revoked })).into_response()
}

/// `GET /api/users/{username}/sessions` — admin-only session metadata.
pub async fn admin_user_sessions(
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
    match state.db.list_user_sessions(target.id).await {
        Ok(sessions) => {
            let current = (target.id == user.user_id)
                .then_some(user.session_hash.as_ref())
                .flatten();
            let sessions: Vec<Value> = sessions
                .iter()
                .map(|session| session_json(session, current))
                .collect();
            no_store(Json(json!({ "sessions": sessions })).into_response())
        }
        Err(_) => internal_error(),
    }
}

/// Returns the effective quota in bytes (`0` = unlimited).
fn effective_quota(state: &AppState, override_bytes: Option<i64>) -> u64 {
    match override_bytes {
        Some(quota) if quota > 0 => quota as u64,
        Some(_) => 0,
        None => state.vfs.store().default_quota(),
    }
}

/// Usage as a whole percentage of the effective quota (`0` when unlimited).
pub(crate) fn quota_percent(used: u64, quota: u64) -> u64 {
    used.saturating_mul(100).checked_div(quota).unwrap_or(0)
}

/// The warning percentage (at or above 90% of quota) when a user is close
/// to or over their quota; `None` when unlimited or comfortably under.
pub(crate) fn quota_warning_percent(used: u64, quota: u64) -> Option<u8> {
    if quota == 0 || used.saturating_mul(10) < quota.saturating_mul(9) {
        return None;
    }
    Some(quota_percent(used, quota).min(u64::from(u8::MAX)) as u8)
}

/// `GET /api/users/{username}/usage` — admin-only, freshly measured usage.
///
/// Walks the user's blob tree, refreshes the cached counter, and returns
/// the quota. Intended for a single user, never for bulk listing.
pub async fn user_usage(
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
    let used = match state.vfs.reconcile_usage(target.id).await {
        Ok(bytes) => bytes,
        Err(_) => target.used_bytes.max(0) as u64,
    };
    let quota = effective_quota(&state, target.quota_bytes);
    let warning = quota_warning_percent(used, quota);
    Json(json!({
        "username": target.username,
        "used_bytes": used,
        "quota_bytes": target.quota_bytes,
        "effective_quota_bytes": quota,
        "used_percent": quota_percent(used, quota),
        "over_quota": quota > 0 && used >= quota,
        "warning": warning.is_some(),
        "warning_percent": warning,
    }))
    .into_response()
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
    /// Per-user storage quota in bytes (`0` = unlimited, `null` = the
    /// server default). Absent leaves it unchanged.
    #[serde(default, deserialize_with = "double_option::deserialize")]
    quota_bytes: Option<Option<i64>>,
}

mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Ok(Some(Option::<T>::deserialize(deserializer)?))
    }
}

/// `PATCH /api/users/{username}` — admin-only account changes.
pub async fn update_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    if req.disabled.is_none() && req.admin.is_none() && req.quota_bytes.is_none() {
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
    if let Some(quota) = req.quota_bytes {
        if let Some(bytes) = quota
            && bytes < 0
        {
            return bad_request("quota_bytes must be >= 0");
        }
        if let Err(error) = state.db.set_quota_bytes(target.id, quota).await {
            return db_error(error);
        }
        audit(
            &state,
            Some(user.user_id),
            Some(&user.username),
            "user.quota",
            &target.username,
            json!({ "quota_bytes": quota }),
        )
        .await;
    }
    // A change to an account (disabled/admin/quota) must invalidate any
    // cached Basic-auth credential for it, so it takes effect immediately.
    state.cred_cache.clear();
    match state.db.find_user(&username).await {
        Ok(Some(updated)) => Json(json!(updated)).into_response(),
        _ => internal_error(),
    }
}

/// `DELETE /api/users/{username}` — admin-only account deletion.
pub async fn delete_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    if !user.is_admin {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(response) = crate::reauth::require(&state, user.user_id, &headers) {
        return response;
    }
    let Some(target) = state.db.find_user(&username).await.ok().flatten() else {
        return not_found();
    };
    if target.id == user.user_id {
        return bad_request("cannot delete your own account");
    }
    match state.db.delete_user(&username).await {
        Ok(()) => {
            // Drop any cached Basic-auth credential for the deleted account.
            state.cred_cache.clear();
            // The DB cascades don't reach the search index: drop the
            // user's documents too, or their filenames stay searchable.
            if let Err(error) = state
                .search
                .delete_user(target.id)
                .and_then(|()| state.search.commit())
            {
                tracing::error!(%error, user_id = target.id, "could not remove deleted user's search data");
            }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{quota_percent, quota_warning_percent};

    #[test]
    fn quota_warning_threshold_is_ninety_percent() {
        assert_eq!(quota_warning_percent(0, 0), None, "unlimited never warns");
        assert_eq!(quota_warning_percent(89, 100), None);
        assert_eq!(quota_warning_percent(90, 100), Some(90));
        assert_eq!(quota_warning_percent(120, 100), Some(120));
        assert_eq!(quota_percent(50, 100), 50);
        assert_eq!(quota_percent(1, 0), 0);
    }
}
