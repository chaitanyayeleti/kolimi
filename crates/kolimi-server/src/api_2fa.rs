//! TOTP two-factor endpoints (enroll, verify at login, disable).

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kolimi_auth::{CurrentUser, password, totp};
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, api, audit};

/// Body for a re-authentication request.
#[derive(Deserialize, Default)]
pub struct ReauthRequest {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

/// `POST /api/reauth` — prove presence for a sensitive account change.
///
/// Accepts the account password or, when TOTP is enrolled, a current code
/// (or a recovery code). Returns a single-use token valid for five minutes.
pub async fn reauth(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<ReauthRequest>,
) -> Response {
    let lockout_key = format!("reauth:{}:{ip}", user.user_id);
    if state.lockout.check(&lockout_key).is_some() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many failed attempts, try again later" })),
        )
            .into_response();
    }
    let Some(account) = state.db.get_user(user.user_id).await.ok().flatten() else {
        return api::unauthorized("invalid credentials");
    };
    let password_ok = req
        .password
        .as_deref()
        .filter(|value| !value.is_empty())
        .is_some_and(|candidate| {
            password::verify_password(&account.password_hash, candidate).unwrap_or(false)
        });
    let mut verified = password_ok;
    if !verified && let Some(code) = req.code.as_deref().filter(|value| !value.is_empty()) {
        let totp = state.db.totp_secret(user.user_id).await.ok().flatten();
        if let Some((secret_b32, last_step)) = totp
            && let Ok(secret) = totp::TotpSecret::from_base32(&secret_b32)
        {
            let now = (kolimi_db::now_millis() / 1000) as u64;
            if let Some(step) = totp::verify(&secret, code, now, last_step.map(|step| step as u64))
            {
                verified = state
                    .db
                    .consume_totp_step(user.user_id, step)
                    .await
                    .unwrap_or(false);
            }
        }
        if !verified {
            verified = state
                .db
                .consume_recovery_code(user.user_id, &totp::hash_recovery_code(code))
                .await
                .unwrap_or(false);
        }
    }
    if !verified {
        state.lockout.record_failure(&lockout_key);
        audit(
            &state,
            Some(user.user_id),
            Some(&user.username),
            "auth.reauth_failed",
            &user.username,
            json!({}),
        )
        .await;
        return api::unauthorized("invalid credentials");
    }
    state.lockout.record_success(&lockout_key);
    let Some(token) = state.reauth.issue(user.user_id) else {
        return api::internal_error();
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "auth.reauth",
        &user.username,
        json!({}),
    )
    .await;
    Json(json!({
        "token": token,
        "expires_in_secs": crate::reauth::REAUTH_TTL.as_secs(),
    }))
    .into_response()
}

/// `GET /api/totp` — enrollment status.
pub async fn status(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let enabled = state
        .db
        .totp_secret(user.user_id)
        .await
        .ok()
        .flatten()
        .is_some();
    let remaining = if enabled {
        state
            .db
            .count_recovery_codes(user.user_id)
            .await
            .unwrap_or(0)
    } else {
        0
    };
    Json(json!({ "enabled": enabled, "recovery_codes_remaining": remaining })).into_response()
}

/// `POST /api/totp/begin` — generate a secret and provisioning URI.
///
/// Nothing is stored until [`enable`] verifies a code, so an abandoned
/// enrollment cannot lock anyone out.
pub async fn begin(
    State(_state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    let secret = match totp::TotpSecret::generate() {
        Ok(secret) => secret,
        Err(_) => return api::internal_error(),
    };
    let url = secret.otpauth_url("Kolimi", &user.username);
    let svg = qrcode::QrCode::new(url.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(220, 220)
                .build()
        })
        .unwrap_or_default();
    Json(json!({
        "secret": secret.to_base32(),
        "otpauth_url": url,
        "qr_svg": svg,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct EnableRequest {
    secret: String,
    code: String,
}

/// `POST /api/totp/enable` — verify a code and activate TOTP.
///
/// Returns the one-time recovery codes; they are shown exactly once.
pub async fn enable(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<EnableRequest>,
) -> Response {
    // A session alone must not replace an existing second factor: that
    // would let a stolen cookie permanently lock the real user out. The
    // account must disable TOTP first, which requires a current code or a
    // recovery code.
    match state.db.totp_secret(user.user_id).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "TOTP is already enabled; disable it first" })),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(_) => return api::internal_error(),
    }
    let Ok(secret) = totp::TotpSecret::from_base32(&req.secret) else {
        return api::bad_request("invalid secret");
    };
    let now = (kolimi_db::now_millis() / 1000) as u64;
    if totp::verify(&secret, &req.code, now, None).is_none() {
        return api::bad_request("code does not match; check your authenticator clock");
    }
    if state
        .db
        .set_totp_secret(user.user_id, &secret.to_base32())
        .await
        .is_err()
    {
        return api::internal_error();
    }
    let Ok(codes) = totp::generate_recovery_codes() else {
        return api::internal_error();
    };
    let hashes: Vec<Vec<u8>> = codes
        .iter()
        .map(|code| totp::hash_recovery_code(code))
        .collect();
    if state
        .db
        .replace_recovery_codes(user.user_id, &hashes)
        .await
        .is_err()
    {
        return api::internal_error();
    }
    let _ = state.db.set_must_setup_mfa(user.user_id, false).await;
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "totp.enable",
        &user.username,
        json!({}),
    )
    .await;
    Json(json!({ "recovery_codes": codes })).into_response()
}

#[derive(Deserialize)]
pub struct DisableRequest {
    code: String,
}

/// `POST /api/totp/disable` — turn TOTP off (requires a live code or a
/// recovery code).
pub async fn disable(
    State(state): State<AppState>,
    crate::hardening::ClientIp(ip): crate::hardening::ClientIp,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<DisableRequest>,
) -> Response {
    // Per-account lockout on top of the global rate limiter, so a stolen
    // session cannot brute-force the 6-digit code unbounded.
    let lockout_key = format!("totp-disable:{}:{ip}", user.user_id);
    if state.lockout.check(&lockout_key).is_some() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many failed attempts, try again later" })),
        )
            .into_response();
    }
    let Some((secret_b32, last_step)) = state.db.totp_secret(user.user_id).await.ok().flatten()
    else {
        return api::bad_request("two-factor is not enabled");
    };
    let Ok(secret) = totp::TotpSecret::from_base32(&secret_b32) else {
        return api::internal_error();
    };
    let now = (kolimi_db::now_millis() / 1000) as u64;
    let matched_step = totp::verify(&secret, &req.code, now, last_step.map(|s| s as u64));
    let mut verified = matched_step.is_some();
    // Consume the step so the same code cannot be replayed.
    if let Some(step) = matched_step
        && !state
            .db
            .consume_totp_step(user.user_id, step)
            .await
            .unwrap_or(false)
    {
        verified = false;
    }
    if !verified {
        verified = state
            .db
            .consume_recovery_code(user.user_id, &totp::hash_recovery_code(&req.code))
            .await
            .unwrap_or(false);
    }
    if !verified {
        state.lockout.record_failure(&lockout_key);
        return api::unauthorized("invalid code");
    }
    state.lockout.record_success(&lockout_key);
    if state.db.clear_totp(user.user_id).await.is_err() {
        return api::internal_error();
    }
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "totp.disable",
        &user.username,
        json!({}),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}
