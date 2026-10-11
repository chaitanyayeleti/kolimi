//! TOTP two-factor endpoints (enroll, verify at login, disable).

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kolimi_auth::{CurrentUser, totp};
use serde::Deserialize;
use serde_json::json;

use crate::{AppState, api, audit};

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
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<DisableRequest>,
) -> Response {
    let Some((secret_b32, last_step)) = state.db.totp_secret(user.user_id).await.ok().flatten()
    else {
        return api::bad_request("two-factor is not enabled");
    };
    let Ok(secret) = totp::TotpSecret::from_base32(&secret_b32) else {
        return api::internal_error();
    };
    let now = (kolimi_db::now_millis() / 1000) as u64;
    let verified = totp::verify(&secret, &req.code, now, last_step.map(|s| s as u64)).is_some()
        || state
            .db
            .consume_recovery_code(user.user_id, &totp::hash_recovery_code(&req.code))
            .await
            .unwrap_or(false);
    if !verified {
        return api::unauthorized("invalid code");
    }
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
