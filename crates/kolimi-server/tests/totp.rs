//! M6 integration tests: TOTP enrollment, two-step login, replay guard,
//! recovery codes, and the CLI escape hatch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use kolimi_auth::{password::hash_password, totp::TotpSecret};
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "alice";
const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user(ALICE, &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

fn basic() -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    format!("Basic {}", STANDARD.encode(format!("{ALICE}:{PASS}")))
}

async fn post(app: &Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, basic())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn login_body(code: Option<&str>) -> Value {
    match code {
        Some(code) => json!({ "username": ALICE, "password": PASS, "code": code }),
        None => json!({ "username": ALICE, "password": PASS }),
    }
}

/// Logs in via `/api/session` and returns `(session_cookie, csrf_cookie)`.
async fn login_session(app: &Router, code: Option<&str>) -> (StatusCode, Vec<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(login_body(code).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| {
            v.to_str()
                .ok()
                .map(|s| s.split(';').next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();
    (status, cookies)
}

fn csrf_token_from(cookies: &[String]) -> String {
    cookies
        .iter()
        .find_map(|c| c.strip_prefix("kolimi_csrf="))
        .unwrap_or("")
        .to_string()
}

async fn send_cookie(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: &str,
    csrf: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie);
    if matches!(method, "POST" | "PATCH" | "PUT" | "DELETE") {
        builder = builder.header("x-csrf-token", csrf);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn current_code(secret: &TotpSecret) -> String {
    secret.code_at((kolimi_db::now_millis() / 1000) as u64)
}

#[tokio::test]
async fn totp_enrollment_login_replay_and_recovery() {
    let (_dir, state, app) = setup().await;

    // Plain login works before enrollment.
    let (status, _) = post(&app, "/api/session", &login_body(None)).await;
    assert_eq!(status, StatusCode::OK);

    // Enroll: begin returns a QR SVG + secret; enable verifies a code.
    let (status, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(begin["qr_svg"].as_str().unwrap().contains("<svg"));
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();

    let code = current_code(&secret);
    let (status, enable) = post(
        &app,
        "/api/totp/enable",
        &json!({ "secret": begin["secret"], "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enable}");
    let recovery_codes: Vec<String> = enable["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery_codes.len(), 10);

    // Login now requires the second factor.
    let (status, body) = post(&app, "/api/session", &login_body(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["totp_required"], true);

    let (status, _) = post(&app, "/api/session", &login_body(Some("000000"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let code = current_code(&secret);
    let (status, _) = post(&app, "/api/session", &login_body(Some(&code))).await;
    assert_eq!(status, StatusCode::OK);

    // Replay of the same code is refused.
    let (status, _) = post(&app, "/api/session", &login_body(Some(&code))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A recovery code works exactly once.
    let recovery = recovery_codes[0].clone();
    let (status, _) = post(&app, "/api/session", &login_body(Some(&recovery))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(&app, "/api/session", &login_body(Some(&recovery))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Status reflects enrollment and remaining codes.
    // Basic auth is rejected once TOTP is enrolled, so use the session.
    // Use the next time step: the current one was consumed by logins above.
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64 + 30);
    let (status, cookies) = login_session(&app, Some(&code)).await;
    assert_eq!(status, StatusCode::OK);
    let cookie_header = cookies.join("; ");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/totp")
                .header(header::COOKIE, &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let status_body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(status_body["enabled"], true);
    assert_eq!(status_body["recovery_codes_remaining"], 9);

    // Disable with an unused recovery code (the TOTP steps were consumed
    // by the logins above); login goes back to password-only.
    // Session POSTs need the double-submit CSRF token.
    let csrf = csrf_token_from(&cookies);
    let code = recovery_codes[1].clone();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/totp/disable")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie_header)
                .header("x-csrf-token", &csrf)
                .body(Body::from(json!({ "code": code }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let (status, _) = post(&app, "/api/session", &login_body(None)).await;
    assert_eq!(status, StatusCode::OK);

    // Audit trail.
    let entries = state.db.audit_list(100, None).await.unwrap();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    for expected in ["totp.enable", "totp.disable", "auth.totp_required"] {
        assert!(
            actions.contains(&expected),
            "missing {expected}: {actions:?}"
        );
    }
}

#[tokio::test]
async fn cli_escape_hatch_disables_totp() {
    let (dir, state, app) = setup().await;

    let (_, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = current_code(&secret);
    let (status, _) = post(
        &app,
        "/api/totp/enable",
        &json!({ "secret": begin["secret"], "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["user", "totp-disable", ALICE])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let (status, _) = post(&app, "/api/session", &login_body(None)).await;
    assert_eq!(status, StatusCode::OK);

    let entries = state.db.audit_list(50, None).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "totp.admin_disable")
    );
}

#[tokio::test]
async fn recovery_code_is_consumed_once_under_concurrency() {
    let (_dir, state, app) = setup().await;
    let (_, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = current_code(&secret);
    let (status, enable) = post(
        &app,
        "/api/totp/enable",
        &json!({ "secret": begin["secret"], "code": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enable}");
    let recovery = enable["recovery_codes"]
        .as_array()
        .unwrap()
        .first()
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // Two logins use the same recovery code at the same time. The DELETE
    // that consumes it is atomic, so exactly one may succeed.
    let login = login_body(Some(&recovery));
    let (first, second) = tokio::join!(
        post(&app, "/api/session", &login),
        post(&app, "/api/session", &login),
    );
    let statuses = [first.0, second.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count(),
        1,
        "{statuses:?}"
    );

    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    assert_eq!(state.db.count_recovery_codes(alice.id).await.unwrap(), 9);
}

#[tokio::test]
async fn totp_cannot_be_re_enrolled_from_a_session() {
    let (_dir, state, app) = setup().await;
    // Create a session while login is still password-only; Basic auth is
    // refused once TOTP is enrolled, so the re-enrollment attempt must use
    // a cookie like a real browser session.
    let (status, cookies) = login_session(&app, None).await;
    assert_eq!(status, StatusCode::OK);
    let cookie_header = cookies.join("; ");
    let csrf = csrf_token_from(&cookies);

    let (_, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let first_secret = begin["secret"].as_str().unwrap().to_string();
    let code = current_code(&secret);
    // Enable through the cookie session so that it is the session kept by
    // the enrollment session-revocation rule.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/totp/enable")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie_header)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    json!({ "secret": begin["secret"], "code": code }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A session without a current factor must not replace the secret (and
    // thereby lock the real user out of their own second factor).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/totp/begin")
                .header(header::COOKIE, &cookie_header)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let begin: Value = serde_json::from_slice(&bytes).unwrap();
    let replacement = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = current_code(&replacement);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/totp/enable")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie_header)
                .header("x-csrf-token", &csrf)
                .body(Body::from(
                    json!({ "secret": begin["secret"], "code": code }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|e| e.contains("already enabled"))
    );

    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    let (stored, _) = state.db.totp_secret(alice.id).await.unwrap().unwrap();
    assert_eq!(stored, first_secret);
}

#[tokio::test]
async fn totp_session_token_authenticates_bearer_requests() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    let secret = TotpSecret::generate().unwrap();
    state
        .db
        .set_totp_secret(alice.id, &secret.to_base32())
        .await
        .unwrap();

    // A desktop client without a code learns that a second factor is needed.
    let (status, body) = post(&app, "/api/session", &login_body(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["totp_required"], true);

    // A code produces a session cookie; the desktop client uses its raw
    // value as a bearer token for background sync.
    let code = current_code(&secret);
    let (status, cookies) = login_session(&app, Some(&code)).await;
    assert_eq!(status, StatusCode::OK);
    let token = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("kolimi_session="))
        .expect("login must set a session cookie");
    assert_eq!(token.len(), 64);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/me/usage")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The account password alone still cannot satisfy Basic when TOTP is on.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/me/usage")
                .header(header::AUTHORIZATION, basic())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reauth_requires_both_factors_when_totp_is_enabled() {
    let (_dir, _state, app) = setup().await;

    // Create the session before enrollment so it survives enable and can be
    // used for the re-auth attempts.
    let (status, cookies) = login_session(&app, None).await;
    assert_eq!(status, StatusCode::OK);
    let cookie = cookies.join("; ");
    let csrf = csrf_token_from(&cookies);

    let (_, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let enable_code = current_code(&secret);
    let (status, enabled) = send_cookie(
        &app,
        "POST",
        "/api/totp/enable",
        &cookie,
        &csrf,
        Some(json!({ "secret": begin["secret"], "code": enable_code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    let recovery = enabled["recovery_codes"].as_array().unwrap()[0]
        .as_str()
        .unwrap()
        .to_string();

    // Password alone is not enough.
    let (status, body) = send_cookie(
        &app,
        "POST",
        "/api/reauth",
        &cookie,
        &csrf,
        Some(json!({ "password": PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // A code alone is not enough either. Next step is inside the accepted
    // clock-skew window and was not consumed by enable.
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64 + 30);
    let (status, body) = send_cookie(
        &app,
        "POST",
        "/api/reauth",
        &cookie,
        &csrf,
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Password plus that fresh TOTP code succeeds.
    let (status, body) = send_cookie(
        &app,
        "POST",
        "/api/reauth",
        &cookie,
        &csrf,
        Some(json!({ "password": PASS, "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].as_str().is_some(), "{body}");

    // Password plus a recovery code succeeds and consumes the code.
    let (status, body) = send_cookie(
        &app,
        "POST",
        "/api/reauth",
        &cookie,
        &csrf,
        Some(json!({ "password": PASS, "code": recovery })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn totp_enrollment_revokes_other_sessions() {
    let (_dir, _state, app) = setup().await;

    let (status, first) = login_session(&app, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, second) = login_session(&app, None).await;
    assert_eq!(status, StatusCode::OK);

    let first_cookie = first.join("; ");
    let first_csrf = csrf_token_from(&first);
    let second_cookie = second.join("; ");
    let second_csrf = csrf_token_from(&second);

    let (_, begin) = post(&app, "/api/totp/begin", &json!({})).await;
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = current_code(&secret);
    let (status, body) = send_cookie(
        &app,
        "POST",
        "/api/totp/enable",
        &first_cookie,
        &first_csrf,
        Some(json!({ "secret": begin["secret"], "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The session that enabled TOTP survives; every other session is gone.
    let (status, _) = send_cookie(&app, "GET", "/api/me", &first_cookie, &first_csrf, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_cookie(&app, "GET", "/api/me", &second_cookie, &second_csrf, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
