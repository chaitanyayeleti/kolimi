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
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/totp")
                .header(header::AUTHORIZATION, basic())
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

    // Disable with a code from the next step (the current one was
    // consumed by the login above); login goes back to password-only.
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64 + 30);
    let (status, _) = post(&app, "/api/totp/disable", &json!({ "code": code })).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
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
