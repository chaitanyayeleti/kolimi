//! Account recovery (`user recover`): the privileged path for a user who
//! lost every credential.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::Value;
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password("old-pass-123").unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

async fn login(app: &Router, username: &str, password: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "username": username, "password": password }).to_string(),
                ))
                .unwrap(),
        )
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

#[tokio::test]
async fn recover_restores_password_login_and_clears_totp() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user("alice").await.unwrap().unwrap();
    state
        .db
        .set_totp_secret(alice.id, "JBSWY3DPEHPK3PXP")
        .await
        .unwrap();
    state
        .db
        .create_session(
            alice.id,
            b"session-hash",
            b"csrf-hash",
            kolimi_db::now_millis() + 3_600_000,
        )
        .await
        .unwrap();

    // Before recovery the password alone is not enough: TOTP is required.
    let (status, body) = login(&app, "alice", "old-pass-123").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["totp_required"].as_bool(), Some(true));

    let hash = hash_password("recovered-pass-456").unwrap();
    let report = kolimi_server::admin::recover_user(&state.db, "alice", &hash, false, true)
        .await
        .unwrap();
    assert!(report.totp_disabled);
    assert!(
        report.sessions_dropped >= 1,
        "live sessions must be dropped"
    );
    assert_eq!(report.passkeys_removed, 0);

    // The new password logs in with no second factor.
    let (status, body) = login(&app, "alice", "recovered-pass-456").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["totp_required"].as_bool(), Some(true));

    // The old password no longer works.
    let (status, _) = login(&app, "alice", "old-pass-123").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
