//! M6 integration tests: audit log hooks over HTTP and passkey-only mode.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::json;
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

fn basic(username: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{PASS}")))
}

async fn send(app: &Router, request: Request<Body>) -> StatusCode {
    app.clone().oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn hooks_record_auth_and_file_events() {
    let (_dir, state, app) = setup().await;

    // Failed login (bad password).
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": ALICE, "password": "wrong" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Successful login.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": ALICE, "password": PASS }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap().to_string())
        .collect();
    let cookie = cookies
        .iter()
        .find(|value| value.starts_with("kolimi_session="))
        .unwrap()
        .clone();
    let csrf = cookies
        .iter()
        .find(|value| value.starts_with("kolimi_csrf="))
        .unwrap()
        .strip_prefix("kolimi_csrf=")
        .unwrap()
        .to_string();

    // A file write over WebDAV lands in the change feed and the audit log.
    let status = send(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/dav/note.txt")
            .header(header::AUTHORIZATION, basic(ALICE))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("audited"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Logout.
    let status = send(
        &app,
        Request::builder()
            .method("DELETE")
            .uri("/api/session")
            .header(header::COOKIE, format!("{cookie}; kolimi_csrf={csrf}"))
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let entries = state.db.audit_list(100, None).await.unwrap();
    let actions: Vec<&str> = entries.iter().map(|e| e.action.as_str()).collect();
    for expected in [
        "auth.login_failed",
        "auth.login",
        "file.upsert",
        "auth.logout",
    ] {
        assert!(
            actions.contains(&expected),
            "missing {expected}: {actions:?}"
        );
    }
    let failed = entries
        .iter()
        .find(|e| e.action == "auth.login_failed")
        .unwrap();
    assert!(failed.details.contains("bad_password"));
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    let file = entries.iter().find(|e| e.action == "file.upsert").unwrap();
    assert_eq!(file.subject, "/note.txt");
    assert_eq!(file.actor_id, Some(alice.id));
    assert!(file.details.contains("content_id"));

    let verify = state.db.audit_verify().await.unwrap();
    assert_eq!(verify.first_bad, None);
}

#[tokio::test]
async fn passkey_only_mode() {
    let (dir, state, app) = setup().await;

    // Without a registered passkey the CLI refuses to clear the password.
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["user", "passkey-only", ALICE])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no passkeys"), "stderr: {stderr}");

    // Register a passkey row, then the CLI clears the password.
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    state
        .db
        .add_passkey(alice.id, "test key", "{}", kolimi_db::now_millis())
        .await
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["user", "passkey-only", ALICE])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Password login is now rejected and the reason is audited.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": ALICE, "password": PASS }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let entries = state.db.audit_list(50, None).await.unwrap();
    let rejected = entries
        .iter()
        .find(|e| e.action == "auth.login_failed" && e.details.contains("passkey_only"))
        .expect("passkey_only rejection audited");
    assert_eq!(rejected.subject, ALICE);

    // The CLI can verify the chain it appended to.
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "verify"])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("audit chain ok"));
}
