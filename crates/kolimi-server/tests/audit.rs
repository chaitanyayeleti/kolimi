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

#[tokio::test]
async fn cli_audit_prune_exports_and_verifies_from_the_anchor() {
    let (dir, state, _app) = setup().await;
    for name in ["a", "b", "c", "d"] {
        state
            .db
            .audit_append(None, Some("cli"), "user.add", name, &json!({}))
            .await
            .unwrap();
    }
    // Seal the four entries, then append a tail that must survive the prune.
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "seal"])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    state
        .db
        .audit_append(None, Some("cli"), "user.add", "tail", &json!({}))
        .await
        .unwrap();

    let export = dir.path().join("audit.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "prune", "--before", "4", "--to"])
        .arg(&export)
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exported 4 audit entries through 4"),
        "{stdout}"
    );
    let lines = std::fs::read_to_string(&export).unwrap();
    assert_eq!(lines.lines().count(), 5, "header plus four entries");

    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "verify"])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("audit chain ok (1 entries, 1 checkpoints, 1 pruned)"),
        "{stdout}"
    );
    assert!(stdout.contains("anchor: entries through 4"), "{stdout}");

    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "verify-export", "--file"])
        .arg(&export)
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("export ok"));
}

#[tokio::test]
async fn cli_audit_signs_checkpoints_and_anchors_them() {
    let (dir, state, _app) = setup().await;
    for name in ["a", "b", "c"] {
        state
            .db
            .audit_append(None, Some("cli"), "user.add", name, &json!({}))
            .await
            .unwrap();
    }
    let key = dir.path().join("audit-signing.key");
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "keygen", "--out"])
        .arg(&key)
        .args(["--label", "test"])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signer = kolimi_db::AuditSigner::load(&key).unwrap();

    let journal = dir.path().join("audit-anchors.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "seal", "--key"])
        .arg(&key)
        .env("KOLIMI_DATA", dir.path())
        .env("KOLIMI_AUDIT_ANCHOR_LOG", &journal)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("signed"), "{stdout}");
    assert!(stdout.contains("anchors: 1 journaled"), "{stdout}");
    let anchors = std::fs::read_to_string(&journal).unwrap();
    assert_eq!(anchors.lines().count(), 1);
    assert!(anchors.contains("kolimi-audit-anchor-v1"));
    assert!(anchors.contains(signer.key_id()));

    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "verify", "--trusted-key"])
        .arg(signer.public_key_hex())
        .arg("--anchor-log")
        .arg(&journal)
        .arg("--require-signatures")
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("signatures: 1 signed, 1 verified, 0 unsigned"),
        "{stdout}"
    );
    assert!(stdout.contains("anchors: 1 checked"), "{stdout}");

    state
        .db
        .audit_append(None, Some("cli"), "user.add", "tail", &json!({}))
        .await
        .unwrap();
    let export = dir.path().join("signed-bundle.jsonl");
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "prune", "--checkpoint", "1", "--to"])
        .arg(&export)
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "verify-export", "--file"])
        .arg(&export)
        .args(["--trusted-key", &signer.public_key_hex()])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("1 signatures (1 trusted)"), "{stdout}");

    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["audit", "head"])
        .env("KOLIMI_DATA", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let head: serde_json::Value = serde_json::from_slice(&output.stdout).expect("head is JSON");
    assert_eq!(head["kind"], "kolimi-audit-anchor-v1");
    assert_eq!(head["checkpoint_id"], 1);
}

#[tokio::test]
async fn janitor_refuses_to_seal_when_the_configured_key_is_unavailable() {
    let (dir, state, _app) = setup().await;
    let state = state.with_audit_signing(Some(dir.path().join("missing.key")), None);
    for index in 0..1024 {
        state
            .db
            .audit_append(
                None,
                Some("cli"),
                "user.add",
                &format!("u{index}"),
                &json!({}),
            )
            .await
            .unwrap();
    }
    let report = kolimi_server::janitor::run_once(&state, kolimi_db::now_millis())
        .await
        .unwrap();
    assert!(report.audit_seal_failed, "{report:?}");
    assert_eq!(report.audit_checkpoints_sealed, 0, "{report:?}");
    assert!(
        state.db.audit_checkpoints(10).await.unwrap().is_empty(),
        "must not write an unsigned checkpoint"
    );
}

#[tokio::test]
async fn janitor_signs_and_anchors_a_checkpoint() {
    let (dir, state, _app) = setup().await;
    let key = dir.path().join("audit-signing.key");
    let signer = kolimi_db::AuditSigner::generate(&key, Some("janitor")).unwrap();
    let journal = dir.path().join("anchors.jsonl");
    let state = state
        .with_audit_signing(Some(key), Some(std::sync::Arc::new(signer)))
        .with_audit_anchors(Some(std::sync::Arc::new(
            kolimi_server::anchor::AnchorConfig {
                journal: Some(journal.clone()),
                url: None,
                token: None,
            },
        )));
    for index in 0..1024 {
        state
            .db
            .audit_append(
                None,
                Some("cli"),
                "user.add",
                &format!("u{index}"),
                &json!({}),
            )
            .await
            .unwrap();
    }
    let report = kolimi_server::janitor::run_once(&state, kolimi_db::now_millis())
        .await
        .unwrap();
    assert_eq!(report.audit_checkpoints_sealed, 1, "{report:?}");
    assert_eq!(report.audit_checkpoints_signed, 1, "{report:?}");
    assert_eq!(report.audit_anchors_journaled, 1, "{report:?}");
    assert!(!report.audit_seal_failed, "{report:?}");
    let anchors = std::fs::read_to_string(&journal).unwrap();
    assert_eq!(anchors.lines().count(), 1);
    let verify = state.db.audit_verify().await.unwrap();
    assert_eq!(verify.signed_checkpoints, 1);
    assert_eq!(verify.first_bad, None);
}
