//! Per-user storage quotas: enforcement via the cached usage counter and
//! janitor reconciliation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

async fn put(app: &Router, path: &str, body: Vec<u8>) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::AUTHORIZATION, basic("alice", PASS))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn per_user_quota_blocks_and_counts() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user("alice").await.unwrap().unwrap();
    state
        .db
        .set_quota_bytes(alice.id, Some(1024))
        .await
        .unwrap();

    assert_eq!(
        put(&app, "/dav/small.bin", vec![1u8; 800]).await,
        StatusCode::CREATED
    );
    let used = state
        .db
        .find_user("alice")
        .await
        .unwrap()
        .unwrap()
        .used_bytes;
    assert!(used >= 800, "counter should track usage, got {used}");

    // Over quota -> 413.
    assert_eq!(
        put(&app, "/dav/big.bin", vec![2u8; 800]).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // Raising the quota lets the same upload through.
    state
        .db
        .set_quota_bytes(alice.id, Some(10_000))
        .await
        .unwrap();
    assert_eq!(
        put(&app, "/dav/big.bin", vec![2u8; 800]).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn janitor_reconciles_usage_from_disk() {
    let (_dir, state, app) = setup().await;
    assert_eq!(
        put(&app, "/dav/x.bin", vec![5u8; 3000]).await,
        StatusCode::CREATED
    );

    // Corrupt the counter, then let the janitor recompute it from disk.
    let alice = state.db.find_user("alice").await.unwrap().unwrap();
    state.db.add_used_bytes(alice.id, -100_000).await.unwrap();
    assert_eq!(
        state
            .db
            .find_user("alice")
            .await
            .unwrap()
            .unwrap()
            .used_bytes,
        0
    );

    kolimi_server::janitor::run_once(&state, kolimi_db::now_millis())
        .await
        .unwrap();

    let used = state
        .db
        .find_user("alice")
        .await
        .unwrap()
        .unwrap()
        .used_bytes;
    assert!(used >= 3000, "reconciled to on-disk usage, got {used}");
}
