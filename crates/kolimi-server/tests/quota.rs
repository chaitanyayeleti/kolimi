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

async fn admin_req(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, basic("alice", PASS));
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
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
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
async fn admin_manages_quota_and_reads_usage() {
    let (_dir, _state, app) = setup().await;
    assert_eq!(
        put(&app, "/dav/a.bin", vec![9u8; 2000]).await,
        StatusCode::CREATED
    );

    // The list carries the cached quota/usage (no blob-tree walk).
    let (status, body) = admin_req(&app, "GET", "/api/users", None).await;
    assert_eq!(status, StatusCode::OK);
    let account = &body["users"][0];
    assert_eq!(account["username"], "alice");
    assert!(account["used_bytes"].as_i64().unwrap() >= 2000);

    // Fresh usage endpoint reflects reality; default quota is unlimited.
    let (status, body) = admin_req(&app, "GET", "/api/users/alice/usage", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["used_bytes"].as_i64().unwrap() >= 2000);
    assert_eq!(body["effective_quota_bytes"], 0);

    // Set a per-user quota.
    let (status, body) = admin_req(
        &app,
        "PATCH",
        "/api/users/alice",
        Some(serde_json::json!({ "quota_bytes": 4096 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["quota_bytes"], 4096);
    let (_, body) = admin_req(&app, "GET", "/api/users/alice/usage", None).await;
    assert_eq!(body["effective_quota_bytes"], 4096);

    // Clear the override back to the server default (`null`).
    let (status, body) = admin_req(
        &app,
        "PATCH",
        "/api/users/alice",
        Some(serde_json::json!({ "quota_bytes": null })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["quota_bytes"].is_null());

    // Negative quotas are refused.
    let (status, _) = admin_req(
        &app,
        "PATCH",
        "/api/users/alice",
        Some(serde_json::json!({ "quota_bytes": -5 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Detail endpoint.
    let (status, body) = admin_req(&app, "GET", "/api/users/alice", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "alice");
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

#[tokio::test]
async fn purging_trash_updates_usage_immediately() {
    let (_dir, state, app) = setup().await;
    assert_eq!(
        put(&app, "/dav/gone.bin", vec![7u8; 5000]).await,
        StatusCode::CREATED
    );
    let alice = state.db.find_user("alice").await.unwrap().unwrap();
    assert!(alice.used_bytes >= 5000);

    // Delete to trash, then empty the trash.
    let (status, _) = admin_req(&app, "DELETE", "/dav/gone.bin", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, trash) = admin_req(&app, "GET", "/api/trash", None).await;
    assert_eq!(status, StatusCode::OK);
    let id = trash.as_array().unwrap()[0]["id"].as_i64().unwrap();
    let (status, _) = admin_req(&app, "DELETE", &format!("/api/trash/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Usage reflects the deletion at once, even though the blobs remain on
    // disk until the grace-period GC reclaims them.
    let used = state
        .db
        .find_user("alice")
        .await
        .unwrap()
        .unwrap()
        .used_bytes;
    assert_eq!(used, 0, "usage must drop on trash purge");
    let disk = state.vfs.store().usage_bytes(alice.id).await.unwrap();
    assert!(disk >= 5000, "blobs linger until GC, got {disk}");
}
