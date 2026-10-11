//! M7 integration: sandboxed plugins over HTTP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::Value;
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../kolimi-plugins/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn install_plugins(data: &Path) {
    let dir = data.join("plugins");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.wasm"), fixture("hello.wasm")).unwrap();
    std::fs::write(
        dir.join("hello.json"),
        r#"{"name":"hello","version":"0.1.0","description":"greeting","enabled":true}"#,
    )
    .unwrap();
    std::fs::write(dir.join("spin.wasm"), fixture("spin.wasm")).unwrap();
    std::fs::write(dir.join("spin.json"), r#"{"name":"spin"}"#).unwrap();
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    install_plugins(dir.path());
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

fn basic() -> String {
    format!("Basic {}", STANDARD.encode(format!("alice:{PASS}")))
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    body: &[u8],
    auth: bool,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if auth {
        builder = builder.header(header::AUTHORIZATION, basic());
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.to_vec())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn plugins_serve_routes_and_stay_sandboxed() {
    let (_dir, state, app) = setup().await;

    // Listing requires auth.
    let (status, _) = request(&app, "GET", "/api/plugins", b"", false).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = request(&app, "GET", "/api/plugins", b"", true).await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["plugins"][0]["name"], "hello");

    // Greeting, echo, and the KV-backed counter.
    let (status, body) = request(&app, "GET", "/plugins/hello", b"", true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&body).contains("hello from plugin, alice"),
        "{body:?}"
    );

    let (status, body) = request(&app, "POST", "/plugins/hello/echo", b"ping", true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ping");

    let (_, first) = request(&app, "GET", "/plugins/hello/counter", b"", true).await;
    let (_, second) = request(&app, "GET", "/plugins/hello/counter", b"", true).await;
    assert!(String::from_utf8_lossy(&first).contains("hits: 1"));
    assert!(String::from_utf8_lossy(&second).contains("hits: 2"));

    // Sandbox: no filesystem access even though the route tries.
    let (status, body) = request(&app, "GET", "/plugins/hello/read", b"", true).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&body).starts_with("denied:"),
        "{body:?}"
    );

    // A runaway plugin is stopped by the fuel limit.
    let (status, _) = request(&app, "GET", "/plugins/spin", b"", true).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let entries = state.db.audit_list(50, None).await.unwrap();
    assert!(
        entries.iter().any(|entry| entry.action == "plugin.error"),
        "plugin trap audited"
    );

    // Unknown plugin.
    let (status, _) = request(&app, "GET", "/plugins/missing", b"", true).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
