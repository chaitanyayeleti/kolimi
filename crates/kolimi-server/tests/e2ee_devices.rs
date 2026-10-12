//! Multi-device E2EE enrollment (RFC 0008): create → approve → collect,
//! plus device listing and removal.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_crypto::Identity;
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";
const PASS: &str = "test password 123";

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

fn basic() -> String {
    format!("Basic {}", STANDARD.encode(format!("alice:{PASS}")))
}

async fn req(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, basic());
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

#[tokio::test]
async fn device_enrollment_roundtrip() {
    let (_dir, _state, app) = setup().await;

    // The master key (held by an unlocked device) and a brand-new device.
    let master_key = [7u8; 32];
    let new_device = Identity::generate().unwrap();

    // The new device requests enrollment.
    let (status, body) = req(
        &app,
        "POST",
        "/api/e2ee/enrollments",
        Some(json!({
            "device_name": "laptop",
            "device_public_key": STANDARD.encode(new_device.public_key()),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_i64().unwrap();

    // An unlocked device sees it pending.
    let (status, body) = req(&app, "GET", "/api/e2ee/enrollments", None).await;
    assert_eq!(status, StatusCode::OK);
    let pending = body["enrollments"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["device_name"], "laptop");
    assert_eq!(
        pending[0]["device_public_key"],
        STANDARD.encode(new_device.public_key())
    );

    // It wraps the master key for the new device and approves.
    let wrapped = kolimi_crypto::wrap_secret_for(&new_device.public_key(), &master_key).unwrap();
    let (status, _) = req(
        &app,
        "POST",
        &format!("/api/e2ee/enrollments/{id}/approve"),
        Some(json!({ "wrapped_master_key": STANDARD.encode(&wrapped) })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The new device collects the wrapped key and unwraps the master key.
    let (status, body) = req(&app, "GET", &format!("/api/e2ee/enrollments/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["approved"], true);
    let collected = STANDARD
        .decode(body["wrapped_master_key"].as_str().unwrap())
        .unwrap();
    let recovered = kolimi_crypto::unwrap_secret(&new_device.private_bytes(), &collected).unwrap();
    assert_eq!(recovered, master_key);

    // The device is now registered.
    let (status, body) = req(&app, "GET", "/api/e2ee/devices", None).await;
    assert_eq!(status, StatusCode::OK);
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["name"], "laptop");
    let device_id = devices[0]["id"].as_i64().unwrap();

    // The enrollment no longer appears as pending.
    let (_, body) = req(&app, "GET", "/api/e2ee/enrollments", None).await;
    assert!(body["enrollments"].as_array().unwrap().is_empty());

    // Cleanup.
    let (status, _) = req(&app, "DELETE", &format!("/api/e2ee/enrollments/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = req(
        &app,
        "DELETE",
        &format!("/api/e2ee/devices/{device_id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, body) = req(&app, "GET", "/api/e2ee/devices", None).await;
    assert!(body["devices"].as_array().unwrap().is_empty());
}
