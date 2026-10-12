//! Prometheus metrics endpoint (administrators only).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn basic(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    )
}

async fn get(app: &Router, uri: &str, auth: Option<&str>) -> (StatusCode, String, String) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        content_type,
        String::from_utf8(bytes.to_vec()).unwrap(),
    )
}

async fn post(app: &Router, uri: &str, body: serde_json::Value) {
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn metrics_cover_requests_logins_and_health() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    // The first user is an admin.
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state);

    // One failed login, one success, one health check.
    for password in ["wrong", PASS] {
        post(
            &app,
            "/api/session",
            json!({ "username": "alice", "password": password }),
        )
        .await;
    }
    let _ = get(&app, "/healthz", None).await;

    let (status, content_type, body) = get(&app, "/metrics", Some(&basic("alice", PASS))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/plain"), "{content_type}");
    assert!(body.contains("kolimi_http_requests_total"), "{body}");
    assert!(
        body.contains("path=\"/api/session\"") && body.contains("status=\"200\""),
        "successful login counted: {body}"
    );
    assert!(
        body.contains("status=\"401\""),
        "failed login counted: {body}"
    );
    assert!(
        body.contains("kolimi_login_failures_total 1"),
        "failure counter: {body}"
    );
    assert!(
        body.contains("kolimi_http_request_duration_seconds_bucket"),
        "latency histogram: {body}"
    );
    assert!(body.contains("path=\"/healthz\""), "{body}");
}

#[tokio::test]
async fn metrics_require_an_admin() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    // bob is a regular user.
    state
        .db
        .create_user("bob", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state);

    // Anonymous: 401.
    let (status, _, _) = get(&app, "/metrics", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Bad password: 401.
    let (status, _, _) = get(&app, "/metrics", Some(&basic("alice", "nope"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Authenticated but not an admin: 403.
    let (status, _, _) = get(&app, "/metrics", Some(&basic("bob", PASS))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin: 200.
    let (status, _, body) = get(&app, "/metrics", Some(&basic("alice", PASS))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("kolimi_"));
}

#[tokio::test]
async fn metrics_render_html_for_browsers() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state);
    let auth = basic("alice", PASS);

    // A browser (Accept: text/html) gets the HTML dashboard.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .header(header::AUTHORIZATION, &auth)
                .header(header::ACCEPT, "text/html,application/xhtml+xml")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.starts_with("<!doctype html>"), "{body}");
    assert!(body.contains("kolimi_users_by_usage_bucket"), "{body}");

    // `?format=text` forces the Prometheus format even from a browser.
    let (status, content_type, body) = get(&app, "/metrics?format=text", Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/plain"), "{content_type}");
    assert!(
        body.contains("# TYPE kolimi_users_by_usage_bucket"),
        "{body}"
    );
}
