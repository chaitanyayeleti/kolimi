//! Prometheus metrics endpoint.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, header},
};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::json;
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

async fn scrape(app: &Router) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn metrics_cover_requests_logins_and_health() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state);

    // One failed login, one success, one health check.
    for password in ["wrong", PASS] {
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "username": "alice", "password": password }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = scrape(&app).await;
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
