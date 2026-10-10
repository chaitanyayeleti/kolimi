//! UI asset serving tests (work with the placeholder or a built UI).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kolimi_server::{AppState, build_app};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";

async fn setup() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    (build_app(state), dir)
}

async fn get(app: &Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn serves_app_shell_assets_and_public_pages() {
    let (app, _dir) = setup().await;

    // `/` redirects to the app.
    let (status, headers, _) = get(&app, "/").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(headers.get(header::LOCATION).unwrap(), "/app/");

    // The app shell is HTML with a CSP.
    for uri in ["/app", "/app/", "/s/sometoken"] {
        let (status, headers, body) = get(&app, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html",
            "{uri}"
        );
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("x-content-type-options"));
        assert!(!body.is_empty());
    }

    // Missing files under /app 404 rather than falling back to HTML.
    let (status, _, _) = get(&app, "/app/nope.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
