//! Phase 5 hardening: re-auth for user mutations, recovery rate limiting,
//! no-store session responses, and session labels.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app, hardening::RECOVERY_LIMIT};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

struct Login {
    cookie: String,
    csrf: String,
    headers: HeaderMap,
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
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
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

async fn request_cookie(
    app: &Router,
    method: &str,
    uri: &str,
    login: &Login,
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, format!("{}; {}", login.cookie, login.csrf));
    if matches!(method, "POST" | "PATCH" | "PUT" | "DELETE") {
        let csrf = login.csrf.split_once('=').unwrap().1;
        builder = builder.header("X-CSRF-Token", csrf);
    }
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
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

async fn login(app: &Router, user: &str, password: &str) -> Login {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": user, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let mut cookie = None;
    let mut csrf = None;
    for value in headers.get_all(header::SET_COOKIE) {
        let pair = value.to_str().unwrap().split(';').next().unwrap();
        if pair.starts_with("kolimi_session=") {
            cookie = Some(pair.to_string());
        } else if pair.starts_with("kolimi_csrf=") {
            csrf = Some(pair.to_string());
        }
    }
    Login {
        cookie: cookie.expect("session cookie"),
        csrf: csrf.expect("csrf cookie"),
        headers,
    }
}

async fn reauth(app: &Router, user: &str, password: &str) -> String {
    let (status, _, body) = request(
        app,
        "POST",
        "/api/reauth",
        Some(&basic(user, password)),
        Some(json!({ "password": password })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["token"].as_str().unwrap().to_string()
}

fn no_store(headers: &HeaderMap) -> bool {
    headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        == Some("no-store")
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    state
        .db
        .create_user("bob", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

#[tokio::test]
async fn user_mutations_require_fresh_reauth() {
    let (_dir, _state, app) = setup().await;
    let alice = basic("alice", PASS);

    for (method, uri, body) in [
        (
            "PATCH",
            "/api/users/bob",
            Some(json!({ "quota_bytes": 4096 })),
        ),
        ("DELETE", "/api/users/bob", None),
    ] {
        let (status, _, _) = request(&app, method, uri, Some(&alice), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }

    let token = reauth(&app, "alice", PASS).await;
    let (status, _, body) = request(
        &app,
        "PATCH",
        "/api/users/bob",
        Some(&alice),
        Some(json!({ "quota_bytes": 4096, "x-reauth-token": token })),
    )
    .await;
    // The token must travel in the header, not the JSON body.
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/users/bob")
                .header(header::AUTHORIZATION, &alice)
                .header("x-reauth-token", reauth(&app, "alice", PASS).await)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "quota_bytes": 4096 }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/users/bob")
                .header(header::AUTHORIZATION, &alice)
                .header("x-reauth-token", reauth(&app, "alice", PASS).await)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn recovery_is_rate_limited() {
    let (_dir, _state, app) = setup().await;
    let alice = basic("alice", PASS);
    for _ in 0..RECOVERY_LIMIT {
        let (status, _, _) = request(
            &app,
            "POST",
            "/api/users/bob/recover",
            Some(&alice),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, headers, _) = request(
        &app,
        "POST",
        "/api/users/bob/recover",
        Some(&alice),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
}

#[tokio::test]
async fn session_responses_are_no_store_and_labels_roundtrip() {
    let (_dir, _state, app) = setup().await;
    let alice = login(&app, "alice", PASS).await;
    assert!(no_store(&alice.headers), "login response");

    let (status, headers, body) =
        request_cookie(&app, "GET", "/api/me/sessions", &alice, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(no_store(&headers), "session list");
    let session = &body["sessions"][0];
    let id = session["id"].as_i64().unwrap();
    assert!(session["label"].is_null());

    let (status, headers, body) = request_cookie(
        &app,
        "PATCH",
        &format!("/api/me/sessions/{id}"),
        &alice,
        Some(json!({ "label": "  Work laptop  " })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(no_store(&headers));
    assert_eq!(body["label"], "Work laptop");

    let (_, _, body) = request_cookie(&app, "GET", "/api/me/sessions", &alice, None).await;
    assert_eq!(body["sessions"][0]["label"], "Work laptop");

    // Empty input clears the label.
    let (status, _, body) = request_cookie(
        &app,
        "PATCH",
        &format!("/api/me/sessions/{id}"),
        &alice,
        Some(json!({ "label": "   " })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["label"].is_null());

    let (status, _, _) = request_cookie(
        &app,
        "PATCH",
        &format!("/api/me/sessions/{id}"),
        &alice,
        Some(json!({ "label": "x".repeat(81) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Labels are scoped to the owner.
    let bob = login(&app, "bob", PASS).await;
    let (_, _, bob_sessions) = request_cookie(&app, "GET", "/api/me/sessions", &bob, None).await;
    let bob_id = bob_sessions["sessions"][0]["id"].as_i64().unwrap();
    let (status, _, _) = request_cookie(
        &app,
        "PATCH",
        &format!("/api/me/sessions/{bob_id}"),
        &alice,
        Some(json!({ "label": "stolen" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The admin session view is no-store too.
    let (status, headers, body) = request(
        &app,
        "GET",
        "/api/users/alice/sessions",
        Some(&basic("alice", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(no_store(&headers));
}
