//! User management: listing, disabling, deleting, and the guards that
//! keep the server from being locked out of administration.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
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
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn status_with_cookie(app: &Router, uri: &str, cookie: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Logs in and returns the `kolimi_session=…` cookie pair.
async fn login(app: &Router, user: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": user, "password": PASS }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|cookie| cookie.starts_with("kolimi_session="))
        .map(|cookie| cookie.split(';').next().unwrap().to_string())
        .expect("session cookie")
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    // First user is an admin.
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
async fn listing_and_creation_are_admin_only() {
    let (_dir, _state, app) = setup().await;

    let (status, body) =
        request(&app, "GET", "/api/users", Some(&basic("alice", PASS)), None).await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["username"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"alice") && names.contains(&"bob"), "{body}");

    // A regular user may neither list nor create.
    let (status, _) = request(&app, "GET", "/api/users", Some(&basic("bob", PASS)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = request(
        &app,
        "POST",
        "/api/users",
        Some(&basic("bob", PASS)),
        Some(json!({ "username": "mallory", "password": "pw123456" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin creates a user.
    let (status, body) = request(
        &app,
        "POST",
        "/api/users",
        Some(&basic("alice", PASS)),
        Some(json!({ "username": "carol", "password": "pw123456" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["username"], "carol");
    assert_eq!(body["is_admin"], false);

    // Non-admins cannot patch or delete.
    let (status, _) = request(
        &app,
        "PATCH",
        "/api/users/bob",
        Some(&basic("bob", PASS)),
        Some(json!({ "disabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = request(
        &app,
        "DELETE",
        "/api/users/alice",
        Some(&basic("bob", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn disable_blocks_login_and_drops_sessions() {
    let (_dir, state, app) = setup().await;

    // Bob signs in and has a working session.
    let cookie = login(&app, "bob").await;
    assert_eq!(
        status_with_cookie(&app, "/api/me", &cookie).await,
        StatusCode::OK
    );

    // Disable bob.
    let (status, body) = request(
        &app,
        "PATCH",
        "/api/users/bob",
        Some(&basic("alice", PASS)),
        Some(json!({ "disabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["disabled"], true);

    // Existing session is dead, and fresh logins are refused.
    assert_eq!(
        status_with_cookie(&app, "/api/me", &cookie).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = request(&app, "GET", "/api/me", Some(&basic("bob", PASS)), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = request(
        &app,
        "POST",
        "/api/session",
        None,
        Some(json!({ "username": "bob", "password": PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Re-enable restores access.
    let (status, _) = request(
        &app,
        "PATCH",
        "/api/users/bob",
        Some(&basic("alice", PASS)),
        Some(json!({ "disabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = request(&app, "GET", "/api/me", Some(&basic("bob", PASS)), None).await;
    assert_eq!(status, StatusCode::OK);

    // You cannot disable yourself.
    let (status, _) = request(
        &app,
        "PATCH",
        "/api/users/alice",
        Some(&basic("alice", PASS)),
        Some(json!({ "disabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The last enabled admin cannot be disabled or demoted.
    assert!(state.db.set_disabled("alice", true).await.is_err());
    let alice = state.db.find_user("alice").await.unwrap().unwrap();
    assert!(state.db.set_admin(alice.id, false).await.is_err());

    // Disable/enable are audited.
    let entries = state.db.audit_list(50, None).await.unwrap();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"user.disable"), "{actions:?}");
    assert!(actions.contains(&"user.enable"), "{actions:?}");
}

#[tokio::test]
async fn delete_removes_the_user_and_cascades() {
    let (_dir, state, app) = setup().await;

    // Bob owns a file.
    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/dav/bobfile.txt")
                .header(header::AUTHORIZATION, basic("bob", PASS))
                .body(Body::from("bob's data"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);

    // You cannot delete yourself; a missing user is 404.
    let (status, _) = request(
        &app,
        "DELETE",
        "/api/users/alice",
        Some(&basic("alice", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = request(
        &app,
        "DELETE",
        "/api/users/nobody",
        Some(&basic("alice", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The last admin cannot be deleted.
    assert!(state.db.delete_user("alice").await.is_err());

    // Admin deletes bob.
    let (status, _) = request(
        &app,
        "DELETE",
        "/api/users/bob",
        Some(&basic("alice", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert!(state.db.find_user("bob").await.unwrap().is_none());
    let (status, _) = request(&app, "GET", "/api/me", Some(&basic("bob", PASS)), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, body) = request(&app, "GET", "/api/users", Some(&basic("alice", PASS)), None).await;
    let names: Vec<&str> = body["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["username"].as_str().unwrap())
        .collect();
    assert!(!names.contains(&"bob"), "{body}");

    // An admin can be deleted when another enabled admin remains.
    request(
        &app,
        "POST",
        "/api/users",
        Some(&basic("alice", PASS)),
        Some(json!({ "username": "carol", "password": "pw123456" })),
    )
    .await;
    let (status, _) = request(
        &app,
        "PATCH",
        "/api/users/carol",
        Some(&basic("alice", PASS)),
        Some(json!({ "admin": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = request(
        &app,
        "DELETE",
        "/api/users/alice",
        Some(&basic("carol", "pw123456")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(state.db.find_user("alice").await.unwrap().is_none());

    // The deletion is audited.
    let entries = state.db.audit_list(50, None).await.unwrap();
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"user.delete"), "{actions:?}");
}
