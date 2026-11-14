//! Self-service account security: password changes and session management.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

struct Login {
    cookie: String,
    csrf: String,
}

fn cookie_pair(value: &str) -> String {
    value.split(';').next().unwrap().to_string()
}

fn csrf_value(pair: &str) -> &str {
    pair.split_once('=').unwrap().1
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

async fn login(app: &Router, username: &str) -> Login {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::USER_AGENT, "account-test-agent")
                .body(Body::from(
                    json!({ "username": username, "password": PASS }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut cookie = None;
    let mut csrf = None;
    for value in response.headers().get_all(header::SET_COOKIE).iter() {
        let value = value.to_str().unwrap();
        let pair = cookie_pair(value);
        if pair.starts_with("kolimi_session=") {
            cookie = Some(pair);
        } else if pair.starts_with("kolimi_csrf=") {
            csrf = Some(pair);
        }
    }
    Login {
        cookie: cookie.expect("session cookie"),
        csrf: csrf.expect("csrf cookie"),
    }
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    login: Option<&Login>,
    reauth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(login) = login {
        builder = builder.header(header::COOKIE, format!("{}; {}", login.cookie, login.csrf));
        if matches!(method, "POST" | "PATCH" | "PUT" | "DELETE") {
            builder = builder.header("X-CSRF-Token", csrf_value(&login.csrf));
        }
    }
    if let Some(token) = reauth {
        builder = builder.header("X-Reauth-Token", token);
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
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn login_status(app: &Router, password: &str) -> StatusCode {
    app.clone()
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
        .unwrap()
        .status()
}

#[tokio::test]
async fn sessions_are_scoped_and_revocable() {
    let (_dir, _state, app) = setup().await;
    let alice_first = login(&app, "alice").await;
    let alice_second = login(&app, "alice").await;
    let bob = login(&app, "bob").await;

    let (status, body) = send(
        &app,
        "GET",
        "/api/me/sessions",
        Some(&alice_first),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2, "{body}");
    assert_eq!(
        sessions
            .iter()
            .filter(|session| session["current"].as_bool() == Some(true))
            .count(),
        1,
        "{body}"
    );
    assert!(
        sessions
            .iter()
            .all(|session| session["user_agent"] == "account-test-agent"),
        "{body}"
    );
    let other_id = sessions
        .iter()
        .find(|session| session["current"].as_bool() == Some(false))
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // A user cannot revoke someone else's session.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/me/sessions/{other_id}"),
        Some(&bob),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/me/sessions/{other_id}"),
        Some(&alice_first),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, "GET", "/api/me", Some(&alice_second), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = send(&app, "GET", "/api/me", Some(&alice_first), None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn revoke_other_sessions_keeps_the_current_one() {
    let (_dir, _state, app) = setup().await;
    let current = login(&app, "alice").await;
    let other = login(&app, "alice").await;

    let (status, _) = send(
        &app,
        "DELETE",
        "/api/me/sessions?keep_current=true",
        Some(&current),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(&app, "GET", "/api/me", Some(&current), None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, "GET", "/api/me", Some(&other), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_all_sessions_signs_out_the_current_one() {
    let (_dir, _state, app) = setup().await;
    let current = login(&app, "alice").await;

    let (status, _) = send(
        &app,
        "DELETE",
        "/api/me/sessions",
        Some(&current),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "GET", "/api/me", Some(&current), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_change_requires_reauth_and_revokes_other_sessions() {
    let (_dir, state, app) = setup().await;
    let current = login(&app, "alice").await;
    let other = login(&app, "alice").await;

    // No re-auth token: refused.
    let (status, _) = send(
        &app,
        "POST",
        "/api/me/password",
        Some(&current),
        None,
        Some(json!({ "new_password": "new password 456" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A weak password is rejected before the token is consumed.
    let (status, token) = send(
        &app,
        "POST",
        "/api/reauth",
        Some(&current),
        None,
        Some(json!({ "password": PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = token["token"].as_str().unwrap().to_string();
    let (status, _) = send(
        &app,
        "POST",
        "/api/me/password",
        Some(&current),
        Some(&token),
        Some(json!({ "new_password": "short" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The token was not consumed, so the same one still works.
    let (status, body) = send(
        &app,
        "POST",
        "/api/me/password",
        Some(&current),
        Some(&token),
        Some(json!({ "new_password": "new password 456" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // The current session survives; the other one and the old password do not.
    let (status, _) = send(&app, "GET", "/api/me", Some(&current), None, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&app, "GET", "/api/me", Some(&other), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(login_status(&app, PASS).await, StatusCode::UNAUTHORIZED);
    assert_eq!(login_status(&app, "new password 456").await, StatusCode::OK);

    let entries = state.db.audit_list(50, None).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "user.password_change"),
        "{entries:?}"
    );
}

#[tokio::test]
async fn me_reports_password_login_and_creation_time() {
    let (_dir, _state, app) = setup().await;
    let login = login(&app, "alice").await;
    let (status, body) = send(&app, "GET", "/api/me", Some(&login), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "alice");
    assert_eq!(body["password_login"], true);
    assert!(body["created_at"].as_i64().unwrap_or(0) > 0);
}
