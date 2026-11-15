//! Phase 4 integration tests: invite onboarding, forced password rotation,
//! and optional profile fields.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_auth::totp::TotpSecret;
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASS: &str = "test password 123";
const NEW_PASS: &str = "new password 456";
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

async fn request_cookie(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie);
    if matches!(method, "POST" | "PATCH" | "PUT" | "DELETE")
        && let Some(csrf) = cookie
            .split(';')
            .map(str::trim)
            .find_map(|pair| pair.strip_prefix("kolimi_csrf="))
    {
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
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

/// Logs in, returning the session cookie and response body.
async fn login(app: &Router, user: &str, password: &str) -> (String, Value) {
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
    let mut session = None;
    let mut csrf = None;
    for value in response.headers().get_all(header::SET_COOKIE) {
        let value = value.to_str().unwrap();
        let pair = value.split(';').next().unwrap();
        if pair.starts_with("kolimi_session=") {
            session = Some(pair.to_string());
        } else if pair.starts_with("kolimi_csrf=") {
            csrf = Some(pair.to_string());
        }
    }
    let cookie = format!(
        "{}; {}",
        session.expect("session cookie"),
        csrf.expect("csrf cookie")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (cookie, serde_json::from_slice(&bytes).unwrap())
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    // The first account is an administrator.
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

async fn create_invite(app: &Router, auth: &str, username: &str) -> (StatusCode, Value) {
    request(
        app,
        "POST",
        "/api/invites",
        Some(auth),
        Some(json!({
            "username": username,
            "display_name": "Invited Person",
            "email": "invited@example.test",
            "expires_in_secs": 86_400,
        })),
    )
    .await
}

fn invite_token(body: &Value) -> String {
    body["url"]
        .as_str()
        .unwrap()
        .strip_prefix("/invite#token=")
        .expect("invite url")
        .to_string()
}

#[tokio::test]
async fn invite_flow_creates_the_account_once() {
    let (_dir, state, app) = setup().await;
    let alice = basic("alice", PASS);
    state
        .db
        .create_user("bob", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let bob = basic("bob", PASS);

    // Invite management is administrator-only.
    let (status, _) = request(&app, "GET", "/api/invites", Some(&bob), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = create_invite(&app, &bob, "carol").await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, created) = create_invite(&app, &alice, "carol").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["username"], "carol");
    assert_eq!(created["display_name"], "Invited Person");
    assert_eq!(created["email"], "invited@example.test");
    assert!(created.get("token_hash").is_none());
    let token = invite_token(&created);

    let (status, list) = request(&app, "GET", "/api/invites", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let invites = list["invites"].as_array().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0]["username"], "carol");
    assert_eq!(invites[0]["expired"], false);
    assert!(invites[0].get("token_hash").is_none());

    // A duplicate pending invite and an existing username are conflicts.
    let (status, _) = create_invite(&app, &alice, "CAROL").await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = create_invite(&app, &alice, "bob").await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Public lookup accepts the token in the body, never in a URL path.
    let (status, lookup) = request(
        &app,
        "POST",
        "/api/invites/lookup",
        None,
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{lookup}");
    assert_eq!(lookup["username"], "carol");
    assert_eq!(lookup["display_name"], "Invited Person");
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/lookup",
        None,
        Some(json!({ "token": "not-a-token" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Weak passwords are rejected before the account exists.
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/accept",
        None,
        Some(json!({ "token": token, "password": "short" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(state.db.find_user("carol").await.unwrap().is_none());

    let (status, accepted) = request(
        &app,
        "POST",
        "/api/invites/accept",
        None,
        Some(json!({ "token": token, "password": NEW_PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    assert_eq!(accepted["username"], "carol");
    let carol = state.db.find_user("carol").await.unwrap().unwrap();
    assert_eq!(carol.display_name.as_deref(), Some("Invited Person"));
    assert_eq!(carol.email.as_deref(), Some("invited@example.test"));

    // The link is single-use.
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/lookup",
        None,
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/accept",
        None,
        Some(json!({ "token": token, "password": NEW_PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, list) = request(&app, "GET", "/api/invites", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(list["invites"].as_array().unwrap().is_empty());

    // The account works with the chosen password and does not require a
    // second rotation.
    let (_, body) = login(&app, "carol", NEW_PASS).await;
    assert_eq!(body["must_change_password"], false);

    let entries = state.db.audit_list(100, None).await.unwrap();
    let alice_id = state.db.find_user("alice").await.unwrap().unwrap().id;
    let created_entry = entries
        .iter()
        .find(|entry| entry.action == "invite.create")
        .expect("invite.create audit");
    assert_eq!(created_entry.actor_id, Some(alice_id));
    assert_eq!(created_entry.subject, "carol");
    assert!(!created_entry.details.contains(&token));
    let accepted_entry = entries
        .iter()
        .find(|entry| entry.action == "invite.accept")
        .expect("invite.accept audit");
    assert_eq!(accepted_entry.actor_id, None);
    assert_eq!(accepted_entry.subject, "carol");
}

#[tokio::test]
async fn invites_can_be_revoked_and_expire() {
    let (_dir, state, app) = setup().await;
    let alice = basic("alice", PASS);
    state
        .db
        .create_user("bob", &hash_password(PASS).unwrap())
        .await
        .unwrap();

    let (status, created) = create_invite(&app, &alice, "dave").await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["id"].as_i64().unwrap();
    let token = invite_token(&created);
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/invites/{id}"),
        Some(&basic("bob", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/invites/{id}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/lookup",
        None,
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let entries = state.db.audit_list(50, None).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "invite.revoke" && entry.subject == "dave")
    );

    // An expired invite neither resolves nor reserves its username.
    let (status, expired) = create_invite(&app, &alice, "erin").await;
    assert_eq!(status, StatusCode::CREATED);
    let expired_token = invite_token(&expired);
    sqlx::query("UPDATE invites SET expires_at = ? WHERE id = ?")
        .bind(kolimi_db::now_millis() - 1)
        .bind(expired["id"].as_i64().unwrap())
        .execute(state.db.pool())
        .await
        .unwrap();
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/lookup",
        None,
        Some(json!({ "token": expired_token })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &app,
        "POST",
        "/api/invites/accept",
        None,
        Some(json!({ "token": expired_token, "password": NEW_PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = create_invite(&app, &alice, "erin").await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn forced_password_change_blocks_the_api_until_replaced() {
    let (_dir, state, app) = setup().await;
    let alice = basic("alice", PASS);

    let (status, created) = request(
        &app,
        "POST",
        "/api/users",
        Some(&alice),
        Some(json!({
            "username": "bob",
            "password": PASS,
            "display_name": "Bob Example",
            "email": "bob@example.test",
            "must_change_password": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["must_change_password"], true);
    assert_eq!(created["display_name"], "Bob Example");

    let (cookie, login_body) = login(&app, "bob", PASS).await;
    assert_eq!(login_body["must_change_password"], true);
    assert_eq!(login_body["display_name"], "Bob Example");

    let (status, me) = request_cookie(&app, "GET", "/api/me", &cookie, None).await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["must_change_password"], true);
    assert_eq!(me["email"], "bob@example.test");

    // Normal API and WebDAV surfaces are blocked; Basic auth is blocked too.
    let (status, _) = request_cookie(&app, "GET", "/api/browse", &cookie, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = request(
        &app,
        "GET",
        "/api/me/usage",
        Some(&basic("bob", PASS)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = request(&app, "PROPFIND", "/dav/", Some(&basic("bob", PASS)), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Re-auth and the password change are allowed.
    let (status, body) = request(
        &app,
        "POST",
        "/api/reauth",
        Some(&basic("bob", PASS)),
        Some(json!({ "password": PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let reauth = body["token"].as_str().unwrap();
    let csrf = cookie
        .split(';')
        .map(str::trim)
        .find_map(|pair| pair.strip_prefix("kolimi_csrf="))
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/me/password")
                .header(header::COOKIE, &cookie)
                .header("X-CSRF-Token", csrf)
                .header("x-reauth-token", reauth)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "new_password": NEW_PASS }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (status, me) = request_cookie(&app, "GET", "/api/me", &cookie, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["must_change_password"], false);
    assert_eq!(me["must_setup_mfa"], true);

    // Data surfaces stay blocked until the user enrolls a second factor.
    let (status, _) = request_cookie(&app, "GET", "/api/me/usage", &cookie, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, begin) =
        request_cookie(&app, "POST", "/api/totp/begin", &cookie, Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64);
    let (status, enabled) = request_cookie(
        &app,
        "POST",
        "/api/totp/enable",
        &cookie,
        Some(json!({ "secret": begin["secret"], "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");

    let (status, me) = request_cookie(&app, "GET", "/api/me", &cookie, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["must_setup_mfa"], false);
    let (status, _) = request_cookie(&app, "GET", "/api/me/usage", &cookie, None).await;
    assert_eq!(status, StatusCode::OK);

    // The old temporary password no longer works.
    let (status, _) = request(
        &app,
        "POST",
        "/api/session",
        None,
        Some(json!({ "username": "bob", "password": PASS })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let entries = state.db.audit_list(100, None).await.unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.action == "user.password_change")
    );
}

#[tokio::test]
async fn profile_fields_are_optional_and_validated() {
    let (_dir, _state, app) = setup().await;
    let (cookie, _) = login(&app, "alice", PASS).await;

    let (status, body) = request_cookie(
        &app,
        "PATCH",
        "/api/me",
        &cookie,
        Some(json!({ "display_name": "Alice Example", "email": "alice@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "Alice Example");
    let (status, me) = request_cookie(&app, "GET", "/api/me", &cookie, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["display_name"], "Alice Example");
    assert_eq!(me["email"], "alice@example.test");

    // Omitting a field preserves it.
    let (status, body) = request_cookie(
        &app,
        "PATCH",
        "/api/me",
        &cookie,
        Some(json!({ "email": "alice+new@example.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["display_name"], "Alice Example");
    assert_eq!(body["email"], "alice+new@example.test");

    // Empty values clear the fields.
    let (status, _) = request_cookie(
        &app,
        "PATCH",
        "/api/me",
        &cookie,
        Some(json!({ "display_name": "", "email": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, me) = request_cookie(&app, "GET", "/api/me", &cookie, None).await;
    assert!(me["display_name"].is_null());
    assert!(me["email"].is_null());

    let (status, _) = request_cookie(
        &app,
        "PATCH",
        "/api/me",
        &cookie,
        Some(json!({ "email": "not an email" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
