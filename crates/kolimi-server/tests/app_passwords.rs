//! App-password authentication and mandatory first-login MFA enrollment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::{password::hash_password, token, totp::TotpSecret};
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "alice";
const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user(ALICE, &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

async fn login(app: &Router) -> (StatusCode, Vec<String>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": ALICE, "password": PASS }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| {
            v.to_str()
                .ok()
                .map(|s| s.split(';').next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();
    (status, cookies)
}

fn cookie(cookies: &[String], name: &str) -> String {
    cookies
        .iter()
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .unwrap_or("")
        .to_string()
}

fn basic(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{ALICE}:{password}")))
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> (StatusCode, Value, Vec<String>) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_else(Body::empty);
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| {
            v.to_str()
                .ok()
                .map(|s| s.split(';').next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value, cookies)
}

#[tokio::test]
async fn app_password_works_with_totp_and_can_revoke_itself() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    state
        .db
        .set_totp_secret(alice.id, &TotpSecret::generate().unwrap().to_base32())
        .await
        .unwrap();

    // A fresh session may create an app password without a second prompt.
    let (status, _cookies) = login(&app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "TOTP must be required");
    let secret = state.db.totp_secret(alice.id).await.unwrap().unwrap().0;
    let secret = TotpSecret::from_base32(&secret).unwrap();
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({ "username": ALICE, "password": PASS, "code": code }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| {
            v.to_str()
                .ok()
                .map(|s| s.split(';').next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty())
        .collect();
    let session_cookie = cookie(&cookies, "kolimi_session");
    let csrf = cookie(&cookies, "kolimi_csrf");
    let (status, body, _) = send(
        &app,
        "POST",
        "/api/me/app-passwords",
        Some(json!({ "name": "Laptop sync" })),
        &[
            ("content-type", "application/json".to_string()),
            (
                "cookie",
                format!("kolimi_session={session_cookie}; kolimi_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf.clone()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let app_password = body["token"].as_str().unwrap().to_string();

    // The app password authenticates even though TOTP is enrolled, while the
    // account password alone still does not.
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("authorization", basic(&app_password))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("authorization", basic(PASS))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A device can revoke the credential it authenticated with.
    let (status, _, _) = send(
        &app,
        "DELETE",
        "/api/me/app-passwords/current",
        None,
        &[("authorization", basic(&app_password))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("authorization", basic(&app_password))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

async fn create_app_password(
    state: &AppState,
    name: &str,
    scopes: &str,
    expires_at: Option<i64>,
) -> String {
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    let plaintext = token::new_session_token().unwrap();
    let hash = token::hash_token(&plaintext);
    state
        .db
        .create_app_password(alice.id, name, &hash, scopes, expires_at)
        .await
        .unwrap();
    plaintext
}

#[tokio::test]
async fn scoped_app_passwords_enforce_least_privilege() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    state.vfs.mkdir(alice.id, "/docs").await.unwrap();

    let read = create_app_password(&state, "files read", "files:read", None).await;
    let write = create_app_password(&state, "files write", "files:write", None).await;
    let sync = create_app_password(&state, "sync", "files:read,files:write,sync", None).await;

    // Read scope can browse, but cannot mutate or reach account/share APIs.
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/browse?path=/",
        None,
        &[("authorization", basic(&read))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body, _) = send(
        &app,
        "PUT",
        "/api/files/encrypt",
        Some(json!({ "path": "/docs", "encrypted": false })),
        &[
            ("content-type", "application/json".to_string()),
            ("authorization", basic(&read)),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["insufficient_scope"], true);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/users",
        None,
        &[("authorization", basic(&read))],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/app-passwords",
        None,
        &[("authorization", basic(&read))],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Write scope passes the scope gate (the handler may still reject the
    // operation for its own reasons, but never with insufficient_scope).
    let (status, body, _) = send(
        &app,
        "PUT",
        "/api/files/encrypt",
        Some(json!({ "path": "/docs", "encrypted": false })),
        &[
            ("content-type", "application/json".to_string()),
            ("authorization", basic(&write)),
        ],
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN, "{body}");

    // Sync can reach keyring and share metadata, but not account admin.
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/e2ee/keyring",
        None,
        &[("authorization", basic(&sync))],
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/shares/owned",
        None,
        &[("authorization", basic(&sync))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/users",
        None,
        &[("authorization", basic(&sync))],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A token with no explicit scopes is still full access (compatibility).
    let full = create_app_password(&state, "legacy", "*", None).await;
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/app-passwords",
        None,
        &[("authorization", basic(&full))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Expired tokens are rejected before the scope gate.
    let expired = create_app_password(
        &state,
        "expired",
        "files:read",
        Some(kolimi_db::now_millis() - 1),
    )
    .await;
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/browse?path=/",
        None,
        &[("authorization", basic(&expired))],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A device can revoke the token it authenticated with even without the
    // account-management scope.
    let (status, _, _) = send(
        &app,
        "DELETE",
        "/api/me/app-passwords/current",
        None,
        &[("authorization", basic(&read))],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn app_password_can_be_rescoped_without_rotation() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    state.vfs.mkdir(alice.id, "/docs").await.unwrap();
    let token = create_app_password(&state, "rescope", "files:read", None).await;
    let id = state.db.list_app_passwords(alice.id).await.unwrap()[0].id;

    let (status, cookies) = login(&app).await;
    assert_eq!(status, StatusCode::OK);
    let session = cookie(&cookies, "kolimi_session");
    let csrf = cookie(&cookies, "kolimi_csrf");
    let (status, body, _) = send(
        &app,
        "PATCH",
        &format!("/api/me/app-passwords/{id}"),
        Some(json!({ "scopes": ["files:write"], "expires_in_secs": 0 })),
        &[
            ("content-type", "application/json".to_string()),
            (
                "cookie",
                format!("kolimi_session={session}; kolimi_csrf={csrf}"),
            ),
            ("x-csrf-token", csrf),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["scopes"], json!(["files:write"]));
    assert_eq!(body["expires_at"], Value::Null);

    // The same token now passes the write gate; no rotation was needed.
    let (status, body, _) = send(
        &app,
        "PUT",
        "/api/files/encrypt",
        Some(json!({ "path": "/docs", "encrypted": false })),
        &[
            ("content-type", "application/json".to_string()),
            ("authorization", basic(&token)),
        ],
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn repeated_requests_do_not_write_auth_timestamps() {
    let (_dir, state, app) = setup().await;
    let user_id = state.db.find_user(ALICE).await.unwrap().unwrap().id;
    let app_token = create_app_password(&state, "throttle", "files:read", None).await;

    // First use records last_used_at; the next request inside the window
    // must not write it again.
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/browse?path=/",
        None,
        &[("authorization", basic(&app_token))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = state.db.list_app_passwords(user_id).await.unwrap()[0]
        .last_used_at
        .expect("first use should stamp the token");
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/browse?path=/",
        None,
        &[("authorization", basic(&app_token))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = state.db.list_app_passwords(user_id).await.unwrap()[0]
        .last_used_at
        .expect("timestamp remains set");
    assert_eq!(
        second, first,
        "second request must not rewrite last_used_at"
    );

    // The same throttle applies to cookie sessions.
    let (status, cookies) = login(&app).await;
    assert_eq!(status, StatusCode::OK);
    let session_token = cookie(&cookies, "kolimi_session");
    let hash = token::hash_token(&session_token);
    let session = state.db.find_session(&hash).await.unwrap().unwrap();
    sqlx::query("UPDATE sessions SET last_seen_at = 0 WHERE id = ?")
        .bind(session.id)
        .execute(state.db.pool())
        .await
        .unwrap();
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("cookie", format!("kolimi_session={session_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first = state
        .db
        .find_session(&hash)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;
    assert!(first > 0);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("cookie", format!("kolimi_session={session_token}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = state
        .db
        .find_session(&hash)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;
    assert_eq!(
        second, first,
        "second request must not rewrite last_seen_at"
    );
}

#[tokio::test]
async fn mfa_setup_blocks_the_api_until_totp_is_enabled() {
    let (_dir, state, app) = setup().await;
    let alice = state.db.find_user(ALICE).await.unwrap().unwrap();
    state.db.set_must_setup_mfa(alice.id, true).await.unwrap();

    let (status, cookies) = login(&app).await;
    assert_eq!(status, StatusCode::OK);
    let session_cookie = cookie(&cookies, "kolimi_session");
    let csrf = cookie(&cookies, "kolimi_csrf");
    let cookie_header = format!("kolimi_session={session_cookie}; kolimi_csrf={csrf}");

    let (status, body, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("cookie", cookie_header.clone())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["must_setup_mfa"], true);

    let (status, begin, _) = send(
        &app,
        "POST",
        "/api/totp/begin",
        Some(json!({})),
        &[
            ("content-type", "application/json".to_string()),
            ("cookie", cookie_header.clone()),
            ("x-csrf-token", csrf.clone()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{begin}");
    let secret = TotpSecret::from_base32(begin["secret"].as_str().unwrap()).unwrap();
    let code = secret.code_at((kolimi_db::now_millis() / 1000) as u64);
    let (status, _, _) = send(
        &app,
        "POST",
        "/api/totp/enable",
        Some(json!({ "secret": begin["secret"], "code": code })),
        &[
            ("content-type", "application/json".to_string()),
            ("cookie", cookie_header.clone()),
            ("x-csrf-token", csrf),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, me, _) = send(
        &app,
        "GET",
        "/api/me",
        None,
        &[("cookie", cookie_header.clone())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["must_setup_mfa"], false);
    let (status, _, _) = send(
        &app,
        "GET",
        "/api/me/usage",
        None,
        &[("cookie", cookie_header)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
