//! App-password authentication and mandatory first-login MFA enrollment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::{password::hash_password, totp::TotpSecret};
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
