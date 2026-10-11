//! Rate limiting and baseline security headers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app, hardening};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";
const PASS: &str = "test password 123";

async fn setup_state(secure: bool) -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), secure, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

async fn setup(secure: bool) -> (tempfile::TempDir, Router) {
    let (dir, _state, app) = setup_state(secure).await;
    (dir, app)
}

fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{password}")))
}

async fn get_status(app: &Router, uri: &str, auth: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

fn passkey_begin(username: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/passkeys/login/begin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!("{{\"username\":\"{username}\"}}")))
        .unwrap()
}

fn login(username: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            "{{\"username\":\"{username}\",\"password\":\"x\"}}"
        )))
        .unwrap()
}

#[tokio::test]
async fn auth_endpoints_are_rate_limited_per_client() {
    let (_dir, app) = setup(false).await;
    // oneshot requests carry no peer address, so they share the "unknown"
    // client bucket; each probe uses a distinct username so the per-account
    // lockout is never the thing that triggers.
    let mut throttled = false;
    for i in 0..(hardening::AUTH_LIMIT + 3) {
        let response = app
            .clone()
            .oneshot(passkey_begin(&format!("probe{i}")))
            .await
            .unwrap();
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "60");
            throttled = true;
            break;
        }
    }
    assert!(throttled, "expected 429 once the auth limit is exceeded");
}

#[tokio::test]
async fn unknown_user_and_bad_password_share_the_same_error() {
    let (_dir, app) = setup(false).await;
    let unknown = app.clone().oneshot(login("ghost")).await.unwrap();
    let wrong = app.clone().oneshot(login("alice")).await.unwrap();
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let body = |r: axum::response::Response| async move {
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    };
    assert_eq!(body(unknown).await, body(wrong).await);
}

#[tokio::test]
async fn repeated_failures_lock_the_account_for_that_source() {
    let (_dir, app) = setup(false).await;
    let mut codes = Vec::new();
    for _ in 0..6 {
        codes.push(app.clone().oneshot(login("alice")).await.unwrap().status());
    }
    // Wrong password, then locked (the lockout is keyed on account+source,
    // which is the shared "unknown" bucket here).
    assert_eq!(codes[0], StatusCode::UNAUTHORIZED);
    assert_eq!(codes[5], StatusCode::TOO_MANY_REQUESTS, "{codes:?}");
}

#[tokio::test]
async fn security_headers_are_present() {
    let (_dir, app) = setup(true).await;
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert!(
        headers
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("max-age=31536000"),
        "HSTS present when secure cookies are on"
    );
}

#[tokio::test]
async fn version_requires_authentication() {
    let (_dir, app) = setup(false).await;
    assert_eq!(
        get_status(&app, "/version", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_status(&app, "/version", Some(&basic("alice", PASS))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn group_roster_is_scoped_to_members_and_admins() {
    let (_dir, state, app) = setup_state(false).await;
    let bob = state
        .db
        .create_user("bob", &hash_password("pw123456").unwrap())
        .await
        .unwrap();
    state
        .db
        .create_user("mallory", &hash_password("pw123456").unwrap())
        .await
        .unwrap();
    let group = state.db.create_group("team").await.unwrap();
    state.db.add_group_member(group.id, bob.id).await.unwrap();

    // Member and administrator may see the roster.
    assert_eq!(
        get_status(
            &app,
            "/api/groups/team/members",
            Some(&basic("bob", "pw123456"))
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(
            &app,
            "/api/groups/team/members",
            Some(&basic("alice", PASS))
        )
        .await,
        StatusCode::OK
    );
    // A non-member, non-admin may not.
    assert_eq!(
        get_status(
            &app,
            "/api/groups/team/members",
            Some(&basic("mallory", "pw123456"))
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // Unknown group is still 404.
    assert_eq!(
        get_status(
            &app,
            "/api/groups/nope/members",
            Some(&basic("alice", PASS))
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn hsts_is_omitted_without_secure_cookies() {
    let (_dir, app) = setup(false).await;
    let response = app
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
    assert!(
        response
            .headers()
            .get("strict-transport-security")
            .is_none()
    );
    // nosniff is still applied.
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}
