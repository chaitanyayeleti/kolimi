//! Phase 3 admin integration tests: group management and the audit log API.

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
    request_with_reauth(app, method, uri, auth, None, body).await
}

async fn request_with_reauth(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    reauth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(value) = reauth {
        builder = builder.header("X-Reauth-Token", value);
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

/// Performs an admin group mutation with a fresh single-use proof.
async fn admin_request(
    app: &Router,
    state: &AppState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let alice_id = state.db.find_user("alice").await.unwrap().unwrap().id;
    let token = state.reauth.issue(alice_id).unwrap();
    request_with_reauth(
        app,
        method,
        uri,
        Some(&basic("alice", PASS)),
        Some(&token),
        body,
    )
    .await
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
    state
        .db
        .create_user("bob", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    (dir, state, app)
}

#[tokio::test]
async fn groups_crud_is_admin_only_and_audited() {
    let (_dir, state, app) = setup().await;
    let alice = basic("alice", PASS);
    let bob = basic("bob", PASS);

    // Every group-management route refuses a regular user.
    for (method, uri, body) in [
        ("GET", "/api/groups", None),
        (
            "POST",
            "/api/groups",
            Some(json!({ "username": "team", "name": "team" })),
        ),
        ("DELETE", "/api/groups/team", None),
        ("POST", "/api/groups/team/members/bob", None),
        ("DELETE", "/api/groups/team/members/bob", None),
        ("GET", "/api/audit", None),
        ("GET", "/api/audit/verify", None),
    ] {
        let (status, _) = request(&app, method, uri, Some(&bob), body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }

    // An administrator session without a fresh proof is refused too.
    let (status, _) = request(
        &app,
        "POST",
        "/api/groups",
        Some(&alice),
        Some(json!({ "name": "nope" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Create, duplicate, and list.
    let (status, _) = admin_request(
        &app,
        &state,
        "POST",
        "/api/groups",
        Some(json!({ "name": "  " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, created) = admin_request(
        &app,
        &state,
        "POST",
        "/api/groups",
        Some(json!({ "name": "team" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "team");
    assert_eq!(created["members"], json!([]));

    let (status, _) = admin_request(
        &app,
        &state,
        "POST",
        "/api/groups",
        Some(json!({ "name": "team" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, list) = request(&app, "GET", "/api/groups", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let groups = list["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "team");
    assert_eq!(groups[0]["members"], json!([]));

    // Membership is idempotent, visible in the overview, and removable.
    for _ in 0..2 {
        let (status, _) =
            admin_request(&app, &state, "POST", "/api/groups/team/members/bob", None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let (status, list) = request(&app, "GET", "/api/groups", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["groups"][0]["members"], json!(["bob"]));

    let (status, _) =
        admin_request(&app, &state, "DELETE", "/api/groups/team/members/bob", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Removing a non-member is still a success.
    let (status, _) =
        admin_request(&app, &state, "DELETE", "/api/groups/team/members/bob", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) =
        admin_request(&app, &state, "POST", "/api/groups/nope/members/bob", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = admin_request(
        &app,
        &state,
        "POST",
        "/api/groups/team/members/nobody",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleting the group is audited under the real administrator.
    let (status, _) = admin_request(&app, &state, "DELETE", "/api/groups/team", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = admin_request(&app, &state, "DELETE", "/api/groups/team", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let entries = state.db.audit_list(100, None).await.unwrap();
    let alice_id = state.db.find_user("alice").await.unwrap().unwrap().id;
    let actions: Vec<&str> = entries.iter().map(|entry| entry.action.as_str()).collect();
    assert!(actions.contains(&"group.add"), "{actions:?}");
    assert!(actions.contains(&"group.member_add"), "{actions:?}");
    assert!(actions.contains(&"group.member_remove"), "{actions:?}");
    assert!(actions.contains(&"group.delete"), "{actions:?}");
    for action in [
        "group.add",
        "group.member_add",
        "group.member_remove",
        "group.delete",
    ] {
        let entry = entries.iter().find(|entry| entry.action == action).unwrap();
        assert_eq!(entry.actor_id, Some(alice_id));
        assert_eq!(entry.actor.as_deref(), Some("alice"));
        assert_eq!(entry.subject, "team");
    }
}

#[tokio::test]
async fn audit_api_filters_pages_and_verifies() {
    let (_dir, state, app) = setup().await;
    let alice = basic("alice", PASS);

    for name in ["team", "ops"] {
        let (status, _) = admin_request(
            &app,
            &state,
            "POST",
            "/api/groups",
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) =
        admin_request(&app, &state, "POST", "/api/groups/team/members/bob", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, audit) = request(&app, "GET", "/api/audit", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    let entries = audit["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["action"], "group.member_add");
    assert!(entries[0]["details"].is_object(), "{audit}");
    assert!(entries[0].get("hash").is_none());
    assert!(entries[0].get("prev_hash").is_none());

    let (status, filtered) = request(
        &app,
        "GET",
        "/api/audit?action=group.add",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let entries = filtered["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| entry["action"] == "group.add"));

    let (status, filtered) =
        request(&app, "GET", "/api/audit?subject=team", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(filtered["entries"].as_array().unwrap().len(), 2);

    // A one-row page exposes a cursor that advances without repeating rows.
    let (status, first) = request(
        &app,
        "GET",
        "/api/audit?action=group.add&limit=1",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["has_more"], true);
    let first_id = first["entries"][0]["id"].as_i64().unwrap();
    let cursor = first["next_before"].as_i64().unwrap();
    assert_eq!(cursor, first_id);
    let (status, second) = request(
        &app,
        "GET",
        &format!("/api/audit?action=group.add&limit=1&before={cursor}"),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["has_more"], false);
    assert_ne!(second["entries"][0]["id"].as_i64().unwrap(), first_id);

    let (status, verify) = request(&app, "GET", "/api/audit/verify", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{verify}");
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["entries"], 3);
    assert!(verify["first_bad"].is_null());
    assert!(verify["anchor"].is_null());

    // A broken chain is reported, not hidden.
    sqlx::query("UPDATE audit_log SET subject = 'tampered' WHERE id = 1")
        .execute(state.db.pool())
        .await
        .unwrap();
    let (status, verify) = request(&app, "GET", "/api/audit/verify", Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(verify["ok"], false);
    assert_eq!(verify["first_bad"], 1);
}
