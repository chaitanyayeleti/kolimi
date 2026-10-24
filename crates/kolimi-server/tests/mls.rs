//! MLS group-state API: ACLs, opaque key packages, ordered messages and
//! the epoch-guarded encrypted share keyring.

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

fn basic(user: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{PASS}")))
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    user: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, basic(user));
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(body.map(Body::from).unwrap_or_else(Body::empty))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn setup() -> (tempfile::TempDir, AppState, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    for user in ["alice", "bob", "carol"] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state.clone());
    (dir, state, app)
}

#[tokio::test]
async fn group_state_acl_epochs_and_share_keyring() {
    let (_dir, _state, app) = setup().await;

    // Alice owns a folder and shares it read-only with bob.
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, share) = send(
        &app,
        "POST",
        "/api/shares",
        "alice",
        Some(
            json!({ "path": "/Team", "kind": "user", "recipient": "bob", "permission": "read" })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{share}");
    let share_id = share["id"].as_i64().unwrap();

    // Only the owner can initialize the MLS group.
    let group_id = STANDARD.encode([7u8; 32]);
    let body = json!({ "group_id": group_id }).to_string().into_bytes();
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/group?path=/Shared%20with%20me%2FTeam",
        "bob",
        Some(body.clone()),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, created) = send(
        &app,
        "PUT",
        "/api/mls/group?path=%2FTeam",
        "alice",
        Some(body),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["epoch"], 0);
    assert_eq!(created["group_id"], group_id);

    // A read share can fetch the group, but cannot append messages.
    let (status, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FShared%20with%20me%2FTeam",
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{group}");
    assert_eq!(group["epoch"], 0);
    assert_eq!(group["messages"].as_array().unwrap().len(), 0);
    assert!(group["keyring"].is_null());

    let message = json!({
        "epoch": 0,
        "kind": "proposal",
        "payload": STANDARD.encode(b"proposal"),
    })
    .to_string()
    .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(message),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Owner commits epoch 1.
    let commit = json!({
        "epoch": 1,
        "kind": "commit",
        "payload": STANDARD.encode(b"commit"),
    })
    .to_string()
    .into_bytes();
    let (status, sent) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FTeam",
        "alice",
        Some(commit),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["seq"], 1);

    let (status, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FShared%20with%20me%2FTeam",
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(group["epoch"], 1);
    assert_eq!(group["messages"].as_array().unwrap().len(), 1);
    assert_eq!(group["messages"][0]["kind"], "commit");

    // Epochs cannot go backwards.
    let old = json!({
        "epoch": 0,
        "kind": "commit",
        "payload": STANDARD.encode(b"old"),
    })
    .to_string()
    .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FTeam",
        "alice",
        Some(old),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A commit cannot skip epochs.
    let skip = json!({
        "epoch": 3,
        "kind": "commit",
        "payload": STANDARD.encode(b"skip"),
    })
    .to_string()
    .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FTeam",
        "alice",
        Some(skip),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Keyring writes are epoch-guarded.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FTeam&if_epoch=0",
        "alice",
        Some(b"stale".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FTeam&if_epoch=1",
        "alice",
        Some(b"keyring-1".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FShared%20with%20me%2FTeam",
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(group["keyring"]["epoch"], 1);
    assert_eq!(group["keyring"]["payload"], STANDARD.encode(b"keyring-1"));

    // Promote bob to write: he can now send messages and update the keyring.
    let (status, _) = send(
        &app,
        "PATCH",
        &format!("/api/shares/{share_id}"),
        "alice",
        Some(json!({ "permission": "write" }).to_string().into_bytes()),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let proposal = json!({
        "epoch": 1,
        "kind": "proposal",
        "payload": STANDARD.encode(b"bob-proposal"),
    })
    .to_string()
    .into_bytes();
    let (status, sent) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(proposal),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["seq"], 2);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FShared%20with%20me%2FTeam&if_epoch=1",
        "bob",
        Some(b"keyring-from-bob".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Key packages are public to authenticated users, and non-members cannot
    // read a group they have no share for.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/key-packages",
        "bob",
        Some(
            json!({ "device_id": "bob-laptop", "payload": STANDARD.encode(b"key-package") })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, packages) = send(
        &app,
        "GET",
        "/api/mls/key-packages/bob",
        "alice",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{packages}");
    assert_eq!(packages["packages"][0]["device_id"], "bob-laptop");
    assert_eq!(
        packages["packages"][0]["payload"],
        STANDARD.encode(b"key-package")
    );
    let (status, _) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FTeam",
        "carol",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
