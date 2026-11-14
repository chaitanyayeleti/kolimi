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
async fn commits_and_welcomes_must_use_the_atomic_endpoint() {
    let (_dir, _state, app) = setup().await;
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let group_id = STANDARD.encode([7u8; 16]);
    let (status, body) = send(
        &app,
        "PUT",
        "/api/mls/group?path=/Team",
        "alice",
        Some(json!({ "group_id": group_id }).to_string().into_bytes()),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for kind in ["commit", "welcome"] {
        let (status, body) = send(
            &app,
            "POST",
            "/api/mls/messages?path=/Team",
            "alice",
            Some(
                json!({
                    "epoch": 1,
                    "kind": kind,
                    "payload": STANDARD.encode(b"x"),
                })
                .to_string()
                .into_bytes(),
            ),
            Some("application/json"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind}: {body}");
    }

    // Proposals at the current epoch still work.
    let (status, body) = send(
        &app,
        "POST",
        "/api/mls/messages?path=/Team",
        "alice",
        Some(
            json!({
                "epoch": 0,
                "kind": "proposal",
                "payload": STANDARD.encode(b"x"),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn keyring_writes_require_a_matching_revision() {
    let (_dir, _state, app) = setup().await;
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/group?path=/Team",
        "alice",
        Some(
            json!({ "group_id": STANDARD.encode([5u8; 16]) })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Omitting if_revision must not fall back to an unconditional write.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=/Team&if_epoch=0",
        "alice",
        Some(b"first".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=/Team&if_epoch=0&if_revision=0",
        "alice",
        Some(b"first".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A stale revision loses instead of overwriting newer keys.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=/Team&if_epoch=0&if_revision=0",
        "alice",
        Some(b"stale".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=/Team&if_epoch=0&if_revision=1",
        "alice",
        Some(b"second".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn key_package_consumption_is_scoped_to_the_group() {
    let (_dir, _state, app) = setup().await;
    let mut ids = std::collections::HashMap::new();
    for (user, device) in [("bob", "bob-dev"), ("carol", "carol-dev")] {
        let (status, _) = send(
            &app,
            "PUT",
            "/api/mls/key-packages",
            user,
            Some(
                json!({
                    "device_id": device,
                    "device_name": device,
                    "payload": STANDARD.encode(format!("package-{device}").as_bytes()),
                })
                .to_string()
                .into_bytes(),
            ),
            Some("application/json"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = send(
            &app,
            "GET",
            &format!("/api/mls/key-packages/{user}"),
            "alice",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        ids.insert(user, body["packages"][0]["id"].as_i64().unwrap());
    }

    // Alice owns Team and shares it with Bob only.
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        "POST",
        "/api/shares",
        "alice",
        Some(
            json!({
                "path": "/Team",
                "kind": "user",
                "recipient": "bob",
                "permission": "read",
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Carol has no access to Team, so her package cannot be consumed there.
    let (status, body) = send(
        &app,
        "POST",
        "/api/mls/key-packages/consume",
        "alice",
        Some(
            json!({ "path": "/Team", "ids": [ids["carol"]] })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bob already has access (the add flow creates the share first).
    let (status, body) = send(
        &app,
        "POST",
        "/api/mls/key-packages/consume",
        "alice",
        Some(
            json!({ "path": "/Team", "ids": [ids["bob"]] })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // A non-member cannot reach the group path at all.
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/key-packages/consume",
        "carol",
        Some(
            json!({ "path": "/Shared with me/Team", "ids": [ids["bob"]] })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mls_device_roster_lists_metadata_and_removes_packages() {
    let (_dir, _state, app) = setup().await;

    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/key-packages",
        "bob",
        Some(
            json!({
                "device_id": "bob-laptop",
                "device_name": "Bob's laptop",
                "signature_key": STANDARD.encode(b"public-signature-key"),
                "payload": STANDARD.encode(b"key-package"),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, roster) = send(&app, "GET", "/api/mls/devices", "bob", None, None).await;
    assert_eq!(status, StatusCode::OK, "{roster}");
    assert_eq!(roster["devices"].as_array().unwrap().len(), 1);
    assert_eq!(roster["devices"][0]["device_id"], "bob-laptop");
    assert_eq!(roster["devices"][0]["device_name"], "Bob's laptop");
    assert_eq!(
        roster["devices"][0]["signature_key"],
        STANDARD.encode(b"public-signature-key")
    );
    assert!(roster["devices"][0]["last_seen_at"].as_i64().unwrap() > 0);

    // Another account cannot see Bob's device in its own roster.
    let (status, other) = send(&app, "GET", "/api/mls/devices", "carol", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(other["devices"].as_array().unwrap().is_empty(), "{other}");

    // The per-user roster requires a share relationship. Alice shares a
    // folder with Bob first; Carol still gets a 404.
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        "POST",
        "/api/shares",
        "alice",
        Some(
            json!({
                "path": "/Team",
                "kind": "user",
                "recipient": "bob",
                "permission": "read",
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(&app, "GET", "/api/mls/devices/bob", "carol", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, public) = send(&app, "GET", "/api/mls/devices/bob", "alice", None, None).await;
    assert_eq!(status, StatusCode::OK, "{public}");
    assert_eq!(public["devices"][0]["device_id"], "bob-laptop");
    assert_eq!(
        public["devices"][0]["signature_key"],
        STANDARD.encode(b"public-signature-key")
    );
    assert!(public["devices"][0]["last_seen_at"].is_null(), "{public}");

    let (status, _) = send(
        &app,
        "DELETE",
        "/api/mls/devices?device_id=bob-laptop",
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, roster) = send(&app, "GET", "/api/mls/devices", "bob", None, None).await;
    assert!(roster["devices"].as_array().unwrap().is_empty(), "{roster}");
    let (_, packages) = send(
        &app,
        "GET",
        "/api/mls/key-packages/bob",
        "alice",
        None,
        None,
    )
    .await;
    assert!(
        packages["packages"].as_array().unwrap().is_empty(),
        "{packages}"
    );
}

#[tokio::test]
async fn group_revocations_are_visible_and_clearable() {
    let (_dir, _state, app) = setup().await;
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
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
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/group?path=%2FTeam",
        "alice",
        Some(
            json!({ "group_id": STANDARD.encode([9u8; 32]) })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let revocation = json!({ "signature_key": STANDARD.encode(b"removed-signature") })
        .to_string()
        .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/revocations?path=%2FTeam",
        "alice",
        Some(revocation.clone()),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FTeam",
        "alice",
        None,
        None,
    )
    .await;
    assert_eq!(group["revocations"].as_array().unwrap().len(), 1, "{group}");
    assert_eq!(
        group["revocations"][0]["signature_key"],
        STANDARD.encode(b"removed-signature")
    );

    // A read member cannot add or clear revocations.
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/revocations?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(revocation),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        "DELETE",
        &format!(
            "/api/mls/revocations?path=%2FShared%20with%20me%2FTeam&signature_key={}",
            STANDARD.encode(b"removed-signature")
        ),
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = send(
        &app,
        "DELETE",
        &format!(
            "/api/mls/revocations?path=%2FTeam&signature_key={}",
            STANDARD.encode(b"removed-signature")
        ),
        "alice",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FTeam",
        "alice",
        None,
        None,
    )
    .await;
    assert!(
        group["revocations"].as_array().unwrap().is_empty(),
        "{group}"
    );
}

#[tokio::test]
async fn revocations_are_owner_or_self_only() {
    let (_dir, _state, app) = setup().await;
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/group?path=%2FTeam",
        "alice",
        Some(
            json!({ "group_id": STANDARD.encode([4u8; 16]) })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &app,
        "POST",
        "/api/shares",
        "alice",
        Some(
            json!({
                "path": "/Team",
                "kind": "user",
                "recipient": "bob",
                "permission": "write",
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    for (user, device, signature) in [
        ("bob", "bob-phone", "bob-signature"),
        ("alice", "alice-phone", "alice-signature"),
    ] {
        let (status, _) = send(
            &app,
            "PUT",
            "/api/mls/key-packages",
            user,
            Some(
                json!({
                    "device_id": device,
                    "device_name": device,
                    "signature_key": STANDARD.encode(signature.as_bytes()),
                    "payload": STANDARD.encode(b"package"),
                })
                .to_string()
                .into_bytes(),
            ),
            Some("application/json"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    // Bob may self-revoke a device in his own roster...
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/revocations?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(
            json!({ "signature_key": STANDARD.encode(b"bob-signature") })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // ...but not an arbitrary key or Alice's key.
    for signature in ["victim-signature", "alice-signature"] {
        let body = json!({ "signature_key": STANDARD.encode(signature.as_bytes()) })
            .to_string()
            .into_bytes();
        let (status, _) = send(
            &app,
            "POST",
            "/api/mls/revocations?path=%2FShared%20with%20me%2FTeam",
            "bob",
            Some(body),
            Some("application/json"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{signature}");
    }

    // Clearing a revocation is owner-only.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!(
            "/api/mls/revocations?path=%2FShared%20with%20me%2FTeam&signature_key={}",
            STANDARD.encode(b"bob-signature")
        ),
        "bob",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        "DELETE",
        &format!(
            "/api/mls/revocations?path=%2FTeam&signature_key={}",
            STANDARD.encode(b"bob-signature")
        ),
        "alice",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
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
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/commit?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(
            json!({
                "epoch": 1,
                "commit": STANDARD.encode(b"commit"),
                "welcome": STANDARD.encode(b"welcome"),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Owner commits epoch 1. The commit and its Welcome are one atomic
    // append, so a concurrent committer cannot advance the epoch between
    // them and leave the new device without a Welcome.
    let commit = json!({
        "epoch": 1,
        "commit": STANDARD.encode(b"commit"),
        "welcome": STANDARD.encode(b"welcome"),
    })
    .to_string()
    .into_bytes();
    let (status, sent) = send(
        &app,
        "POST",
        "/api/mls/commit?path=%2FTeam",
        "alice",
        Some(commit),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["seq"], 1);
    assert_eq!(sent["welcome_seq"], 2);

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
    assert_eq!(group["messages"].as_array().unwrap().len(), 2);
    assert_eq!(group["messages"][0]["kind"], "commit");
    assert_eq!(group["messages"][1]["kind"], "welcome");

    // Epochs cannot go backwards.
    let old = json!({
        "epoch": 0,
        "commit": STANDARD.encode(b"old"),
    })
    .to_string()
    .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/commit?path=%2FTeam",
        "alice",
        Some(old),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // A commit cannot skip epochs.
    let skip = json!({
        "epoch": 3,
        "commit": STANDARD.encode(b"skip"),
    })
    .to_string()
    .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/commit?path=%2FTeam",
        "alice",
        Some(skip),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Devices report their processed epoch for safe pruning. A read member
    // may report; a non-member may not, and an ahead epoch is rejected.
    let report = json!({ "device_id": "bob-laptop", "epoch": 0 })
        .to_string()
        .into_bytes();
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/epoch?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(report.clone()),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/epoch?path=%2FShared%20with%20me%2FTeam",
        "bob",
        Some(
            json!({ "device_id": "bob-laptop", "epoch": 2 })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/epoch?path=%2FTeam",
        "carol",
        Some(report),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Keyring writes are epoch-guarded.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FTeam&if_epoch=0&if_revision=0",
        "alice",
        Some(b"stale".to_vec()),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FTeam&if_epoch=1&if_revision=0",
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
    assert_eq!(sent["seq"], 3);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FShared%20with%20me%2FTeam&if_epoch=1&if_revision=1",
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
    assert!(
        packages["packages"][0]["expires_at"].as_i64().is_some(),
        "an unexpired package gets the default TTL"
    );
    // The server caps live packages per device (8). The first package above
    // plus seven more fill the pool; the ninth is rejected with 409.
    for _ in 0..7 {
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
    }
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
    assert_eq!(status, StatusCode::CONFLICT);
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
