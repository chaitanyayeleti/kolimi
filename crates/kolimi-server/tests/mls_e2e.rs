//! End-to-end MLS group share: device key packages, Welcome join, exporter
//! agreement, and a writer updating the epoch-bound share keyring.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_mls::SHARE_KEYRING_EXPORTER;
use kolimi_mls::client::{Device, Group};
use kolimi_mls::keyring::{ShareKeyring, decrypt, encrypt};
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
    for user in ["alice", "bob"] {
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
async fn mls_group_share_roundtrip_and_writer_keyring() {
    let (_dir, _state, app) = setup().await;

    // Alice owns /Team and shares it with bob as a writer.
    let (status, _) = send(&app, "MKCOL", "/dav/Team", "alice", None, None).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, share) = send(
        &app,
        "POST",
        "/api/shares",
        "alice",
        Some(
            json!({ "path": "/Team", "kind": "user", "recipient": "bob", "permission": "write" })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{share}");

    // Both devices publish key packages.
    let alice = Device::new(b"alice@laptop").unwrap();
    let bob = Device::new(b"bob@phone").unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/key-packages",
        "alice",
        Some(
            json!({
                "device_id": "alice-laptop",
                "payload": STANDARD.encode(alice.key_package().unwrap()),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/key-packages",
        "bob",
        Some(
            json!({
                "device_id": "bob-phone",
                "payload": STANDARD.encode(bob.key_package().unwrap()),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Alice fetches bob's public key package from the server.
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
    let bob_key_package = STANDARD
        .decode(packages["packages"][0]["payload"].as_str().unwrap())
        .unwrap();

    // Alice initializes the node group and adds bob.
    let group_id = [9u8; 32];
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/group?path=%2FTeam",
        "alice",
        Some(
            json!({ "group_id": STANDARD.encode(group_id) })
                .to_string()
                .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut alice_group = Group::create(&alice, &group_id).unwrap();
    let (welcome, commit) = alice_group.add(&alice, &bob_key_package).unwrap();
    assert_eq!(alice_group.epoch(), 1);
    let (status, sent) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FTeam",
        "alice",
        Some(
            json!({
                "epoch": 1,
                "kind": "commit",
                "payload": STANDARD.encode(&commit),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let (status, _) = send(
        &app,
        "POST",
        "/api/mls/messages?path=%2FTeam",
        "alice",
        Some(
            json!({
                "epoch": 1,
                "kind": "welcome",
                "payload": STANDARD.encode(&welcome),
            })
            .to_string()
            .into_bytes(),
        ),
        Some("application/json"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Bob follows the messages, joins from the Welcome, and agrees on the
    // epoch exporter.
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
    let welcome_message = group["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["kind"] == "welcome")
        .unwrap();
    let welcome_bytes = STANDARD
        .decode(welcome_message["payload"].as_str().unwrap())
        .unwrap();
    let bob_group = Group::join(&bob, &welcome_bytes).unwrap();
    assert_eq!(bob_group.epoch(), 1);

    let alice_export = alice_group
        .export(&alice, SHARE_KEYRING_EXPORTER, 32)
        .unwrap();
    let bob_export = bob_group.export(&bob, SHARE_KEYRING_EXPORTER, 32).unwrap();
    assert_eq!(alice_export, bob_export);
    let alice_secret: [u8; 32] = alice_export.try_into().unwrap();
    let bob_secret: [u8; 32] = bob_export.try_into().unwrap();

    // Alice publishes the first keyring with one file key.
    let mut keyring = ShareKeyring::new();
    keyring.insert("docs/a.txt", &[1u8; 32]);
    let blob = encrypt(&alice_secret, &group_id, 1, &keyring).unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FTeam&if_epoch=1",
        "alice",
        Some(blob),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Bob (a writer) reads it and adds his own file key in a new keyring.
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
    let payload = STANDARD
        .decode(group["keyring"]["payload"].as_str().unwrap())
        .unwrap();
    let opened = decrypt(&bob_secret, &group_id, 1, &payload).unwrap();
    assert_eq!(opened, keyring);
    let mut updated = opened;
    updated.insert("docs/b.txt", &[2u8; 32]);
    let blob = encrypt(&bob_secret, &group_id, 1, &updated).unwrap();
    let (status, _) = send(
        &app,
        "PUT",
        "/api/mls/keyring?path=%2FShared%20with%20me%2FTeam&if_epoch=1",
        "bob",
        Some(blob),
        Some("application/octet-stream"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Alice sees both file keys.
    let (status, group) = send(
        &app,
        "GET",
        "/api/mls/group?path=%2FTeam",
        "alice",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let payload = STANDARD
        .decode(group["keyring"]["payload"].as_str().unwrap())
        .unwrap();
    let opened = decrypt(&alice_secret, &group_id, 1, &payload).unwrap();
    assert_eq!(opened, updated);
    assert!(opened.get("docs/b.txt").is_some());
}
