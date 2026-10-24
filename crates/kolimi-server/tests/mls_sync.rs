//! Sync/desktop MLS shares: the owner creates a node group and keyring, the
//! recipient joins from the Welcome on the next sync, and decrypts shared
//! files through the epoch keyring (no per-file X25519 wraps).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use kolimi_auth::password::hash_password;
use kolimi_crypto::Argon2Params;
use kolimi_server::{AppState, build_app};
use kolimi_sync::{
    E2eeOptions, SharePermission, SyncConfig, create_keyring_with_params,
    share_path_with_permission, sync_once, upload_keyring,
};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "e2ee passphrase 123";
const ORIGIN: &str = "http://localhost:8080";

struct Server {
    url: String,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn start_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    for user in ["alice", "bob"] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server {
        url: format!("http://{addr}"),
        _dir: dir,
        handle,
    }
}

fn fast_params() -> Argon2Params {
    Argon2Params {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn config(server: &str, username: &str, local: &Path) -> SyncConfig {
    SyncConfig {
        server: server.to_string(),
        username: username.to_string(),
        password: PASS.to_string(),
        token: None,
        local_dir: local.to_path_buf(),
        e2ee: Some(E2eeOptions {
            passphrase: Some(E2EE_PASS.to_string()),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: vec!["Private".to_string()],
            mls: true,
        }),
    }
}

async fn setup_keyring(server: &str, username: &str, local: &Path) {
    let config = config(server, username, local);
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config, &keyring).await.unwrap();
    kolimi_sync::publish_identity(&config).await.unwrap();
}

async fn get_json(server: &str, username: &str, path: &str) -> (u16, serde_json::Value) {
    let response = reqwest::Client::new()
        .get(format!("{server}{path}"))
        .basic_auth(username, Some(PASS))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
}

fn query(path: &str) -> String {
    path.replace('%', "%25")
        .replace('/', "%2F")
        .replace(' ', "%20")
}

async fn stored_dir(server: &str, username: &str, prefix: &str) -> String {
    let (status, body) = get_json(server, username, "/api/sync/tree?after_id=0&limit=100").await;
    assert_eq!(status, 200, "{body}");
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| {
            entry["kind"] == "dir"
                && entry["path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with(prefix) && path != prefix)
        })
        .and_then(|entry| entry["path"].as_str())
        .map(str::to_string)
        .expect("stored folder")
}

#[tokio::test]
async fn encrypted_folder_share_uses_mls_keyring() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private/Team/Sub")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    let alice = config(&server.url, "alice", &alice_dir);
    let bob = config(&server.url, "bob", &bob_dir);

    // Bob publishes his MLS key package. The owner needs it before sharing.
    sync_once(&bob).await.unwrap();

    std::fs::write(alice_dir.join("Private/Team/a.txt"), b"alpha").unwrap();
    std::fs::write(alice_dir.join("Private/Team/Sub/b.txt"), b"beta").unwrap();
    sync_once(&alice).await.unwrap();

    let wrapped = share_path_with_permission(
        &alice,
        "/",
        "Private/Team",
        kolimi_sync::ShareTarget::User("bob".to_string()),
        SharePermission::Read,
    )
    .await
    .unwrap();
    assert_eq!(wrapped, 0, "MLS shares do not upload per-file wraps");

    // The server has a node group and an epoch-bound keyring. Stored names
    // inside the encrypted root are opaque, so resolve the folder first.
    let stored = stored_dir(&server.url, "alice", "/Private/").await;
    let (status, group) = get_json(
        &server.url,
        "alice",
        &format!("/api/mls/group?path={}", query(&stored)),
    )
    .await;
    assert_eq!(status, 200, "{group}");
    assert!(group["keyring"].is_object(), "{group}");
    let group_id = group["group_id"].as_str().unwrap().to_string();
    assert!(!group_id.is_empty());

    // Bob joins from the Welcome during his next sync and decrypts through
    // the keyring.
    let report = sync_once(&bob).await.unwrap();
    assert!(report.pulled >= 2, "{report:?}");
    assert_eq!(
        std::fs::read(bob_dir.join("Shared with me/Team/a.txt")).unwrap(),
        b"alpha"
    );
    assert_eq!(
        std::fs::read(bob_dir.join("Shared with me/Team/Sub/b.txt")).unwrap(),
        b"beta"
    );

    // Bob now has a local MLS group; a second pass is a no-op.
    assert!(bob_dir.join(".kolimi/mls-state.bin").exists());
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report, Default::default());

    // Alice adds a file; Bob decrypts it through the same keyring update.
    std::fs::write(alice_dir.join("Private/Team/c.txt"), b"gamma").unwrap();
    sync_once(&alice).await.unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert!(report.pulled >= 1, "{report:?}");
    assert_eq!(
        std::fs::read(bob_dir.join("Shared with me/Team/c.txt")).unwrap(),
        b"gamma"
    );

    server.handle.abort();
}

#[tokio::test]
async fn write_recipient_adds_and_edits_files_visible_to_owner() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private/Team")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    let alice = config(&server.url, "alice", &alice_dir);
    let bob = config(&server.url, "bob", &bob_dir);
    sync_once(&bob).await.unwrap();
    std::fs::write(alice_dir.join("Private/Team/a.txt"), b"alpha").unwrap();
    sync_once(&alice).await.unwrap();

    let wrapped = share_path_with_permission(
        &alice,
        "/",
        "Private/Team",
        kolimi_sync::ShareTarget::User("bob".to_string()),
        SharePermission::Write,
    )
    .await
    .unwrap();
    assert_eq!(wrapped, 0);

    // Bob joins and receives the write ACL mount.
    let report = sync_once(&bob).await.unwrap();
    assert!(report.pulled >= 1, "{report:?}");

    // Bob creates a new file and edits the owner's file.
    std::fs::write(bob_dir.join("Shared with me/Team/new.txt"), b"from bob").unwrap();
    std::fs::write(bob_dir.join("Shared with me/Team/a.txt"), b"alpha edited").unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert!(report.pushed >= 2, "{report:?}");

    // Alice pulls both; the editor's node key is not hers, so decryption
    // must go through the MLS keyring.
    let report = sync_once(&alice).await.unwrap();
    assert!(report.pulled >= 2, "{report:?}");
    assert_eq!(
        std::fs::read(alice_dir.join("Private/Team/new.txt")).unwrap(),
        b"from bob"
    );
    assert_eq!(
        std::fs::read(alice_dir.join("Private/Team/a.txt")).unwrap(),
        b"alpha edited"
    );

    // A write recipient can delete a file; the owner follows on pull.
    std::fs::remove_file(bob_dir.join("Shared with me/Team/new.txt")).unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert!(report.removed_remote >= 1, "{report:?}");
    sync_once(&alice).await.unwrap();
    assert!(!alice_dir.join("Private/Team/new.txt").exists());

    server.handle.abort();
}

#[tokio::test]
async fn existing_v1_folder_share_can_be_migrated_to_mls() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private/Team")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    // Alice shares before MLS is enabled: the old per-file wrap path.
    let mut legacy = config(&server.url, "alice", &alice_dir);
    if let Some(e2ee) = legacy.e2ee.as_mut() {
        e2ee.mls = false;
    }
    let bob_legacy = config(&server.url, "bob", &bob_dir);
    sync_once(&bob_legacy).await.unwrap();
    std::fs::write(alice_dir.join("Private/Team/old.txt"), b"legacy").unwrap();
    sync_once(&legacy).await.unwrap();
    let wrapped = share_path_with_permission(
        &legacy,
        "/",
        "Private/Team",
        kolimi_sync::ShareTarget::User("bob".to_string()),
        SharePermission::Read,
    )
    .await
    .unwrap();
    assert!(wrapped >= 1, "legacy share wraps file keys");
    sync_once(&bob_legacy).await.unwrap();

    // Enable MLS and migrate; the recipient keeps reading the same files.
    let alice = config(&server.url, "alice", &alice_dir);
    let migrated = kolimi_sync::migrate_mls_shares(&alice).await.unwrap();
    assert_eq!(migrated.len(), 1, "{migrated:?}");
    let stored = stored_dir(&server.url, "alice", "/Private/").await;
    let (status, group) = get_json(
        &server.url,
        "alice",
        &format!("/api/mls/group?path={}", query(&stored)),
    )
    .await;
    assert_eq!(status, 200, "{group}");
    assert!(group["keyring"].is_object(), "{group}");
    assert_eq!(
        std::fs::read(bob_dir.join("Shared with me/Team/old.txt")).unwrap(),
        b"legacy"
    );

    server.handle.abort();
}
