//! Tier-0 E2EE hardening integration tests.
//!
//! Covers recipient-key pinning (trust on first use) and keyring
//! anti-rollback / anti-downgrade. The enrollment-code ceremony is covered in
//! `e2ee_enroll.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::Path;

use kolimi_auth::password::hash_password;
use kolimi_crypto::Argon2Params;
use kolimi_server::{AppState, build_app};
use kolimi_sync::{
    E2eeOptions, SyncConfig, create_keyring_with_params, known_recipient_keys, publish_identity,
    share_file, sync_once, upload_keyring,
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
        }),
    }
}

async fn setup_keyring(server: &str, username: &str, local: &Path) {
    let config = config(server, username, local);
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config, &keyring).await.unwrap();
    publish_identity(&config).await.unwrap();
}

async fn fetch_keyring(server: &str, username: &str) -> String {
    let response = reqwest::Client::new()
        .get(format!("{server}/api/e2ee/keyring"))
        .basic_auth(username, Some(PASS))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = response.json().await.unwrap();
    body["keyring"].as_str().unwrap().to_string()
}

async fn put_keyring(server: &str, username: &str, keyring: &str) {
    let status = reqwest::Client::new()
        .put(format!("{server}/api/e2ee/keyring"))
        .basic_auth(username, Some(PASS))
        .body(keyring.to_string())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(status, 204);
}

#[tokio::test]
async fn recipient_key_pinning_refuses_a_changed_key() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    let alice = config(&server.url, "alice", &alice_dir);
    std::fs::write(alice_dir.join("Private/secret.bin"), b"pinned secret").unwrap();
    sync_once(&alice).await.unwrap();

    // The first share pins bob's key.
    share_file(&alice, "Private/secret.bin", "bob")
        .await
        .unwrap();
    let pinned = known_recipient_keys(&alice_dir).unwrap();
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].0, "bob");

    // Simulate a server-side key substitution: the pinned key no longer
    // matches what the server offers.
    let pins_path = alice_dir.join(".kolimi").join("known_keys.json");
    let mut pins: BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(&pins_path).unwrap()).unwrap();
    pins.insert("bob".to_string(), "00".repeat(32));
    std::fs::write(&pins_path, serde_json::to_vec(&pins).unwrap()).unwrap();

    let error = share_file(&alice, "Private/secret.bin", "bob")
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("encryption key changed"),
        "{error}"
    );

    // After the operator re-pins (having verified the new fingerprint out of
    // band), sharing works again.
    std::fs::remove_file(&pins_path).unwrap();
    share_file(&alice, "Private/secret.bin", "bob")
        .await
        .unwrap();

    server.handle.abort();
}

#[tokio::test]
async fn keyring_rollback_and_downgrade_are_refused() {
    let server = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("alice");
    std::fs::create_dir_all(&local).unwrap();
    setup_keyring(&server.url, "alice", &local).await;
    let alice = config(&server.url, "alice", &local);

    // A successful unlock records the keyring epoch locally.
    let epoch_path = local.join(".kolimi").join("keyring.epoch");
    let seen: u64 = std::fs::read_to_string(&epoch_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(seen >= 1, "a new keyring is tagged and has an epoch");

    // The server replaying an older keyring is refused.
    std::fs::write(&epoch_path, (seen + 5).to_string()).unwrap();
    let error = publish_identity(&alice).await.unwrap_err();
    assert!(error.to_string().contains("rollback"), "{error}");

    // Downgrading to an untagged keyring is refused as well.
    std::fs::write(&epoch_path, seen.to_string()).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_str(&fetch_keyring(&server.url, "alice").await).unwrap();
    value.as_object_mut().unwrap().remove("mac");
    put_keyring(&server.url, "alice", &value.to_string()).await;
    let error = publish_identity(&alice).await.unwrap_err();
    assert!(error.to_string().contains("downgrade"), "{error}");

    server.handle.abort();
}
