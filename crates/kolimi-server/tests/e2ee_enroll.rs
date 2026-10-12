//! Multi-device E2EE: client enrollment (RFC 0008).
//!
//! Device A (unlocked) approves device B's enrollment; B unwraps the master
//! key from the transferred blob and syncs using its local device file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::time::Duration;

use kolimi_auth::password::hash_password;
use kolimi_crypto::Argon2Params;
use kolimi_server::{AppState, build_app};
use kolimi_sync::{E2eeOptions, SyncConfig, create_keyring_with_params, upload_keyring};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "e2ee passphrase 123";
const ORIGIN: &str = "http://localhost:8080";

struct Server {
    url: String,
    _dir: tempfile::TempDir,
    _handle: tokio::task::JoinHandle<()>,
}

async fn start_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server {
        url: format!("http://{addr}"),
        _dir: dir,
        _handle: handle,
    }
}

fn fast_params() -> Argon2Params {
    Argon2Params {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn config(server: &str, local: &Path, e2ee: Option<E2eeOptions>) -> SyncConfig {
    SyncConfig {
        server: server.to_string(),
        username: "alice".to_string(),
        password: PASS.to_string(),
        local_dir: local.to_path_buf(),
        e2ee,
    }
}

fn passphrase_options() -> E2eeOptions {
    E2eeOptions {
        passphrase: Some(E2EE_PASS.to_string()),
        recovery_code: None,
        prf_secret: None,
        encrypted_roots: vec!["Private".to_string()],
    }
}

async fn pending_enrollments(server: &str) -> serde_json::Value {
    let response = reqwest::Client::new()
        .get(format!("{server}/api/e2ee/enrollments"))
        .basic_auth("alice", Some(PASS))
        .send()
        .await
        .unwrap();
    response.json().await.unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn device_enrollment_transfers_the_master_key() {
    let server = start_server().await;
    let device_a = tempfile::tempdir().unwrap();
    let device_b = tempfile::tempdir().unwrap();

    // Device A: set up E2EE (keyring + identity) with a passphrase.
    let approve_config = config(&server.url, device_a.path(), Some(passphrase_options()));
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&approve_config, &keyring).await.unwrap();
    kolimi_sync::publish_identity(&approve_config)
        .await
        .unwrap();

    // Device B enrolls (spawned; it polls until approved).
    let enroll_config = config(&server.url, device_b.path(), None);
    let enroll = tokio::spawn({
        let config = enroll_config.clone();
        async move { kolimi_sync::enroll_device(&config, "laptop").await }
    });

    // Device A sees the pending enrollment and approves it.
    let id = loop {
        let body = pending_enrollments(&server.url).await;
        if let Some(item) = body["enrollments"].as_array().and_then(|list| list.first()) {
            break item["id"].as_i64().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let name = kolimi_sync::approve_device(&approve_config, id)
        .await
        .unwrap();
    assert_eq!(name, "laptop");

    // Device B finishes and persists its device file.
    let enrolled_id = enroll.await.unwrap().unwrap();
    assert_eq!(enrolled_id, id);
    assert!(device_b.path().join(".kolimi").join("device.json").exists());

    // Device B now syncs using the device file — no passphrase.
    let unlocked = config(
        &server.url,
        device_b.path(),
        Some(E2eeOptions {
            passphrase: None,
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: vec!["Private".to_string()],
        }),
    );
    let report = kolimi_sync::sync_once(&unlocked).await.unwrap();
    assert_eq!(report.pushed, 0);
}
