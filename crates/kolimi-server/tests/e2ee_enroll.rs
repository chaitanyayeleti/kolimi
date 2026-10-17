//! Multi-device E2EE: client enrollment (RFC 0008).
//!
//! Device A (unlocked) approves device B's enrollment; B unwraps the master
//! key from the transferred blob and syncs using its local device file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

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
        token: None,
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

    // Device B: start the enrollment and get the code to display.
    let enroll_config = config(&server.url, device_b.path(), None);
    let pending = kolimi_sync::start_enrollment(&enroll_config, "laptop")
        .await
        .unwrap();
    let id = pending.id();
    let code = pending.details.code.clone();

    // Device A: fetch the pending enrollment and compare the code.
    let pending_a = kolimi_sync::pending_enrollment(&approve_config, id)
        .await
        .unwrap();
    assert_eq!(pending_a.name, "laptop");
    assert_eq!(pending_a.code, code, "both devices must show the same code");
    assert_eq!(pending_a.fingerprint, pending.details.fingerprint);

    // Device B waits for approval (spawned; it polls until approved).
    let finish = tokio::spawn({
        let config = enroll_config.clone();
        async move { kolimi_sync::finish_enrollment(&config, &pending).await }
    });

    // Device A approves only after confirming the code.
    let name = kolimi_sync::approve_device(&approve_config, id, &code)
        .await
        .unwrap();
    assert_eq!(name, "laptop");

    // Device B finishes and persists its device file.
    let enrolled_id = finish.await.unwrap().unwrap();
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

    // Clean up the local enrollment and its OS-keystore entry, if the
    // `keystore` feature stored the key there.
    assert!(kolimi_sync::forget_device(device_b.path()).unwrap());
}

#[tokio::test]
async fn enrollment_code_mismatch_is_refused() {
    let server = start_server().await;
    let device_a = tempfile::tempdir().unwrap();
    let approve_config = config(&server.url, device_a.path(), Some(passphrase_options()));
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&approve_config, &keyring).await.unwrap();
    kolimi_sync::publish_identity(&approve_config)
        .await
        .unwrap();

    let device_b = tempfile::tempdir().unwrap();
    let enroll_config = config(&server.url, device_b.path(), None);
    let pending = kolimi_sync::start_enrollment(&enroll_config, "laptop")
        .await
        .unwrap();
    let id = pending.id();

    // Approving with a code that does not match the device's key (exactly what
    // a server-side key substitution produces) is refused.
    let error = kolimi_sync::approve_device(&approve_config, id, "0000-0000-0000")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("code mismatch"), "{error}");

    // The enrollment is untouched, and the correct code is accepted.
    let still_pending = kolimi_sync::pending_enrollment(&approve_config, id)
        .await
        .unwrap();
    assert_eq!(still_pending.code, pending.details.code);
    kolimi_sync::approve_device(&approve_config, id, &pending.details.code)
        .await
        .unwrap();
}
