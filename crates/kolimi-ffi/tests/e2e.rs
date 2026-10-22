//! The FFI surface end-to-end against an in-process server: E2EE setup,
//! encrypted sync, recovery-code unlock, and failure paths.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kolimi_auth::password::hash_password;
use kolimi_ffi::{FfiSyncConfig, KolimiSync};
use kolimi_server::{AppState, build_app};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "ffi passphrase 123";
const ORIGIN: &str = "http://localhost:8080";

async fn start_server() -> (tempfile::TempDir, String, tokio::task::JoinHandle<()>) {
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
    (dir, format!("http://{addr}"), handle)
}

fn config(
    server: &str,
    local: &std::path::Path,
    passphrase: Option<&str>,
    recovery: Option<&str>,
) -> FfiSyncConfig {
    FfiSyncConfig {
        server: server.to_string(),
        username: "alice".to_string(),
        password: PASS.to_string(),
        token: None,
        local_dir: local.to_string_lossy().to_string(),
        remote: None,
        encrypted_roots: vec!["Private".to_string()],
        e2ee_passphrase: passphrase.map(str::to_string),
        e2ee_recovery_code: recovery.map(str::to_string),
        e2ee_prf_secret: None,
    }
}

#[tokio::test]
async fn e2ee_setup_and_encrypted_sync_through_the_ffi() {
    let (dir, server, handle) = start_server().await;
    let local = dir.path().join("local");
    let mirror = dir.path().join("mirror");
    std::fs::create_dir_all(local.join("Private")).unwrap();
    std::fs::create_dir_all(&mirror).unwrap();
    std::fs::write(local.join("Private/secret.txt"), b"ffi secret").unwrap();
    std::fs::write(local.join("public.txt"), b"plain").unwrap();

    // Setup: returns a formatted recovery code.
    let client = KolimiSync::new(config(&server, &local, None, None));
    let recovery = client.e2ee_setup(E2EE_PASS.to_string()).await.unwrap();
    assert_eq!(recovery.len(), 71, "formatted recovery code");

    // Push with the passphrase.
    let client = KolimiSync::new(config(&server, &local, Some(E2EE_PASS), None));
    let report = client.sync_once().await.unwrap();
    assert_eq!(report.pushed, 2, "{report:?}");

    // Pull with the recovery code into a fresh directory.
    let client = KolimiSync::new(config(&server, &mirror, None, Some(&recovery)));
    let report = client.sync_once().await.unwrap();
    assert_eq!(report.pulled, 2, "{report:?}");
    assert_eq!(
        std::fs::read(mirror.join("Private/secret.txt")).unwrap(),
        b"ffi secret"
    );
    assert_eq!(std::fs::read(mirror.join("public.txt")).unwrap(), b"plain");

    // A second pass is a no-op.
    let report = client.sync_once().await.unwrap();
    assert_eq!(report.pulled, 0);
    assert_eq!(report.pushed, 0);

    handle.abort();
}

#[tokio::test]
async fn wrong_passphrase_fails_with_a_message() {
    let (dir, server, handle) = start_server().await;
    let local = dir.path().join("local");
    std::fs::create_dir_all(local.join("Private")).unwrap();
    std::fs::write(local.join("Private/secret.txt"), b"x").unwrap();

    let client = KolimiSync::new(config(&server, &local, None, None));
    client.e2ee_setup(E2EE_PASS.to_string()).await.unwrap();

    let client = KolimiSync::new(config(&server, &local, Some("wrong passphrase"), None));
    let error = client.sync_once().await.unwrap_err();
    let message = error.to_string();
    assert!(message.contains("passphrase"), "{message}");

    handle.abort();
}
