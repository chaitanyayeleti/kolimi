//! CLI migration of legacy flat manifests into the fanout layout.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use kolimi_auth::password::hash_password;
use kolimi_server::AppState;

const PASS: &str = "manifest pass 123";
const ORIGIN: &str = "http://localhost:8080";

#[tokio::test]
async fn cli_migrate_manifests_moves_flat_blobs() {
    let data = tempfile::tempdir().unwrap();
    let state = AppState::init(data.path(), false, ORIGIN).await.unwrap();
    let alice = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    state
        .vfs
        .put_bytes(alice.id, "/file.txt", b"migrate me")
        .await
        .unwrap();
    let manifest = state.vfs.manifest_of(alice.id, "/file.txt").await.unwrap();
    let hex = manifest.content_id().to_hex();
    let manifests = data
        .path()
        .join("blobs")
        .join("users")
        .join(alice.id.to_string())
        .join("manifests");
    let legacy = manifests.join(&hex);
    let fanout = manifests.join(&hex[..2]).join(&hex[2..4]).join(&hex);
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::rename(&fanout, &legacy).unwrap();
    assert!(legacy.exists() && !fanout.exists());

    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["migrate-manifests", "--data"])
        .arg(data.path())
        .env("KOLIMI_DATA", data.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("migrated 1 legacy manifests"), "{stdout}");
    assert!(!legacy.exists());
    assert!(fanout.exists());
}
