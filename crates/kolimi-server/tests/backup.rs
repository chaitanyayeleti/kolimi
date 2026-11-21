//! CLI backup: full and incremental copies.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use kolimi_auth::password::hash_password;
use kolimi_server::AppState;

const PASS: &str = "backup pass 123";
const ORIGIN: &str = "http://localhost:8080";

#[tokio::test]
async fn cli_backup_incremental_skips_existing_blobs() {
    let data = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let state = AppState::init(data.path(), false, ORIGIN).await.unwrap();
    let alice = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    state
        .vfs
        .put_bytes(alice.id, "/file.txt", b"hello backup")
        .await
        .unwrap();
    let manifest = state.vfs.manifest_of(alice.id, "/file.txt").await.unwrap();

    let run = |incremental: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kolimi-server"));
        command
            .args(["backup", "--data"])
            .arg(data.path())
            .arg("--to")
            .arg(backup.path());
        if incremental {
            command.arg("--incremental");
        }
        command.env("KOLIMI_DATA", data.path()).output().unwrap()
    };

    let output = run(false);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(backup.path().join("kolimi.db").exists());
    assert!(backup.path().join("blobs/users").exists());

    let output = run(true);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("incremental backup complete"), "{stdout}");
    assert!(stdout.contains("already present"), "{stdout}");

    let restored = kolimi_store::BlobStore::open(backup.path().join("blobs"))
        .await
        .unwrap();
    assert_eq!(
        restored.read_content(alice.id, &manifest).await.unwrap(),
        b"hello backup"
    );
}
