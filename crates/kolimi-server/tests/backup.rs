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
    let offsite = tempfile::tempdir().unwrap();

    let run = |incremental: bool, offsite: Option<&std::path::Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kolimi-server"));
        command
            .args(["backup", "--data"])
            .arg(data.path())
            .arg("--to")
            .arg(backup.path());
        if incremental {
            command.arg("--incremental");
        }
        if let Some(offsite) = offsite {
            command.arg("--offsite").arg(offsite);
        }
        command.env("KOLIMI_DATA", data.path()).output().unwrap()
    };

    let output = run(false, None);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(backup.path().join("kolimi.db").exists());
    assert!(backup.path().join("blobs/users").exists());
    assert!(backup.path().join("kolimi-backup.json").exists());

    let output = run(true, Some(offsite.path()));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("incremental backup complete"), "{stdout}");
    assert!(stdout.contains("already present"), "{stdout}");
    assert!(stdout.contains("offsite mirror complete"), "{stdout}");

    let restored = kolimi_store::BlobStore::open(backup.path().join("blobs"))
        .await
        .unwrap();
    assert_eq!(
        restored.read_content(alice.id, &manifest).await.unwrap(),
        b"hello backup"
    );
    let offsite_store = kolimi_store::BlobStore::open(offsite.path().join("blobs"))
        .await
        .unwrap();
    assert_eq!(
        offsite_store
            .read_content(alice.id, &manifest)
            .await
            .unwrap(),
        b"hello backup"
    );
    assert!(offsite.path().join("kolimi.db").exists());
    assert!(offsite.path().join("kolimi-backup.json").exists());
}

#[tokio::test]
async fn cli_backup_retention_prunes_only_marked_backups() {
    let data = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();
    let state = AppState::init(data.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();

    for (name, created_at) in [("old-1", 1), ("old-2", 2), ("old-3", 3)] {
        let dir = backups.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("kolimi-backup.json"),
            serde_json::json!({
                "format": "kolimi-backup",
                "version": 1,
                "created_at": created_at,
            })
            .to_string(),
        )
        .unwrap();
    }
    // A directory without the marker is never touched.
    std::fs::create_dir_all(backups.path().join("keepme")).unwrap();

    let target = backups.path().join("new");
    let output = Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["backup", "--data"])
        .arg(data.path())
        .arg("--to")
        .arg(&target)
        .args(["--retain", "2"])
        .env("KOLIMI_DATA", data.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pruned 2 old backup(s)"), "{stdout}");

    assert!(target.exists());
    assert!(
        backups.path().join("old-3").exists(),
        "newest old backup kept"
    );
    assert!(!backups.path().join("old-2").exists());
    assert!(!backups.path().join("old-1").exists());
    assert!(backups.path().join("keepme").exists());
}
