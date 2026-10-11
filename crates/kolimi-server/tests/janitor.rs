//! M2 integration test: the janitor's incremental BLAKE3 scrubber.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, janitor};

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

fn find_chunk(root: &Path) -> PathBuf {
    let mut stack = vec![root.join("blobs/users")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.components().any(|c| c.as_os_str() == "chunks") {
                return path;
            }
        }
    }
    panic!("no chunk found under {root:?}");
}

#[tokio::test]
async fn janitor_scrubs_and_audits_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    let user = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    state
        .vfs
        .put_bytes(user.id, "/note.txt", b"scrub target bytes")
        .await
        .unwrap();

    // A clean pass verifies the chunk and the manifest.
    let report = janitor::run_once(&state, kolimi_db::now_millis())
        .await
        .unwrap();
    assert!(report.scrubbed >= 2, "{report:?}");
    assert_eq!(report.corrupt, 0, "{report:?}");

    // Corrupt the stored chunk: the next pass detects and audits it.
    let chunk = find_chunk(dir.path());
    let mut bytes = std::fs::read(&chunk).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&chunk, &bytes).unwrap();

    let report = janitor::run_once(&state, kolimi_db::now_millis())
        .await
        .unwrap();
    assert_eq!(report.corrupt, 1, "{report:?}");

    let entries = state.db.audit_list(50, None).await.unwrap();
    let corrupt = entries
        .iter()
        .find(|entry| entry.action == "scrub.corrupt")
        .expect("corruption audited");
    assert!(corrupt.actor.as_deref() == Some("janitor"));
}
