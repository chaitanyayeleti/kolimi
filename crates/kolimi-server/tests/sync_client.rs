//! M5 integration tests: the desktop sync core against a live server
//! (in-process axum listener on an ephemeral port).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use kolimi_sync::{SyncConfig, sync_once};

const PASS: &str = "sync pass 123";
const ORIGIN: &str = "http://localhost:8080";

struct Server {
    url: String,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
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
        handle,
    }
}

fn config(server: &str, local: &Path) -> SyncConfig {
    SyncConfig {
        server: server.to_string(),
        username: "alice".to_string(),
        password: PASS.to_string(),
        local_dir: local.to_path_buf(),
        e2ee: None,
    }
}

fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn tree(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".kolimi" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    walk(root, root, &mut out);
    out
}

#[tokio::test]
async fn bidirectional_sync_roundtrip_with_conflicts() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");
    let mirror = root.path().join("mirror");
    std::fs::create_dir_all(seed.join("sub")).unwrap();
    std::fs::create_dir_all(&mirror).unwrap();
    std::fs::write(seed.join("a.txt"), b"hello sync").unwrap();
    std::fs::write(seed.join("sub/note.md"), b"# notes\n").unwrap();
    std::fs::write(seed.join("sub/deep.bin"), pseudorandom(1_500_000, 42)).unwrap();

    // Push the seed tree.
    let report = sync_once(&config(&server.url, &seed)).await.unwrap();
    assert_eq!(report.pushed, 3, "{report:?}");

    // Pull it into the mirror; trees must match byte-for-byte.
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.pulled, 3, "{report:?}");
    assert_eq!(tree(&seed), tree(&mirror));

    // A second pass is a no-op in both directions.
    let report = sync_once(&config(&server.url, &seed)).await.unwrap();
    assert_eq!(report, Default::default());
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report, Default::default());

    // Edit, add, and delete in the seed; the mirror follows.
    std::fs::write(seed.join("a.txt"), b"hello sync, edited").unwrap();
    std::fs::write(seed.join("new.txt"), b"fresh file").unwrap();
    std::fs::remove_file(seed.join("sub/note.md")).unwrap();
    let report = sync_once(&config(&server.url, &seed)).await.unwrap();
    assert_eq!(report.pushed, 2, "{report:?}");
    assert_eq!(report.removed_remote, 1, "{report:?}");
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.pulled, 2, "{report:?}");
    assert_eq!(report.removed_local, 1, "{report:?}");
    assert_eq!(tree(&seed), tree(&mirror));

    // Conflict: both sides edit the same file.
    std::fs::write(seed.join("a.txt"), b"server wins").unwrap();
    sync_once(&config(&server.url, &seed)).await.unwrap();
    std::fs::write(mirror.join("a.txt"), b"local edits").unwrap();
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.conflicts, 1, "{report:?}");
    // The server version is in place; the local edit survives as a copy.
    assert_eq!(std::fs::read(mirror.join("a.txt")).unwrap(), b"server wins");
    let conflict_copy = std::fs::read_dir(&mirror)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("a.txt.conflict-")
        })
        .expect("conflict copy");
    assert_eq!(std::fs::read(conflict_copy.path()).unwrap(), b"local edits");

    // Local deletion propagates to the server.
    std::fs::remove_file(mirror.join("new.txt")).unwrap();
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.removed_remote, 1, "{report:?}");
    let report = sync_once(&config(&server.url, &seed)).await.unwrap();
    assert_eq!(report.removed_local, 1, "{report:?}");
    assert!(!seed.join("new.txt").exists());

    server.handle.abort();
}

#[tokio::test]
async fn pulls_delta_chunks_from_the_cache() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");
    let mirror = root.path().join("mirror");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::create_dir_all(&mirror).unwrap();

    // A 6 MiB file, then a small edit near the front.
    let mut data = pseudorandom(6 * 1024 * 1024, 7);
    std::fs::write(seed.join("big.bin"), &data).unwrap();
    sync_once(&config(&server.url, &seed)).await.unwrap();
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.pulled, 1);

    data[0] ^= 0xff;
    std::fs::write(seed.join("big.bin"), &data).unwrap();
    sync_once(&config(&server.url, &seed)).await.unwrap();
    let report = sync_once(&config(&server.url, &mirror)).await.unwrap();
    assert_eq!(report.pulled, 1);
    assert_eq!(std::fs::read(mirror.join("big.bin")).unwrap(), data);

    // The chunk cache was populated and is reused (it holds many chunks).
    let cache = mirror.join(".kolimi/chunks");
    let mut cached = 0;
    for entry in walkdir(&cache) {
        if entry.is_file() {
            cached += 1;
        }
    }
    assert!(cached > 2, "expected cached chunks, found {cached}");

    server.handle.abort();
}

fn walkdir(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walkdir(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
