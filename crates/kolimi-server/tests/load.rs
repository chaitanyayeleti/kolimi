//! Performance gates (run with `--ignored`, in release mode, in CI).
//!
//! Targets from the roadmap §7:
//! - 10k changed-metadata files: delta read < 5 s
//! - metadata API p95 < 10 ms (asserted with a CI margin; the measured
//!   value is printed)
//! - release binary < 50 MB (checked by the CI script)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};

const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

struct Server {
    url: String,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn start(state: AppState) -> Server {
    let app = build_app(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Server {
        url: format!("http://{addr}"),
        _dir: tempfile::tempdir().unwrap(),
        handle,
    }
}

async fn get_json(url: &str) -> (u16, serde_json::Value) {
    let response = reqwest::Client::new()
        .get(url)
        .basic_auth("alice", Some(PASS))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let value = response.json().await.unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
#[ignore = "performance gate; run in release mode"]
async fn ten_thousand_metadata_changes_under_five_seconds() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    let user = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let root = state.db.root_node(user.id).await.unwrap();

    // Seed 10k files through the normal node + change-feed paths.
    let now = kolimi_db::now_millis();
    let seeding = Instant::now();
    for i in 0..10_000 {
        let node = state
            .db
            .insert_node(
                user.id,
                Some(root.id),
                &format!("file-{i:05}.txt"),
                "file",
                None,
                12,
                now,
            )
            .await
            .unwrap();
        state
            .db
            .record_change(
                user.id,
                &format!("/file-{i:05}.txt"),
                "upsert",
                None,
                12,
                now,
                None,
            )
            .await
            .unwrap();
        std::hint::black_box(node.id);
    }
    println!("seeding 10k changes took {:?}", seeding.elapsed());

    let server = start(state).await;

    // Full tree walk, 1000 entries per page.
    let started = Instant::now();
    let mut after = 0i64;
    let mut entries = 0usize;
    loop {
        let (status, body) = get_json(&format!(
            "{}/api/sync/tree?after_id={after}&limit=1000",
            server.url
        ))
        .await;
        assert_eq!(status, 200);
        entries += body["entries"].as_array().unwrap().len();
        after = body["last_id"].as_i64().unwrap();
        if !body["has_more"].as_bool().unwrap_or(false) {
            break;
        }
    }
    let tree_time = started.elapsed();
    assert!(entries >= 10_000, "walked {entries} entries");
    println!("tree walk of {entries} entries: {tree_time:?}");
    assert!(
        tree_time < Duration::from_secs(5),
        "tree walk took {tree_time:?} (target < 5 s)"
    );

    // Delta: page through the whole change feed like a sync client.
    let started = Instant::now();
    let mut since = 0i64;
    let mut changes = 0usize;
    loop {
        let (status, body) = get_json(&format!(
            "{}/api/sync/changes?since={since}&limit=1000",
            server.url
        ))
        .await;
        assert_eq!(status, 200);
        changes += body["changes"].as_array().unwrap().len();
        since = body["next_seq"].as_i64().unwrap();
        if !body["has_more"].as_bool().unwrap_or(false) {
            break;
        }
    }
    let delta_time = started.elapsed();
    println!("change feed of {changes} events: {delta_time:?}");
    assert!(changes >= 10_000, "changes: {changes}");
    assert!(
        delta_time < Duration::from_secs(5),
        "change feed took {delta_time:?} (target < 5 s)"
    );

    server.handle.abort();
}

#[tokio::test]
#[ignore = "performance gate; run in release mode"]
async fn metadata_p95_under_target() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    let user = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let root = state.db.root_node(user.id).await.unwrap();
    let now = kolimi_db::now_millis();
    for i in 0..500 {
        state
            .db
            .insert_node(
                user.id,
                Some(root.id),
                &format!("entry-{i:03}.txt"),
                "file",
                None,
                1,
                now,
            )
            .await
            .unwrap();
    }
    let server = start(state).await;

    // Warm up, then measure.
    let _ = get_json(&format!("{}/api/browse?path=/", server.url)).await;
    let mut samples = Vec::with_capacity(200);
    for _ in 0..200 {
        let started = Instant::now();
        let (status, body) = get_json(&format!("{}/api/browse?path=/", server.url)).await;
        assert_eq!(status, 200);
        // 500 entries plus the four default folders every account has.
        assert_eq!(
            body["entries"].as_array().unwrap().len(),
            500 + kolimi_db::DEFAULT_FOLDERS.len()
        );
        samples.push(started.elapsed());
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95) / 100];
    println!("browse 500 entries: p50 {p50:?}, p95 {p95:?}");
    assert!(
        p95 < Duration::from_millis(25),
        "metadata p95 {p95:?} exceeds the CI budget (target < 10 ms)"
    );

    server.handle.abort();
}
