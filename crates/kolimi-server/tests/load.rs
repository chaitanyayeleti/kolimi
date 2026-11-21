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
async fn concurrent_webdav_writes_and_browse_stay_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let server = start(state).await;
    let client = reqwest::Client::new();

    const WORKERS: usize = 16;
    const ROUNDS: usize = 10;
    let mut tasks = Vec::with_capacity(WORKERS);
    for worker in 0..WORKERS {
        let client = client.clone();
        let url = server.url.clone();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(ROUNDS * 3);
            let mut errors = 0u32;
            for round in 0..ROUNDS {
                let started = Instant::now();
                let put = client
                    .put(format!("{url}/dav/load-{worker}-{round}.txt"))
                    .basic_auth("alice", Some(PASS))
                    .body(format!("worker {worker} round {round}"))
                    .send()
                    .await
                    .unwrap();
                if put.status() != reqwest::StatusCode::CREATED {
                    errors += 1;
                }
                samples.push(started.elapsed());

                let started = Instant::now();
                let get = client
                    .get(format!("{url}/dav/load-{worker}-{round}.txt"))
                    .basic_auth("alice", Some(PASS))
                    .send()
                    .await
                    .unwrap();
                if get.status() != reqwest::StatusCode::OK {
                    errors += 1;
                }
                samples.push(started.elapsed());

                let started = Instant::now();
                let browse = client
                    .get(format!("{url}/api/browse?path=/"))
                    .basic_auth("alice", Some(PASS))
                    .send()
                    .await
                    .unwrap();
                if browse.status() != reqwest::StatusCode::OK {
                    errors += 1;
                }
                samples.push(started.elapsed());
            }
            (samples, errors)
        }));
    }

    let mut samples = Vec::new();
    let mut errors = 0u32;
    for task in tasks {
        let (mut worker_samples, worker_errors) = task.await.unwrap();
        samples.append(&mut worker_samples);
        errors += worker_errors;
    }
    samples.sort();
    let p95 = samples[(samples.len() as f64 * 0.95).floor() as usize];
    println!(
        "{WORKERS} clients x {ROUNDS} rounds: p95 {p95:?}, {} requests, {errors} errors",
        samples.len()
    );
    assert_eq!(errors, 0, "mixed concurrent load returned errors");
    assert!(p95 < Duration::from_secs(5), "p95 {p95:?} exceeded 5 s");
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

#[tokio::test]
#[ignore = "soak gate; run in release mode"]
async fn hundred_thousand_files_and_multi_client_soak() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    let user = state
        .db
        .create_user("alice", &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let root = state.db.root_node(user.id).await.unwrap();
    let now = kolimi_db::now_millis();

    // Seed 100k files and one change-feed row each in one transaction. The
    // HTTP path is what this gate measures, so skip the per-event audit rows
    // that the normal VFS path would add.
    const FILES: usize = 100_000;
    let seeding = Instant::now();
    let mut tx = state.db.pool().begin().await.unwrap();
    for index in 0..FILES {
        let name = format!("f-{index:06}.txt");
        sqlx::query(
            "INSERT INTO nodes
                 (user_id, parent_id, name, kind, content_id, size, created_at, modified_at)
             VALUES (?, ?, ?, 'file', NULL, 1, ?, ?)",
        )
        .bind(user.id)
        .bind(root.id)
        .bind(&name)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO changes (user_id, path, from_path, op, content_id, size, modified_at)
             VALUES (?, ?, NULL, 'upsert', NULL, 1, ?)",
        )
        .bind(user.id)
        .bind(format!("/{name}"))
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    println!("seeded {FILES} files + changes in {:?}", seeding.elapsed());

    let server = start(state).await;

    // Full 100k-entry tree walk, 1000 per page.
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
    println!("100k tree walk ({entries} entries): {tree_time:?}");
    assert!(entries >= FILES);
    assert!(
        tree_time < Duration::from_secs(60),
        "100k tree walk took {tree_time:?}"
    );

    // Full 100k-entry change feed, 1000 per page.
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
    let feed_time = started.elapsed();
    println!("100k change feed ({changes} events): {feed_time:?}");
    assert!(changes >= FILES);
    assert!(
        feed_time < Duration::from_secs(60),
        "100k change feed took {feed_time:?}"
    );

    // 16 clients read tiny pages while 8 of them also write.
    const CLIENTS: usize = 16;
    const ROUNDS: usize = 10;
    let client = reqwest::Client::new();
    let mut tasks = Vec::with_capacity(CLIENTS);
    for worker in 0..CLIENTS {
        let client = client.clone();
        let url = server.url.clone();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(ROUNDS * 2);
            let mut errors = 0u32;
            for round in 0..ROUNDS {
                let started = Instant::now();
                let browse = client
                    .get(format!("{url}/api/browse?path=/&limit=100"))
                    .basic_auth("alice", Some(PASS))
                    .send()
                    .await
                    .unwrap();
                if browse.status() != reqwest::StatusCode::OK {
                    errors += 1;
                }
                samples.push(started.elapsed());

                let started = Instant::now();
                let changes = client
                    .get(format!("{url}/api/sync/changes?since=0&limit=100"))
                    .basic_auth("alice", Some(PASS))
                    .send()
                    .await
                    .unwrap();
                if changes.status() != reqwest::StatusCode::OK {
                    errors += 1;
                }
                samples.push(started.elapsed());

                if worker < 8 {
                    let put = client
                        .put(format!("{url}/dav/soak-{worker}-{round}.txt"))
                        .basic_auth("alice", Some(PASS))
                        .body("soak")
                        .send()
                        .await
                        .unwrap();
                    if put.status() != reqwest::StatusCode::CREATED {
                        errors += 1;
                    }
                }
            }
            (samples, errors)
        }));
    }
    let mut samples = Vec::new();
    let mut errors = 0u32;
    for task in tasks {
        let (mut worker_samples, worker_errors) = task.await.unwrap();
        samples.append(&mut worker_samples);
        errors += worker_errors;
    }
    samples.sort();
    let p95 = samples[(samples.len() as f64 * 0.95).floor() as usize];
    println!(
        "{CLIENTS} clients x {ROUNDS} rounds at 100k files: p95 {p95:?}, {} reads, {errors} errors",
        samples.len()
    );
    assert_eq!(errors, 0, "multi-client soak returned errors");
    assert!(
        p95 < Duration::from_millis(500),
        "multi-client p95 {p95:?} exceeded 500 ms"
    );

    server.handle.abort();
}
