//! Native sync API tests: delta transfers, change feed, trash, versions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kolimi_auth::password::hash_password;
use kolimi_chunk::{Hash, Manifest, chunker};
use kolimi_server::{AppState, build_app, janitor};
use serde_json::Value;
use tower::ServiceExt;

const USER: &str = "alice";
const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

struct TestServer {
    app: Router,
    state: AppState,
    _dir: tempfile::TempDir,
}

async fn setup() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    state
        .db
        .create_user(USER, &hash_password(PASS).unwrap())
        .await
        .unwrap();
    let app = build_app(state.clone());
    TestServer {
        app,
        state,
        _dir: dir,
    }
}

fn basic(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        STANDARD.encode(format!("{username}:{password}"))
    )
}

fn auth() -> String {
    basic(USER, PASS)
}

fn request(method: &str, uri: &str, body: Option<&[u8]>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, auth());
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/octet-stream");
    }
    builder
        .body(Body::from(body.unwrap_or_default().to_vec()))
        .unwrap()
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn json(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

fn pseudorandom(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

#[tokio::test]
async fn delta_download_and_upload_flow() {
    let server = setup().await;
    let original = pseudorandom(3 * 1024 * 1024);
    let (status, _, _) = send(
        &server.app,
        request("PUT", "/dav/data.bin", Some(&original)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 1. Fetch the manifest.
    let (status, _, body) = send(
        &server.app,
        Request::builder()
            .method("GET")
            .uri("/api/files/manifest?path=/data.bin")
            .header(header::AUTHORIZATION, auth())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let manifest: Manifest = serde_json::from_slice(&body).unwrap();
    assert!(manifest.chunks.len() > 1);
    assert_eq!(manifest.size, original.len() as u64);
    let current = manifest.content_id().to_hex();

    // 2. Fetch only the missing chunks and reassemble.
    let mut assembled = Vec::new();
    for chunk in &manifest.chunks {
        let uri = format!("/api/chunks/{}", chunk.hash.to_hex());
        let (status, _, bytes) = send(&server.app, request("GET", &uri, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(Hash::of(&bytes), chunk.hash);
        assembled.extend_from_slice(&bytes);
    }
    assert_eq!(assembled, original);

    // 3. Edit locally: append bytes, upload only the new chunks, commit.
    let mut edited = original.clone();
    edited.extend_from_slice(&pseudorandom(600 * 1024));
    let new_manifest = Manifest::for_data(&edited);
    let mut uploaded = 0;
    for chunk in &new_manifest.chunks {
        let uri = format!("/api/chunks/{}", chunk.hash.to_hex());
        let (status, _, _) = send(
            &server.app,
            request("PUT", &uri, Some(chunk.data_of(&edited))),
        )
        .await;
        if status == StatusCode::CREATED {
            uploaded += 1;
        } else {
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
    }
    assert!(
        uploaded < new_manifest.chunks.len(),
        "delta upload must reuse existing chunks"
    );

    let commit_uri = format!("/api/files?path=/data.bin&if_content_id={current}");
    let commit_body = serde_json::to_vec(&new_manifest).unwrap();
    let (status, _, body) =
        send(&server.app, request("PUT", &commit_uri, Some(&commit_body))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let committed = json(&body);
    assert_eq!(
        committed["content_id"].as_str().unwrap(),
        new_manifest.content_id().to_hex()
    );

    // 4. WebDAV sees the new content.
    let (status, _, body) = send(&server.app, request("GET", "/dav/data.bin", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, edited);

    // 5. A stale commit is rejected with the current content id.
    let stale_uri = format!("{}x", commit_uri);
    let (status, _, body) = send(&server.app, request("PUT", &stale_uri, Some(&commit_body))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let conflict = json(&body);
    assert_eq!(
        conflict["current_content_id"].as_str().unwrap(),
        new_manifest.content_id().to_hex()
    );
}

trait ChunkData {
    fn data_of<'a>(&'a self, content: &'a [u8]) -> &'a [u8];
}

impl ChunkData for kolimi_chunk::ChunkRef {
    fn data_of<'a>(&'a self, content: &'a [u8]) -> &'a [u8] {
        let chunks = chunker::split(content);
        chunks
            .iter()
            .find(|chunk| chunk.hash == self.hash)
            .expect("chunk must come from this content")
            .data
    }
}

#[tokio::test]
async fn chunk_upload_rejects_hash_mismatch() {
    let server = setup().await;
    let wrong = Hash::of(b"declared content");
    let uri = format!("/api/chunks/{}", wrong.to_hex());
    let (status, _, _) = send(
        &server.app,
        request("PUT", &uri, Some(b"different content")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let invalid = "/api/chunks/not-a-hash";
    let (status, _, _) = send(&server.app, request("GET", invalid, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn chunk_existence_reports_only_missing() {
    let server = setup().await;
    let present = b"present chunk".to_vec();
    let present_hash = Hash::of(&present);
    let (status, _, _) = send(
        &server.app,
        request(
            "PUT",
            &format!("/api/chunks/{}", present_hash.to_hex()),
            Some(&present),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let absent_hash = Hash::of(b"absent chunk");
    let body = serde_json::to_vec(&serde_json::json!({
        "hashes": [present_hash.to_hex(), absent_hash.to_hex()],
    }))
    .unwrap();
    let (status, _, body) = send(
        &server.app,
        Request::builder()
            .method("POST")
            .uri("/api/chunks/exist")
            .header(header::AUTHORIZATION, auth())
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body)["missing"],
        serde_json::json!([absent_hash.to_hex()])
    );
}

#[tokio::test]
async fn change_feed_reports_lifecycle() {
    let server = setup().await;
    send(&server.app, request("PUT", "/dav/a.txt", Some(b"one"))).await;

    let move_request = Request::builder()
        .method("MOVE")
        .uri("/dav/a.txt")
        .header(header::AUTHORIZATION, auth())
        .header("destination", "/dav/b.txt")
        .body(Body::empty())
        .unwrap();
    send(&server.app, move_request).await;
    send(&server.app, request("DELETE", "/dav/b.txt", None)).await;

    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/sync/changes?since=0", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let feed = json(&body);
    let changes = feed["changes"].as_array().unwrap();
    let ops: Vec<&str> = changes.iter().map(|c| c["op"].as_str().unwrap()).collect();
    assert_eq!(ops, vec!["upsert", "move", "delete"]);
    assert_eq!(changes[1]["from_path"].as_str().unwrap(), "/a.txt");
    assert_eq!(changes[1]["path"].as_str().unwrap(), "/b.txt");

    let next_seq = feed["next_seq"].as_i64().unwrap();
    let (_, _, body) = send(
        &server.app,
        request("GET", &format!("/api/sync/changes?since={next_seq}"), None),
    )
    .await;
    assert!(json(&body)["changes"].as_array().unwrap().is_empty());

    let (_, _, body) = send(
        &server.app,
        request("GET", "/api/sync/changes?since=0&limit=1", None),
    )
    .await;
    let feed = json(&body);
    assert_eq!(feed["changes"].as_array().unwrap().len(), 1);
    assert_eq!(feed["has_more"], true);
}

#[tokio::test]
async fn sync_tree_lists_paths_and_kinds() {
    let server = setup().await;
    send(
        &server.app,
        Request::builder()
            .method("MKCOL")
            .uri("/dav/docs")
            .header(header::AUTHORIZATION, auth())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    send(&server.app, request("PUT", "/dav/docs/a.txt", Some(b"x"))).await;

    let (status, _, body) = send(&server.app, request("GET", "/api/sync/tree", None)).await;
    assert_eq!(status, StatusCode::OK);
    let tree = json(&body);
    let entries = tree["entries"].as_array().unwrap();
    let docs = entries
        .iter()
        .find(|entry| entry["path"] == "/docs")
        .expect("docs entry");
    assert_eq!(docs["kind"], "dir");
    let file = entries
        .iter()
        .find(|entry| entry["path"] == "/docs/a.txt")
        .expect("file entry");
    assert_eq!(file["kind"], "file");
    assert_eq!(file["size"], 1);
}

#[tokio::test]
async fn trash_restore_and_purge_via_api() {
    let server = setup().await;
    send(
        &server.app,
        request("PUT", "/dav/trash-me.txt", Some(b"bye")),
    )
    .await;
    send(&server.app, request("DELETE", "/dav/trash-me.txt", None)).await;

    let (status, _, body) = send(&server.app, request("GET", "/api/trash", None)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = json(&body);
    let entry = &entries.as_array().unwrap()[0];
    assert_eq!(entry["name"], "trash-me.txt");
    assert_eq!(entry["original_path"], "/trash-me.txt");
    let id = entry["id"].as_i64().unwrap();

    let (status, _, _) = send(
        &server.app,
        request("POST", &format!("/api/trash/{id}/restore"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = send(&server.app, request("GET", "/dav/trash-me.txt", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"bye");

    // Trash it again and purge it permanently.
    send(&server.app, request("DELETE", "/dav/trash-me.txt", None)).await;
    let id = json(
        &send(&server.app, request("GET", "/api/trash", None))
            .await
            .2,
    )
    .as_array()
    .unwrap()[0]["id"]
        .as_i64()
        .unwrap();
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/trash/{id}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, body) = send(&server.app, request("GET", "/api/trash", None)).await;
    assert!(json(&body).as_array().unwrap().is_empty());
}

#[tokio::test]
async fn versions_list_and_restore_via_api() {
    let server = setup().await;
    send(
        &server.app,
        request("PUT", "/dav/poem.txt", Some(b"first draft")),
    )
    .await;
    send(
        &server.app,
        request("PUT", "/dav/poem.txt", Some(b"second draft")),
    )
    .await;

    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/versions?path=/poem.txt", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let versions = json(&body);
    let version = &versions.as_array().unwrap()[0];
    assert_eq!(version["size"], 11);
    let version_id = version["id"].as_i64().unwrap();

    let restore = Request::builder()
        .method("POST")
        .uri(format!("/api/versions/{version_id}/restore"))
        .header(header::AUTHORIZATION, auth())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"path":"/poem.txt"}"#))
        .unwrap();
    let (status, _, _) = send(&server.app, restore).await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, body) = send(&server.app, request("GET", "/dav/poem.txt", None)).await;
    assert_eq!(body, b"first draft");
}

#[tokio::test]
async fn manifest_endpoints() {
    let server = setup().await;
    send(
        &server.app,
        request("PUT", "/dav/m.bin", Some(b"manifest me")),
    )
    .await;

    let (_, _, body) = send(
        &server.app,
        request("GET", "/api/files/manifest?path=/m.bin", None),
    )
    .await;
    let manifest: Manifest = serde_json::from_slice(&body).unwrap();

    let uri = format!("/api/manifests/{}", manifest.content_id().to_hex());
    let (status, _, body) = send(&server.app, request("GET", &uri, None)).await;
    assert_eq!(status, StatusCode::OK);
    let fetched: Manifest = serde_json::from_slice(&body).unwrap();
    assert_eq!(fetched.content_id(), manifest.content_id());

    let (status, _, _) = send(&server.app, request("GET", "/api/manifests/zzz", None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let missing = Hash::of(b"never stored");
    let (status, _, _) = send(
        &server.app,
        request("GET", &format!("/api/manifests/{}", missing.to_hex()), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn janitor_purges_expired_trash_and_reclaims_blobs() {
    let server = setup().await;
    send(
        &server.app,
        request("PUT", "/dav/old.txt", Some(b"forget me")),
    )
    .await;
    send(&server.app, request("DELETE", "/dav/old.txt", None)).await;

    // Run the janitor far in the future: trash retention has elapsed.
    let far_future = kolimi_db::now_millis() + janitor::TRASH_RETENTION_MILLIS + 60_000;
    let report = janitor::run_once(&server.state, far_future).await.unwrap();
    assert!(report.purged_trash >= 1);
    assert!(
        server
            .state
            .vfs
            .trash(user_id(&server).await)
            .await
            .unwrap()
            .is_empty()
    );

    // Blobs were protected by the GC grace period...
    let user = user_id(&server).await;
    let (chunks, _) = server.state.vfs.verify_all(user).await.unwrap();
    assert_eq!(chunks, 0, "purged trash must not keep content referenced");

    // ...and a no-grace sweep reclaims them.
    let swept = server
        .state
        .vfs
        .collect_garbage(user, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert!(swept.manifests_deleted >= 1);
}

async fn user_id(server: &TestServer) -> i64 {
    server.state.db.find_user(USER).await.unwrap().unwrap().id
}
