//! M5 integration tests: full-text search over names and content.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app, search_indexer};
use serde_json::Value;
use tower::ServiceExt;

const ALICE: &str = "alice";
const BOB: &str = "bob";
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
    for user in [ALICE, BOB] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state.clone());
    TestServer {
        app,
        state,
        _dir: dir,
    }
}

fn basic(username: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{username}:{PASS}")))
}

fn request(method: &str, uri: &str, username: &str, body: Option<&[u8]>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, basic(username));
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

async fn put(server: &TestServer, username: &str, path: &str, data: &[u8]) -> StatusCode {
    send(&server.app, request("PUT", path, username, Some(data)))
        .await
        .0
}

async fn search(server: &TestServer, username: &str, query: &str) -> (StatusCode, Value) {
    let (status, _, body) = send(
        &server.app,
        request(
            "GET",
            &format!("/api/search?q={}", query.replace(' ', "%20")),
            username,
            None,
        ),
    )
    .await;
    (status, json(&body))
}

async fn index(server: &TestServer) {
    search_indexer::run_once(&server.state).await.unwrap();
}

#[tokio::test]
async fn indexes_names_and_text_content() {
    let server = setup().await;
    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/docs", ALICE, None)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        put(
            &server,
            ALICE,
            "/dav/docs/notes.txt",
            b"the quick brown fox"
        )
        .await,
        StatusCode::CREATED
    );
    // A binary file whose bytes happen to contain the word must not match.
    assert_eq!(
        put(&server, ALICE, "/dav/docs/blob.bin", b"fox\x00\x01binary").await,
        StatusCode::CREATED
    );
    assert_eq!(
        put(
            &server,
            ALICE,
            "/dav/report-quarterly.md",
            b"foxes in the quarterly haystack"
        )
        .await,
        StatusCode::CREATED
    );
    index(&server).await;

    // Content match.
    let (status, body) = search(&server, ALICE, "quick").await;
    assert_eq!(status, StatusCode::OK);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1, "{body}");
    assert_eq!(results[0]["path"], "/docs/notes.txt");
    assert!(results[0]["snippet"].as_str().unwrap().contains("quick"));

    // Name match.
    let (_, body) = search(&server, ALICE, "quarterly").await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    assert_eq!(body["results"][0]["path"], "/report-quarterly.md");

    // Binary content is not indexed.
    let (_, body) = search(&server, ALICE, "binary").await;
    assert!(body["results"].as_array().unwrap().is_empty(), "{body}");

    // Users are isolated.
    let (_, body) = search(&server, BOB, "quick").await;
    assert!(body["results"].as_array().unwrap().is_empty(), "{body}");
}

#[tokio::test]
async fn tracks_deletes_moves_and_directories() {
    let server = setup().await;
    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/projects", ALICE, None)).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        put(&server, ALICE, "/dav/draft.txt", b"revision one").await,
        StatusCode::CREATED
    );
    index(&server).await;

    // Directories are searchable by name.
    let (_, body) = search(&server, ALICE, "projects").await;
    assert_eq!(body["results"][0]["is_dir"], true);

    // Rename: old name disappears, new name appears.
    let (status, _, _) = send(
        &server.app,
        Request::builder()
            .method("MOVE")
            .uri("/dav/draft.txt")
            .header(header::AUTHORIZATION, basic(ALICE))
            .header("destination", "/dav/final.txt")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    index(&server).await;
    let (_, body) = search(&server, ALICE, "draft").await;
    assert!(body["results"].as_array().unwrap().is_empty(), "{body}");
    let (_, body) = search(&server, ALICE, "final").await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);

    // Delete removes it from the index.
    let (status, _, _) = send(
        &server.app,
        request("DELETE", "/dav/final.txt", ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    index(&server).await;
    let (_, body) = search(&server, ALICE, "final").await;
    assert!(body["results"].as_array().unwrap().is_empty(), "{body}");
}

#[tokio::test]
async fn rejects_invalid_queries() {
    let server = setup().await;
    index(&server).await;
    let (status, body) = search(&server, ALICE, "AND OR").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("invalid query"));
}
