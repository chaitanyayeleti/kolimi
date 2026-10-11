//! M5 integration tests: sandboxed previews and crash isolation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use image::{ImageFormat, RgbImage};
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use tower::ServiceExt;

const ALICE: &str = "alice";
const BOB: &str = "bob";
const PASS: &str = "test password 123";
const ORIGIN: &str = "http://localhost:8080";

struct TestServer {
    app: Router,
    _dir: tempfile::TempDir,
}

async fn setup() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let mut state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    // Integration tests must run the real server binary as the worker.
    state.preview_worker = PathBuf::from(env!("CARGO_BIN_EXE_kolimi-server"));
    for user in [ALICE, BOB] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state.clone());
    TestServer { app, _dir: dir }
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

async fn put(server: &TestServer, username: &str, path: &str, data: &[u8]) -> StatusCode {
    send(&server.app, request("PUT", path, username, Some(data)))
        .await
        .0
}

fn preview_request(path: &str, size: u32) -> String {
    format!("/api/preview?path={}&size={size}", path.replace('/', "%2F"))
}

fn png(width: u32, height: u32) -> Vec<u8> {
    let image = RgbImage::from_fn(width, height, |x, y| {
        image::Rgb([(x % 256) as u8, (y % 256) as u8, 64])
    });
    let mut out = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
        .unwrap();
    out
}

#[tokio::test]
async fn produces_sandboxed_image_thumbnails() {
    let server = setup().await;
    let source = png(320, 240);
    assert_eq!(
        put(&server, ALICE, "/dav/pic.png", &source).await,
        StatusCode::CREATED
    );

    let (status, headers, body) = send(
        &server.app,
        request("GET", &preview_request("/pic.png", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "image/png");
    let decoded = image::load_from_memory_with_format(&body, ImageFormat::Png).unwrap();
    assert!(decoded.width() <= 64 && decoded.height() <= 64);
    assert_eq!(decoded.width(), 64);
    assert_eq!(decoded.height(), 48);
}

#[tokio::test]
async fn worker_crash_does_not_affect_the_server() {
    let server = setup().await;
    // A file that claims to be a PNG but is not: the sandboxed worker
    // exits unsuccessfully; the request fails cleanly.
    assert_eq!(
        put(
            &server,
            ALICE,
            "/dav/broken.png",
            b"this is not a png at all"
        )
        .await,
        StatusCode::CREATED
    );
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/broken.png", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // The server is unaffected and keeps serving previews and traffic.
    let (status, _, _) = send(&server.app, request("GET", "/healthz", ALICE, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        put(&server, ALICE, "/dav/good.png", &png(32, 32)).await,
        StatusCode::CREATED
    );
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/good.png", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn text_previews_and_unsupported_types() {
    let server = setup().await;
    assert_eq!(
        put(&server, ALICE, "/dav/notes.txt", b"hello preview world").await,
        StatusCode::CREATED
    );
    let (status, headers, body) = send(
        &server.app,
        request("GET", &preview_request("/notes.txt", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    assert!(String::from_utf8_lossy(&body).starts_with("hello preview"));

    assert_eq!(
        put(&server, ALICE, "/dav/data.bin", b"\x00\x01\x02").await,
        StatusCode::CREATED
    );
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/data.bin", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/folder", ALICE, None)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/folder", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn previews_respect_permissions_and_size_caps() {
    let server = setup().await;
    assert_eq!(
        put(&server, ALICE, "/dav/private.png", &png(16, 16)).await,
        StatusCode::CREATED
    );
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/private.png", 64), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Over the input cap (20 MiB): rejected before the worker starts.
    let huge = vec![0u8; 21 * 1024 * 1024];
    assert_eq!(
        put(&server, ALICE, "/dav/huge.png", &huge).await,
        StatusCode::CREATED
    );
    let (status, _, _) = send(
        &server.app,
        request("GET", &preview_request("/huge.png", 64), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
