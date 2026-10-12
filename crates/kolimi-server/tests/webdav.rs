//! End-to-end HTTP tests: WebDAV methods, session API, and security cases.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kolimi_auth::{
    passkey::{CreationChallengeResponse, RequestChallengeResponse},
    password::hash_password,
};
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

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

fn request(method: &str, uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::empty()).unwrap()
}

fn request_with_body(
    method: &str,
    uri: &str,
    auth: &str,
    content_type: &str,
    body: &[u8],
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body.to_vec()))
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

fn cookie_pair(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let pair = value.split(';').next()?;
            let (key, _) = pair.split_once('=')?;
            (key == name).then(|| pair.to_string())
        })
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let pair = cookie_pair(headers, name)?;
    pair.split_once('=').map(|(_, value)| value.to_string())
}

#[tokio::test]
async fn unauthenticated_requests_are_rejected_with_basic_challenge() {
    let server = setup().await;
    let (status, headers, _) = send(&server.app, request("PROPFIND", "/dav/", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("Basic"))
    );
}

#[tokio::test]
async fn put_get_roundtrip_with_conditional_requests() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    let (status, headers, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/hello.txt", &auth, "text/plain", b"hello world"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let etag = headers
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (status, headers, body) =
        send(&server.app, request("GET", "/dav/hello.txt", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello world");
    assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "text/plain");
    assert_eq!(headers.get(header::ETAG).unwrap().to_str().unwrap(), etag);

    let mut conditional = request("GET", "/dav/hello.txt", Some(&auth));
    conditional
        .headers_mut()
        .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
    let (status, _, body) = send(&server.app, conditional).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
    assert!(body.is_empty());

    let head = request("HEAD", "/dav/hello.txt", Some(&auth));
    let (status, headers, body) = send(&server.app, head).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONTENT_LENGTH).unwrap(), "11");
    assert!(body.is_empty());
}

#[tokio::test]
async fn encrypted_files_are_refused_over_dav() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    // Create a file, then mark it end-to-end encrypted the way the sync
    // client does: store a wrapped key for the node.
    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/secret.bin",
            &auth,
            "application/octet-stream",
            b"ciphertext",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PUT",
            "/api/files/key?path=/secret.bin",
            &auth,
            "application/octet-stream",
            b"wrapped-key-bytes",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The server holds no keys, so it must not serve ciphertext as a file.
    let (status, _, _) = send(&server.app, request("GET", "/dav/secret.bin", Some(&auth))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = send(&server.app, request("HEAD", "/dav/secret.bin", Some(&auth))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And it must not let plaintext overwrite an encrypted file.
    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/secret.bin", &auth, "text/plain", b"plaintext"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // COPY/MOVE of encrypted content is refused in both directions.
    let mut copy = request("COPY", "/dav/secret.bin", Some(&auth));
    copy.headers_mut()
        .insert("destination", "/dav/copy.bin".parse().unwrap());
    let (status, _, _) = send(&server.app, copy).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut move_req = request("MOVE", "/dav/plain.txt", Some(&auth));
    move_req
        .headers_mut()
        .insert("destination", "/dav/secret.bin".parse().unwrap());
    // A plaintext source cannot overwrite the encrypted destination.
    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/plain.txt", &auth, "text/plain", b"plain"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(&server.app, move_req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn range_requests_serve_partial_content() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let data = b"0123456789abcdefghij";
    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/range.bin",
            &auth,
            "application/octet-stream",
            data,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // A full response advertises byte-range support.
    let (status, headers, got) =
        send(&server.app, request("GET", "/dav/range.bin", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::ACCEPT_RANGES).unwrap(), "bytes");
    assert_eq!(got, data);

    // Bounded range.
    let mut req = request("GET", "/dav/range.bin", Some(&auth));
    req.headers_mut()
        .insert(header::RANGE, "bytes=2-5".parse().unwrap());
    let (status, headers, got) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(got, b"2345");
    assert_eq!(headers.get(header::CONTENT_RANGE).unwrap(), "bytes 2-5/20");
    assert_eq!(headers.get(header::CONTENT_LENGTH).unwrap(), "4");

    // Suffix range.
    let mut req = request("GET", "/dav/range.bin", Some(&auth));
    req.headers_mut()
        .insert(header::RANGE, "bytes=-3".parse().unwrap());
    let (status, headers, got) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(got, b"hij");
    assert_eq!(
        headers.get(header::CONTENT_RANGE).unwrap(),
        "bytes 17-19/20"
    );

    // Start past the end is unsatisfiable.
    let mut req = request("GET", "/dav/range.bin", Some(&auth));
    req.headers_mut()
        .insert(header::RANGE, "bytes=99-".parse().unwrap());
    let (status, headers, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(headers.get(header::CONTENT_RANGE).unwrap(), "bytes */20");

    // HEAD carries range headers but no body.
    let mut req = request("HEAD", "/dav/range.bin", Some(&auth));
    req.headers_mut()
        .insert(header::RANGE, "bytes=0-3".parse().unwrap());
    let (status, headers, got) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(got.is_empty());
    assert_eq!(headers.get(header::CONTENT_LENGTH).unwrap(), "4");
}

#[tokio::test]
async fn range_spans_multiple_chunks() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/big.bin",
            &auth,
            "application/octet-stream",
            &data,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let start = 1_000_000u64;
    let end = 1_200_000u64;
    let mut req = request("GET", "/dav/big.bin", Some(&auth));
    req.headers_mut().insert(
        header::RANGE,
        format!("bytes={start}-{}", end - 1).parse().unwrap(),
    );
    let (status, headers, got) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(got, data[start as usize..end as usize]);
    assert_eq!(
        headers
            .get(header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap(),
        format!("bytes {start}-{}/{size}", end - 1, size = data.len())
    );
}

#[tokio::test]
async fn lock_enforces_writes_and_unlock_releases() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/locked.txt", &auth, "text/plain", b"v1"),
    )
    .await;

    let lockinfo = r#"<?xml version="1.0"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype><d:owner>alice</d:owner></d:lockinfo>"#;
    let lock = |uri: &str, body: &str| {
        Request::builder()
            .method("LOCK")
            .uri(uri)
            .header(header::AUTHORIZATION, &auth)
            .header(header::CONTENT_TYPE, "application/xml")
            .header("timeout", "Second-600")
            .body(Body::from(body.to_string()))
            .unwrap()
    };

    let (status, headers, body) = send(&server.app, lock("/dav/locked.txt", lockinfo)).await;
    assert_eq!(status, StatusCode::OK);
    let token = headers
        .get("lock-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(token.starts_with('<') && token.ends_with('>'), "{token}");
    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("<d:activelock>"), "{xml}");
    assert!(xml.contains("alice"), "{xml}");

    // Writes without the token are refused with 423.
    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/locked.txt", &auth, "text/plain", b"v2"),
    )
    .await;
    assert_eq!(status, StatusCode::LOCKED);

    // Supplying the token in `If` allows the write.
    let mut req = request_with_body("PUT", "/dav/locked.txt", &auth, "text/plain", b"v2");
    req.headers_mut()
        .insert("if", format!("({token})").parse().unwrap());
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A second exclusive lock conflicts.
    let (status, _, _) = send(&server.app, lock("/dav/locked.txt", lockinfo)).await;
    assert_eq!(status, StatusCode::LOCKED);

    // lockdiscovery reports it.
    let pf = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:lockdiscovery/></d:prop></d:propfind>"#;
    let (_, _, body) = send(
        &server.app,
        request_with_body(
            "PROPFIND",
            "/dav/locked.txt",
            &auth,
            "application/xml",
            pf.as_bytes(),
        ),
    )
    .await;
    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("<d:activelock>"), "{xml}");

    // UNLOCK releases it, and writes flow again.
    let req = Request::builder()
        .method("UNLOCK")
        .uri("/dav/locked.txt")
        .header(header::AUTHORIZATION, &auth)
        .header("lock-token", &token)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/locked.txt", &auth, "text/plain", b"v3"),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn lock_on_unmapped_url_creates_then_put() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let lockinfo = r#"<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#;

    let req = Request::builder()
        .method("LOCK")
        .uri("/dav/fresh.txt")
        .header(header::AUTHORIZATION, &auth)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::from(lockinfo))
        .unwrap();
    let (status, headers, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::CREATED);
    let token = headers
        .get("lock-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/fresh.txt", &auth, "text/plain", b"body"),
    )
    .await;
    assert_eq!(status, StatusCode::LOCKED);

    let mut req = request_with_body("PUT", "/dav/fresh.txt", &auth, "text/plain", b"body");
    req.headers_mut()
        .insert("if", format!("({token})").parse().unwrap());
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::CREATED);

    // OPTIONS advertises DAV class 2.
    let (status, headers, _) = send(&server.app, request("OPTIONS", "/dav", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get("dav").unwrap().to_str().unwrap().contains('2'));
}

#[tokio::test]
async fn conditional_put_with_unknown_token_is_412() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/c.txt", &auth, "text/plain", b"x"),
    )
    .await;
    let mut req = request_with_body("PUT", "/dav/c.txt", &auth, "text/plain", b"y");
    req.headers_mut()
        .insert("if", "(<opaquelocktoken:bogus>)".parse().unwrap());
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn indirect_lock_refresh_via_member() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(&server.app, request("MKCOL", "/dav/coll", Some(&auth))).await;
    send(
        &server.app,
        request_with_body("PUT", "/dav/coll/f.txt", &auth, "text/plain", b"x"),
    )
    .await;

    let info = r#"<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>"#;
    let req = Request::builder()
        .method("LOCK")
        .uri("/dav/coll")
        .header(header::AUTHORIZATION, &auth)
        .header(header::CONTENT_TYPE, "application/xml")
        .header("depth", "infinity")
        .body(Body::from(info))
        .unwrap();
    let (status, headers, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::OK);
    let token = headers
        .get("lock-token")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Refresh the collection lock indirectly through a member.
    let req = Request::builder()
        .method("LOCK")
        .uri("/dav/coll/f.txt")
        .header(header::AUTHORIZATION, &auth)
        .header(header::CONTENT_TYPE, "application/xml")
        .header("if", format!("({token})"))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn propfind_exposes_quota_properties() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/fill.bin",
            &auth,
            "application/octet-stream",
            b"0123456789",
        ),
    )
    .await;

    let body = r#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:quota-used-bytes/><d:quota-available-bytes/></d:prop></d:propfind>"#;
    let (status, _, out) = send(
        &server.app,
        request_with_body(
            "PROPFIND",
            "/dav/",
            &auth,
            "application/xml",
            body.as_bytes(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    let xml = String::from_utf8(out).unwrap();
    assert!(
        xml.contains("<d:quota-used-bytes>10</d:quota-used-bytes>"),
        "{xml}"
    );
}

#[tokio::test]
async fn propfind_lists_files_with_properties() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/report.txt", &auth, "text/plain", b"data"),
    )
    .await;

    let (status, headers, body) =
        send(&server.app, request("PROPFIND", "/dav/", Some(&auth))).await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/xml; charset=utf-8"
    );

    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("<d:href>/dav/</d:href>"));
    assert!(xml.contains("<d:href>/dav/report.txt</d:href>"));
    assert!(xml.contains("<d:displayname>report.txt</d:displayname>"));
    assert!(xml.contains("<d:getcontentlength>4</d:getcontentlength>"));
    assert!(xml.contains("<d:collection/>"));
}

#[tokio::test]
async fn propfind_depth_zero_returns_only_target() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(&server.app, request("MKCOL", "/dav/docs", Some(&auth))).await;

    let mut req = request("PROPFIND", "/dav/docs", Some(&auth));
    req.headers_mut().insert("depth", "0".parse().unwrap());
    let (status, _, body) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("<d:href>/dav/docs</d:href>"));
    assert_eq!(xml.matches("<d:response>").count(), 1);
}

#[tokio::test]
async fn propfind_specific_props_and_unknown_prop_404() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"xy"),
    )
    .await;

    let body =
        br#"<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
        <d:prop><d:displayname/><oc:checksums/></d:prop></d:propfind>"#;
    let (status, _, body) = send(
        &server.app,
        request_with_body("PROPFIND", "/dav/a.txt", &auth, "application/xml", body),
    )
    .await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("<d:displayname>a.txt</d:displayname>"));
    assert!(xml.contains("<d:checksums/>"));
    assert!(xml.contains("<d:status>HTTP/1.1 404 Not Found</d:status>"));
}

#[tokio::test]
async fn propfind_infinity_depth_is_forbidden() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let mut req = request("PROPFIND", "/dav/", Some(&auth));
    req.headers_mut()
        .insert("depth", "infinity".parse().unwrap());
    let (status, _, _) = send(&server.app, req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn propfind_missing_target_is_404() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let (status, _, _) = send(&server.app, request("PROPFIND", "/dav/nope", Some(&auth))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mkcol_semantics() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/docs", Some(&auth))).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/docs", Some(&auth))).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    let (status, _, _) = send(&server.app, request("MKCOL", "/dav/nope/docs", Some(&auth))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let with_body = request_with_body("MKCOL", "/dav/doc2", &auth, "text/plain", b"x");
    let (status, _, _) = send(&server.app, with_body).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn move_and_copy_semantics() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"a"),
    )
    .await;
    send(
        &server.app,
        request_with_body("PUT", "/dav/target.txt", &auth, "text/plain", b"t"),
    )
    .await;

    let move_req = Request::builder()
        .method("MOVE")
        .uri("/dav/a.txt")
        .header(header::AUTHORIZATION, &auth)
        .header("destination", "http://localhost/dav/moved.txt")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, move_req).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(&server.app, request("GET", "/dav/a.txt", Some(&auth))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, body) = send(&server.app, request("GET", "/dav/moved.txt", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"a");

    let no_overwrite = Request::builder()
        .method("MOVE")
        .uri("/dav/moved.txt")
        .header(header::AUTHORIZATION, &auth)
        .header("destination", "http://localhost/dav/target.txt")
        .header("overwrite", "F")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, no_overwrite).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let copy_req = Request::builder()
        .method("COPY")
        .uri("/dav/moved.txt")
        .header(header::AUTHORIZATION, &auth)
        .header("destination", "/dav/copy.txt")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, copy_req).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        send(&server.app, request("GET", "/dav/moved.txt", Some(&auth)))
            .await
            .2,
        b"a"
    );
    assert_eq!(
        send(&server.app, request("GET", "/dav/copy.txt", Some(&auth)))
            .await
            .2,
        b"a"
    );
}

#[tokio::test]
async fn delete_semantics() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"a"),
    )
    .await;

    let (status, _, _) = send(&server.app, request("DELETE", "/dav/a.txt", Some(&auth))).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(&server.app, request("GET", "/dav/a.txt", Some(&auth))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(&server.app, request("DELETE", "/dav", Some(&auth))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn path_traversal_is_rejected() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    for uri in [
        "/dav/..%2Fescape.txt",
        "/dav/%2e%2e/escape.txt",
        "/dav/..%00/x",
    ] {
        let (status, _, _) = send(
            &server.app,
            request_with_body("PUT", uri, &auth, "text/plain", b"x"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "uri {uri} must be rejected"
        );
    }
}

#[tokio::test]
async fn put_conditional_headers() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"one"),
    )
    .await;

    let mut create_only = request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"two");
    create_only
        .headers_mut()
        .insert(header::IF_NONE_MATCH, "*".parse().unwrap());
    let (status, _, _) = send(&server.app, create_only).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let mut stale = request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"two");
    stale
        .headers_mut()
        .insert(header::IF_MATCH, "\"bogus\"".parse().unwrap());
    let (status, _, _) = send(&server.app, stale).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);

    let (_, headers, _) = send(&server.app, request("GET", "/dav/a.txt", Some(&auth))).await;
    let etag = headers.get(header::ETAG).unwrap().clone();
    let mut matching = request_with_body("PUT", "/dav/a.txt", &auth, "text/plain", b"two");
    matching.headers_mut().insert(header::IF_MATCH, etag);
    let (status, _, _) = send(&server.app, matching).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn put_into_missing_parent_is_conflict() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let (status, _, _) = send(
        &server.app,
        request_with_body("PUT", "/dav/nope/a.txt", &auth, "text/plain", b"x"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn options_advertises_dav_support() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let (status, headers, _) = send(&server.app, request("OPTIONS", "/dav", Some(&auth))).await;
    assert_eq!(status, StatusCode::OK);
    let dav = headers.get("dav").unwrap().to_str().unwrap();
    assert!(dav.contains('1'), "{dav}");
    assert!(dav.contains("sync-collection"), "{dav}");
    assert!(
        headers
            .get(header::ALLOW)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("PROPFIND") && v.contains("MOVE") && v.contains("REPORT"))
    );
}

#[tokio::test]
async fn session_login_logout_flow() {
    let server = setup().await;

    let login = request_with_body(
        "POST",
        "/api/session",
        "",
        "application/json",
        format!(r#"{{"username":"{USER}","password":"{PASS}"}}"#).as_bytes(),
    );
    let (status, headers, _) = send(&server.app, login).await;
    assert_eq!(status, StatusCode::OK);
    let session_cookie = cookie_pair(&headers, "kolimi_session").unwrap();
    let csrf = cookie_value(&headers, "kolimi_csrf").unwrap();
    assert!(!csrf.is_empty());
    let both_cookies = format!("{session_cookie}; kolimi_csrf={csrf}");

    let me = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&server.app, me).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains(USER));

    let logout = Request::builder()
        .method("DELETE")
        .uri("/api/session")
        .header(header::COOKIE, &both_cookies)
        .header("x-csrf-token", &csrf)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, logout).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let me = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, me).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_mutations_require_csrf_token() {
    let server = setup().await;
    let login = request_with_body(
        "POST",
        "/api/session",
        "",
        "application/json",
        format!(r#"{{"username":"{USER}","password":"{PASS}"}}"#).as_bytes(),
    );
    let (_, headers, _) = send(&server.app, login).await;
    let session_cookie = cookie_pair(&headers, "kolimi_session").unwrap();

    let logout = Request::builder()
        .method("DELETE")
        .uri("/api/session")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, logout).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bearer_tokens_authenticate_api_requests() {
    let server = setup().await;
    let login = request_with_body(
        "POST",
        "/api/session",
        "",
        "application/json",
        format!(r#"{{"username":"{USER}","password":"{PASS}"}}"#).as_bytes(),
    );
    let (_, headers, _) = send(&server.app, login).await;
    let session = cookie_value(&headers, "kolimi_session").unwrap();

    let me = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::AUTHORIZATION, format!("Bearer {session}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, me).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn failed_logins_trigger_lockout() {
    let server = setup().await;
    for _ in 0..5 {
        let attempt = request_with_body(
            "POST",
            "/api/session",
            "",
            "application/json",
            format!(r#"{{"username":"{USER}","password":"wrong password"}}"#).as_bytes(),
        );
        let (status, _, _) = send(&server.app, attempt).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let blocked = request_with_body(
        "POST",
        "/api/session",
        "",
        "application/json",
        format!(r#"{{"username":"{USER}","password":"{PASS}"}}"#).as_bytes(),
    );
    let (status, _, _) = send(&server.app, blocked).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn admin_api_creates_users_and_respects_permissions() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    let create = Request::builder()
        .method("POST")
        .uri("/api/users")
        .header(header::AUTHORIZATION, &auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"bob","password":"bob password 1"}"#,
        ))
        .unwrap();
    let (status, _, _) = send(&server.app, create).await;
    assert_eq!(status, StatusCode::CREATED);

    let bob_auth = basic("bob", "bob password 1");
    let bob_create = Request::builder()
        .method("POST")
        .uri("/api/users")
        .header(header::AUTHORIZATION, &bob_auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"username":"carol","password":"carol password"}"#,
        ))
        .unwrap();
    let (status, _, _) = send(&server.app, bob_create).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_users_list_sorts_filters_and_warns_on_quota() {
    let server = setup().await;
    let auth = basic(USER, PASS);

    for name in ["bob", "carol"] {
        let create = json_request(
            "POST",
            "/api/users",
            Some(&auth),
            &format!(r#"{{"username":"{name}","password":"{name} password 1"}}"#),
        );
        let (status, _, _) = send(&server.app, create).await;
        assert_eq!(status, StatusCode::CREATED);
    }

    // Give both a small quota.
    for name in ["bob", "carol"] {
        let patch = json_request(
            "PATCH",
            &format!("/api/users/{name}"),
            Some(&auth),
            r#"{"quota_bytes":100}"#,
        );
        let (status, _, _) = send(&server.app, patch).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Bob really uses 95/100 bytes (uploaded), which is in the warning band.
    let bob = basic("bob", "bob password 1");
    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/bob.bin",
            &bob,
            "application/octet-stream",
            &[0u8; 95],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // Carol has no files but a cached over-quota figure (as the janitor
    // would leave after a large delete-then-account-change).
    let carol = server.state.db.find_user("carol").await.unwrap().unwrap();
    server
        .state
        .db
        .set_used_bytes(carol.id, 120, 0)
        .await
        .unwrap();

    // Sorting by used_bytes desc puts carol (120) above bob (95).
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/users?sort=used_bytes&order=desc", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(list["users"][0]["username"], "carol");
    assert_eq!(list["users"][1]["username"], "bob");

    // filter=over_quota returns only carol (cached 120 >= 100).
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/users?filter=over_quota", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = list["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["carol"]);

    // filter=admin returns only alice.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/users?filter=admin", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let list: Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = list["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alice"]);

    // An unknown sort is rejected.
    let (status, _, _) = send(
        &server.app,
        request("GET", "/api/users?sort=bogus", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Bob is at 95%: warning, but not over quota.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/users/bob/usage", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let usage: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(usage["warning"], true);
    assert_eq!(usage["over_quota"], false);
    assert_eq!(usage["warning_percent"].as_u64(), Some(95));
}

#[tokio::test]
async fn users_cannot_reach_each_others_files() {
    let server = setup().await;
    server
        .state
        .db
        .create_user("bob", &hash_password("bob password 1").unwrap())
        .await
        .unwrap();

    let alice = basic(USER, PASS);
    let bob = basic("bob", "bob password 1");
    send(
        &server.app,
        request_with_body(
            "PUT",
            "/dav/secret.txt",
            &alice,
            "text/plain",
            b"top secret",
        ),
    )
    .await;
    let (status, _, _) = send(&server.app, request("GET", "/dav/secret.txt", Some(&bob))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

fn json_request(method: &str, uri: &str, auth: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn proppatch_roundtrip_and_protected_props() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/p.txt", &auth, "text/plain", b"x"),
    )
    .await;

    let patch = br#"<propertyupdate xmlns='DAV:'>
        <set><prop><color xmlns='http://example.com/ns'>blue</color></prop></set>
        <set><prop><D:getetag xmlns:D='DAV:'>hack</D:getetag></prop></set>
    </propertyupdate>"#;
    let (status, _, body) = send(
        &server.app,
        request_with_body("PROPPATCH", "/dav/p.txt", &auth, "application/xml", patch),
    )
    .await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    let xml = String::from_utf8(body).unwrap();
    assert!(xml.contains("HTTP/1.1 200 OK"));
    assert!(xml.contains("HTTP/1.1 403 Forbidden"));

    let find =
        br#"<propfind xmlns='DAV:'><prop><color xmlns='http://example.com/ns'/></prop></propfind>"#;
    let (status, _, body) = send(
        &server.app,
        request_with_body("PROPFIND", "/dav/p.txt", &auth, "application/xml", find),
    )
    .await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    assert!(String::from_utf8(body).unwrap().contains("blue"));

    let copy = Request::builder()
        .method("COPY")
        .uri("/dav/p.txt")
        .header(header::AUTHORIZATION, &auth)
        .header("destination", "/dav/p2.txt")
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&server.app, copy).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, body) = send(
        &server.app,
        request_with_body("PROPFIND", "/dav/p2.txt", &auth, "application/xml", find),
    )
    .await;
    assert_eq!(status, StatusCode::from_u16(207).unwrap());
    assert!(
        String::from_utf8(body).unwrap().contains("blue"),
        "dead properties must survive COPY"
    );
}

#[tokio::test]
async fn malformed_xml_bodies_are_rejected() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    send(
        &server.app,
        request_with_body("PUT", "/dav/p.txt", &auth, "text/plain", b"x"),
    )
    .await;

    for body in [
        &b"<foo>"[..],
        &b"<D:propfind xmlns:D=\"DAV:\"><D:prop><bar:foo xmlns:bar=\"\"/></D:prop></D:propfind>"[..],
    ] {
        let (status, _, _) = send(
            &server.app,
            request_with_body("PROPFIND", "/dav/p.txt", &auth, "application/xml", body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    let (status, _, _) = send(
        &server.app,
        request_with_body(
            "PROPPATCH",
            "/dav/p.txt",
            &auth,
            "application/xml",
            b"<nope/>",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn passkey_registration_requires_authentication() {
    let server = setup().await;
    let (status, _, _) = send(
        &server.app,
        request("POST", "/api/passkeys/register/begin", None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn passkey_list_and_delete_scope_to_owner() {
    let server = setup().await;
    server
        .state
        .db
        .create_user("bob", &hash_password("bob password 1").unwrap())
        .await
        .unwrap();
    let alice = basic(USER, PASS);
    let bob = basic("bob", "bob password 1");

    // Alice registers a passkey directly in the database.
    let alice_user = server.state.db.find_user(USER).await.unwrap().unwrap();
    server
        .state
        .db
        .add_passkey(alice_user.id, "alice-key", "{}", 0)
        .await
        .unwrap();

    let (status, _, body) = send(&server.app, request("GET", "/api/passkeys", Some(&bob))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"[]");

    let (status, _, body) = send(&server.app, request("GET", "/api/passkeys", Some(&alice))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("alice-key"));

    // Bob cannot delete Alice's passkey.
    let passkey_id = server.state.db.list_passkeys(alice_user.id).await.unwrap()[0].id;
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/passkeys/{passkey_id}"), Some(&bob)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &server.app,
        request(
            "DELETE",
            &format!("/api/passkeys/{passkey_id}"),
            Some(&alice),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn passkey_register_finish_rejects_bogus_credentials() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let (status, _, body) = send(
        &server.app,
        request("POST", "/api/passkeys/register/begin", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let challenge_id = parsed["challenge_id"].as_str().unwrap().to_string();
    assert_eq!(parsed["options"]["publicKey"]["rp"]["id"], "localhost");

    let bogus = json!({
        "challenge_id": challenge_id,
        "name": "bogus",
        "credential": {
            "id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "rawId": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "type": "public-key",
            "response": { "clientDataJSON": "e30", "attestationObject": "e30" }
        }
    })
    .to_string();
    let (status, _, _) = send(
        &server.app,
        json_request("POST", "/api/passkeys/register/finish", Some(&auth), &bogus),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Challenge was consumed: replaying the request fails the same way.
    let (status, _, _) = send(
        &server.app,
        json_request("POST", "/api/passkeys/register/finish", Some(&auth), &bogus),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn passkey_login_begin_hides_unknown_users() {
    let server = setup().await;
    for username in ["nobody", USER] {
        let body = json!({ "username": username }).to_string();
        let (status, _, _) = send(
            &server.app,
            json_request("POST", "/api/passkeys/login/begin", None, &body),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn passkey_full_register_and_login_flow() {
    let server = setup().await;
    let auth = basic(USER, PASS);
    let origin = url::Url::parse(ORIGIN).unwrap();
    let mut token = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // Begin + finish registration.
    let (status, _, body) = send(
        &server.app,
        request("POST", "/api/passkeys/register/begin", Some(&auth)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let challenge_id = parsed["challenge_id"].as_str().unwrap().to_string();
    let creation: CreationChallengeResponse =
        serde_json::from_value(parsed["options"].clone()).unwrap();
    let credential = token.do_registration(origin.clone(), creation).unwrap();

    let finish_body = json!({
        "challenge_id": challenge_id,
        "name": "soft passkey",
        "credential": credential,
    })
    .to_string();
    let (status, _, body) = send(
        &server.app,
        json_request(
            "POST",
            "/api/passkeys/register/finish",
            Some(&auth),
            &finish_body,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "body: {}",
        String::from_utf8_lossy(&body)
    );

    // Begin + finish login (no password involved).
    let begin_body = json!({ "username": USER }).to_string();
    let (status, _, body) = send(
        &server.app,
        json_request("POST", "/api/passkeys/login/begin", None, &begin_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let challenge_id = parsed["challenge_id"].as_str().unwrap().to_string();
    let request_options: RequestChallengeResponse =
        serde_json::from_value(parsed["options"].clone()).unwrap();
    let assertion = token.do_authentication(origin, request_options).unwrap();

    let finish_body = json!({
        "username": USER,
        "challenge_id": challenge_id,
        "credential": assertion,
    })
    .to_string();
    let (status, headers, _) = send(
        &server.app,
        json_request("POST", "/api/passkeys/login/finish", None, &finish_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session_cookie = cookie_pair(&headers, "kolimi_session").unwrap();

    let me = Request::builder()
        .method("GET")
        .uri("/api/me")
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(&server.app, me).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains(USER));
}
