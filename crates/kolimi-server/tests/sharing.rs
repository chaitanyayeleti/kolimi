//! M3 integration tests: shares, groups, public links, and the
//! permission engine as seen over HTTP (WebDAV + JSON API).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use kolimi_auth::password::hash_password;
use kolimi_server::{AppState, build_app};
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "alice";
const BOB: &str = "bob";
const CAROL: &str = "carol";
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
    for user in [ALICE, BOB, CAROL] {
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

fn json_request(method: &str, uri: &str, username: &str, value: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, basic(username))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(value.to_string()))
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

fn json_body(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

async fn mkdir(server: &TestServer, username: &str, path: &str) {
    let (status, _, _) = send(&server.app, request("MKCOL", path, username, None)).await;
    assert_eq!(status, StatusCode::CREATED, "mkdir {path}");
}

async fn upload(server: &TestServer, username: &str, path: &str, data: &[u8]) -> StatusCode {
    send(&server.app, request("PUT", path, username, Some(data)))
        .await
        .0
}

async fn share(
    server: &TestServer,
    username: &str,
    path: &str,
    kind: &str,
    recipient: Option<&str>,
    permission: &str,
) -> (StatusCode, Value) {
    let mut payload = json!({ "path": path, "kind": kind, "permission": permission });
    if let Some(recipient) = recipient {
        payload["recipient"] = json!(recipient);
    }
    let (status, _, body) = send(
        &server.app,
        json_request("POST", "/api/shares", username, &payload),
    )
    .await;
    (status, json_body(&body))
}

#[tokio::test]
async fn user_share_lifecycle_over_http() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/docs").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/docs/a.txt", b"hello bob").await,
        StatusCode::CREATED
    );

    // Share, duplicate rejected.
    let (status, body) = share(&server, ALICE, "/docs", "user", Some(BOB), "read").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["kind"], "user");
    assert_eq!(body["recipient"], BOB);
    assert_eq!(body["path"], "/docs");
    let share_id = body["id"].as_i64().unwrap();
    let (status, _) = share(&server, ALICE, "/docs", "user", Some(BOB), "read").await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Alice sees the share on the node.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/shares?path=/docs", ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["shares"].as_array().unwrap().len(), 1);

    // Bob sees the mount.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/shares/received", BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mounts = json_body(&body);
    assert_eq!(mounts["mounts"][0]["owner"], ALICE);
    assert_eq!(mounts["mounts"][0]["mount"], "/Shared with me/docs");
    assert_eq!(mounts["mounts"][0]["permission"], "read");

    // Read through WebDAV works; write is forbidden.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/dav/Shared%20with%20me/docs/a.txt", BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"hello bob");
    assert_eq!(
        upload(
            &server,
            BOB,
            "/dav/Shared%20with%20me/docs/new.txt",
            b"nope"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    // The mount root cannot be deleted by the recipient.
    let (status, _, _) = send(
        &server.app,
        request("DELETE", "/dav/Shared%20with%20me/docs", BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // PROPFIND on the virtual root lists the mount.
    let (status, _, body) = send(
        &server.app,
        Request::builder()
            .method("PROPFIND")
            .uri("/dav/Shared%20with%20me")
            .header(header::AUTHORIZATION, basic(BOB))
            .header("depth", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("/dav/Shared%20with%20me/docs"), "{xml}");

    // Revocation is immediate.
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/shares/{share_id}"), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &server.app,
        request("GET", "/dav/Shared%20with%20me/docs/a.txt", BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn write_share_and_group_membership() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/proj").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/proj/notes.txt", b"v1").await,
        StatusCode::CREATED
    );
    let group = server.state.db.create_group("team").await.unwrap();
    let bob = server.state.db.find_user(BOB).await.unwrap().unwrap();
    server
        .state
        .db
        .add_group_member(group.id, bob.id)
        .await
        .unwrap();

    let (status, body) = share(&server, ALICE, "/proj", "group", Some("team"), "write").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // A member can create and overwrite inside the mount.
    assert_eq!(
        upload(
            &server,
            BOB,
            "/dav/Shared%20with%20me/proj/sub.txt",
            b"made by bob"
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(
            &server,
            BOB,
            "/dav/Shared%20with%20me/proj/notes.txt",
            b"v2"
        )
        .await,
        StatusCode::NO_CONTENT
    );
    // Alice sees both changes in her tree and version history.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/dav/proj/sub.txt", ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"made by bob");
    let (status, _, body) = send(
        &server.app,
        request("GET", "/dav/proj/notes.txt", ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"v2");

    // Non-members see nothing.
    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/shares/received", CAROL, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json_body(&body)["mounts"].as_array().unwrap().is_empty());

    // A member can remove the group share from their own view.
    let share_id = body_share_id(&server, ALICE, "/proj").await;
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/shares/{share_id}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, _, body) = send(
        &server.app,
        request("GET", "/api/shares/received", BOB, None),
    )
    .await;
    assert!(json_body(&body)["mounts"].as_array().unwrap().is_empty());

    // Non-recipients cannot revoke shares.
    let (status, _) = share(&server, ALICE, "/proj", "user", Some(CAROL), "read").await;
    assert_eq!(status, StatusCode::CREATED);
    let share_id = body_share_id(&server, ALICE, "/proj").await;
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/shares/{share_id}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

async fn body_share_id(server: &TestServer, owner: &str, path: &str) -> i64 {
    let (_, _, body) = send(
        &server.app,
        request("GET", &format!("/api/shares?path={path}"), owner, None),
    )
    .await;
    json_body(&body)["shares"][0]["id"].as_i64().unwrap()
}

#[tokio::test]
async fn link_share_password_expiry_and_revocation() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/pub").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/pub/report.txt", b"public data").await,
        StatusCode::CREATED
    );

    // Password omitted: one is generated and returned once.
    let (status, body) = share(&server, ALICE, "/pub/report.txt", "link", None, "read").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let generated = body["password"].as_str().unwrap();
    assert_eq!(generated.len(), 12);
    let token = body["token"].as_str().unwrap().to_string();
    let share_id = body["id"].as_i64().unwrap();
    assert_eq!(body["url"], format!("/s/{token}"));
    assert!(body["expires_at"].as_i64().unwrap() > kolimi_db::now_millis());

    // Locked: metadata and download require the password.
    let (status, _, body) = send(
        &server.app,
        request("GET", &format!("/public/{token}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json_body(&body)["password_required"], true);

    // Rotate to a known password.
    let (status, _, _) = send(
        &server.app,
        json_request(
            "PATCH",
            &format!("/api/shares/{share_id}"),
            ALICE,
            &json!({ "password": "knownpass" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Wrong password is rejected; correct password unlocks.
    let (status, _, _) = send(
        &server.app,
        Request::builder()
            .method("POST")
            .uri(format!("/public/{token}/unlock"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "password": "wrong" }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, headers, _) = send(
        &server.app,
        Request::builder()
            .method("POST")
            .uri(format!("/public/{token}/unlock"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "password": "knownpass" }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookie = headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with(&format!("kolimi_link_{share_id}=")));

    let (status, _, body) = send(
        &server.app,
        Request::builder()
            .method("GET")
            .uri(format!("/public/{token}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["name"], "report.txt");

    let (status, _, body) = send(
        &server.app,
        Request::builder()
            .method("GET")
            .uri(format!("/public/{token}/download"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"public data");
    // No cookie: locked again.
    let (status, _, _) = send(
        &server.app,
        request("GET", &format!("/public/{token}/download"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Clearing the password opens the link.
    let (status, _, _) = send(
        &server.app,
        json_request(
            "PATCH",
            &format!("/api/shares/{share_id}"),
            ALICE,
            &json!({ "password": "" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = send(
        &server.app,
        request("GET", &format!("/public/{token}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["size"], 11);

    // Expiry: force the timestamp into the past.
    server
        .state
        .db
        .update_share_expiry(share_id, Some(kolimi_db::now_millis() - 1))
        .await
        .unwrap();
    let (status, _, _) = send(
        &server.app,
        request("GET", &format!("/public/{token}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);

    // Revocation.
    server
        .state
        .db
        .update_share_expiry(share_id, None)
        .await
        .unwrap();
    let (status, _, _) = send(
        &server.app,
        request("DELETE", &format!("/api/shares/{share_id}"), ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) = send(
        &server.app,
        request("GET", &format!("/public/{token}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn link_unlock_is_rate_limited() {
    let server = setup().await;
    assert_eq!(
        upload(&server, ALICE, "/dav/secret.txt", b"s").await,
        StatusCode::CREATED
    );
    let (_, body) = share(&server, ALICE, "/secret.txt", "link", None, "read").await;
    let token = body["token"].as_str().unwrap().to_string();
    let share_id = body["id"].as_i64().unwrap();
    send(
        &server.app,
        json_request(
            "PATCH",
            &format!("/api/shares/{share_id}"),
            ALICE,
            &json!({ "password": "hunter2" }),
        ),
    )
    .await;

    for _ in 0..5 {
        let (status, _, _) = send(
            &server.app,
            Request::builder()
                .method("POST")
                .uri(format!("/public/{token}/unlock"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "password": "wrong" }).to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _, _) = send(
        &server.app,
        Request::builder()
            .method("POST")
            .uri(format!("/public/{token}/unlock"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "password": "hunter2" }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn link_folder_listing_and_traversal_rejected() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/folder").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/folder/one.txt", b"1").await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&server, ALICE, "/dav/folder/two.txt", b"2").await,
        StatusCode::CREATED
    );
    let (status, body) = share(&server, ALICE, "/folder", "link", None, "read").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let share_id = body["id"].as_i64().unwrap();
    send(
        &server.app,
        json_request(
            "PATCH",
            &format!("/api/shares/{share_id}"),
            ALICE,
            &json!({ "password": "" }),
        ),
    )
    .await;

    let (status, _, body) = send(
        &server.app,
        request("GET", &format!("/public/{token}"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let meta = json_body(&body);
    assert_eq!(meta["kind"], "dir");
    assert_eq!(meta["entries"].as_array().unwrap().len(), 2);

    let (status, _, body) = send(
        &server.app,
        request("GET", &format!("/public/{token}/list"), BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body)["entries"].as_array().unwrap().len(), 2);

    let (status, _, body) = send(
        &server.app,
        request(
            "GET",
            &format!("/public/{token}/download/one.txt"),
            BOB,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"1");

    // Traversal and unknown paths are rejected.
    let (status, _, _) = send(
        &server.app,
        request(
            "GET",
            &format!("/public/{token}/download/..%2Fsecret.txt"),
            BOB,
            None,
        ),
    )
    .await;
    assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND);
    let (status, _, _) = send(
        &server.app,
        request(
            "GET",
            &format!("/public/{token}/download/nope.txt"),
            BOB,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn browse_merges_mounts_and_reports_permissions() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/docs").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/docs/a.txt", b"a").await,
        StatusCode::CREATED
    );
    let (status, _) = share(&server, ALICE, "/docs", "user", Some(BOB), "read").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, body) =
        send(&server.app, request("GET", "/api/browse?path=/", BOB, None)).await;
    assert_eq!(status, StatusCode::OK);
    let root = json_body(&body);
    let entries = root["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"], "docs");
    assert_eq!(entries[0]["shared"], true);
    assert_eq!(entries[0]["owner"], ALICE);
    assert_eq!(entries[0]["permission"], "read");

    let (status, _, body) = send(
        &server.app,
        request("GET", "/api/browse?path=/Shared%20with%20me", BOB, None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let virtual_root = json_body(&body);
    assert_eq!(virtual_root["entries"].as_array().unwrap().len(), 1);
    assert_eq!(virtual_root["parent"], "/");

    let (status, _, body) = send(
        &server.app,
        request(
            "GET",
            "/api/browse?path=/Shared%20with%20me/docs",
            BOB,
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listing = json_body(&body);
    assert_eq!(listing["entries"][0]["name"], "a.txt");
    assert_eq!(listing["entries"][0]["shared"], true);
    assert_eq!(listing["parent"], "/Shared with me");
}

#[tokio::test]
async fn cross_owner_moves_are_rejected_over_dav() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/docs").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/docs/a.txt", b"a").await,
        StatusCode::CREATED
    );
    let (status, _) = share(&server, ALICE, "/docs", "user", Some(BOB), "write").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) = send(
        &server.app,
        Request::builder()
            .method("MOVE")
            .uri("/dav/Shared%20with%20me/docs/a.txt")
            .header(header::AUTHORIZATION, basic(BOB))
            .header("destination", "/dav/stolen.txt")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // Same-owner MOVE inside the share works.
    let (status, _, _) = send(
        &server.app,
        Request::builder()
            .method("MOVE")
            .uri("/dav/Shared%20with%20me/docs/a.txt")
            .header(header::AUTHORIZATION, basic(BOB))
            .header("destination", "/dav/Shared%20with%20me/docs/b.txt")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn sharing_requires_ownership_and_non_root() {
    let server = setup().await;
    mkdir(&server, ALICE, "/dav/docs").await;
    assert_eq!(
        upload(&server, ALICE, "/dav/docs/a.txt", b"a").await,
        StatusCode::CREATED
    );
    // Bob cannot see or share Alice's path.
    let (status, _) = share(&server, BOB, "/docs", "user", Some(CAROL), "read").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The root cannot be shared.
    let (status, _) = share(&server, ALICE, "/", "user", Some(BOB), "read").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Unknown recipients are rejected.
    let (status, _) = share(&server, ALICE, "/docs", "user", Some("nobody"), "read").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = share(&server, ALICE, "/docs", "group", Some("nogroup"), "read").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Sharing with yourself is rejected.
    let (status, _) = share(&server, ALICE, "/docs", "user", Some(ALICE), "read").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Public write links are not supported yet.
    let (status, _) = share(&server, ALICE, "/docs", "link", None, "write").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Sharing a trashed node is rejected.
    let (status, _, _) = send(
        &server.app,
        request("DELETE", "/dav/docs/a.txt", ALICE, None),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = share(&server, ALICE, "/docs/a.txt", "user", Some(BOB), "read").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn shareable_lists_users_and_groups() {
    let server = setup().await;
    server.state.db.create_group("team").await.unwrap();
    let (status, _, body) = send(&server.app, request("GET", "/api/shareable", BOB, None)).await;
    assert_eq!(status, StatusCode::OK);
    let shareable = json_body(&body);
    let users: Vec<&str> = shareable["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(users, vec![ALICE, CAROL]);
    assert_eq!(shareable["groups"][0], "team");
}
