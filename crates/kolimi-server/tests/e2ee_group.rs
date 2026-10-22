//! M6 v2 integration: group E2EE sharing.
//!
//! Group shares use per-member X25519 wrapping (RFC 0007 v2). This is
//! deliberately *not* MLS: it reuses the audited single-recipient
//! primitives and documents its limits (no forward secrecy on membership
//! change beyond key revocation). RFC 9420 remains the roadmap item.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_crypto::Argon2Params;
use kolimi_server::{AppState, build_app};
use kolimi_sync::{
    E2eeOptions, SyncConfig, create_keyring_with_params, share_file_to_group, sync_once,
    upload_keyring,
};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "e2ee passphrase 123";
const ORIGIN: &str = "http://localhost:8080";
const MARKER: &[u8] = b"E2EE-GROUP-MARKER-7";

struct Server {
    url: String,
    dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn start_server() -> (Server, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    for user in ["alice", "bob", "carol"] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
    let app = build_app(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (
        Server {
            url: format!("http://{addr}"),
            dir,
            handle,
        },
        state,
    )
}

fn fast_params() -> Argon2Params {
    Argon2Params {
        m_cost: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn config(server: &str, username: &str, local: &Path) -> SyncConfig {
    SyncConfig {
        server: server.to_string(),
        username: username.to_string(),
        password: PASS.to_string(),
        token: None,
        local_dir: local.to_path_buf(),
        e2ee: Some(E2eeOptions {
            passphrase: Some(E2EE_PASS.to_string()),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: vec!["Private".to_string()],
        }),
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

async fn setup_keyring(server: &str, username: &str, local: &Path) {
    let config = config(server, username, local);
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config, &keyring).await.unwrap();
    kolimi_sync::publish_identity(&config).await.unwrap();
}

async fn post_json(server: &str, username: &str, path: &str, body: &serde_json::Value) -> u16 {
    reqwest::Client::new()
        .post(format!("{server}{path}"))
        .basic_auth(username, Some(PASS))
        .json(body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn group_share_reaches_members_and_removal_revokes() {
    let (server, state) = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    let carol_dir = root.path().join("carol");
    std::fs::create_dir_all(alice_dir.join("Private")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    std::fs::create_dir_all(&carol_dir).unwrap();
    for (user, dir) in [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
    ] {
        setup_keyring(&server.url, user, dir).await;
    }

    // Group "team" with alice (the sharer) + bob + carol. Wrapping keys
    // for a group requires the sharer to be a member (rosters are only
    // visible to members and admins).
    let group = state.db.create_group("team").await.unwrap();
    for username in ["alice", "bob", "carol"] {
        let user = state.db.find_user(username).await.unwrap().unwrap();
        state.db.add_group_member(group.id, user.id).await.unwrap();
    }

    let alice = config(&server.url, "alice", &alice_dir);
    let bob = config(&server.url, "bob", &bob_dir);
    let carol = config(&server.url, "carol", &carol_dir);

    // Alice pushes an encrypted file and shares it with the group.
    let mut secret = MARKER.to_vec();
    secret.extend(pseudorandom(500_000, 21));
    std::fs::write(alice_dir.join("Private/doc.bin"), &secret).unwrap();
    sync_once(&alice).await.unwrap();

    let wrapped = share_file_to_group(&alice, "/", "Private/doc.bin", "team")
        .await
        .unwrap();
    assert_eq!(wrapped, 2, "one wrap per member");

    // Both members pull it decrypted.
    for (name, dir) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        let config = config(&server.url, name, dir);
        let report = sync_once(&config).await.unwrap();
        assert_eq!(report.pulled, 1, "{name}: {report:?}");
        assert_eq!(
            std::fs::read(dir.join("Shared with me/doc.bin")).unwrap(),
            secret
        );
    }

    // Public links to encrypted files are allowed: the file key travels in
    // the URL fragment, which the browser never sends to the server.
    let status = post_json(
        &server.url,
        "alice",
        "/api/shares",
        &serde_json::json!({
            "path": "/Private/doc.bin",
            "kind": "link",
        }),
    )
    .await;
    assert_eq!(status, 201);

    // Remove carol through the CLI: membership and wrapped keys go away.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kolimi-server"))
        .args(["group", "remove-member", "team", "carol"])
        .env("KOLIMI_DATA", server.dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let alice_user = state.db.find_user("alice").await.unwrap().unwrap();
    let carol_user = state.db.find_user("carol").await.unwrap().unwrap();
    let bob_user = state.db.find_user("bob").await.unwrap().unwrap();
    let encrypted = state.db.encrypted_node_ids(alice_user.id).await.unwrap();
    assert_eq!(encrypted.len(), 1);
    let node = encrypted[0];
    assert!(
        state
            .db
            .share_key(node, bob_user.id)
            .await
            .unwrap()
            .is_some(),
        "bob keeps his wrapped key"
    );
    assert!(
        state
            .db
            .share_key(node, carol_user.id)
            .await
            .unwrap()
            .is_none(),
        "carol's wrapped key is gone"
    );

    // Carol's next sync removes the local copy; bob's is a no-op.
    let report = sync_once(&carol).await.unwrap();
    assert_eq!(report.removed_local, 1, "{report:?}");
    assert!(!carol_dir.join("Shared with me/doc.bin").exists());
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report, Default::default());
    assert!(bob_dir.join("Shared with me/doc.bin").exists());

    server.handle.abort();
}

#[tokio::test]
async fn group_members_endpoint_lists_usernames() {
    let (server, state) = start_server().await;
    let group = state.db.create_group("team").await.unwrap();
    let bob = state.db.find_user("bob").await.unwrap().unwrap();
    state.db.add_group_member(group.id, bob.id).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("{}/api/groups/team/members", server.url))
        .basic_auth("alice", Some(PASS))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["members"], serde_json::json!(["bob"]));

    let response = reqwest::Client::new()
        .get(format!("{}/api/groups/nope/members", server.url))
        .basic_auth("alice", Some(PASS))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);

    server.handle.abort();
}

// Silence an unused-import warning when helpers change.
#[allow(dead_code)]
fn _unused() -> String {
    STANDARD.encode(b"")
}
