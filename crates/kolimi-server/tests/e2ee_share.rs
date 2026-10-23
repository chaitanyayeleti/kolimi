//! M6 v2 integration: sharing encrypted files with named users.
//!
//! The owner's client wraps per-file keys for the recipient (X25519
//! ECIES); the recipient's client syncs the shared file decrypted. The
//! second test proves the protocol independently of the sync library.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_crypto::{Argon2Params, Identity, Keyring};
use kolimi_server::{AppState, build_app};
use kolimi_sync::{
    E2eeOptions, SyncConfig, create_keyring_with_params, share_file, sync_once, unshare_file,
    upload_keyring,
};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "e2ee passphrase 123";
const ORIGIN: &str = "http://localhost:8080";
const MARKER: &[u8] = b"E2EE-SHARE-MARKER-42";

struct Server {
    url: String,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

async fn start_server() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::init(dir.path(), false, ORIGIN).await.unwrap();
    for user in ["alice", "bob"] {
        state
            .db
            .create_user(user, &hash_password(PASS).unwrap())
            .await
            .unwrap();
    }
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

async fn get_json(server: &str, username: &str, path: &str) -> (u16, serde_json::Value) {
    let response = reqwest::Client::new()
        .get(format!("{server}{path}"))
        .basic_auth(username, Some(PASS))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        response.json().await.unwrap_or(serde_json::Value::Null),
    )
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

/// Stored path of the first file below `prefix` in a user's tree.
async fn stored_path(server: &str, username: &str, prefix: &str) -> String {
    // Owned files come from the tree; received shares from shared-tree.
    for endpoint in [
        "/api/sync/tree?after_id=0&limit=100",
        "/api/sync/shared-tree",
    ] {
        let (status, body) = get_json(server, username, endpoint).await;
        assert_eq!(status, 200, "{endpoint}");
        if let Some(path) = body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| {
                entry["path"]
                    .as_str()
                    .is_some_and(|path| path.starts_with(prefix))
            })
            .and_then(|entry| entry["path"].as_str())
        {
            return path.to_string();
        }
    }
    panic!("no file below {prefix}");
}

/// Percent-encodes a stored path for use as a query value.
fn query(path: &str) -> String {
    path.replace('%', "%25")
        .replace('/', "%2F")
        .replace(' ', "%20")
}

/// The single file mounted under `Shared with me` (its name is opaque for
/// encrypted shares).
fn shared_file(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir.join("Shared with me"))
        .ok()?
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .map(|entry| entry.path())
}

async fn setup_keyring(server: &str, username: &str, local: &Path) {
    let config = config(server, username, local);
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config, &keyring).await.unwrap();
    kolimi_sync::publish_identity(&config).await.unwrap();
}

#[tokio::test]
async fn encrypted_file_shared_with_a_user_syncs_decrypted() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    let alice = config(&server.url, "alice", &alice_dir);
    let bob = config(&server.url, "bob", &bob_dir);

    // Alice pushes an encrypted file.
    let mut secret = MARKER.to_vec();
    secret.extend(pseudorandom(700_000, 9));
    std::fs::write(alice_dir.join("Private/secret.bin"), &secret).unwrap();
    let report = sync_once(&alice).await.unwrap();
    assert_eq!(report.pushed, 1, "{report:?}");

    // Share it with bob (one wrapped file key).
    let wrapped = share_file(&alice, "/", "Private/secret.bin", "bob")
        .await
        .unwrap();
    assert_eq!(wrapped, 1);

    // Group shares of encrypted files stay refused.
    let stored = stored_path(&server.url, "alice", "/Private/").await;
    let status = post_json(
        &server.url,
        "alice",
        "/api/shares",
        &serde_json::json!({
            "path": stored,
            "kind": "group",
            "recipient": "everyone",
        }),
    )
    .await;
    assert_eq!(status, 400);

    // Bob syncs: the file arrives decrypted under `Shared with me/`.
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report.pulled, 1, "{report:?}");
    let bob_copy = shared_file(&bob_dir).expect("shared file mounted");
    assert!(
        !bob_copy
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains("secret.bin"),
        "the shared file name must stay encrypted"
    );
    assert_eq!(std::fs::read(&bob_copy).unwrap(), secret);

    // A second pass is a no-op.
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report, Default::default());

    // Alice edits; bob follows on the next pull.
    let mut edited = secret.clone();
    edited[0] ^= 0xff;
    std::fs::write(alice_dir.join("Private/secret.bin"), &edited).unwrap();
    sync_once(&alice).await.unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report.pulled, 1, "{report:?}");
    assert_eq!(std::fs::read(&bob_copy).unwrap(), edited);

    // Bob's local edits are never pushed (read-only mirror).
    std::fs::write(&bob_copy, b"local tampering").unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report.pushed, 0, "{report:?}");

    // Revoking the share removes bob's local copy on the next pass.
    unshare_file(&alice, "/", "Private/secret.bin", "bob")
        .await
        .unwrap();
    let report = sync_once(&bob).await.unwrap();
    assert_eq!(report.removed_local, 1, "{report:?}");
    assert!(!bob_copy.exists());

    server.handle.abort();
}

#[tokio::test]
async fn independent_recipient_decoder() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let alice_dir = root.path().join("alice");
    let bob_dir = root.path().join("bob");
    std::fs::create_dir_all(alice_dir.join("Private")).unwrap();
    std::fs::create_dir_all(&bob_dir).unwrap();
    setup_keyring(&server.url, "alice", &alice_dir).await;
    setup_keyring(&server.url, "bob", &bob_dir).await;

    let alice = config(&server.url, "alice", &alice_dir);
    let mut secret = MARKER.to_vec();
    secret.extend(pseudorandom(600_000, 3));
    std::fs::write(alice_dir.join("Private/secret.bin"), &secret).unwrap();
    sync_once(&alice).await.unwrap();
    share_file(&alice, "/", "Private/secret.bin", "bob")
        .await
        .unwrap();

    // Harness: raw HTTP + kolimi-crypto only, as bob.
    let (status, body) = get_json(&server.url, "bob", "/api/e2ee/keyring").await;
    assert_eq!(status, 200);
    let keyring = Keyring::from_json(body["keyring"].as_str().unwrap()).unwrap();
    let master = keyring.unlock_with_passphrase(E2EE_PASS).unwrap();

    let (status, body) = get_json(&server.url, "bob", "/api/e2ee/identity").await;
    assert_eq!(status, 200);
    let wrapped_private = STANDARD
        .decode(body["wrapped_private"].as_str().unwrap())
        .unwrap();
    let identity: Identity = master.unwrap_identity(&wrapped_private).unwrap();

    let shared_path = stored_path(&server.url, "bob", "/Shared with me/").await;
    let shared_query = query(&shared_path);
    let (status, body) = get_json(
        &server.url,
        "bob",
        &format!("/api/e2ee/share-key?path={shared_query}"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let wrapped_key = STANDARD
        .decode(body["wrapped_key"].as_str().unwrap())
        .unwrap();
    let file_key = identity.unwrap_file_key(&wrapped_key).unwrap();

    let (status, manifest) = get_json(
        &server.url,
        "bob",
        &format!("/api/files/manifest?path={shared_query}"),
    )
    .await;
    assert_eq!(status, 200);
    let chunks = manifest["chunks"].as_array().unwrap();
    assert!(chunks.len() > 1);
    let mut decoded = Vec::new();
    for chunk in chunks {
        let hash = chunk["hash"].as_str().unwrap();
        // Chunk reads need the path context to reach the owner's store.
        let (status, bytes) = {
            let response = reqwest::Client::new()
                .get(format!(
                    "{}/api/chunks/{hash}?path={shared_query}",
                    server.url
                ))
                .basic_auth("bob", Some(PASS))
                .send()
                .await
                .unwrap();
            (
                response.status().as_u16(),
                response.bytes().await.unwrap().to_vec(),
            )
        };
        assert_eq!(status, 200, "chunk {hash}");
        decoded.extend_from_slice(file_key.decrypt_chunk(&bytes).unwrap().as_slice());
    }
    let decoded = kolimi_crypto::unpad_file(&decoded).unwrap();
    assert_eq!(decoded, secret);

    // Without the path context bob's own store does not have the chunk.
    let hash = chunks[0]["hash"].as_str().unwrap();
    let (status, _) = get_json(&server.url, "bob", &format!("/api/chunks/{hash}")).await;
    assert_eq!(status, 404);

    server.handle.abort();
}
