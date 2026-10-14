//! M6 integration tests: E2EE end-to-end over a live server, including an
//! independent decoder (raw HTTP + kolimi-crypto only) for interop.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_auth::password::hash_password;
use kolimi_crypto::{Argon2Params, Keyring};
use kolimi_server::{AppState, build_app};
use kolimi_sync::{E2eeOptions, SyncConfig, create_keyring_with_params, sync_once, upload_keyring};

const PASS: &str = "sync pass 123";
const E2EE_PASS: &str = "e2ee passphrase 123";
const ORIGIN: &str = "http://localhost:8080";
const MARKER: &[u8] = b"KOLIMI-E2EE-MARKER-7f3a";

struct Server {
    url: String,
    dir: tempfile::TempDir,
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
        dir,
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

fn e2ee_options(passphrase: Option<&str>, recovery: Option<&str>) -> E2eeOptions {
    E2eeOptions {
        passphrase: passphrase.map(str::to_string),
        recovery_code: recovery.map(str::to_string),
        prf_secret: None,
        encrypted_roots: vec!["Private".to_string()],
    }
}

fn e2ee_options_prf(prf_secret: &[u8]) -> E2eeOptions {
    E2eeOptions {
        passphrase: None,
        recovery_code: None,
        prf_secret: Some(prf_secret.to_vec()),
        encrypted_roots: vec!["Private".to_string()],
    }
}

fn config(server: &str, local: &Path, e2ee: Option<E2eeOptions>) -> SyncConfig {
    SyncConfig {
        server: server.to_string(),
        username: "alice".to_string(),
        password: PASS.to_string(),
        token: None,
        local_dir: local.to_path_buf(),
        e2ee,
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

async fn get(server: &str, path: &str) -> (u16, Vec<u8>) {
    let response = reqwest::Client::new()
        .get(format!("{server}{path}"))
        .basic_auth("alice", Some(PASS))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.bytes().await.unwrap().to_vec())
}

async fn get_json(server: &str, path: &str) -> serde_json::Value {
    let (status, bytes) = get(server, path).await;
    assert_eq!(status, 200, "GET {path}");
    serde_json::from_slice(&bytes).unwrap()
}

fn scan_for(root: &Path, needle: &[u8]) -> Vec<std::path::PathBuf> {
    let mut hits = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|window| window == needle)
            {
                hits.push(path);
            }
        }
    }
    hits
}

async fn seed_encrypted_tree(server: &Server, seed: &Path, secret: &[u8]) {
    let (keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config(&server.url, seed, None), &keyring)
        .await
        .unwrap();
    std::fs::create_dir_all(seed.join("Private")).unwrap();
    std::fs::write(seed.join("Private/secret.bin"), secret).unwrap();
    std::fs::write(seed.join("public.txt"), b"plain").unwrap();
    let report = sync_once(&config(
        &server.url,
        seed,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    assert_eq!(report.pushed, 2, "{report:?}");
}

#[tokio::test]
async fn encrypted_files_never_reach_the_server_in_plaintext() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");
    let mirror = root.path().join("mirror");
    std::fs::create_dir_all(&mirror).unwrap();

    let mut secret = MARKER.to_vec();
    secret.extend(pseudorandom(3 * 1024 * 1024, 11));
    seed_encrypted_tree(&server, &seed, &secret).await;

    // Nothing on disk under the server's data directory contains the marker.
    let leaked = scan_for(server.dir.path(), MARKER);
    assert!(leaked.is_empty(), "plaintext leaked into {leaked:?}");

    // The tree flags the encrypted file and only that file.
    let tree = get_json(&server.url, "/api/sync/tree?after_id=0&limit=100").await;
    let entries = tree["entries"].as_array().unwrap();
    let secret_entry = entries
        .iter()
        .find(|entry| entry["path"] == "/Private/secret.bin")
        .unwrap();
    assert_eq!(secret_entry["encrypted"], true);
    let public_entry = entries
        .iter()
        .find(|entry| entry["path"] == "/public.txt")
        .unwrap();
    assert_eq!(public_entry["encrypted"], false);

    // Pull with the passphrase: byte-identical plaintext locally.
    let report = sync_once(&config(
        &server.url,
        &mirror,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    assert_eq!(report.pulled, 2, "{report:?}");
    assert_eq!(
        std::fs::read(mirror.join("Private/secret.bin")).unwrap(),
        secret
    );
    assert_eq!(std::fs::read(mirror.join("public.txt")).unwrap(), b"plain");

    // A second pass is a no-op.
    let report = sync_once(&config(
        &server.url,
        &mirror,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    assert_eq!(report, Default::default());

    // An edit stays delta-friendly and decrypts on the other side.
    let mut edited = secret.clone();
    edited[0] ^= 0xff;
    std::fs::write(seed.join("Private/secret.bin"), &edited).unwrap();
    let report = sync_once(&config(
        &server.url,
        &seed,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    assert_eq!(report.pushed, 1, "{report:?}");
    let report = sync_once(&config(
        &server.url,
        &mirror,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    assert_eq!(report.pulled, 1, "{report:?}");
    assert_eq!(
        std::fs::read(mirror.join("Private/secret.bin")).unwrap(),
        edited
    );

    server.handle.abort();
}

#[tokio::test]
async fn recovery_code_unlocks_and_conflicts_resolve() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");
    let mirror = root.path().join("mirror");
    std::fs::create_dir_all(&mirror).unwrap();

    // Keyring created here so the recovery code is known.
    let (keyring, recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    upload_keyring(&config(&server.url, &seed, None), &keyring)
        .await
        .unwrap();
    std::fs::create_dir_all(seed.join("Private")).unwrap();
    std::fs::write(seed.join("Private/note.txt"), b"v1").unwrap();
    sync_once(&config(
        &server.url,
        &seed,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();

    // A fresh directory unlocked with the recovery code pulls it.
    let recovery_dir = root.path().join("recovery");
    std::fs::create_dir_all(&recovery_dir).unwrap();
    let recovery_text = kolimi_crypto::recovery_code_display(&recovery);
    let report = sync_once(&config(
        &server.url,
        &recovery_dir,
        Some(e2ee_options(None, Some(&recovery_text))),
    ))
    .await
    .unwrap();
    assert_eq!(report.pulled, 1, "{report:?}");
    assert_eq!(
        std::fs::read(recovery_dir.join("Private/note.txt")).unwrap(),
        b"v1"
    );

    // Conflict on an encrypted file: server wins, local edit is preserved.
    std::fs::write(seed.join("Private/note.txt"), b"server edit").unwrap();
    sync_once(&config(
        &server.url,
        &seed,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();
    std::fs::write(recovery_dir.join("Private/note.txt"), b"local edit").unwrap();
    let report = sync_once(&config(
        &server.url,
        &recovery_dir,
        Some(e2ee_options(None, Some(&recovery_text))),
    ))
    .await
    .unwrap();
    assert_eq!(report.conflicts, 1, "{report:?}");
    assert_eq!(
        std::fs::read(recovery_dir.join("Private/note.txt")).unwrap(),
        b"server edit"
    );
    let conflict_copy = std::fs::read_dir(recovery_dir.join("Private"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains("note.txt.conflict-")
        })
        .expect("conflict copy");
    assert_eq!(std::fs::read(conflict_copy.path()).unwrap(), b"local edit");

    server.handle.abort();
}

#[tokio::test]
async fn passkey_prf_unlocks_the_keyring() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");
    let mirror = root.path().join("mirror");
    std::fs::create_dir_all(&mirror).unwrap();

    // Setup adds a PRF wrap (the platform shell would supply the PRF
    // output from a WebAuthn ceremony; here it is a fixed test secret).
    let prf = [0x5au8; 32];
    let (mut keyring, _recovery) = create_keyring_with_params(E2EE_PASS, &fast_params()).unwrap();
    let master = keyring.unlock_with_passphrase(E2EE_PASS).unwrap();
    keyring.add_prf(&master, &prf).unwrap();
    assert!(keyring.methods().contains(&"prf"));
    upload_keyring(&config(&server.url, &seed, None), &keyring)
        .await
        .unwrap();

    std::fs::create_dir_all(seed.join("Private")).unwrap();
    std::fs::write(seed.join("Private/prf.txt"), b"unlocked with a passkey").unwrap();
    sync_once(&config(
        &server.url,
        &seed,
        Some(e2ee_options(Some(E2EE_PASS), None)),
    ))
    .await
    .unwrap();

    // The mirror unlocks with the PRF secret alone.
    let report = sync_once(&config(&server.url, &mirror, Some(e2ee_options_prf(&prf))))
        .await
        .unwrap();
    assert_eq!(report.pulled, 1, "{report:?}");
    assert_eq!(
        std::fs::read(mirror.join("Private/prf.txt")).unwrap(),
        b"unlocked with a passkey"
    );

    // A wrong PRF secret fails closed.
    let error = sync_once(&config(
        &server.url,
        &mirror,
        Some(e2ee_options_prf(&[0u8; 32])),
    ))
    .await
    .unwrap_err();
    assert!(error.is_locked(), "{error}");
    assert!(error.to_string().contains("PRF"), "{error}");

    server.handle.abort();
}

#[tokio::test]
async fn independent_decoder_reads_client_uploads() {
    let server = start_server().await;
    let root = tempfile::tempdir().unwrap();
    let seed = root.path().join("seed");

    let mut secret = MARKER.to_vec();
    secret.extend(pseudorandom(5 * 1024 * 1024, 5));
    seed_encrypted_tree(&server, &seed, &secret).await;

    // Harness B: raw HTTP + kolimi-crypto only, no sync code.
    let keyring_json = get_json(&server.url, "/api/e2ee/keyring").await;
    let keyring = Keyring::from_json(keyring_json["keyring"].as_str().unwrap()).unwrap();
    let master = keyring.unlock_with_passphrase(E2EE_PASS).unwrap();

    let key_json = get_json(&server.url, "/api/files/key?path=%2FPrivate%2Fsecret.bin").await;
    let wrapped = STANDARD
        .decode(key_json["wrapped_key"].as_str().unwrap())
        .unwrap();
    let file_key = master.unwrap_file_key(&wrapped).unwrap();

    let manifest = get_json(
        &server.url,
        "/api/files/manifest?path=%2FPrivate%2Fsecret.bin",
    )
    .await;
    let chunks = manifest["chunks"].as_array().unwrap();
    assert!(chunks.len() > 1, "expected multiple chunks");
    let mut decoded = Vec::new();
    for chunk in chunks {
        let hash = chunk["hash"].as_str().unwrap();
        let (status, bytes) = get(&server.url, &format!("/api/chunks/{hash}")).await;
        assert_eq!(status, 200);
        assert!(
            !bytes.windows(MARKER.len()).any(|window| window == MARKER),
            "chunk {hash} contains plaintext"
        );
        decoded.extend_from_slice(file_key.decrypt_chunk(&bytes).unwrap().as_slice());
    }
    assert_eq!(decoded, secret);

    server.handle.abort();
}
