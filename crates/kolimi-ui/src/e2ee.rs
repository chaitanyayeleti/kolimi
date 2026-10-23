//! Browser E2EE (RFC 0007): unlock the keyring and decrypt files client-side.
//!
//! The server only ever serves ciphertext chunks and wrapped keys; all
//! decryption happens here with `kolimi-crypto` compiled to wasm.

use crate::app::encode;
use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_crypto::{CryptoError, FileKey, Keyring, MasterKey};
use serde_json::Value;
use wasm_bindgen::JsCast;

use crate::api;

/// Triggers a browser download of `bytes` as `name`.
pub fn save_bytes(name: &str, bytes: &[u8]) {
    let Some(document) = web_sys::window().and_then(|window| window.document()) else {
        return;
    };
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(array.as_ref());
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type("application/octet-stream");
    let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence_and_options(parts.as_ref(), &bag)
    else {
        return;
    };
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else {
        return;
    };
    let Ok(element) = document.create_element("a") else {
        return;
    };
    let Ok(anchor) = element.dyn_into::<web_sys::HtmlAnchorElement>() else {
        return;
    };
    anchor.set_href(&url);
    anchor.set_download(name);
    if let Some(body) = document.body() {
        let _ = body.append_child(&anchor);
        anchor.click();
        let _ = body.remove_child(&anchor);
    }
    let _ = web_sys::Url::revoke_object_url(&url);
}

/// Unlocks the account's master key with a passphrase.
pub async fn unlock(passphrase: &str) -> Result<MasterKey, String> {
    let keyring = load_keyring().await?;
    check_keyring(&keyring)?;
    let master = keyring
        .unlock_with_passphrase(passphrase)
        .map_err(|error| unlock_error(error, "Wrong passphrase"))?;
    record_epoch(&keyring);
    Ok(master)
}

/// Unlocks the account's master key with the recovery code.
pub async fn unlock_recovery(code: &str) -> Result<MasterKey, String> {
    let keyring = load_keyring().await?;
    check_keyring(&keyring)?;
    let parsed = kolimi_crypto::recovery_code_parse(code)
        .map_err(|_| "Malformed recovery code".to_string())?;
    let master = keyring
        .unlock_with_recovery(&parsed)
        .map_err(|error| unlock_error(error, "Wrong recovery code"))?;
    record_epoch(&keyring);
    Ok(master)
}

/// Maps a keyring unlock failure: an integrity failure means tampering, not a
/// wrong secret, so it must not be reported as one.
fn unlock_error(error: CryptoError, wrong: &str) -> String {
    match error {
        CryptoError::Keyring(_) => {
            "Keyring integrity check failed — refusing to unlock (tampered or spliced keyring)"
                .to_string()
        }
        _ => wrong.to_string(),
    }
}

/// localStorage key holding the highest keyring epoch this browser accepted.
const EPOCH_KEY: &str = "kolimi.keyring.epoch";

fn stored_epoch() -> u64 {
    web_sys::window()
        .and_then(|window| window.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item(EPOCH_KEY).ok().flatten())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Refuses a keyring the server downgraded (integrity tag stripped) or rolled
/// back (older than one this browser has already accepted).
fn check_keyring(keyring: &Keyring) -> Result<(), String> {
    let seen = stored_epoch();
    if seen > 0 && keyring.mac.is_none() {
        return Err(
            "Keyring downgrade detected — the server offered a keyring without its integrity tag"
                .to_string(),
        );
    }
    if keyring.epoch < seen {
        return Err(format!(
            "Keyring rollback detected (server offered epoch {}, this browser has seen {seen})",
            keyring.epoch
        ));
    }
    Ok(())
}

/// Remembers the accepted epoch, after a successful unlock.
fn record_epoch(keyring: &Keyring) {
    if keyring.epoch <= stored_epoch() {
        return;
    }
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item(EPOCH_KEY, &keyring.epoch.to_string());
    }
}

/// Whether the account has a keyring on the server yet (E2EE set up).
pub async fn keyring_exists() -> Result<bool, String> {
    let response = api::get("/api/e2ee/keyring").await?;
    Ok(response.status == 200)
}

/// First-time E2EE setup: generates the master key and a recovery code,
/// uploads the keyring, and publishes this user's identity. Returns the
/// recovery code to show once.
pub async fn setup(passphrase: &str) -> Result<String, String> {
    if passphrase.is_empty() {
        return Err("Enter a passphrase".to_string());
    }
    // Never replace an existing keyring: a second setup would re-wrap a
    // brand-new master key and orphan every file already encrypted.
    if keyring_exists().await? {
        return Err(
            "Encryption is already set up for this account — unlock it instead of creating a new one"
                .to_string(),
        );
    }
    let master = MasterKey::generate().map_err(|_| "could not generate the key".to_string())?;
    let recovery = kolimi_crypto::generate_recovery_code()
        .map_err(|_| "could not generate the recovery code".to_string())?;
    let keyring = Keyring::create(
        &master,
        passphrase,
        &kolimi_crypto::Argon2Params::default(),
        &recovery,
    )
    .map_err(|_| "could not create the keyring".to_string())?;
    let json = keyring
        .to_json()
        .map_err(|_| "could not serialize the keyring".to_string())?;
    let response = api::dav(
        "PUT",
        "/api/e2ee/keyring",
        Some(json.into_bytes()),
        &[("Content-Type", "application/json")],
    )
    .await?;
    if response.status != 204 {
        return Err(format!(
            "could not upload the keyring (HTTP {})",
            response.status
        ));
    }
    let identity = kolimi_crypto::Identity::generate()
        .map_err(|_| "could not generate the identity".to_string())?;
    let wrapped = master
        .wrap_identity(&identity)
        .map_err(|_| "could not wrap the identity".to_string())?;
    let response = api::send_json(
        "PUT",
        "/api/e2ee/identity",
        &serde_json::json!({
            "public_key": STANDARD.encode(identity.public_key()),
            "wrapped_private": STANDARD.encode(&wrapped),
        }),
    )
    .await?;
    if response.status != 204 {
        return Err(format!(
            "could not publish the identity (HTTP {})",
            response.status
        ));
    }
    Ok(kolimi_crypto::recovery_code_display(&recovery))
}

/// Loads the account's keyring from the server.
async fn load_keyring() -> Result<Keyring, String> {
    let response = api::get("/api/e2ee/keyring").await?;
    match response.status {
        200 => {}
        404 => {
            return Err(
                "No E2EE keyring on the server — set up E2EE with the sync client first."
                    .to_string(),
            );
        }
        _ => {
            return Err(response
                .error()
                .unwrap_or("Could not load the keyring")
                .to_string());
        }
    }
    let keyring_json = response.body["keyring"].as_str().unwrap_or_default();
    Keyring::from_json(keyring_json).map_err(|_| "Malformed keyring".to_string())
}

/// The raw file key and the ciphertext chunk lengths of an encrypted file.
/// Used to build a public-link fragment (`#k=…&l=…`).
pub async fn file_key_and_lengths(
    master: &MasterKey,
    path: &str,
) -> Result<([u8; 32], Vec<u32>), String> {
    let (file_key, manifest) = load_file(master, path).await?;
    let lengths = manifest["chunks"]
        .as_array()
        .map(|chunks| {
            chunks
                .iter()
                .map(|chunk| chunk["len"].as_u64().unwrap_or(0) as u32)
                .collect()
        })
        .unwrap_or_default();
    Ok((*file_key.as_bytes(), lengths))
}

/// Decrypts an encrypted file, returning its name and plaintext bytes.
pub async fn decrypt_file(master: &MasterKey, path: &str) -> Result<(String, Vec<u8>), String> {
    let (file_key, manifest) = load_file(master, path).await?;
    let name = path.rsplit('/').next().unwrap_or("file").to_string();
    let Some(chunks) = manifest["chunks"].as_array() else {
        return Ok((name, Vec::new()));
    };
    let mut out = Vec::new();
    for chunk in chunks {
        let hash = chunk["hash"].as_str().unwrap_or_default();
        let ciphertext =
            api::get_bytes(&format!("/api/chunks/{hash}?path={}", encode(path))).await?;
        let plaintext = file_key
            .decrypt_chunk(&ciphertext)
            .map_err(|_| "Decryption failed (wrong key or corrupt data)".to_string())?;
        out.extend_from_slice(plaintext.as_slice());
    }
    Ok((name, out))
}

/// Decrypts a public-link ciphertext blob given the raw file key and the
/// chunk lengths from the URL fragment (`#k=…&l=…`).
pub fn decrypt_public(
    key: &[u8; 32],
    lengths: &[u32],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let file_key = FileKey::from_bytes(*key);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for &length in lengths {
        let end = offset + length as usize;
        if end > ciphertext.len() {
            return Err("Truncated ciphertext".to_string());
        }
        let plaintext = file_key
            .decrypt_chunk(&ciphertext[offset..end])
            .map_err(|_| "Decryption failed (wrong key or corrupt data)".to_string())?;
        out.extend_from_slice(plaintext.as_slice());
        offset = end;
    }
    Ok(out)
}

/// Fetches an encrypted file's wrapped key (unwrapped) and its manifest.
async fn load_file(master: &MasterKey, path: &str) -> Result<(FileKey, Value), String> {
    let key_response = api::get(&format!("/api/files/key?path={}", encode(path))).await?;
    if key_response.status != 200 {
        return Err(key_response
            .error()
            .unwrap_or("This file has no key")
            .to_string());
    }
    let wrapped = STANDARD
        .decode(
            key_response.body["wrapped_key"]
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|_| "Malformed wrapped key".to_string())?;
    let file_key = master
        .unwrap_file_key(&wrapped)
        .map_err(|_| "Could not unwrap the file key".to_string())?;

    let manifest = api::get(&format!("/api/files/manifest?path={}", encode(path))).await?;
    if manifest.status != 200 {
        return Err("Could not load the file manifest".to_string());
    }
    Ok((file_key, manifest.body))
}

/// The account's pending device enrollments (RFC 0008).
pub async fn pending_enrollments() -> Result<Vec<Value>, String> {
    let response = api::get("/api/e2ee/enrollments").await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not load enrollments")
            .to_string());
    }
    Ok(response.body["enrollments"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// The account's registered devices.
pub async fn devices() -> Result<Vec<Value>, String> {
    let response = api::get("/api/e2ee/devices").await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not load devices")
            .to_string());
    }
    Ok(response.body["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default())
}

/// Revokes a device record.
pub async fn revoke_device(id: i64) -> Result<(), String> {
    let response = api::delete(&format!("/api/e2ee/devices/{id}")).await?;
    if response.status == 204 {
        Ok(())
    } else {
        Err(response
            .error()
            .unwrap_or("could not revoke the device")
            .to_string())
    }
}

/// Approves a pending enrollment by wrapping the master key for its device.
///
/// `expected_code` is the code shown on the new device when the approver
/// wants verification: it commits to the device's public key, so a server
/// that substituted the key produces a mismatch and the approval is refused.
/// `None` skips the comparison (one-click, trust-on-first-use): convenient
/// on a server you operate yourself, weaker against a malicious server.
pub async fn approve_enrollment(
    id: i64,
    device_public_key_b64: &str,
    expected_code: Option<&str>,
    master: &MasterKey,
) -> Result<(), String> {
    let public = decode_public(device_public_key_b64)?;
    if let Some(expected) = expected_code {
        let code = kolimi_crypto::enrollment_code(&public, id);
        if kolimi_crypto::normalize_code(&code) != kolimi_crypto::normalize_code(expected) {
            return Err(format!(
                "Code mismatch: the server offered key {}, which does not match the code shown on the \
                 new device. Refusing to approve.",
                kolimi_crypto::fingerprint(&public)
            ));
        }
    }
    let wrapped = kolimi_crypto::wrap_secret_for(&public, master.as_bytes())
        .map_err(|_| "could not wrap the master key".to_string())?;
    let response = api::send_json(
        "POST",
        &format!("/api/e2ee/enrollments/{id}/approve"),
        &serde_json::json!({ "wrapped_master_key": STANDARD.encode(&wrapped) }),
    )
    .await?;
    if response.status == 204 {
        Ok(())
    } else {
        Err(response
            .error()
            .unwrap_or("could not approve the enrollment")
            .to_string())
    }
}

/// Starts enrolling this browser as a new device: generates a device key,
/// creates the enrollment, and returns its id, the device secret to poll with
/// (kept in memory only), and the approval code to show for comparison.
pub async fn start_enrollment(name: &str) -> Result<(i64, [u8; 32], String), String> {
    let device = kolimi_crypto::Identity::generate()
        .map_err(|_| "could not generate a device key".to_string())?;
    let public = device.public_key();
    let response = api::send_json(
        "POST",
        "/api/e2ee/enrollments",
        &serde_json::json!({
            "device_name": name,
            "device_public_key": STANDARD.encode(public),
        }),
    )
    .await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not start the enrollment")
            .to_string());
    }
    let id = response.body["id"]
        .as_i64()
        .ok_or("malformed enrollment response")?;
    Ok((
        id,
        device.private_bytes(),
        kolimi_crypto::enrollment_code(&public, id),
    ))
}

/// The approval code for a pending enrollment (shown on both devices).
pub fn device_code(device_public_key_b64: &str, id: i64) -> String {
    decode_public(device_public_key_b64)
        .map(|key| kolimi_crypto::enrollment_code(&key, id))
        .unwrap_or_default()
}

/// The fingerprint of a device or recipient public key.
pub fn key_fingerprint(public_key_b64: &str) -> String {
    decode_public(public_key_b64)
        .map(|key| kolimi_crypto::fingerprint(&key))
        .unwrap_or_default()
}

fn decode_public(public_key_b64: &str) -> Result<[u8; 32], String> {
    STANDARD
        .decode(public_key_b64)
        .map_err(|_| "malformed device key".to_string())?
        .try_into()
        .map_err(|_| "device key must be 32 bytes".to_string())
}

/// Polls an enrollment once; returns the unlocked master key once approved.
pub async fn poll_enrollment(id: i64, secret: &[u8; 32]) -> Result<Option<MasterKey>, String> {
    let response = api::get(&format!("/api/e2ee/enrollments/{id}")).await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not poll the enrollment")
            .to_string());
    }
    if response.body["approved"].as_bool() != Some(true) {
        return Ok(None);
    }
    let wrapped = STANDARD
        .decode(
            response.body["wrapped_master_key"]
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|_| "malformed wrapped key".to_string())?;
    let umk = kolimi_crypto::unwrap_secret(secret, &wrapped)
        .map_err(|_| "could not unwrap the master key".to_string())?;
    Ok(Some(MasterKey::from_bytes(umk)))
}

/// sessionStorage key holding the unlocked master key (base64) for the
/// lifetime of the tab. This is what "remember me" means in the browser:
/// a reload keeps you unlocked, closing the tab (or Lock / sign out)
/// forgets the key. sessionStorage is origin-scoped and never leaves the
/// browser, so the server still never sees key material.
const SESSION_MASTER_KEY: &str = "kolimi.session.master";

/// Remembers an unlocked master key for this tab session.
pub fn remember_master(master: &MasterKey) {
    if let Some(storage) =
        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
    {
        let _ = storage.set_item(SESSION_MASTER_KEY, &STANDARD.encode(master.as_bytes()));
    }
}

/// Forgets the tab-session master key (Lock, sign out, expired session).
pub fn forget_master() {
    if let Some(storage) =
        web_sys::window().and_then(|window| window.session_storage().ok().flatten())
    {
        let _ = storage.remove_item(SESSION_MASTER_KEY);
    }
}

/// Restores the tab-session master key after a reload, if the tab is still
/// the one that unlocked.
pub fn recalled_master() -> Option<MasterKey> {
    let bytes = web_sys::window()?
        .session_storage()
        .ok()??
        .get_item(SESSION_MASTER_KEY)
        .ok()??;
    let raw: [u8; 32] = STANDARD.decode(&bytes).ok()?.try_into().ok()?;
    Some(MasterKey::from_bytes(raw))
}

/// Renders `data` as an inline SVG QR code (empty string on failure).
pub fn qr_svg(data: &str) -> String {
    match qrcode::QrCode::new(data.as_bytes()) {
        Ok(code) => code.render::<qrcode::render::svg::Color>().build(),
        Err(_) => String::new(),
    }
}

/// Metadata for one node: kind and encryption state.
pub async fn file_info(path: &str) -> Result<Value, String> {
    let response = api::get(&format!("/api/files/info?path={}", encode(path))).await?;
    if response.status == 200 {
        Ok(response.body)
    } else {
        Err(response
            .error()
            .unwrap_or("Could not load file info")
            .to_string())
    }
}

/// Metadata-only rename/move. Works for encrypted files too (moving
/// ciphertext pointers never exposes plaintext to the server).
pub async fn move_file(from: &str, to: &str) -> Result<(), String> {
    let response = api::send_json(
        "POST",
        "/api/files/move",
        &serde_json::json!({ "from": from, "to": to }),
    )
    .await?;
    match response.status {
        200 => Ok(()),
        404 => Err("That file no longer exists.".to_string()),
        409 => Err("A file with that name already exists.".to_string()),
        _ => Err(response
            .error()
            .unwrap_or("Could not move the file")
            .to_string()),
    }
}

/// Uploads `data` as a new encrypted file at `path` (parent must exist):
/// chunks are encrypted client-side, uploaded, committed, and the wrapped
/// file key is stored — mirroring the sync client.
pub async fn upload_encrypted(master: &MasterKey, path: &str, data: &[u8]) -> Result<(), String> {
    let file_key =
        FileKey::generate().map_err(|_| "could not generate the file key".to_string())?;
    let mut chunks = Vec::new();
    let mut total = 0u64;
    for chunk in kolimi_chunk::chunker::split(data) {
        let ciphertext = file_key
            .encrypt_chunk(chunk.data)
            .map_err(|_| "could not encrypt the file".to_string())?;
        total += ciphertext.len() as u64;
        let hash = kolimi_chunk::Hash::of(&ciphertext);
        chunks.push(kolimi_chunk::ChunkRef {
            hash,
            len: ciphertext.len() as u32,
        });
        let url = format!("/api/chunks/{}", hash.to_hex());
        let response = api::put_bytes(&url, &ciphertext).await?;
        if response.status != 201 && response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not upload the file")
                .to_string());
        }
    }
    let wrapped = master
        .wrap_file_key(&file_key)
        .map_err(|_| "could not wrap the file key".to_string())?;
    // One request: manifest + wrapped key. The server refuses ciphertext
    // into an encrypted folder without the key, and a crash can't leave a
    // half-written file behind.
    let mut manifest = serde_json::to_value(&kolimi_chunk::Manifest {
        version: kolimi_chunk::Manifest::VERSION,
        size: total,
        chunks,
    })
    .map_err(|_| "could not build the file manifest".to_string())?;
    manifest["wrapped_key"] = serde_json::json!(STANDARD.encode(&wrapped));
    let response = api::send_json(
        "PUT",
        &format!("/api/files?path={}", encode(path)),
        &manifest,
    )
    .await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not save the file")
            .to_string());
    }
    Ok(())
}

/// The caller's X25519 identity, unwrapped with the master key.
async fn own_identity(master: &MasterKey) -> Result<kolimi_crypto::Identity, String> {
    let response = api::get("/api/e2ee/identity").await?;
    if response.status != 200 {
        return Err("No E2EE identity on this account yet.".to_string());
    }
    let wrapped = STANDARD
        .decode(
            response.body["wrapped_private"]
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|_| "Malformed identity".to_string())?;
    master
        .unwrap_identity(&wrapped)
        .map_err(|_| "Could not unwrap the identity".to_string())
}

/// Decrypts a file shared with the caller (`/Shared with me/...`): unwraps
/// the recipient share key with the caller's identity instead of the master
/// key, then decrypts the chunks.
pub async fn decrypt_shared_file(
    master: &MasterKey,
    server_path: &str,
) -> Result<(String, Vec<u8>), String> {
    let identity = own_identity(master).await?;
    let response = api::get(&format!("/api/e2ee/share-key?path={}", encode(server_path))).await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("No share key for this file — ask the owner to re-share it")
            .to_string());
    }
    let wrapped = STANDARD
        .decode(response.body["wrapped_key"].as_str().unwrap_or_default())
        .map_err(|_| "Malformed share key".to_string())?;
    let secret = identity.private_bytes();
    let raw = kolimi_crypto::unwrap_secret(&secret, &wrapped)
        .map_err(|_| "Could not unwrap the share key".to_string())?;
    let file_key = FileKey::from_bytes(raw);
    let name = server_path.rsplit('/').next().unwrap_or("file").to_string();
    let manifest = api::get(&format!("/api/files/manifest?path={}", encode(server_path))).await?;
    if manifest.status != 200 {
        return Err("Could not load the file manifest".to_string());
    }
    decrypt_manifest(&file_key, server_path, &manifest.body, &name).await
}

/// Shared chunk-decryption core for owned and shared files.
async fn decrypt_manifest(
    file_key: &FileKey,
    path: &str,
    manifest: &Value,
    name: &str,
) -> Result<(String, Vec<u8>), String> {
    let Some(chunks) = manifest["chunks"].as_array() else {
        return Ok((name.to_string(), Vec::new()));
    };
    let mut out = Vec::new();
    for chunk in chunks {
        let hash = chunk["hash"].as_str().unwrap_or_default();
        let ciphertext =
            api::get_bytes(&format!("/api/chunks/{hash}?path={}", encode(path))).await?;
        let plaintext = file_key
            .decrypt_chunk(&ciphertext)
            .map_err(|_| "Decryption failed (wrong key or corrupt data)".to_string())?;
        out.extend_from_slice(plaintext.as_slice());
    }
    Ok((name.to_string(), out))
}

/// Decrypts a file to an in-memory blob URL for image preview (lightbox).
/// The caller should revoke the URL when done.
pub fn blob_url(name: &str, bytes: &[u8]) -> String {
    let array = js_sys::Uint8Array::from(bytes);
    let parts = js_sys::Array::new();
    parts.push(array.as_ref());
    let lower = name.to_ascii_lowercase();
    let mime = if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".bmp") {
        "image/bmp"
    } else {
        "image/jpeg"
    };
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type(mime);
    let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence_and_options(parts.as_ref(), &bag)
    else {
        return String::new();
    };
    web_sys::Url::create_object_url_with_blob(&blob).unwrap_or_default()
}

/// A recipient's published X25519 public key.
async fn recipient_public(username: &str) -> Result<[u8; 32], String> {
    let response = api::get(&format!("/api/e2ee/identity/{}", encode(username))).await?;
    if response.status != 200 {
        return Err(format!("{username} has not set up encryption yet."));
    }
    STANDARD
        .decode(response.body["public_key"].as_str().unwrap_or_default())
        .map_err(|_| "Malformed public key".to_string())?
        .try_into()
        .map_err(|_| "Malformed public key".to_string())
}

/// Wraps the file key of an encrypted file (or every encrypted file under
/// an encrypted directory) for one recipient and stores it. Plaintext
/// paths are a no-op. Returns the number of keys wrapped.
pub async fn share_encrypted_with(
    master: &MasterKey,
    path: &str,
    username: &str,
) -> Result<usize, String> {
    let info = file_info(path).await?;
    if info["kind"].as_str() == Some("dir") {
        share_encrypted_dir(master, path, username).await
    } else if info["encrypted"].as_bool() == Some(true) {
        let wrapped = wrap_share_key(master, path, username).await?;
        put_share_key(path, username, &wrapped).await?;
        Ok(1)
    } else {
        Ok(0)
    }
}

/// Recursive directory half of [`share_encrypted_with`] (iterative, so no
/// async boxing is needed).
async fn share_encrypted_dir(
    master: &MasterKey,
    dir: &str,
    username: &str,
) -> Result<usize, String> {
    let mut wrapped = 0usize;
    let mut stack = vec![dir.to_string()];
    while let Some(current) = stack.pop() {
        let response = api::get(&format!("/api/browse?path={}", encode(&current))).await?;
        if response.status != 200 {
            return Err(response
                .error()
                .unwrap_or("Could not list the shared folder")
                .to_string());
        }
        let entries = response.body["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for entry in &entries {
            let Some(path) = entry["path"].as_str() else {
                continue;
            };
            if entry["kind"].as_str() == Some("dir") {
                stack.push(path.to_string());
            } else if entry["encrypted"].as_bool() == Some(true) {
                let key = wrap_share_key(master, path, username).await?;
                put_share_key(path, username, &key).await?;
                wrapped += 1;
            }
        }
    }
    Ok(wrapped)
}

/// Wraps the file key of an owned encrypted file for one recipient.
pub async fn wrap_share_key(
    master: &MasterKey,
    file_path: &str,
    username: &str,
) -> Result<Vec<u8>, String> {
    let key_response = api::get(&format!("/api/files/key?path={}", encode(file_path))).await?;
    if key_response.status != 200 {
        return Err("This file has no key to share.".to_string());
    }
    let wrapped = STANDARD
        .decode(
            key_response.body["wrapped_key"]
                .as_str()
                .unwrap_or_default(),
        )
        .map_err(|_| "Malformed wrapped key".to_string())?;
    let file_key = master
        .unwrap_file_key(&wrapped)
        .map_err(|_| "Could not unwrap the file key".to_string())?;
    let public = recipient_public(username).await?;
    let identity = kolimi_crypto::Identity::generate()
        .map_err(|_| "could not generate a wrapping key".to_string())?;
    identity
        .wrap_file_key_for(&public, &file_key)
        .map_err(|_| format!("Could not wrap the key for {username}"))
}

/// Stores a wrapped file key for one recipient on the server.
pub async fn put_share_key(file_path: &str, username: &str, wrapped: &[u8]) -> Result<(), String> {
    let response = api::put_bytes(
        &format!(
            "/api/e2ee/share-key?path={}&recipient={}",
            encode(file_path),
            encode(username)
        ),
        wrapped,
    )
    .await?;
    if response.status == 204 {
        Ok(())
    } else {
        Err(response
            .error()
            .unwrap_or("Could not share the key")
            .to_string())
    }
}

/// Usernames of a group's members (for per-member key wrapping).
pub async fn group_members(group: &str) -> Result<Vec<String>, String> {
    let response = api::get(&format!("/api/groups/{}/members", encode(group))).await?;
    if response.status != 200 {
        return Err("Could not load group members".to_string());
    }
    Ok(response.body["members"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|m| m.as_str().map(str::to_string))
        .collect())
}
