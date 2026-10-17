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
/// `expected_code` must be the code shown on the new device: it commits to the
/// device's public key, so a server that substituted the key produces a
/// mismatch here and the approval is refused.
pub async fn approve_enrollment(
    id: i64,
    device_public_key_b64: &str,
    expected_code: &str,
    master: &MasterKey,
) -> Result<(), String> {
    let public = decode_public(device_public_key_b64)?;
    let code = kolimi_crypto::enrollment_code(&public, id);
    if kolimi_crypto::normalize_code(&code) != kolimi_crypto::normalize_code(expected_code) {
        return Err(format!(
            "Code mismatch: the server offered key {}, which does not match the code shown on the \
             new device. Refusing to approve.",
            kolimi_crypto::fingerprint(&public)
        ));
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

/// Renders `data` as an inline SVG QR code (empty string on failure).
pub fn qr_svg(data: &str) -> String {
    match qrcode::QrCode::new(data.as_bytes()) {
        Ok(code) => code.render::<qrcode::render::svg::Color>().build(),
        Err(_) => String::new(),
    }
}
