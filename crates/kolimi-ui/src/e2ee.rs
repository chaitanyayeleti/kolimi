//! Browser E2EE (RFC 0007): unlock the keyring and decrypt files client-side.
//!
//! The server only ever serves ciphertext chunks and wrapped keys; all
//! decryption happens here with `kolimi-crypto` compiled to wasm.

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_crypto::{FileKey, Keyring, MasterKey};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use wasm_bindgen::JsCast;

use crate::api;

fn encode(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

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
    let keyring = Keyring::from_json(keyring_json).map_err(|_| "Malformed keyring".to_string())?;
    keyring
        .unlock_with_passphrase(passphrase)
        .map_err(|_| "Wrong passphrase".to_string())
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
        out.extend_from_slice(&plaintext);
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
        out.extend_from_slice(&plaintext);
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
