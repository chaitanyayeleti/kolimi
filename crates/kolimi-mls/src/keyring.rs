//! Encrypted share keyring format for MLS group shares.
//!
//! A shared folder needs a stable, offline-readable map of file keys. The
//! map is serialized, encrypted under a key derived from the MLS epoch
//! exporter, and stored by the server as an opaque blob (RFC 0012).
//!
//! ```text
//! key  = HKDF(exporter, salt = group_id,
//!             info = "kolimi-share-keyring-key-v1" || epoch)
//! blob = nonce || XChaCha20-Poly1305(key, aad = group_id || epoch, JSON)
//! ```
//!
//! The epoch is bound in both the key and the AAD, so a keyring from epoch
//! N cannot be replayed into epoch N+1.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Current wire format version.
pub const FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const INFO: &[u8] = b"kolimi-share-keyring-key-v1";
const AAD: &[u8] = b"kolimi-share-keyring-v1";

/// The file-key map carried by a share.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareKeyring {
    /// Format version.
    pub v: u8,
    /// Path inside the share -> base64 32-byte file key.
    pub entries: BTreeMap<String, String>,
}

impl ShareKeyring {
    /// An empty v1 keyring.
    pub fn new() -> Self {
        Self {
            v: FORMAT_VERSION,
            entries: BTreeMap::new(),
        }
    }

    /// Inserts a file key, keyed by the path relative to the share root.
    pub fn insert(&mut self, path: &str, file_key: &[u8; 32]) {
        self.entries
            .insert(path.to_string(), STANDARD.encode(file_key));
    }

    /// Returns one file key.
    pub fn get(&self, path: &str) -> Option<[u8; 32]> {
        self.entries
            .get(path)
            .and_then(|encoded| STANDARD.decode(encoded).ok())
            .and_then(|bytes| bytes.try_into().ok())
    }
}

fn derive_key(exporter: &[u8; 32], group_id: &[u8], epoch: u64) -> Result<[u8; 32], &'static str> {
    let hkdf = Hkdf::<Sha256>::new(Some(group_id), exporter);
    let mut info = Vec::with_capacity(INFO.len() + 8);
    info.extend_from_slice(INFO);
    info.extend_from_slice(&epoch.to_le_bytes());
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| "share keyring key derivation failed")?;
    Ok(key)
}

fn aad(group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD.len() + group_id.len() + 8);
    aad.extend_from_slice(AAD);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// Encrypts a keyring for one MLS epoch.
pub fn encrypt(
    exporter: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    keyring: &ShareKeyring,
) -> Result<Vec<u8>, String> {
    if keyring.v != FORMAT_VERSION {
        return Err("unsupported keyring version".to_string());
    }
    let key = derive_key(exporter, group_id, epoch).map_err(str::to_string)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|error| error.to_string())?;
    let plaintext = serde_json::to_vec(keyring).map_err(|error| error.to_string())?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(group_id, epoch),
            },
        )
        .map_err(|_| "share keyring encryption failed".to_string())?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypts a keyring from one MLS epoch.
pub fn decrypt(
    exporter: &[u8; 32],
    group_id: &[u8],
    epoch: u64,
    blob: &[u8],
) -> Result<ShareKeyring, String> {
    if blob.len() < NONCE_LEN + 16 {
        return Err("share keyring is truncated".to_string());
    }
    let key = derive_key(exporter, group_id, epoch).map_err(str::to_string)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| "bad nonce")?;
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(group_id, epoch),
            },
        )
        .map_err(|_| "share keyring decryption failed".to_string())?;
    let keyring: ShareKeyring =
        serde_json::from_slice(&plaintext).map_err(|error| error.to_string())?;
    if keyring.v != FORMAT_VERSION {
        return Err("unsupported keyring version".to_string());
    }
    Ok(keyring)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn exporter(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn roundtrip_and_epoch_binding() {
        let group_id = b"group-1";
        let mut keyring = ShareKeyring::new();
        keyring.insert("/docs/a.txt", &[1u8; 32]);
        keyring.insert("/docs/sub/b.txt", &[2u8; 32]);

        let blob = encrypt(&exporter(7), group_id, 3, &keyring).unwrap();
        let opened = decrypt(&exporter(7), group_id, 3, &blob).unwrap();
        assert_eq!(opened, keyring);
        assert_eq!(opened.get("/docs/a.txt"), Some([1u8; 32]));

        assert!(
            decrypt(&exporter(7), group_id, 4, &blob).is_err(),
            "wrong epoch"
        );
        assert!(
            decrypt(&exporter(8), group_id, 3, &blob).is_err(),
            "wrong key"
        );
        assert!(
            decrypt(&exporter(7), b"group-2", 3, &blob).is_err(),
            "wrong group"
        );

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decrypt(&exporter(7), group_id, 3, &tampered).is_err());
    }

    #[test]
    fn new_epoch_needs_a_reencrypted_keyring() {
        let group_id = b"group-1";
        let mut keyring = ShareKeyring::new();
        keyring.insert("/secret.bin", &[9u8; 32]);

        let old_blob = encrypt(&exporter(1), group_id, 0, &keyring).unwrap();
        // The exporter changes on add/remove; the old blob is unreadable.
        assert!(decrypt(&exporter(2), group_id, 1, &old_blob).is_err());

        // A committer re-encrypts the keyring for the new epoch.
        let new_blob = encrypt(&exporter(2), group_id, 1, &keyring).unwrap();
        assert_eq!(
            decrypt(&exporter(2), group_id, 1, &new_blob).unwrap(),
            keyring
        );
    }
}
