//! Deterministic client-side encryption of file and folder names.
//!
//! The server stores names as opaque strings (`k1_` + base64url). Names are
//! encrypted under a **per-folder** key, derived from the account root key
//! and the plaintext path:
//!
//! ```text
//! K_root        = HKDF(UMK, "kolimi-name-root-v2")
//! K_folder      = HKDF(K_parent, "kolimi-folder-key-v2" || name)
//! stored name   = k1_ || base64(nonce || AEAD(K_parent, name))
//! ```
//!
//! The key used for a child is the key of its **parent** folder. This means
//! sharing `/Vault/Team` can wrap only `K(Team)`: the recipient can decode
//! the folder's contents but not the names of siblings under `/Vault`.
//!
//! Encryption is deterministic (the nonce is derived from the key and the
//! name), so the same plaintext name always yields the same stored name.
//! That keeps per-folder uniqueness, rename and dedup semantics unchanged.
//! Leakage: the server can tell when two folders contain a file with the
//! same name (identical ciphertext); it cannot guess a name without the key.
//!
//! Legacy names (0.1.37–0.1.38) were encrypted with the account root key at
//! every depth. [`decode_name_path`] falls back to the root key so existing
//! data stays readable; new names use the per-folder keys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::{
    CryptoError, MasterKey,
    keys::{KEY_LEN, NONCE_LEN, aead_decrypt, aead_encrypt, hkdf32},
};

/// Prefix that marks a name as client-encoded.
pub const NAME_PREFIX: &str = "k1_";
const NAME_AAD: &[u8] = b"kolimi-name-v1";
const ROOT_INFO: &[u8] = b"kolimi-name-root-v2";
const FOLDER_INFO: &[u8] = b"kolimi-folder-key-v2";

/// A key that encrypts the names of one folder's children.
///
/// The root key encrypts nothing directly in the v2 scheme; it is the seed
/// for a top-level folder's key.
#[derive(Clone)]
pub struct NameKey(Zeroizing<[u8; KEY_LEN]>);

impl NameKey {
    /// The account's root name key (never used to encrypt a name directly).
    pub fn root(master: &MasterKey) -> Self {
        // HKDF with a fixed 32-byte output cannot fail.
        let key = hkdf32(master.as_bytes(), None, ROOT_INFO).unwrap_or([0u8; KEY_LEN]);
        Self(Zeroizing::new(key))
    }

    /// The key for the children of a folder named `name`.
    pub fn child(&self, name: &str) -> Result<Self, CryptoError> {
        let mut info = Vec::with_capacity(FOLDER_INFO.len() + 5 + name.len());
        info.extend_from_slice(FOLDER_INFO);
        info.push(0);
        info.extend_from_slice(&(name.len() as u32).to_le_bytes());
        info.extend_from_slice(name.as_bytes());
        Ok(Self(Zeroizing::new(hkdf32(&self.0[..], None, &info)?)))
    }

    /// Rebuilds a key from bytes carried in a share envelope.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw bytes, for wrapping in a share envelope.
    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        *self.0
    }

    /// Deterministic nonce derived from the key and name.
    fn nonce(&self, name: &[u8]) -> [u8; NONCE_LEN] {
        let digest = blake3::keyed_hash(&self.0, name);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
        nonce
    }

    /// Encrypts one file or folder name.
    pub fn encode(&self, name: &str) -> Result<String, CryptoError> {
        let nonce = self.nonce(name.as_bytes());
        let ciphertext = aead_encrypt(&self.0, &nonce, NAME_AAD, name.as_bytes())?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(format!("{NAME_PREFIX}{}", URL_SAFE_NO_PAD.encode(blob)))
    }

    /// Decrypts a stored name, if this is the right folder key.
    pub fn decode(&self, stored: &str) -> Option<String> {
        let encoded = stored.strip_prefix(NAME_PREFIX)?;
        let blob = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        if blob.len() < NONCE_LEN + 16 {
            return None;
        }
        let (nonce, body) = blob.split_at(NONCE_LEN);
        let plaintext = aead_decrypt(&self.0, nonce.try_into().ok()?, NAME_AAD, body).ok()?;
        String::from_utf8(plaintext.to_vec()).ok()
    }
}

/// The key for the children of a **plaintext** path, walking one folder key
/// per segment from the account root. `/Vault/Team` yields `K(Team)`.
pub fn name_key_for_path(master: &MasterKey, path: &str) -> Result<NameKey, CryptoError> {
    let mut key = NameKey::root(master);
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        key = key.child(segment)?;
    }
    Ok(key)
}

/// Decodes every segment of a stored path.
///
/// Plaintext segments (the visible top-level `Vault` label, or folders that
/// were never encrypted) pass through and become part of the key chain.
/// Names from the pre-0.1.39 scheme (encrypted with the root key at every
/// depth) are still decoded via a root-key fallback.
pub fn decode_name_path(master: &MasterKey, stored_path: &str) -> String {
    let root = NameKey::root(master);
    let mut key = root.clone();
    let mut legacy = false;
    let mut out = Vec::new();
    for segment in stored_path.split('/').filter(|segment| !segment.is_empty()) {
        if let Some(name) = key.decode(segment) {
            out.push(name.clone());
            if let Ok(next) = key.child(&name) {
                key = next;
            }
            continue;
        }
        // Pre-0.1.39 names used the account root key at every depth.
        if let Some(name) = root.decode(segment) {
            out.push(name);
            legacy = true;
            continue;
        }
        out.push(segment.to_string());
        if legacy {
            // All children of a legacy subtree are root-encrypted.
            key = root.clone();
        } else if let Ok(next) = key.child(segment) {
            key = next;
        }
    }
    let decoded = out.join("/");
    if stored_path.starts_with('/') && !decoded.is_empty() {
        format!("/{decoded}")
    } else {
        decoded
    }
}

/// Whether a stored name claims to be client-encoded.
pub fn is_encoded_name(stored: &str) -> bool {
    stored.starts_with(NAME_PREFIX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn per_folder_keys_do_not_cross_decode() {
        let master = MasterKey::generate().unwrap();
        let vault = name_key_for_path(&master, "/Vault").unwrap();
        let team = name_key_for_path(&master, "/Vault/Team").unwrap();

        let encoded = vault.encode("Team").unwrap();
        assert_eq!(vault.decode(&encoded).as_deref(), Some("Team"));
        assert_eq!(team.decode(&encoded), None, "sibling key must not decode");
        assert!(
            NameKey::root(&master).decode(&encoded).is_none(),
            "the root key must not decode folder names"
        );
        assert_eq!(
            decode_name_path(
                &master,
                &format!("/Vault/{encoded}/{}", team.encode("a.txt").unwrap())
            ),
            "/Vault/Team/a.txt"
        );
    }

    #[test]
    fn same_name_in_different_folders_has_different_ciphertext() {
        let master = MasterKey::generate().unwrap();
        let one = name_key_for_path(&master, "/Vault/A")
            .unwrap()
            .encode("x")
            .unwrap();
        let two = name_key_for_path(&master, "/Vault/B")
            .unwrap()
            .encode("x")
            .unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn legacy_root_encrypted_names_still_decode() {
        let master = MasterKey::generate().unwrap();
        let root = NameKey::root(&master);
        let stored = format!(
            "/Vault/{}/{}",
            root.encode("Old").unwrap(),
            root.encode("file.txt").unwrap()
        );
        assert_eq!(decode_name_path(&master, &stored), "/Vault/Old/file.txt");
    }

    #[test]
    fn encoding_is_deterministic_and_url_safe() {
        let master = MasterKey::generate().unwrap();
        let key = name_key_for_path(&master, "/Vault/Team").unwrap();
        for name in ["a/b", "..", "ünïcode 📁", "x".repeat(200).as_str()] {
            let one = key.encode(name).unwrap();
            assert_eq!(one, key.encode(name).unwrap());
            assert!(!one.contains('/'));
            assert_eq!(key.decode(&one).as_deref(), Some(name));
        }
    }

    #[test]
    fn another_keyring_does_not_decode() {
        let master = MasterKey::generate().unwrap();
        let other = MasterKey::generate().unwrap();
        let key = name_key_for_path(&master, "/Vault").unwrap();
        let encoded = key.encode("secret").unwrap();
        let other_key = name_key_for_path(&other, "/Vault").unwrap();
        assert_eq!(other_key.decode(&encoded), None);
        assert!(!decode_name_path(&other, &format!("/Vault/{encoded}")).contains("secret"));
    }
}
