//! Deterministic client-side encryption of file and folder names.
//!
//! The server stores names as opaque strings (`k1_` + base64url). Clients
//! with the master key can decode them; the server cannot. Encryption is
//! deterministic so the same plaintext name always yields the same stored
//! name — that keeps the per-folder uniqueness constraint, `rename` and
//! `move` working unchanged, and dedup deterministic across clients.
//!
//! Leakage: the server can tell when two folders contain a file with the
//! same name (identical ciphertext). It cannot guess a name better than a
//! dictionary attack against the master key, which it does not have.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use crate::{
    CryptoError, MasterKey,
    keys::{KEY_LEN, NONCE_LEN, aead_decrypt, aead_encrypt, hkdf32},
};

/// Prefix that marks a name as client-encoded.
pub const NAME_PREFIX: &str = "k1_";
const NAME_AAD: &[u8] = b"kolimi-name-v1";
const NAME_KEY_INFO: &[u8] = b"kolimi-name-key-v1";

fn name_key(master: &MasterKey) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    Ok(Zeroizing::new(hkdf32(
        master.as_bytes(),
        None,
        NAME_KEY_INFO,
    )?))
}

/// Deterministic nonce derived from the name, so equal names encrypt
/// identically and different names never share a nonce.
fn nonce_for(key: &[u8; KEY_LEN], name: &[u8]) -> [u8; NONCE_LEN] {
    let digest = blake3::keyed_hash(key, name);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    nonce
}

/// Encrypts a file or folder name for storage on the server.
pub fn encode_name(master: &MasterKey, name: &str) -> Result<String, CryptoError> {
    let key = name_key(master)?;
    let nonce = nonce_for(&key, name.as_bytes());
    let ciphertext = aead_encrypt(&key, &nonce, NAME_AAD, name.as_bytes())?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{NAME_PREFIX}{}", URL_SAFE_NO_PAD.encode(blob)))
}

/// Decrypts a stored name. Returns `None` for plaintext names, names from
/// another keyring, or anything tampered with.
pub fn decode_name(master: &MasterKey, stored: &str) -> Option<String> {
    let encoded = stored.strip_prefix(NAME_PREFIX)?;
    let blob = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    if blob.len() < NONCE_LEN + 16 {
        return None;
    }
    let (nonce, body) = blob.split_at(NONCE_LEN);
    let key = name_key(master).ok()?;
    let plaintext = aead_decrypt(&key, nonce.try_into().ok()?, NAME_AAD, body).ok()?;
    String::from_utf8(plaintext.to_vec()).ok()
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
    fn names_roundtrip_and_are_deterministic() {
        let master = MasterKey::generate().unwrap();
        let one = encode_name(&master, "taxes 2026.pdf").unwrap();
        let two = encode_name(&master, "taxes 2026.pdf").unwrap();

        assert_eq!(one, two, "same name must encode identically");
        assert!(one.starts_with(NAME_PREFIX));
        assert!(!one.contains("taxes"), "the plaintext must not leak");
        assert_eq!(
            decode_name(&master, &one).as_deref(),
            Some("taxes 2026.pdf")
        );
        assert_ne!(
            encode_name(&master, "a.txt").unwrap(),
            encode_name(&master, "b.txt").unwrap()
        );
    }

    #[test]
    fn another_keyring_and_tampering_do_not_decode() {
        let master = MasterKey::generate().unwrap();
        let other = MasterKey::generate().unwrap();
        let encoded = encode_name(&master, "secret.docx").unwrap();

        assert_eq!(decode_name(&other, &encoded), None);
        assert_eq!(decode_name(&master, "plain.txt"), None);

        // Flip one base64 character: the AEAD tag must reject it.
        let mut tampered = encoded.clone().into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(decode_name(&master, &tampered), None);
    }

    #[test]
    fn encoded_names_are_url_and_path_safe() {
        let master = MasterKey::generate().unwrap();
        for name in ["a/b", "..", "ünïcode 📁", "x".repeat(200).as_str()] {
            let encoded = encode_name(&master, name).unwrap();
            assert!(!encoded.contains('/'), "must stay a single path segment");
            assert!(!encoded.contains(' '));
            assert_eq!(decode_name(&master, &encoded).as_deref(), Some(name));
        }
    }
}
