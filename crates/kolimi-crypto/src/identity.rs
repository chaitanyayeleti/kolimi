//! X25519 identities and recipient key wrapping (RFC 0007 v2 sharing).
//!
//! Every user has an X25519 keypair. The private key is stored wrapped
//! under the user's master key; the public key is published. To share an
//! encrypted file, the owner performs an ephemeral ECIES-style exchange:
//!
//! ```text
//! ephemeral_secret ──DH──▶ recipient_public
//!        │
//!        └─ HKDF(salt = eph_pub || recipient_pub, info = "kolimi-share-v1")
//!              └─▶ wrap key ──AEAD──▶ file key
//! ```
//!
//! The recipient reverses it with their private key. The server sees an
//! ephemeral public key and a ciphertext it cannot use.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    CryptoError, FileKey,
    keys::{KEY_LEN, NONCE_LEN, TAG_LEN, aead_decrypt, aead_encrypt, hkdf32, random},
};

/// Additional authenticated data for share-key wraps.
const SHARE_AAD: &[u8] = b"kolimi-share-v1";
/// Length of a wrapped share key: ephemeral public key, nonce, ciphertext.
pub const SHARE_KEY_LEN: usize = KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

/// Additional authenticated data for device-enrollment wraps.
const DEVICE_AAD: &[u8] = b"kolimi-device-v1";
/// Length of a device-wrapped secret: ephemeral public key, nonce, ciphertext.
pub const DEVICE_KEY_LEN: usize = KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

/// A user's X25519 identity.
#[derive(Clone)]
pub struct Identity(StaticSecret);

impl Identity {
    /// Generates a fresh identity.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(StaticSecret::from(random::<KEY_LEN>()?)))
    }

    /// Restores an identity from its 32 private bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The private key bytes (wrap these under the master key).
    pub fn private_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// The public key bytes (publish these).
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        PublicKey::from(&self.0).to_bytes()
    }

    /// Wraps a file key for `recipient_public` with a fresh ephemeral key.
    pub fn wrap_file_key_for(
        &self,
        recipient_public: &[u8; KEY_LEN],
        file_key: &FileKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let ephemeral = random::<KEY_LEN>()?;
        wrap_with_ephemeral(&ephemeral, recipient_public, file_key.as_bytes())
    }

    /// Unwraps a file key wrapped for this identity's public key.
    pub fn unwrap_file_key(&self, wrapped: &[u8]) -> Result<FileKey, CryptoError> {
        if wrapped.len() != SHARE_KEY_LEN {
            return Err(CryptoError::Malformed(format!(
                "share key is {} bytes",
                wrapped.len()
            )));
        }
        let (ephemeral_public, rest) = wrapped.split_at(KEY_LEN);
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let ephemeral_public: [u8; KEY_LEN] = ephemeral_public
            .try_into()
            .map_err(|_| CryptoError::Malformed("ephemeral key".to_string()))?;
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::Malformed("nonce".to_string()))?;
        let shared = self.0.diffie_hellman(&PublicKey::from(ephemeral_public));
        ensure_contributory(shared.as_bytes())?;
        let wrap_key = share_wrap_key(shared.as_bytes(), &ephemeral_public, &self.public_key())?;
        let bytes = aead_decrypt(&wrap_key, &nonce, SHARE_AAD, ciphertext)?;
        let bytes: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("file key length".to_string()))?;
        Ok(FileKey::from_bytes(bytes))
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Identity([redacted])")
    }
}

/// Rejects a DH result that is not contributory: an all-zero shared secret,
/// which every low-order X25519 public key produces (X25519 clamps the scalar
/// to a multiple of the cofactor). RFC 7748 §6.1.
fn ensure_contributory(shared: &[u8; KEY_LEN]) -> Result<(), CryptoError> {
    if shared.iter().all(|byte| *byte == 0) {
        Err(CryptoError::Params(
            "X25519 shared secret is not contributory".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Whether a 32-byte X25519 public key is safe to use as a recipient: a DH
/// with a fixed non-zero scalar must be contributory. Low-order points (which
/// yield an all-zero shared secret) are rejected. Defaults that are used when
/// a client cannot perform the check (e.g. the server validating a published
/// key) should reject when this returns `false`.
pub fn is_valid_public_key(key: &[u8; KEY_LEN]) -> bool {
    let probe = StaticSecret::from([0x42u8; KEY_LEN]);
    let shared = probe.diffie_hellman(&PublicKey::from(*key));
    ensure_contributory(shared.as_bytes()).is_ok()
}

/// A short, human-comparable code that commits to a device's public key and
/// an enrollment id (RFC 0008).
///
/// Both devices derive it independently — the new device from its own public
/// key, the approving device from the public key the server returned. A server
/// that substitutes the device's key therefore yields two different codes, and
/// the approving device refuses to approve.
pub fn enrollment_code(device_public: &[u8; KEY_LEN], enrollment_id: i64) -> String {
    let mut material = Vec::with_capacity(KEY_LEN + 8);
    material.extend_from_slice(device_public);
    material.extend_from_slice(&enrollment_id.to_be_bytes());
    let digest = blake3::derive_key("kolimi-enroll-code-v1", &material);
    group_hex(&crate::keyring::hex_encode(&digest[..6]), 4)
}

/// A stable fingerprint of a public key, for out-of-band comparison.
pub fn fingerprint(public: &[u8; KEY_LEN]) -> String {
    let digest = blake3::derive_key("kolimi-fingerprint-v1", public);
    group_hex(&crate::keyring::hex_encode(&digest[..8]), 4)
}

/// Normalizes a user-entered code or fingerprint: strips separators and
/// uppercases, so `abcd-ef01` and `ABCD EF01` compare equal.
pub fn normalize_code(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t' | ':'))
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Formats lowercase hex into dash-separated uppercase groups.
fn group_hex(hex: &str, size: usize) -> String {
    hex.to_uppercase()
        .as_bytes()
        .chunks(size)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Deterministic wrap used by the committed test vectors.
pub fn wrap_with_ephemeral(
    ephemeral_secret: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    file_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = random::<NONCE_LEN>()?;
    wrap_with_ephemeral_nonce(ephemeral_secret, recipient_public, file_key, &nonce)
}

/// Fully deterministic wrap (fixed nonce) for test vectors.
#[doc(hidden)]
pub fn wrap_with_ephemeral_nonce(
    ephemeral_secret: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    file_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_public));
    ensure_contributory(shared.as_bytes())?;
    let wrap_key = share_wrap_key(shared.as_bytes(), &ephemeral_public, recipient_public)?;
    let mut out = Vec::with_capacity(SHARE_KEY_LEN);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&aead_encrypt(&wrap_key, nonce, SHARE_AAD, file_key)?);
    Ok(out)
}

fn share_wrap_key(
    shared: &[u8; KEY_LEN],
    ephemeral_public: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
) -> Result<[u8; KEY_LEN], CryptoError> {
    ecies_wrap_key(shared, ephemeral_public, recipient_public, SHARE_AAD)
}

/// Wraps an arbitrary 32-byte secret (e.g. the user master key) for a
/// device's public key, using a fresh ephemeral key. Used by multi-device
/// enrollment so a new device can receive the master key without the user
/// re-typing their passphrase.
pub fn wrap_secret_for(
    recipient_public: &[u8; KEY_LEN],
    secret: &[u8; KEY_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = random::<KEY_LEN>()?;
    let nonce = random::<NONCE_LEN>()?;
    wrap_secret_with_ephemeral_nonce(&ephemeral, recipient_public, secret, &nonce)
}

/// Fully deterministic device wrap (fixed ephemeral key + nonce) for test
/// vectors.
#[doc(hidden)]
pub fn wrap_secret_with_ephemeral_nonce(
    ephemeral_secret: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    secret: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_public));
    ensure_contributory(shared.as_bytes())?;
    let wrap_key = ecies_wrap_key(
        shared.as_bytes(),
        &ephemeral_public,
        recipient_public,
        DEVICE_AAD,
    )?;
    let mut out = Vec::with_capacity(DEVICE_KEY_LEN);
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&aead_encrypt(&wrap_key, nonce, DEVICE_AAD, secret)?);
    Ok(out)
}

/// Unwraps a secret produced by [`wrap_secret_for`] using the device's
/// private key.
pub fn unwrap_secret(
    device_secret: &[u8; KEY_LEN],
    wrapped: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    if wrapped.len() != DEVICE_KEY_LEN {
        return Err(CryptoError::Malformed(format!(
            "device key is {} bytes",
            wrapped.len()
        )));
    }
    let (ephemeral_public, rest) = wrapped.split_at(KEY_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let ephemeral_public: [u8; KEY_LEN] = ephemeral_public
        .try_into()
        .map_err(|_| CryptoError::Malformed("ephemeral key".to_string()))?;
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoError::Malformed("nonce".to_string()))?;
    let device = StaticSecret::from(*device_secret);
    let device_public = PublicKey::from(&device).to_bytes();
    let shared = device.diffie_hellman(&PublicKey::from(ephemeral_public));
    ensure_contributory(shared.as_bytes())?;
    let wrap_key = ecies_wrap_key(
        shared.as_bytes(),
        &ephemeral_public,
        &device_public,
        DEVICE_AAD,
    )?;
    let bytes = aead_decrypt(&wrap_key, &nonce, DEVICE_AAD, ciphertext)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("device secret length".to_string()))
}

/// HKDF over the ECDH shared secret, salted with the ephemeral and recipient
/// public keys, domain-separated by `aad`.
fn ecies_wrap_key(
    shared: &[u8; KEY_LEN],
    ephemeral_public: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    let mut salt = [0u8; KEY_LEN * 2];
    salt[..KEY_LEN].copy_from_slice(ephemeral_public);
    salt[KEY_LEN..].copy_from_slice(recipient_public);
    hkdf32(shared, Some(&salt), aad)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let file_key = FileKey::generate().unwrap();
        let wrapped = alice
            .wrap_file_key_for(&bob.public_key(), &file_key)
            .unwrap();
        assert_eq!(wrapped.len(), SHARE_KEY_LEN);
        let unwrapped = bob.unwrap_file_key(&wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), file_key.as_bytes());

        // The ciphertext never contains the file key.
        assert_ne!(&wrapped[KEY_LEN + NONCE_LEN..], file_key.as_bytes());
    }

    #[test]
    fn wrong_recipient_fails() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let file_key = FileKey::generate().unwrap();
        let wrapped = alice
            .wrap_file_key_for(&bob.public_key(), &file_key)
            .unwrap();
        assert!(mallory.unwrap_file_key(&wrapped).is_err());
        assert!(bob.unwrap_file_key(&wrapped[..10]).is_err());
    }

    #[test]
    fn rejects_low_order_recipient_key() {
        let alice = Identity::generate().unwrap();
        let file_key = FileKey::generate().unwrap();
        // The all-zero point is low order: DH yields an all-zero secret.
        assert!(alice.wrap_file_key_for(&[0u8; KEY_LEN], &file_key).is_err());
        assert!(wrap_secret_for(&[0u8; KEY_LEN], &random::<KEY_LEN>().unwrap()).is_err());
    }

    #[test]
    fn enrollment_code_binds_key_and_id() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        let code = enrollment_code(&alice.public_key(), 7);
        // Stable for the same key and id.
        assert_eq!(code, enrollment_code(&alice.public_key(), 7));
        // A substituted key (the server's attack) changes the code.
        assert_ne!(code, enrollment_code(&mallory.public_key(), 7));
        // A different enrollment id changes the code too.
        assert_ne!(code, enrollment_code(&alice.public_key(), 8));
        assert_eq!(
            normalize_code(&code),
            normalize_code(&code.replace('-', "").to_lowercase())
        );
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        let alice = Identity::generate().unwrap();
        let mallory = Identity::generate().unwrap();
        assert_eq!(
            fingerprint(&alice.public_key()),
            fingerprint(&alice.public_key())
        );
        assert_ne!(
            fingerprint(&alice.public_key()),
            fingerprint(&mallory.public_key())
        );
        assert_eq!(fingerprint(&alice.public_key()).len(), 19); // 4 groups of 4 + dashes
    }

    #[test]
    fn identity_is_stable_from_bytes() {
        let identity = Identity::generate().unwrap();
        let restored = Identity::from_bytes(identity.private_bytes());
        assert_eq!(restored.public_key(), identity.public_key());
    }

    #[test]
    fn device_secret_roundtrip() {
        let device = Identity::generate().unwrap();
        let secret = random::<KEY_LEN>().unwrap();
        let wrapped = wrap_secret_for(&device.public_key(), &secret).unwrap();
        assert_eq!(wrapped.len(), DEVICE_KEY_LEN);
        assert_eq!(
            unwrap_secret(&device.private_bytes(), &wrapped).unwrap(),
            secret
        );

        // A different device cannot unwrap it.
        let other = Identity::generate().unwrap();
        assert!(unwrap_secret(&other.private_bytes(), &wrapped).is_err());
        assert!(unwrap_secret(&device.private_bytes(), &wrapped[..10]).is_err());
    }
}
