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
use zeroize::Zeroize;

use crate::{
    CryptoError, FileKey,
    keys::{KEY_LEN, NONCE_LEN, TAG_LEN, aead_decrypt, aead_encrypt, hkdf32, random},
};

/// Additional authenticated data for share-key wraps.
const SHARE_AAD: &[u8] = b"kolimi-share-v1";
/// Length of a wrapped share key: ephemeral public key, nonce, ciphertext.
pub const SHARE_KEY_LEN: usize = KEY_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

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
        let wrap_key = share_wrap_key(shared.as_bytes(), &ephemeral_public, &self.public_key())?;
        let bytes = aead_decrypt(&wrap_key, &nonce, SHARE_AAD, ciphertext)?;
        let bytes: [u8; KEY_LEN] = bytes
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

impl Drop for Identity {
    fn drop(&mut self) {
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
    }
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
pub fn wrap_with_ephemeral_nonce(
    ephemeral_secret: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    file_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = StaticSecret::from(*ephemeral_secret);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_public));
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
    let mut salt = [0u8; KEY_LEN * 2];
    salt[..KEY_LEN].copy_from_slice(ephemeral_public);
    salt[KEY_LEN..].copy_from_slice(recipient_public);
    hkdf32(shared, Some(&salt), SHARE_AAD)
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
    fn identity_is_stable_from_bytes() {
        let identity = Identity::generate().unwrap();
        let restored = Identity::from_bytes(identity.private_bytes());
        assert_eq!(restored.public_key(), identity.public_key());
    }
}
