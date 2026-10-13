//! Per-file keys and deterministic chunk encryption.

use zeroize::{Zeroize, Zeroizing};

use crate::{
    CryptoError,
    keys::{CHUNK_AAD, KEY_LEN, NONCE_LEN, TAG_LEN, aead_decrypt, aead_encrypt, hkdf32, random},
};

/// A per-file content key.
///
/// One key covers a file's entire version history, which is what keeps
/// chunk-level delta sync working: identical plaintext chunks encrypt to
/// identical ciphertext under the same key.
#[derive(Clone)]
pub struct FileKey([u8; KEY_LEN]);

impl FileKey {
    /// Generates a fresh random file key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random::<KEY_LEN>()?))
    }

    /// Wraps raw bytes into a file key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// The AEAD key for this file's chunks.
    pub fn chunk_key(&self) -> Result<[u8; KEY_LEN], CryptoError> {
        hkdf32(&self.0, None, b"kolimi-chunk-v1")
    }

    /// The deterministic nonce for a plaintext chunk.
    ///
    /// Derived from the key and the BLAKE3 hash of the plaintext, so
    /// equal chunks encrypt identically (CAS delta works) and different
    /// chunks never reuse a nonce.
    fn nonce_for(&self, plaintext: &[u8]) -> Result<[u8; NONCE_LEN], CryptoError> {
        const PREFIX: &[u8] = b"kolimi-nonce-v1";
        // Fixed-size stack buffer: no heap allocation on the per-chunk path.
        let mut info = [0u8; PREFIX.len() + 32];
        info[..PREFIX.len()].copy_from_slice(PREFIX);
        info[PREFIX.len()..].copy_from_slice(blake3::hash(plaintext).as_bytes());
        let derived = hkdf32(&self.0, None, &info)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&derived[..NONCE_LEN]);
        Ok(nonce)
    }

    /// Encrypts one plaintext chunk.
    ///
    /// Returns `nonce || ciphertext`, deterministic for equal plaintext.
    pub fn encrypt_chunk(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.chunk_key()?;
        let nonce = self.nonce_for(plaintext)?;
        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        out.extend_from_slice(&nonce);
        out.extend(aead_encrypt(&key, &nonce, CHUNK_AAD, plaintext)?);
        Ok(out)
    }

    /// Decrypts one chunk produced by [`Self::encrypt_chunk`].
    pub fn decrypt_chunk(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if ciphertext.len() < NONCE_LEN + TAG_LEN {
            return Err(CryptoError::Malformed(format!(
                "chunk ciphertext is {} bytes",
                ciphertext.len()
            )));
        }
        let (nonce, body) = ciphertext.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CryptoError::Malformed("nonce".to_string()))?;
        let key = self.chunk_key()?;
        aead_decrypt(&key, &nonce, CHUNK_AAD, body)
    }

    /// Overhead added to every chunk by encryption.
    pub const CHUNK_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
}

impl std::fmt::Debug for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileKey([redacted])")
    }
}

impl Drop for FileKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn chunk_roundtrip() {
        let key = FileKey::generate().unwrap();
        for plaintext in [b"".as_slice(), b"hello".as_slice(), &[0x42u8; 300_000]] {
            let ciphertext = key.encrypt_chunk(plaintext).unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + FileKey::CHUNK_OVERHEAD);
            assert_eq!(
                key.decrypt_chunk(&ciphertext).unwrap().as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn encryption_is_deterministic_per_key() {
        let key = FileKey::generate().unwrap();
        let other = FileKey::generate().unwrap();
        let plaintext = b"the same bytes every time";
        let a = key.encrypt_chunk(plaintext).unwrap();
        let b = key.encrypt_chunk(plaintext).unwrap();
        assert_eq!(a, b, "equal chunks must encrypt identically for CAS delta");
        let c = other.encrypt_chunk(plaintext).unwrap();
        assert_ne!(
            a, c,
            "different file keys must not produce equal ciphertext"
        );
        assert_ne!(
            &a[NONCE_LEN..],
            plaintext.as_slice(),
            "ciphertext must not be plaintext"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let key = FileKey::generate().unwrap();
        let mut ciphertext = key.encrypt_chunk(b"integrity").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert!(matches!(
            key.decrypt_chunk(&ciphertext),
            Err(CryptoError::Decryption)
        ));
        assert!(matches!(
            key.decrypt_chunk(&ciphertext[..10]),
            Err(CryptoError::Malformed(_))
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let key = FileKey::generate().unwrap();
        let other = FileKey::generate().unwrap();
        let ciphertext = key.encrypt_chunk(b"secret").unwrap();
        assert!(matches!(
            other.decrypt_chunk(&ciphertext),
            Err(CryptoError::Decryption)
        ));
    }
}
