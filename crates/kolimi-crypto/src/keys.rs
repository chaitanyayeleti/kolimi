//! Master key, key derivation, and key wrapping.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, FileKey};

/// Length of symmetric keys.
pub const KEY_LEN: usize = 32;
/// Length of XChaCha20 nonces.
pub const NONCE_LEN: usize = 24;
/// Length of Poly1305 authentication tags.
pub const TAG_LEN: usize = 16;
/// Length of recovery codes.
pub const RECOVERY_CODE_LEN: usize = 32;

/// Additional authenticated data for file-key wraps.
pub(crate) const FK_AAD: &[u8] = b"kolimi-fk-v1";
/// Additional authenticated data for chunk ciphertexts.
pub(crate) const CHUNK_AAD: &[u8] = b"kolimi-chunk-v1";
/// Additional authenticated data for identity private-key wraps.
pub(crate) const IDENTITY_AAD: &[u8] = b"kolimi-identity-v1";

pub(crate) fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buffer = [0u8; N];
    getrandom::fill(&mut buffer).map_err(|error| CryptoError::Random(error.to_string()))?;
    Ok(buffer)
}

pub(crate) fn hkdf32(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info, &mut *okm)
        .map_err(|error| CryptoError::Params(error.to_string()))?;
    Ok(*okm)
}

pub(crate) fn aead_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Malformed("plaintext too large".to_string()))
}

pub(crate) fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decryption)
        .map(Zeroizing::new)
}

/// Wraps a 32-byte key under `kek` with a random nonce.
///
/// Returns `nonce || ciphertext`.
pub(crate) fn wrap(
    kek: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = random::<NONCE_LEN>()?;
    wrap_with_nonce(kek, key, aad, &nonce)
}

/// Deterministic wrap used by the committed test vectors.
#[doc(hidden)]
pub fn wrap_with_nonce(
    kek: &[u8; KEY_LEN],
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    let mut out = nonce.to_vec();
    out.extend(aead_encrypt(kek, nonce, aad, key)?);
    Ok(out)
}

/// Unwraps `nonce || ciphertext` under `kek`.
pub(crate) fn unwrap(
    kek: &[u8; KEY_LEN],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<[u8; KEY_LEN], CryptoError> {
    if wrapped.len() != NONCE_LEN + KEY_LEN + TAG_LEN {
        return Err(CryptoError::Malformed(format!(
            "wrapped key is {} bytes",
            wrapped.len()
        )));
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoError::Malformed("nonce".to_string()))?;
    let key = aead_decrypt(kek, &nonce, aad, ciphertext)?;
    key.as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("key length".to_string()))
}

/// Derives a key-encryption key from a passphrase with Argon2id.
pub fn kek_from_passphrase(
    passphrase: &str,
    salt: &[u8],
    params: &crate::Argon2Params,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = params.argon2_params()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *okm)
        .map_err(|error| CryptoError::Params(error.to_string()))?;
    Ok(*okm)
}

/// Derives a key-encryption key from a recovery code with HKDF-SHA256.
pub fn kek_from_recovery_code(
    code: &[u8; RECOVERY_CODE_LEN],
) -> Result<[u8; KEY_LEN], CryptoError> {
    hkdf32(code, None, b"kolimi-recovery-v1")
}

/// Derives a key-encryption key from a WebAuthn PRF output with HKDF-SHA256.
pub fn kek_from_prf(prf_output: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], CryptoError> {
    hkdf32(prf_output, None, b"kolimi-prf-v1")
}

/// A user master key: the root of a user's encryption key hierarchy.
///
/// It is never stored unwrapped; the server holds only wrapped copies
/// (the keyring).
#[derive(Clone)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    /// Generates a fresh random master key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random::<KEY_LEN>()?))
    }

    /// Wraps raw bytes into a master key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Wraps a file key for server-side storage.
    pub fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<u8>, CryptoError> {
        wrap(&self.0, file_key.as_bytes(), FK_AAD)
    }

    /// Unwraps a file key previously wrapped with [`Self::wrap_file_key`].
    pub fn unwrap_file_key(&self, wrapped: &[u8]) -> Result<FileKey, CryptoError> {
        Ok(FileKey::from_bytes(unwrap(&self.0, wrapped, FK_AAD)?))
    }

    /// Wraps an X25519 identity's private key for server-side storage.
    pub fn wrap_identity(&self, identity: &crate::Identity) -> Result<Vec<u8>, CryptoError> {
        wrap(&self.0, &identity.private_bytes(), IDENTITY_AAD)
    }

    /// Unwraps an identity private key.
    pub fn unwrap_identity(&self, wrapped: &[u8]) -> Result<crate::Identity, CryptoError> {
        Ok(crate::Identity::from_bytes(unwrap(
            &self.0,
            wrapped,
            IDENTITY_AAD,
        )?))
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Argon2id parameters for passphrase key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// RFC 0007 defaults: 64 MiB, 3 iterations, single lane.
    fn default() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl Argon2Params {
    pub(crate) fn argon2_params(self) -> Result<Params, CryptoError> {
        // Cap memory *and* total work so a tampered (unauthenticated) stored
        // keyring cannot force a huge allocation or CPU burn at unlock time.
        // The default is 64 MiB / t=3, well under these ceilings.
        if self.m_cost < 8 || self.m_cost > 1 << 18 {
            return Err(CryptoError::Params("m_cost out of range".to_string()));
        }
        if self.t_cost == 0 || self.t_cost > 16 {
            return Err(CryptoError::Params("t_cost out of range".to_string()));
        }
        if self.p_cost == 0 || self.p_cost > 16 {
            return Err(CryptoError::Params("p_cost out of range".to_string()));
        }
        if u64::from(self.m_cost) * u64::from(self.t_cost) > 1 << 22 {
            return Err(CryptoError::Params("kdf work out of range".to_string()));
        }
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|error| CryptoError::Params(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::Argon2Params;

    #[test]
    fn rejects_oversized_kdf_params() {
        // Default is well within range.
        assert!(Argon2Params::default().argon2_params().is_ok());
        // A tampered keyring cannot force a huge allocation or CPU burn.
        let huge = Argon2Params {
            m_cost: 1 << 21,
            t_cost: 3,
            p_cost: 1,
        };
        assert!(huge.argon2_params().is_err());
        let cpu = Argon2Params {
            m_cost: 1 << 18,
            t_cost: 64,
            p_cost: 1,
        };
        assert!(cpu.argon2_params().is_err());
    }
}
