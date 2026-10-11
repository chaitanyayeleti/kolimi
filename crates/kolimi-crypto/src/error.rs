//! Errors returned by the crypto layer.

/// Errors returned by the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The system random number generator failed.
    #[error("randomness: {0}")]
    Random(String),
    /// A key blob was malformed (wrong length, truncated, or corrupt).
    #[error("malformed key material: {0}")]
    Malformed(String),
    /// Authentication failed while unwrapping or decrypting.
    #[error("decryption failed")]
    Decryption,
    /// The passphrase/recovery/PRF did not unlock the keyring.
    #[error("unlock failed")]
    Unlock,
    /// The keyring JSON is invalid or unsupported.
    #[error("keyring: {0}")]
    Keyring(String),
    /// Key-derivation parameters are out of range.
    #[error("invalid kdf parameters: {0}")]
    Params(String),
}
