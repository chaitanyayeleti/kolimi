//! Client-side end-to-end encryption for Kolimi (RFC 0007).
//!
//! Everything in this crate runs on the client. The server only ever
//! stores wrapped keys and ciphertext; it can derive nothing from them.
//!
//! Key hierarchy:
//!
//! ```text
//! passphrase ──Argon2id──▶ KEK ┐
//! recovery code ──HKDF──▶ KEK ┤─unwrap─▶ UMK (user master key)
//! passkey PRF ──HKDF───▶ KEK ┘
//!                                        │ wrap
//!                                        ▼
//!                            FK (per-file key) ──HKDF──▶ chunk key + nonce
//! ```
//!
//! Chunk encryption is deterministic (nonce derived from the plaintext
//! chunk hash) so that identical plaintext chunks yield identical
//! ciphertext chunks: the server-side CAS delta and dedup keep working
//! within one file's history. Cross-file dedup is impossible because
//! every file has its own key.

#![forbid(unsafe_code)]

mod error;
mod file;
mod keyring;
mod keys;

pub use error::CryptoError;
pub use file::FileKey;
pub use keyring::{
    Keyring, Wrap, generate_recovery_code, recovery_code_display, recovery_code_parse,
};
pub use keys::{
    Argon2Params, kek_from_passphrase, kek_from_prf, kek_from_recovery_code, wrap_with_nonce,
};
pub use keys::{MasterKey, RECOVERY_CODE_LEN};
