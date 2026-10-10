//! Authentication primitives for Kolimi.
//!
//! - [`password`]: Argon2id hashing and verification
//! - [`token`]: random session tokens, stored only as BLAKE3 hashes
//! - [`lockout`]: in-memory failed-login tracking with lockout
//! - [`cache`]: short-TTL cache for expensive Basic-auth verification
//! - [`CurrentUser`]: the authenticated principal attached to requests

pub mod cache;
pub mod lockout;
pub mod passkey;
pub mod password;
pub mod token;
mod user;

pub use user::CurrentUser;

/// Shared authentication error type.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Password hashing or verification failed.
    #[error("password hashing failed: {0}")]
    Hashing(String),
    /// The password does not meet policy.
    #[error("password must be at least {0} characters")]
    WeakPassword(usize),
    /// Randomness generation failed.
    #[error("randomness error: {0}")]
    Random(String),
    /// The stored hash is malformed.
    #[error("malformed password hash")]
    MalformedHash,
    /// WebAuthn configuration or ceremony failure.
    #[error("passkey error: {0}")]
    Passkey(String),
    /// The passkey challenge is unknown, expired, already used, or
    /// belongs to a different user.
    #[error("passkey challenge is unknown, expired, already used, or belongs to a different user")]
    PasskeyChallenge,
}
