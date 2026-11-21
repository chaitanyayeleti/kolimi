use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use crate::AuthError;

/// Minimum accepted password length.
pub const MIN_PASSWORD_LEN: usize = 10;

/// Small, deliberately conservative blocklist of passwords that appear at
/// the top of every breach corpus. This is not a replacement for a full
/// breached-password check, but it catches the worst choices offline.
const COMMON_PASSWORDS: &[&str] = &[
    "1234567890",
    "12345678910",
    "abc1234567",
    "admin12345",
    "iloveyou123",
    "letmein123",
    "password",
    "password1",
    "password123",
    "password1234",
    "password@123",
    "password@1234",
    "qwerty12345",
    "welcome123",
    "welcome1234",
];

fn is_common_password(password: &str) -> bool {
    let lower = password.to_ascii_lowercase();
    COMMON_PASSWORDS.contains(&lower.as_str())
}

/// Hashes a password with Argon2id and a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword(MIN_PASSWORD_LEN));
    }
    if is_common_password(password) {
        return Err(AuthError::CommonPassword);
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| AuthError::Hashing(e.to_string()))
}

/// Verifies a password against an Argon2id PHC string.
///
/// Returns `Ok(false)` for any mismatch, including a well-formed hash of
/// a different password.
pub fn verify_password(hash: &str, password: &str) -> Result<bool, AuthError> {
    if PasswordHash::new(hash).is_err() {
        return Err(AuthError::MalformedHash);
    }
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password(&hash, "correct horse battery staple").unwrap());
    }

    #[test]
    fn wrong_password_fails() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(!verify_password(&hash, "wrong password").unwrap());
    }

    #[test]
    fn salts_are_unique() {
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn short_passwords_are_rejected() {
        assert!(matches!(
            hash_password("short"),
            Err(AuthError::WeakPassword(_))
        ));
    }

    #[test]
    fn common_passwords_are_rejected_case_insensitively() {
        assert!(matches!(
            hash_password("Password@1234"),
            Err(AuthError::CommonPassword)
        ));
        assert!(matches!(
            hash_password("PASSWORD123"),
            Err(AuthError::CommonPassword)
        ));
    }

    #[test]
    fn malformed_hash_is_rejected() {
        assert!(matches!(
            verify_password("not-a-phc-string", "x"),
            Err(AuthError::MalformedHash)
        ));
    }
}
