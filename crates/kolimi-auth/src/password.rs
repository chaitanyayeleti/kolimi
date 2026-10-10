use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use crate::AuthError;

/// Minimum accepted password length.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Hashes a password with Argon2id and a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword(MIN_PASSWORD_LEN));
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
    fn malformed_hash_is_rejected() {
        assert!(matches!(
            verify_password("not-a-phc-string", "x"),
            Err(AuthError::MalformedHash)
        ));
    }
}
