use crate::AuthError;

/// Generates a new session token (32 random bytes, hex-encoded).
pub fn new_session_token() -> Result<String, AuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| AuthError::Random(e.to_string()))?;
    Ok(hex::encode(bytes))
}

/// Hashes a session token for storage and lookup.
pub fn hash_token(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

/// Generates a CSRF token for double-submit cookie checks.
pub fn new_csrf_token() -> Result<String, AuthError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| AuthError::Random(e.to_string()))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_hex() {
        let a = new_session_token().unwrap();
        let b = new_session_token().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_deterministic_and_not_identity() {
        let token = "sometoken";
        assert_eq!(hash_token(token), hash_token(token));
        assert_ne!(hash_token(token), hash_token("othertoken"));
    }
}
