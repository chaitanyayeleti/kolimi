//! RFC 6238 TOTP (SHA-1, 6 digits, 30 s) and one-time recovery codes.
//!
//! SHA-1 is used because that is what every authenticator app implements
//! (RFC 6238 §1.2); HMAC-SHA-1 is not affected by SHA-1 collision
//! attacks. Codes are compared in constant time and a matched step is
//! recorded so a code cannot be replayed within its validity window.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::AuthError;

/// Digits in a TOTP code.
pub const DIGITS: u32 = 6;
/// TOTP time step in seconds.
pub const PERIOD_SECS: u64 = 30;
/// Secret length in bytes (160 bits, RFC 4226 §4 recommendation).
pub const SECRET_LEN: usize = 20;
/// Accepted steps on either side of the current one (clock skew).
pub const WINDOW: u64 = 1;
/// Number of recovery codes issued at enrollment.
pub const RECOVERY_CODE_COUNT: usize = 10;

/// A TOTP shared secret.
#[derive(Clone)]
pub struct TotpSecret([u8; SECRET_LEN]);

impl TotpSecret {
    /// Generates a fresh random secret.
    pub fn generate() -> Result<Self, AuthError> {
        let mut bytes = [0u8; SECRET_LEN];
        getrandom::fill(&mut bytes).map_err(|error| AuthError::Random(error.to_string()))?;
        Ok(Self(bytes))
    }

    /// Parses a base32 secret (case-insensitive, spaces/dashes ignored).
    pub fn from_base32(text: &str) -> Result<Self, AuthError> {
        let bytes = base32_decode(text)?;
        let bytes: [u8; SECRET_LEN] = bytes
            .try_into()
            .map_err(|_| AuthError::Totp("secret must be 160 bits".to_string()))?;
        Ok(Self(bytes))
    }

    /// Encodes the secret as unpadded uppercase base32.
    pub fn to_base32(&self) -> String {
        base32_encode(&self.0)
    }

    /// The 6-digit code for a given Unix time.
    pub fn code_at(&self, unix_secs: u64) -> String {
        code_at(&self.0, unix_secs, DIGITS)
    }

    /// An `otpauth://` provisioning URI for authenticator apps.
    pub fn otpauth_url(&self, issuer: &str, account: &str) -> String {
        let issuer_encoded = urlencode(issuer);
        let account_encoded = urlencode(account);
        format!(
            "otpauth://totp/{issuer_encoded}:{account_encoded}?secret={}&issuer={issuer_encoded}&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECS}",
            self.to_base32()
        )
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret([redacted])")
    }
}

/// Verifies a code at `unix_secs`, accepting `WINDOW` steps of skew.
///
/// Returns the matched time step if the code is valid, so the caller can
/// persist it and refuse replays. `last_step` is the highest step
/// already consumed.
pub fn verify(
    secret: &TotpSecret,
    code: &str,
    unix_secs: u64,
    last_step: Option<u64>,
) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let step = unix_secs / PERIOD_SECS;
    let start = step.saturating_sub(WINDOW);
    let end = step + WINDOW;
    for candidate in start..=end {
        let expected = code_at(&secret.0, candidate * PERIOD_SECS, DIGITS);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes()))
            && last_step.is_none_or(|last| candidate > last)
        {
            return Some(candidate);
        }
    }
    None
}

fn code_at(secret: &[u8], unix_secs: u64, digits: u32) -> String {
    let counter = unix_secs / PERIOD_SECS;
    // HMAC accepts keys of any length; the error arm is unreachable.
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return "0".repeat(digits as usize);
    };
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = (u32::from(digest[offset]) & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    let modulus = 10u32.pow(digits);
    format!("{:0width$}", value % modulus, width = digits as usize)
}

/// Generates one-time recovery codes (16 hex chars, grouped 4-4-4-4).
pub fn generate_recovery_codes() -> Result<Vec<String>, AuthError> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|error| AuthError::Random(error.to_string()))?;
        let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        codes.push(format!(
            "{}-{}-{}-{}",
            &hex[0..4],
            &hex[4..8],
            &hex[8..12],
            &hex[12..16]
        ));
    }
    Ok(codes)
}

/// Normalizes a recovery code for hashing (lowercase, no separators).
pub fn normalize_recovery_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Hashes a recovery code for storage (SHA-256; codes are 64-bit random).
pub fn hash_recovery_code(input: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let normalized = normalize_recovery_code(input);
    Sha256::digest(normalized.as_bytes()).to_vec()
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut buffer = [0u8; 5];
        buffer[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from(buffer[0]) << 32
            | u64::from(buffer[1]) << 24
            | u64::from(buffer[2]) << 16
            | u64::from(buffer[3]) << 8
            | u64::from(buffer[4]);
        let chars = chunk.len() * 8 / 5 + usize::from(chunk.len() * 8 % 5 != 0);
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(ALPHABET[((bits >> shift) & 0x1f) as usize] as char);
        }
    }
    out
}

fn base32_decode(text: &str) -> Result<Vec<u8>, AuthError> {
    let cleaned: String = text
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '='))
        .flat_map(char::to_uppercase)
        .collect();
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    for c in cleaned.chars() {
        let value = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return Err(AuthError::Totp(format!("invalid base32 character {c}"))),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// RFC 6238 Appendix B test vector secret.
    fn rfc_secret() -> TotpSecret {
        TotpSecret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap()
    }

    #[test]
    fn matches_rfc_6238_vectors() {
        // Appendix B vectors (SHA-1) at 8 digits.
        let secret = rfc_secret();
        assert_eq!(&secret.0, b"12345678901234567890");
        let cases = [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (time, expected) in cases {
            assert_eq!(code_at(&secret.0, time, 8), expected, "time {time}");
        }
    }

    #[test]
    fn six_digit_codes_and_window() {
        let secret = rfc_secret();
        assert_eq!(secret.code_at(59), "287082");
        // Window: a code from one step back is accepted, two steps is not.
        let code = secret.code_at(30);
        assert_eq!(verify(&secret, &code, 59, None), Some(1));
        assert_eq!(verify(&secret, &code, 89, None), Some(1));
        assert_eq!(verify(&secret, &code, 119, None), None);
    }

    #[test]
    fn replay_is_rejected() {
        let secret = rfc_secret();
        let code = secret.code_at(59);
        assert_eq!(verify(&secret, &code, 59, None), Some(1));
        assert_eq!(verify(&secret, &code, 59, Some(1)), None);
    }

    #[test]
    fn malformed_codes_are_rejected() {
        let secret = rfc_secret();
        for bad in ["", "12345", "1234567", "abcdef", "12 34 5"] {
            assert_eq!(verify(&secret, bad, 59, None), None, "code {bad:?}");
        }
    }

    #[test]
    fn base32_roundtrip() {
        let secret = TotpSecret::generate().unwrap();
        let encoded = secret.to_base32();
        assert_eq!(encoded.len(), 32);
        let back = TotpSecret::from_base32(&encoded.to_lowercase()).unwrap();
        assert_eq!(back.0, secret.0);
        assert!(TotpSecret::from_base32("not-base32!").is_err());
        assert!(TotpSecret::from_base32("AAAA").is_err());
    }

    #[test]
    fn otpauth_url_is_wellformed() {
        let secret = rfc_secret();
        let url = secret.otpauth_url("Kolimi", "alice@example.com");
        assert!(url.starts_with("otpauth://totp/Kolimi:alice%40example.com?secret="));
        assert!(url.contains("digits=6&period=30"));
    }

    #[test]
    fn recovery_codes_are_unique_and_hashable() {
        let codes = generate_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let mut unique = std::collections::HashSet::new();
        for code in &codes {
            assert!(unique.insert(code.clone()), "duplicate code");
            assert_eq!(code.len(), 19);
            let normalized = normalize_recovery_code(code);
            assert_eq!(normalized.len(), 16);
            assert_eq!(
                hash_recovery_code(code),
                hash_recovery_code(&normalized.to_uppercase())
            );
        }
    }
}
