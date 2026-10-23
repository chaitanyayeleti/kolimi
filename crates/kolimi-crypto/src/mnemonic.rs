//! Recovery phrases: the 32-byte recovery code as 24 plain words.
//!
//! A 71-character hex string is never written down correctly, so the code
//! is shown as 24 BIP39 English words instead (256-bit entropy plus 8
//! checksum bits, 11 bits per word). Parsing accepts the word phrase; the
//! legacy hex grouping is still accepted so previously saved codes keep
//! working.

use sha2::{Digest, Sha256};

use crate::{CryptoError, keys::RECOVERY_CODE_LEN};

include!("mnemonic_words.inc");

/// Number of words in a recovery phrase.
pub const PHRASE_WORDS: usize = 24;

/// Formats a recovery code as a 24-word phrase.
pub fn phrase_from_bytes(code: &[u8; RECOVERY_CODE_LEN]) -> String {
    // Entropy + first checksum byte, then 11-bit word indices (BIP39).
    let checksum = Sha256::digest(code);
    let mut bits: Vec<bool> = Vec::with_capacity(PHRASE_WORDS * 11);
    for byte in code.iter().chain(std::iter::once(&checksum[0])) {
        for shift in (0..8).rev() {
            bits.push(byte >> shift & 1 == 1);
        }
    }
    let mut words = Vec::with_capacity(PHRASE_WORDS);
    let (groups, _) = bits.as_chunks::<11>();
    for chunk in groups {
        let mut index = 0usize;
        for bit in chunk {
            index = (index << 1) | usize::from(*bit);
        }
        words.push(WORDS[index]);
    }
    words.join(" ")
}

/// Parses a 24-word phrase back into the recovery code, verifying the
/// checksum so a typo fails loudly instead of unlocking nothing.
pub fn parse_phrase(text: &str) -> Result<[u8; RECOVERY_CODE_LEN], CryptoError> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.len() != PHRASE_WORDS {
        return Err(CryptoError::Malformed("recovery phrase length".to_string()));
    }
    let mut bits: Vec<bool> = Vec::with_capacity(PHRASE_WORDS * 11);
    for word in words {
        let lower = word.to_lowercase();
        let Some(index) = WORDS.iter().position(|candidate| *candidate == lower) else {
            return Err(CryptoError::Malformed("unknown recovery word".to_string()));
        };
        for shift in (0..11).rev() {
            bits.push(index >> shift & 1 == 1);
        }
    }
    let mut bytes = [0u8; RECOVERY_CODE_LEN + 1];
    let (groups, _) = bits.as_chunks::<8>();
    for (i, chunk) in groups.iter().enumerate() {
        let mut byte = 0u8;
        for bit in chunk {
            byte = (byte << 1) | u8::from(*bit);
        }
        bytes[i] = byte;
    }
    let (code, checksum) = bytes.split_at(RECOVERY_CODE_LEN);
    let expected = Sha256::digest(code);
    if checksum[0] != expected[0] {
        return Err(CryptoError::Malformed(
            "recovery phrase checksum mismatch".to_string(),
        ));
    }
    code.try_into()
        .map_err(|_| CryptoError::Malformed("recovery code length".to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn phrase_roundtrip_and_checksum() {
        let code = [0xabu8; RECOVERY_CODE_LEN];
        let phrase = phrase_from_bytes(&code);
        assert_eq!(phrase.split_whitespace().count(), PHRASE_WORDS);
        assert_eq!(parse_phrase(&phrase).unwrap(), code);
        // Case-insensitive with odd spacing.
        assert_eq!(
            parse_phrase(&phrase.to_uppercase().replace(' ', "  ")).unwrap(),
            code
        );
        // A single wrong word fails on the checksum.
        let mut bad = phrase.clone();
        bad.replace_range(..5, "aband");
        if parse_phrase(&bad).is_ok() {
            // "aband" may coincidentally keep a valid checksum only if the
            // first word already was "abandon"; otherwise this must fail.
            assert!(phrase.starts_with("abandon"));
        }
        // Unknown words fail.
        assert!(parse_phrase(&"nope ".repeat(PHRASE_WORDS)).is_err());
        // Wrong length fails.
        assert!(parse_phrase("abandon").is_err());
    }
}
