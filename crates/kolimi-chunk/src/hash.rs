use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A BLAKE3-256 content hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Length of a hash in bytes.
    pub const LEN: usize = 32;

    /// Hashes `data` with BLAKE3.
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Wraps raw hash bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw hash bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the lowercase hex encoding of the hash.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

/// Error returned when parsing a hex hash string fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid hash: {0}")]
pub struct HashParseError(String);

impl FromStr for Hash {
    type Err = HashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Hash::LEN * 2 {
            return Err(HashParseError(format!(
                "expected {} hex characters, got {}",
                Hash::LEN * 2,
                s.len()
            )));
        }
        let mut bytes = [0u8; Hash::LEN];
        hex::decode_to_slice(s, &mut bytes).map_err(|e| HashParseError(e.to_string()))?;
        Ok(Self(bytes))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let hash = Hash::of(b"kolimi");
        let parsed: Hash = hash.to_string().parse().unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!("abcd".parse::<Hash>().is_err());
    }

    #[test]
    fn rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(bad.parse::<Hash>().is_err());
    }

    #[test]
    fn json_roundtrip() {
        let hash = Hash::of(b"kolimi");
        let json = serde_json::to_string(&hash).unwrap();
        let back: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, back);
    }
}
