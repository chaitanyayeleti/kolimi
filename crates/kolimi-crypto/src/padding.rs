//! Length padding for encrypted files.
//!
//! Encryption alone hides content, not size: the manifest stores ciphertext
//! lengths, so the server can read a file's exact byte count. Before
//! encrypting, clients prepend a small header carrying the true length and a
//! BLAKE3 checksum, then pad the plaintext up to a coarse bucket. The server
//! learns the bucket, not the size.
//!
//! Legacy encrypted files (written before this format) have no header:
//! [`unpad_file`] returns them unchanged.

use zeroize::Zeroizing;

use crate::CryptoError;

const MAGIC: &[u8; 8] = b"KOLIMIF1";
const VERSION: u8 = 1;
/// magic(8) + version(1) + true length(8) + reserved(7) + checksum(32)
const HEADER_LEN: usize = 56;
const MIN_BUCKET: usize = 4096;
const MIB: usize = 1024 * 1024;

/// Rounds a size up to the bucket the file will occupy.
///
/// Small files use powers of two (4 KiB … 1 MiB); larger files round up to
/// the next whole MiB. This hides the exact size while keeping the overhead
/// proportional for big files.
pub fn padded_len(true_len: usize) -> usize {
    let total = HEADER_LEN.saturating_add(true_len);
    if total <= MIN_BUCKET {
        MIN_BUCKET
    } else if total <= MIB {
        total.next_power_of_two().min(MIB)
    } else {
        total.div_ceil(MIB) * MIB
    }
}

/// Prepends the encrypted-file header and zero-pads to the bucket.
///
/// The caller encrypts the returned bytes (chunked). The zeros are part of
/// the ciphertext and reveal nothing.
pub fn pad_file(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let bucket = padded_len(data.len());
    let mut out = Zeroizing::new(Vec::with_capacity(bucket));
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&[0u8; 7]);
    out.extend_from_slice(blake3::hash(data).as_bytes());
    out.extend_from_slice(data);
    out.resize(bucket, 0);
    out
}

/// Removes the header and padding.
///
/// Files without the magic are legacy and returned unchanged. A file that
/// starts with the magic but fails its checksum is rejected rather than
/// returned with padding bytes.
pub fn unpad_file(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < HEADER_LEN || &data[..8] != MAGIC {
        return Ok(data.to_vec());
    }
    if data[8] != VERSION {
        return Err(CryptoError::Malformed("unknown padding version".into()));
    }
    let mut length = [0u8; 8];
    length.copy_from_slice(&data[9..17]);
    let true_len = u64::from_le_bytes(length) as usize;
    let end = HEADER_LEN
        .checked_add(true_len)
        .ok_or_else(|| CryptoError::Malformed("padded length overflow".into()))?;
    if end > data.len() {
        return Err(CryptoError::Malformed("truncated padded file".into()));
    }
    let plaintext = &data[HEADER_LEN..end];
    if blake3::hash(plaintext).as_bytes() != &data[24..56] {
        return Err(CryptoError::Malformed("padded file checksum".into()));
    }
    // Reject non-zero padding so a corrupt file cannot hide data there.
    if data[end..].iter().any(|byte| *byte != 0) {
        return Err(CryptoError::Malformed("non-zero padding".into()));
    }
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn roundtrip_and_buckets() {
        for len in [0usize, 1, 1000, 4096, 5000, 65_000, 1_048_576, 2_000_000] {
            let data = vec![7u8; len];
            let padded = pad_file(&data);
            assert_eq!(padded.len(), padded_len(len));
            assert!(padded.len() >= HEADER_LEN + len);
            assert_eq!(unpad_file(&padded).unwrap(), data);
        }
    }

    #[test]
    fn exact_size_is_not_recoverable_from_the_bucket() {
        let short = pad_file(&[1u8; 100]);
        let longer = pad_file(&[1u8; 3000]);
        assert_eq!(short.len(), longer.len(), "both fit in the 4 KiB bucket");
    }

    #[test]
    fn legacy_files_pass_through() {
        let legacy = b"not a padded file";
        assert_eq!(unpad_file(legacy).unwrap(), legacy);
    }

    #[test]
    fn tampering_and_truncation_fail() {
        let mut padded = pad_file(b"secret").to_vec();
        let last = padded.len() - 1;
        padded[last] = 1;
        assert!(unpad_file(&padded).is_err(), "non-zero padding");

        let mut padded = pad_file(b"secret").to_vec();
        padded[HEADER_LEN] ^= 1;
        assert!(unpad_file(&padded).is_err(), "checksum");

        let padded = pad_file(b"secret");
        assert!(unpad_file(&padded[..HEADER_LEN + 2]).is_err(), "truncated");
    }
}
