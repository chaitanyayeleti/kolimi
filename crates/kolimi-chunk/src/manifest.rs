use serde::{Deserialize, Serialize};

use crate::{Hash, chunker};

/// A reference to a single chunk stored in the blob store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    /// BLAKE3 hash of the chunk's bytes (also its address in the blob store).
    pub hash: Hash,
    /// Chunk length in bytes.
    pub len: u32,
}

/// An ordered list of chunk references describing a file's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version.
    pub version: u8,
    /// Total file size in bytes.
    pub size: u64,
    /// Chunks in order.
    pub chunks: Vec<ChunkRef>,
}

impl Manifest {
    /// Current manifest format version.
    pub const VERSION: u8 = 1;

    /// Chunks `data` and describes it as a manifest.
    pub fn for_data(data: &[u8]) -> Self {
        let chunks = chunker::split(data)
            .into_iter()
            .map(|c| ChunkRef {
                hash: c.hash,
                len: c.data.len() as u32,
            })
            .collect();
        Self {
            version: Self::VERSION,
            size: data.len() as u64,
            chunks,
        }
    }

    /// Identity of the content this manifest describes.
    ///
    /// A BLAKE3 hash over the format version and the ordered chunk
    /// (hash, length) pairs. Two manifests with the same content id describe
    /// identical bytes, regardless of how the file was named or stored.
    pub fn content_id(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[self.version]);
        for chunk in &self.chunks {
            hasher.update(chunk.hash.as_bytes());
            hasher.update(&chunk.len.to_le_bytes());
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// The size implied by the chunk lengths.
    pub fn declared_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| u64::from(chunk.len)).sum()
    }

    /// Whether `size` agrees with the sum of the chunk lengths.
    ///
    /// A manifest whose `size` lies can otherwise force an oversized
    /// allocation (`Vec::with_capacity(size)`) when it is read.
    pub fn is_consistent(&self) -> bool {
        self.size == self.declared_size()
    }
}

/// Reasons a manifest can fail to match a byte buffer.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The manifest was written in a format version this build does not know.
    #[error("unsupported manifest version {0}")]
    Version(u8),
    /// The manifest and the data disagree on total size.
    #[error("size mismatch: manifest says {expected} bytes, data has {actual}")]
    Size {
        /// Size recorded in the manifest.
        expected: u64,
        /// Size of the provided data.
        actual: u64,
    },
    /// The manifest and the data disagree on content.
    #[error("content mismatch: manifest {expected}, data {actual}")]
    Content {
        /// Content id recorded in the manifest.
        expected: Hash,
        /// Content id of the provided data.
        actual: Hash,
    },
}

/// Verifies that `data` matches `manifest` byte for byte.
pub fn verify(data: &[u8], manifest: &Manifest) -> Result<(), VerifyError> {
    if manifest.version != Manifest::VERSION {
        return Err(VerifyError::Version(manifest.version));
    }
    let actual = Manifest::for_data(data);
    if actual.size != manifest.size {
        return Err(VerifyError::Size {
            expected: manifest.size,
            actual: actual.size,
        });
    }
    let expected_id = manifest.content_id();
    let actual_id = actual.content_id();
    if expected_id != actual_id {
        return Err(VerifyError::Content {
            expected: expected_id,
            actual: actual_id,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudorandom(len: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn empty_file_has_no_chunks() {
        let manifest = Manifest::for_data(b"");
        assert!(manifest.chunks.is_empty());
        assert_eq!(manifest.size, 0);
        verify(b"", &manifest).unwrap();
    }

    #[test]
    fn multi_chunk_file_verifies() {
        let data = pseudorandom(5 * 1024 * 1024);
        let manifest = Manifest::for_data(&data);
        assert!(manifest.chunks.len() > 1);
        verify(&data, &manifest).unwrap();
    }

    #[test]
    fn detects_corruption() {
        let mut data = pseudorandom(2 * 1024 * 1024);
        let manifest = Manifest::for_data(&data);
        data[1_000_000] ^= 0xFF;
        assert!(matches!(
            verify(&data, &manifest),
            Err(VerifyError::Content { .. })
        ));
    }

    #[test]
    fn detects_truncation() {
        let data = pseudorandom(2 * 1024 * 1024);
        let manifest = Manifest::for_data(&data);
        assert!(matches!(
            verify(&data[..data.len() - 1], &manifest),
            Err(VerifyError::Size { .. })
        ));
    }

    #[test]
    fn rejects_unknown_version() {
        let manifest = Manifest::for_data(b"kolimi");
        let mut wrong = manifest.clone();
        wrong.version = 99;
        assert!(matches!(
            verify(b"kolimi", &wrong),
            Err(VerifyError::Version(99))
        ));
    }

    #[test]
    fn json_roundtrip_preserves_identity() {
        let data = pseudorandom(3 * 1024 * 1024);
        let manifest = Manifest::for_data(&data);
        let json = serde_json::to_string(&manifest).unwrap();
        let back: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
        assert_eq!(manifest.content_id(), back.content_id());
    }
}
