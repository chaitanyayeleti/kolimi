use fastcdc::v2020::FastCDC;

use crate::Hash;

/// Minimum chunk size (256 KiB).
pub const MIN_CHUNK_SIZE: u32 = 256 * 1024;
/// Average chunk size (1 MiB).
pub const AVG_CHUNK_SIZE: u32 = 1024 * 1024;
/// Maximum chunk size (4 MiB).
pub const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// A single content-defined chunk of an input buffer.
#[derive(Debug, Clone, Copy)]
pub struct Chunk<'a> {
    /// Byte offset of this chunk in the input.
    pub offset: usize,
    /// The chunk's bytes.
    pub data: &'a [u8],
    /// BLAKE3 hash of `data`.
    pub hash: Hash,
}

/// Splits `data` into content-defined chunks.
///
/// The split is deterministic: the same input always yields the same chunks,
/// and edits only disturb nearby chunks — the basis for delta sync.
pub fn split(data: &[u8]) -> Vec<Chunk<'_>> {
    FastCDC::new(data, MIN_CHUNK_SIZE, AVG_CHUNK_SIZE, MAX_CHUNK_SIZE)
        .map(|c| {
            let chunk = &data[c.offset..c.offset + c.length];
            Chunk {
                offset: c.offset,
                data: chunk,
                hash: Hash::of(chunk),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn pseudorandom(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
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
    fn empty_input_yields_no_chunks() {
        assert!(split(b"").is_empty());
    }

    #[test]
    fn small_input_yields_one_chunk() {
        let data = b"kolimi";
        let chunks = split(data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].data, data);
        assert_eq!(chunks[0].hash, Hash::of(data));
    }

    #[test]
    fn split_is_deterministic() {
        let data = pseudorandom(8 * 1024 * 1024);
        let a: Vec<_> = split(&data).iter().map(|c| c.hash).collect();
        let b: Vec<_> = split(&data).iter().map(|c| c.hash).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn chunks_reassemble_exactly() {
        let data = pseudorandom(8 * 1024 * 1024);
        let mut rebuilt = Vec::with_capacity(data.len());
        for chunk in split(&data) {
            rebuilt.extend_from_slice(chunk.data);
        }
        assert_eq!(rebuilt, data);
    }

    #[test]
    fn insertion_only_disturbs_nearby_chunks() {
        let mut data = pseudorandom(16 * 1024 * 1024);
        let before: Vec<Hash> = split(&data).iter().map(|c| c.hash).collect();

        data.insert(0, 0xAA);
        let after: Vec<Hash> = split(&data).iter().map(|c| c.hash).collect();

        let before_set: HashSet<Hash> = before.into_iter().collect();
        let retained = after.iter().filter(|h| before_set.contains(h)).count();
        assert!(
            retained * 2 >= after.len(),
            "expected most chunks to survive an insertion, kept {retained}/{}",
            after.len()
        );
    }
}
