//! Content-defined chunking and content-addressed manifests.
//!
//! Implements the storage primitives described in
//! `docs/rfc/0001-storage-engine.md`: split a byte stream into
//! content-defined chunks (FastCDC), identify everything by BLAKE3 hashes,
//! and describe files as an ordered list of chunk references (a manifest).

pub mod chunker;
pub mod hash;
pub mod manifest;

pub use chunker::{AVG_CHUNK_SIZE, Chunk, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, split};
pub use hash::Hash;
pub use manifest::{ChunkRef, Manifest, VerifyError, verify};
