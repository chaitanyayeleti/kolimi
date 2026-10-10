#![no_main]

use kolimi_chunk::{Hash, Manifest, chunker, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let chunks = chunker::split(data);

    // Every chunk hash must match its bytes.
    for chunk in &chunks {
        assert_eq!(chunk.hash, Hash::of(chunk.data));
    }

    // Reassembly must reproduce the exact input.
    let mut rebuilt = Vec::with_capacity(data.len());
    for chunk in &chunks {
        rebuilt.extend_from_slice(chunk.data);
    }
    assert_eq!(rebuilt, data);

    // Manifest derivation, verification, and serialization must round-trip.
    let manifest = Manifest::for_data(data);
    verify(data, &manifest).expect("fresh manifest must verify");

    let json = serde_json::to_string(&manifest).expect("manifest must serialize");
    let back: Manifest = serde_json::from_str(&json).expect("manifest must deserialize");
    assert_eq!(manifest, back);
    assert_eq!(manifest.content_id(), back.content_id());
});
