#![no_main]

//! Fuzzes the image decode + thumbnail path used by the sandboxed preview
//! worker. The decoder must never panic, allocate unboundedly, or hang on
//! hostile input (the `image` crate limits cap dimensions and allocation).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    let _ = kolimi_preview::decode_thumbnail(data, 256);
});
