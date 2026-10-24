#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The keyring parser must never panic on arbitrary ciphertext.
    let _ = kolimi_mls::keyring::decrypt(&[7u8; 32], b"group", 3, data);
});
