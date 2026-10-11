#![no_main]

//! The E2EE decryption surface must never panic: arbitrary bytes fed to
//! keyring parsing, identity/share-key unwrapping, and chunk decryption
//! must all fail closed with errors.

use kolimi_crypto::{FileKey, Identity, Keyring, MasterKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Keyring JSON parsing.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(keyring) = Keyring::from_json(text) {
            let _ = keyring.unlock_with_passphrase(text);
            let _ = keyring.unlock_with_recovery(&[0u8; 32]);
            let _ = keyring.unlock_with_prf(&[0u8; 32]);
        }
        let _ = Keyring::from_json(text);
    }

    // Master-key and identity unwrapping with attacker-controlled blobs.
    let master = MasterKey::from_bytes([7u8; 32]);
    let _ = master.unwrap_file_key(data);
    let _ = master.unwrap_identity(data);

    let identity = Identity::from_bytes([9u8; 32]);
    let _ = identity.unwrap_file_key(data);

    // Chunk decryption with a fixed key.
    let file_key = FileKey::from_bytes([11u8; 32]);
    if let Ok(plaintext) = file_key.decrypt_chunk(data) {
        // Anything that decrypts must re-encrypt to exactly the input
        // (deterministic AEAD) — a strong internal consistency check.
        let ciphertext = file_key.encrypt_chunk(&plaintext).expect("re-encrypt");
        assert_eq!(ciphertext, data);
    }

    // Split the input in half: use one part as a wrapped-key prefix and
    // the other as the file key, exercising mixed inputs.
    if data.len() >= 2 {
        let (a, b) = data.split_at(data.len() / 2);
        let mut key = [0u8; 32];
        let take = a.len().min(32);
        key[..take].copy_from_slice(&a[..take]);
        let file_key = FileKey::from_bytes(key);
        let _ = file_key.decrypt_chunk(b);
    }
});
