//! Regenerates `tests/vectors.json` (the committed interop vectors).
//!
//! Run with `cargo run -p kolimi-crypto --example gen_vectors` after any
//! intentional format change, then commit the updated file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kolimi_crypto::{
    Argon2Params, FileKey, Identity, kek_from_passphrase, kek_from_prf, kek_from_recovery_code,
    wrap_with_ephemeral_nonce, wrap_with_nonce,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn ramp(start: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| start.wrapping_add(i as u8)).collect()
}

fn main() {
    let salt = ramp(0x00, 16);
    let passphrase = "correct horse battery staple";
    let params = Argon2Params {
        m_cost: 8192,
        t_cost: 2,
        p_cost: 1,
    };
    let passphrase_kek = kek_from_passphrase(passphrase, &salt, &params).unwrap();

    let recovery_code: [u8; 32] = ramp(0x10, 32).try_into().unwrap();
    let recovery_kek = kek_from_recovery_code(&recovery_code).unwrap();

    let prf: [u8; 32] = ramp(0x30, 32).try_into().unwrap();
    let prf_kek = kek_from_prf(&prf).unwrap();

    let kek: [u8; 32] = ramp(0x50, 32).try_into().unwrap();
    let key: [u8; 32] = ramp(0x70, 32).try_into().unwrap();
    let nonce: [u8; 24] = ramp(0x90, 24).try_into().unwrap();
    let wrapped = wrap_with_nonce(&kek, &key, b"kolimi-keyring-v1:recovery", &nonce).unwrap();

    let file_key = FileKey::from_bytes(ramp(0xb0, 32).try_into().unwrap());
    let plaintext = b"kolimi end-to-end encryption test vector";
    let ciphertext = file_key.encrypt_chunk(plaintext).unwrap();

    // Share-key wrap: fixed ephemeral secret + nonce for reproducibility.
    let recipient_secret: [u8; 32] = ramp(0xd0, 32).try_into().unwrap();
    let recipient_public = Identity::from_bytes(recipient_secret).public_key();
    let ephemeral_secret: [u8; 32] = ramp(0xf0, 32).try_into().unwrap();
    let share_nonce: [u8; 24] = ramp(0x11, 24).try_into().unwrap();
    let shared_file_key: [u8; 32] = ramp(0x33, 32).try_into().unwrap();
    let share_wrapped = wrap_with_ephemeral_nonce(
        &ephemeral_secret,
        &recipient_public,
        &shared_file_key,
        &share_nonce,
    )
    .unwrap();

    let vectors = serde_json::json!({
        "version": 1,
        "kek_passphrase": {
            "passphrase": passphrase,
            "salt": hex(&salt),
            "m_cost": params.m_cost,
            "t_cost": params.t_cost,
            "p_cost": params.p_cost,
            "kek": hex(&passphrase_kek),
        },
        "kek_recovery": {
            "code": hex(&recovery_code),
            "kek": hex(&recovery_kek),
        },
        "kek_prf": {
            "prf": hex(&prf),
            "kek": hex(&prf_kek),
        },
        "wrap": {
            "kek": hex(&kek),
            "key": hex(&key),
            "nonce": hex(&nonce),
            "aad": "kolimi-keyring-v1:recovery",
            "wrapped": hex(&wrapped),
        },
        "share_wrap": {
            "recipient_secret": hex(&recipient_secret),
            "recipient_public": hex(&recipient_public),
            "ephemeral_secret": hex(&ephemeral_secret),
            "nonce": hex(&share_nonce),
            "file_key": hex(&shared_file_key),
            "wrapped": hex(&share_wrapped),
        },
        "chunk": {
            "file_key": hex(file_key.as_bytes()),
            "plaintext": hex(plaintext),
            "ciphertext": hex(&ciphertext),
        },
    });
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
