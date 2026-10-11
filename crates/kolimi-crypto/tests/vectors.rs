//! Committed interop test vectors (RFC 0007).
//!
//! Any client implementation of Kolimi E2EE must reproduce these
//! bit-for-bit. Regenerate with
//! `cargo run -p kolimi-crypto --example gen_vectors`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use kolimi_crypto::{
    Argon2Params, FileKey, kek_from_passphrase, kek_from_prf, kek_from_recovery_code,
    wrap_with_nonce,
};
use serde_json::Value;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors.json")).unwrap()
}

#[test]
fn passphrase_kek_matches_committed_vector() {
    let vectors = vectors();
    let case = &vectors["kek_passphrase"];
    let params = Argon2Params {
        m_cost: case["m_cost"].as_u64().unwrap() as u32,
        t_cost: case["t_cost"].as_u64().unwrap() as u32,
        p_cost: case["p_cost"].as_u64().unwrap() as u32,
    };
    let kek = kek_from_passphrase(
        case["passphrase"].as_str().unwrap(),
        &unhex(case["salt"].as_str().unwrap()),
        &params,
    )
    .unwrap();
    assert_eq!(hex(kek.as_slice()), case["kek"].as_str().unwrap());
}

#[test]
fn recovery_and_prf_keks_match_committed_vectors() {
    let vectors = vectors();
    let case = &vectors["kek_recovery"];
    let code: [u8; 32] = unhex(case["code"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(
        hex(kek_from_recovery_code(&code).unwrap().as_slice()),
        case["kek"].as_str().unwrap()
    );
    let case = &vectors["kek_prf"];
    let prf: [u8; 32] = unhex(case["prf"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(
        hex(kek_from_prf(&prf).unwrap().as_slice()),
        case["kek"].as_str().unwrap()
    );
}

#[test]
fn key_wrap_matches_committed_vector() {
    let vectors = vectors();
    let case = &vectors["wrap"];
    let kek: [u8; 32] = unhex(case["kek"].as_str().unwrap()).try_into().unwrap();
    let key: [u8; 32] = unhex(case["key"].as_str().unwrap()).try_into().unwrap();
    let nonce: [u8; 24] = unhex(case["nonce"].as_str().unwrap()).try_into().unwrap();
    let aad = case["aad"].as_str().unwrap().as_bytes();
    let wrapped = wrap_with_nonce(&kek, &key, aad, &nonce).unwrap();
    assert_eq!(hex(&wrapped), case["wrapped"].as_str().unwrap());
}

#[test]
fn chunk_encryption_matches_committed_vector() {
    let vectors = vectors();
    let case = &vectors["chunk"];
    let file_key: [u8; 32] = unhex(case["file_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let plaintext = unhex(case["plaintext"].as_str().unwrap());
    let file_key = FileKey::from_bytes(file_key);
    let ciphertext = file_key.encrypt_chunk(&plaintext).unwrap();
    assert_eq!(hex(&ciphertext), case["ciphertext"].as_str().unwrap());
    assert_eq!(file_key.decrypt_chunk(&ciphertext).unwrap(), plaintext);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
