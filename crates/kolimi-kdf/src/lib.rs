//! Argon2id derivation isolated in a Web Worker.
//!
//! The web UI runs this tiny wasm module off the main thread so unlocking a
//! keyring does not freeze the tab. It exposes exactly one operation: turn a
//! passphrase + salt + Argon2 parameters into a 32-byte KEK. The passphrase
//! only ever lives in the worker's memory for the duration of the call.

#![cfg(target_arch = "wasm32")]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use wasm_bindgen::prelude::*;

/// Derives the passphrase KEK (the caller unwraps the master key with it).
#[wasm_bindgen]
pub fn derive_kek(
    passphrase: &str,
    salt_b64: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, JsValue> {
    let salt = URL_SAFE_NO_PAD
        .decode(salt_b64)
        .map_err(|_| JsValue::from_str("bad salt"))?;
    let params = kolimi_crypto::Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    let kek = kolimi_crypto::kek_from_passphrase(passphrase, &salt, &params)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(kek.to_vec())
}
