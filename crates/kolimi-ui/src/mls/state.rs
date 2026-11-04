//! Sealed browser-local MLS device and group state.

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_crypto::MasterKey;
use kolimi_mls::client::Device;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::types::State;

const STATE_KEY: &str = "kolimi-mls-state-v1";

const STATE_AAD: &[u8] = b"kolimi-mls-web-state-v1";

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// MLS is on by default in the web client. Set `kolimi-mls` to `"0"` in
/// localStorage to disable group shares (legacy read-only wraps remain).
pub fn enabled() -> bool {
    storage()
        .and_then(|storage| storage.get_item("kolimi-mls").ok().flatten())
        .is_none_or(|value| value != "0")
}

const DB_NAME: &str = "kolimi-mls";

const STORE: &str = "state";

fn request_promise(request: &web_sys::IdbRequest) -> js_sys::Promise {
    js_sys::Promise::new(&mut |resolve, reject| {
        let success_request = request.clone();
        let success = Closure::once_into_js(move || {
            let _ = resolve.call1(
                &JsValue::NULL,
                &success_request.result().unwrap_or(JsValue::UNDEFINED),
            );
        });
        let failure = Closure::once_into_js(move || {
            let _ = reject.call1(
                &JsValue::NULL,
                &JsValue::from_str("IndexedDB request failed"),
            );
        });
        request.set_onsuccess(Some(success.unchecked_ref()));
        request.set_onerror(Some(failure.unchecked_ref()));
    })
}

async fn open_db() -> Result<web_sys::IdbDatabase, String> {
    let window = web_sys::window().ok_or_else(|| "no browser window".to_string())?;
    let factory = window
        .indexed_db()
        .map_err(|_| "IndexedDB is unavailable".to_string())?
        .ok_or_else(|| "IndexedDB is unavailable".to_string())?;
    let request = factory
        .open_with_f64(DB_NAME, 1.0)
        .map_err(|_| "could not open IndexedDB".to_string())?;
    let upgrade_request = request.clone();
    let upgrade = Closure::once_into_js(move || {
        if let Ok(db) = upgrade_request
            .result()
            .and_then(|value| value.dyn_into::<web_sys::IdbDatabase>())
        {
            let _ = db.create_object_store(STORE);
        }
    });
    request.set_onupgradeneeded(Some(upgrade.unchecked_ref()));
    let value = JsFuture::from(request_promise(&request))
        .await
        .map_err(|_| "could not open IndexedDB".to_string())?;
    value
        .dyn_into::<web_sys::IdbDatabase>()
        .map_err(|_| "IndexedDB returned an invalid database".to_string())
}

async fn idb_get(key: &str) -> Result<Option<String>, String> {
    let db = open_db().await?;
    let transaction = db
        .transaction_with_str_and_mode(STORE, web_sys::IdbTransactionMode::Readonly)
        .map_err(|_| "IndexedDB transaction failed".to_string())?;
    let store = transaction
        .object_store(STORE)
        .map_err(|_| "IndexedDB store failed".to_string())?;
    let request = store
        .get(&JsValue::from_str(key))
        .map_err(|_| "IndexedDB get failed".to_string())?;
    let value = JsFuture::from(request_promise(&request))
        .await
        .map_err(|_| "IndexedDB get failed".to_string())?;
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        value
            .as_string()
            .map(Some)
            .ok_or_else(|| "bad MLS state".to_string())
    }
}

async fn idb_set(key: &str, value: &str) -> Result<(), String> {
    let db = open_db().await?;
    let transaction = db
        .transaction_with_str_and_mode(STORE, web_sys::IdbTransactionMode::Readwrite)
        .map_err(|_| "IndexedDB transaction failed".to_string())?;
    let store = transaction
        .object_store(STORE)
        .map_err(|_| "IndexedDB store failed".to_string())?;
    let request = store
        .put_with_key(&JsValue::from_str(value), &JsValue::from_str(key))
        .map_err(|_| "IndexedDB put failed".to_string())?;
    JsFuture::from(request_promise(&request))
        .await
        .map_err(|_| "IndexedDB put failed".to_string())?;
    Ok(())
}

async fn idb_delete(key: &str) -> Result<(), String> {
    let db = open_db().await?;
    let transaction = db
        .transaction_with_str_and_mode(STORE, web_sys::IdbTransactionMode::Readwrite)
        .map_err(|_| "IndexedDB transaction failed".to_string())?;
    let store = transaction
        .object_store(STORE)
        .map_err(|_| "IndexedDB store failed".to_string())?;
    let request = store
        .delete(&JsValue::from_str(key))
        .map_err(|_| "IndexedDB delete failed".to_string())?;
    JsFuture::from(request_promise(&request))
        .await
        .map_err(|_| "IndexedDB delete failed".to_string())?;
    Ok(())
}

async fn delete_db() -> Result<(), String> {
    let window = web_sys::window().ok_or_else(|| "no browser window".to_string())?;
    let factory = window
        .indexed_db()
        .map_err(|_| "IndexedDB is unavailable".to_string())?
        .ok_or_else(|| "IndexedDB is unavailable".to_string())?;
    let request = factory
        .delete_database(DB_NAME)
        .map_err(|_| "could not open IndexedDB".to_string())?;
    JsFuture::from(request_promise(&request))
        .await
        .map_err(|_| "could not delete IndexedDB".to_string())?;
    Ok(())
}

fn slot(master: &MasterKey) -> String {
    // A short, non-secret account fingerprint so several accounts in one
    // browser don't overwrite each other's state.
    let digest = blake3::hash(&master.as_bytes()[..8]);
    format!("{STATE_KEY}:{}", &digest.to_hex()[..16])
}

async fn load_state(master: &MasterKey) -> Result<Option<State>, String> {
    let key = slot(master);
    let raw = match idb_get(&key).await? {
        Some(raw) => Some(raw),
        None => {
            // Migrate the pre-IndexedDB sealed state once.
            let legacy = storage().and_then(|storage| storage.get_item(&key).ok().flatten());
            if let Some(raw) = &legacy {
                idb_set(&key, raw).await?;
                if let Some(storage) = storage() {
                    let _ = storage.remove_item(&key);
                }
            }
            legacy
        }
    };
    let Some(raw) = raw else {
        return Ok(None);
    };
    let blob = STANDARD
        .decode(raw)
        .map_err(|_| "malformed MLS state".to_string())?;
    let plain = master
        .open_local(&blob, STATE_AAD)
        .map_err(|_| "could not decrypt MLS state".to_string())?;
    let (device, groups, pending_commits) =
        Device::import_state(&plain).map_err(|error| format!("MLS state: {error}"))?;
    Ok(Some(State {
        device,
        groups,
        pending_commits,
    }))
}

pub(super) async fn save_state(master: &MasterKey, state: &State) -> Result<(), String> {
    let plain = state
        .device
        .export_state(&state.groups, &state.pending_commits)
        .map_err(|error| format!("MLS state: {error}"))?;
    let blob = master
        .seal_local(&plain, STATE_AAD)
        .map_err(|_| "could not seal MLS state".to_string())?;
    idb_set(&slot(master), &STANDARD.encode(blob)).await
}

/// Deletes this browser's sealed MLS state.
///
/// With an unlocked master key, only this account's slot is removed. When
/// the key is unavailable (the usual state-loss case), the whole browser
/// MLS database is cleared. The caller must warn the user and explain the
/// re-add flow; the E2EE keyring and sync state are untouched.
pub async fn reset_state(master: Option<&MasterKey>) -> Result<bool, String> {
    if let Some(master) = master {
        let key = slot(master);
        let existed = idb_get(&key).await?.is_some();
        idb_delete(&key).await?;
        if let Some(storage) = storage() {
            let _ = storage.remove_item(&key);
        }
        Ok(existed)
    } else {
        delete_db().await?;
        if let Some(storage) = storage() {
            let mut keys = Vec::new();
            for index in 0..storage.length().unwrap_or(0) {
                if let Ok(Some(key)) = storage.key(index)
                    && key.starts_with(STATE_KEY)
                {
                    keys.push(key);
                }
            }
            for key in keys {
                let _ = storage.remove_item(&key);
            }
        }
        Ok(true)
    }
}

pub(super) async fn load_or_create(master: &MasterKey) -> Result<State, String> {
    if let Some(state) = load_state(master).await? {
        return Ok(state);
    }
    create_state(master, b"kolimi-web").await
}

static CREATING_STATE: AtomicBool = AtomicBool::new(false);

struct CreationGuard;

impl Drop for CreationGuard {
    fn drop(&mut self) {
        CREATING_STATE.store(false, Ordering::SeqCst);
    }
}

pub(super) async fn load_or_create_as(
    master: &MasterKey,
    identity: &[u8],
) -> Result<State, String> {
    if let Some(state) = load_state(master).await? {
        return Ok(state);
    }
    create_state(master, identity).await
}

/// Yields a full event-loop turn, not just a microtask.
///
/// A resolved promise only drains the microtask queue; the winning creator
/// is usually waiting on an IndexedDB request, which is a macrotask. Spinning
/// on microtasks would starve it and leave the UI stuck on "Unlocking…".
async fn yield_to_event_loop() {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let callback = Closure::once_into_js(move || {
            let _ = resolve.call0(&JsValue::NULL);
        });
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.unchecked_ref::<js_sys::Function>(),
                0,
            );
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// Creates the initial device state exactly once, even if two UI effects
/// race on first unlock.
async fn create_state(master: &MasterKey, identity: &[u8]) -> Result<State, String> {
    while CREATING_STATE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        yield_to_event_loop().await;
    }
    let _guard = CreationGuard;
    if let Some(state) = load_state(master).await? {
        return Ok(state);
    }
    let device = Device::new(identity).map_err(|error| format!("MLS device: {error}"))?;
    let state = State {
        device,
        groups: Vec::new(),
        pending_commits: BTreeMap::new(),
    };
    save_state(master, &state).await?;
    Ok(state)
}

/// Keeps the linter honest about the storage type on non-wasm builds.
#[allow(dead_code)]
fn _storage_type(_: Option<web_sys::Storage>) {}
