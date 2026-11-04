//! Browser MLS state for group E2EE (RFC 9420).
//!
//! MLS device/group secrets are sealed with the unlocked master key and
//! stored in `localStorage`; the server only ever sees opaque key packages,
//! commits/Welcomes and the epoch-bound share keyring.

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_crypto::MasterKey;
use kolimi_mls::SHARE_KEYRING_EXPORTER;
use kolimi_mls::client::{Device, Group};
use kolimi_mls::keyring::{ShareKeyring, decrypt as decrypt_keyring, encrypt as encrypt_keyring};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::api;
use crate::app::encode;

const STATE_KEY: &str = "kolimi-mls-state-v1";
const STATE_AAD: &[u8] = b"kolimi-mls-web-state-v1";

#[derive(Debug, Clone, Deserialize)]
struct Mount {
    mount: String,
    permission: String,
    encrypted: bool,
    #[serde(default)]
    wrapped_name: Option<String>,
}

struct State {
    device: Device,
    groups: Vec<Vec<u8>>,
    pending_commits: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// One MLS device in this account's server roster.
#[derive(Debug, Clone)]
pub struct MlsDevice {
    pub device_id: String,
    pub device_name: String,
    pub signature_key: Option<Vec<u8>>,
    pub last_seen_at: i64,
    /// Share roots where this browser can currently see the device's leaf.
    pub groups: Vec<String>,
    pub current: bool,
}

/// Roster listing plus groups this browser could not inspect.
#[derive(Debug, Clone, Default)]
pub struct MlsDeviceList {
    pub devices: Vec<MlsDevice>,
    pub warnings: Vec<String>,
}

/// Result of revoking one MLS device from the browser.
#[derive(Debug, Clone, Default)]
pub struct MlsRevokeReport {
    pub groups: Vec<String>,
    pub leaves: usize,
}

fn parse_device_roster(body: &serde_json::Value) -> Vec<MlsDevice> {
    body["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|device| MlsDevice {
            device_id: device["device_id"].as_str().unwrap_or_default().to_string(),
            device_name: device["device_name"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            signature_key: device["signature_key"]
                .as_str()
                .and_then(|encoded| STANDARD.decode(encoded).ok()),
            last_seen_at: device["last_seen_at"].as_i64().unwrap_or(0),
            groups: Vec::new(),
            current: false,
        })
        .collect()
}

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

async fn save_state(master: &MasterKey, state: &State) -> Result<(), String> {
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

async fn load_or_create(master: &MasterKey) -> Result<State, String> {
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

async fn load_or_create_as(master: &MasterKey, identity: &[u8]) -> Result<State, String> {
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

static PUBLISHING: AtomicBool = AtomicBool::new(false);

struct PublishGuard;
impl Drop for PublishGuard {
    fn drop(&mut self) {
        PUBLISHING.store(false, Ordering::SeqCst);
    }
}

/// Publishes a fresh key package pool for this browser device.
pub async fn publish_key_package(master: &MasterKey) -> Result<(), String> {
    if !enabled() {
        return Ok(());
    }
    if PUBLISHING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let _guard = PublishGuard;
    let username = api::get("/api/me")
        .await
        .ok()
        .filter(|response| response.status == 200)
        .and_then(|response| response.body["username"].as_str().map(str::to_string))
        .unwrap_or_else(|| "kolimi-web".to_string());
    let state = load_or_create_as(master, username.as_bytes()).await?;
    const POOL: usize = 4;
    let device_id = state.device.device_id();
    let own = api::get("/api/mls/key-packages").await.ok();
    let have = own
        .filter(|response| response.status == 200)
        .and_then(|response| {
            response.body["packages"].as_array().map(|packages| {
                packages
                    .iter()
                    .filter(|package| package["device_id"].as_str() == Some(&device_id))
                    .count()
            })
        })
        .unwrap_or(0);
    let mut target = POOL;
    if have >= POOL {
        // Upgraded browsers may already have a full pool without the name or
        // signature key. One extra package populates the roster.
        let metadata_missing = match api::get("/api/mls/devices").await {
            Ok(response) if response.status == 200 => response.body["devices"]
                .as_array()
                .and_then(|devices| {
                    devices
                        .iter()
                        .find(|device| device["device_id"].as_str() == Some(&device_id))
                })
                .is_none_or(|device| {
                    device["signature_key"].is_null()
                        || device["device_name"]
                            .as_str()
                            .unwrap_or_default()
                            .is_empty()
                }),
            _ => false,
        };
        if !metadata_missing {
            return Ok(());
        }
        // Add one metadata-bearing package; the server's per-device cap
        // remains authoritative if the pool is already at its limit.
        target = have + 1;
    }
    for _ in have..target {
        let package = state
            .device
            .key_package()
            .map_err(|error| format!("MLS key package: {error}"))?;
        let signature_key = state
            .device
            .key_package_signature_key(&package)
            .map_err(|error| format!("MLS key package: {error}"))?;
        let response = api::send_json(
            "PUT",
            "/api/mls/key-packages",
            &json!({
                "device_id": state.device.device_id(),
                "device_name": "Web browser",
                "signature_key": STANDARD.encode(signature_key),
                "payload": STANDARD.encode(package),
            }),
        )
        .await?;
        if response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not publish the MLS key package")
                .to_string());
        }
    }
    // Persist the private init keys created by the builders.
    save_state(master, &state).await
}

static REFRESHING: AtomicBool = AtomicBool::new(false);

struct RefreshGuard;
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        REFRESHING.store(false, Ordering::SeqCst);
    }
}

/// Re-adds devices that published a fresh key package after losing MLS
/// state. Only groups this browser owns are touched; errors are ignored so
/// one broken share cannot block unlock.
pub async fn refresh_owned_groups(master: &MasterKey) -> Result<(), String> {
    if !enabled() || REFRESHING.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let _guard = RefreshGuard;
    let response = api::get("/api/shares/owned").await?;
    if response.status != 200 {
        return Ok(());
    }
    let mut nodes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for share in response.body["shares"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) else {
            continue;
        };
        let entry = nodes.entry(path.to_string()).or_default();
        match share["kind"].as_str() {
            Some("user") => {
                if let Some(user) = share["recipient"].as_str() {
                    entry.insert(user.to_string());
                }
            }
            Some("group") => {
                if let Some(group) = share["recipient"].as_str() {
                    for member in crate::e2ee::group_members(group).await.unwrap_or_default() {
                        entry.insert(member);
                    }
                }
            }
            _ => {}
        }
    }
    for (path, recipients) in nodes {
        if recipients.is_empty() {
            continue;
        }
        let Some(remote) = (match fetch_group(&path).await {
            Ok(group) => group,
            Err(_) => continue,
        }) else {
            continue;
        };
        // `fetch_group` is exact, so this only refreshes the share's own
        // group, never an ancestor group with wider membership.
        let mut state = match load_or_create(master).await {
            Ok(state) => state,
            Err(_) => continue,
        };
        let mut group = match join_or_load(&mut state, master, &path, &remote).await {
            Ok(group) => group,
            Err(_) => continue,
        };
        let keyring = open_keyring(&group, &state.device, &remote)
            .ok()
            .map(|(keyring, _)| keyring);
        let recipients: Vec<String> = recipients.into_iter().collect();
        let revoked: BTreeSet<Vec<u8>> = remote.revocations.iter().cloned().collect();
        let _ = add_recipients_to_group(
            master,
            &mut state,
            &mut group,
            &path,
            &remote.group_id,
            &recipients,
            keyring.as_ref(),
            &revoked,
            true,
        )
        .await;
    }
    Ok(())
}

async fn mounts() -> Result<Vec<Mount>, String> {
    let response = api::get("/api/shares/received").await?;
    if response.status != 200 {
        return Ok(Vec::new());
    }
    Ok(response.body["mounts"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default())
}

fn mount_for<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|mount| {
            path == mount.mount
                || path
                    .strip_prefix(&mount.mount)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|mount| mount.mount.len())
}

/// Every root that may carry an MLS group: owned shares and received mounts.
async fn group_roots() -> Result<Vec<String>, String> {
    let mut roots = BTreeSet::new();
    let response = api::get("/api/shares/owned").await?;
    if response.status != 200 {
        return Err("could not list owned shares".to_string());
    }
    for share in response.body["shares"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        if let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) {
            roots.insert(path.trim_end_matches('/').to_string());
        }
    }
    for mount in mounts().await? {
        roots.insert(mount.mount.trim_end_matches('/').to_string());
    }
    Ok(roots.into_iter().collect())
}

/// Maps MLS signature keys to the share roots where this browser can see
/// them. Unreadable groups become warnings instead of failing the listing.
async fn signature_groups(
    state: &mut State,
    master: &MasterKey,
) -> Result<(BTreeMap<Vec<u8>, Vec<String>>, Vec<String>), String> {
    let mut groups = BTreeMap::new();
    let mut warnings = Vec::new();
    for root in group_roots().await? {
        let Some(remote) = fetch_group(&root).await? else {
            continue;
        };
        let group = match join_or_load(state, master, &root, &remote).await {
            Ok(group) => group,
            Err(error) => {
                warnings.push(format!("{root}: {error}"));
                continue;
            }
        };
        for member in group.members() {
            let paths: &mut Vec<String> = groups.entry(member.signature_key).or_default();
            if !paths.contains(&root) {
                paths.push(root.clone());
            }
        }
    }
    Ok((groups, warnings))
}

/// Lists the account's MLS roster with the groups this browser can inspect.
pub async fn devices(master: &MasterKey) -> Result<MlsDeviceList, String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let mut state = load_or_create(master).await?;
    let current_id = state.device.device_id();
    let current_signature = state.device.signature_key().to_vec();
    let response = api::get("/api/mls/devices").await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not list MLS devices")
            .to_string());
    }
    let mut devices = parse_device_roster(&response.body);
    let (groups, warnings) = signature_groups(&mut state, master).await?;
    if !devices.iter().any(|device| device.device_id == current_id) {
        devices.push(MlsDevice {
            device_id: current_id.clone(),
            device_name: "Web browser".to_string(),
            signature_key: Some(current_signature.clone()),
            last_seen_at: 0,
            groups: Vec::new(),
            current: true,
        });
    }
    for device in &mut devices {
        device.current = device.device_id == current_id;
        let signature = device
            .signature_key
            .clone()
            .or_else(|| device.current.then(|| current_signature.clone()));
        if let Some(signature) = signature {
            device.groups = groups.get(&signature).cloned().unwrap_or_default();
        }
    }
    Ok(MlsDeviceList { devices, warnings })
}

/// Removes one device's leaf from the exact group at `path` and rotates the
/// keyring. Returns the number of leaves removed.
async fn remove_signature_from_group(
    state: &mut State,
    master: &MasterKey,
    path: &str,
    signature: &[u8],
) -> Result<usize, String> {
    for _ in 0..3 {
        let Some(remote) = fetch_group(path).await? else {
            return Ok(0);
        };
        let mut group = join_or_load(state, master, path, &remote).await?;
        if !group
            .members()
            .iter()
            .any(|member| member.signature_key == state.device.signature_key())
        {
            return Err(format!(
                "this browser is no longer a member of {path}; if no member can open the share, recreate it"
            ));
        }
        let indices: Vec<u32> = group
            .members()
            .into_iter()
            .filter(|member| member.signature_key == signature)
            .map(|member| member.index)
            .collect();
        if indices.is_empty() {
            return Ok(0);
        }
        let old_exporter = exporter(&group, &state.device)?;
        let keyring = match &remote.keyring {
            Some(blob) if blob.epoch == group.epoch() => Some(
                decrypt_keyring(
                    &old_exporter,
                    &remote.group_id,
                    group.epoch(),
                    &blob.payload,
                )
                .map_err(|error| format!("share keyring: {error}"))?,
            ),
            _ => None,
        };
        let pending = group.remove_pending(&state.device, &indices)?;
        state
            .pending_commits
            .insert(remote.group_id.clone(), pending.commit.clone());
        save_state(master, state).await?;
        if let Err(error) = record_revocation(path, signature).await {
            let _ = group.discard_pending(&state.device);
            state.pending_commits.remove(&remote.group_id);
            let _ = save_state(master, state).await;
            return Err(error);
        }
        match post_commit(path, pending.epoch, &pending.commit, None).await {
            Ok(()) => {
                group
                    .merge_pending(&state.device)
                    .map_err(|error| format!("MLS merge commit: {error}"))?;
                state.pending_commits.remove(&remote.group_id);
                save_state(master, state).await?;
                if let Some(keyring) = keyring {
                    publish_epoch_keyring(state, &group, path, &remote.group_id, &keyring).await?;
                }
                return Ok(indices.len());
            }
            Err((409, _)) => {
                group
                    .discard_pending(&state.device)
                    .map_err(|error| format!("MLS discard commit: {error}"))?;
                state.pending_commits.remove(&remote.group_id);
                save_state(master, state).await?;
            }
            Err((_, error)) => return Err(error),
        }
    }
    Err("another member changed the MLS group; retry".to_string())
}

/// Revokes one MLS device: removes its leaves from every group this browser
/// can inspect, rotates the keyrings, then clears the server roster row.
///
/// Inspection is done before any removal. If a group cannot be opened, the
/// operation stops so it cannot leave the device in a share while clearing
/// its roster entry.
pub async fn revoke_device(master: &MasterKey, device_id: &str) -> Result<MlsRevokeReport, String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let mut state = load_or_create(master).await?;
    if device_id == state.device.device_id() {
        return Err(
            "refusing to revoke this browser; use “Reset this browser's MLS state” and enroll it again"
                .to_string(),
        );
    }
    let response = api::get("/api/mls/devices").await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not list MLS devices")
            .to_string());
    }
    let target = parse_device_roster(&response.body)
        .into_iter()
        .find(|device| device.device_id == device_id)
        .ok_or_else(|| "unknown MLS device".to_string())?;
    let signature = target.signature_key.ok_or_else(|| {
        format!(
            "device {device_id} has not reported a signature key; sync it once with this release, then retry"
        )
    })?;

    let mut affected = Vec::new();
    for root in group_roots().await? {
        let Some(remote) = fetch_group(&root).await? else {
            continue;
        };
        let group = join_or_load(&mut state, master, &root, &remote)
            .await
            .map_err(|error| {
                format!(
                    "cannot inspect MLS group {root}: {error}; if no remaining member can open it, recreate the share"
                )
            })?;
        if !group
            .members()
            .iter()
            .any(|member| member.signature_key == state.device.signature_key())
        {
            return Err(format!(
                "this browser is no longer a member of {root}; recreate the share instead of revoking from it"
            ));
        }
        if group
            .members()
            .iter()
            .any(|member| member.signature_key == signature)
        {
            affected.push(root);
        }
    }

    let mut report = MlsRevokeReport::default();
    for root in affected {
        let removed = remove_signature_from_group(&mut state, master, &root, &signature).await?;
        if removed > 0 {
            report.groups.push(root);
            report.leaves += removed;
        }
    }

    let response =
        api::delete(&format!("/api/mls/devices?device_id={}", encode(device_id))).await?;
    if response.status != 204 {
        return Err(response
            .error()
            .unwrap_or("could not remove the MLS roster entry")
            .to_string());
    }
    Ok(report)
}

#[derive(Debug, Clone)]
struct GroupMessage {
    seq: i64,
    epoch: u64,
    kind: String,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct KeyringBlob {
    epoch: u64,
    payload: Vec<u8>,
    revision: i64,
}

#[derive(Debug, Clone)]
struct RemoteGroup {
    group_id: Vec<u8>,
    epoch: u64,
    messages: Vec<GroupMessage>,
    keyring: Option<KeyringBlob>,
    /// Client-asserted revoked signatures; automatic re-add skips these.
    revocations: Vec<Vec<u8>>,
}

async fn fetch_group(path: &str) -> Result<Option<RemoteGroup>, String> {
    let mut after = 0i64;
    let mut messages = Vec::new();
    let mut group_id: Option<Vec<u8>> = None;
    let mut epoch;
    let mut keyring = None;
    let mut revocations = Vec::new();
    loop {
        let response = api::get(&format!(
            "/api/mls/group?path={}&after={after}&limit=1000",
            encode(path)
        ))
        .await?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status != 200 {
            return Err(response
                .error()
                .unwrap_or("could not load the MLS group")
                .to_string());
        }
        if group_id.is_none() {
            group_id = Some(
                STANDARD
                    .decode(response.body["group_id"].as_str().unwrap_or_default())
                    .map_err(|_| "malformed MLS group id".to_string())?,
            );
        }
        epoch = response.body["epoch"].as_u64().unwrap_or(0);
        if keyring.is_none() {
            keyring = response.body["keyring"].as_object().and_then(|keyring| {
                Some(KeyringBlob {
                    epoch: keyring["epoch"].as_u64()?,
                    payload: STANDARD.decode(keyring["payload"].as_str()?).ok()?,
                    revision: keyring["revision"].as_i64().unwrap_or(0),
                })
            });
        }
        if revocations.is_empty() {
            revocations = response.body["revocations"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| STANDARD.decode(item["signature_key"].as_str()?).ok())
                        .collect()
                })
                .unwrap_or_default();
        }
        let page = response.body["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut advanced = false;
        for message in page {
            let seq = message["seq"].as_i64().unwrap_or(0);
            if seq > after {
                after = seq;
                advanced = true;
            }
            messages.push(GroupMessage {
                seq,
                epoch: message["epoch"].as_u64().unwrap_or(0),
                kind: message["kind"].as_str().unwrap_or_default().to_string(),
                payload: STANDARD
                    .decode(message["payload"].as_str().unwrap_or_default())
                    .unwrap_or_default(),
            });
        }
        if !advanced || after == 0 {
            break;
        }
    }
    messages.sort_by_key(|message| message.seq);
    Ok(Some(RemoteGroup {
        group_id: group_id.ok_or_else(|| "MLS group id missing".to_string())?,
        epoch,
        messages,
        keyring,
        revocations,
    }))
}

async fn join_or_load(
    state: &mut State,
    master: &MasterKey,
    path: &str,
    remote: &RemoteGroup,
) -> Result<Group, String> {
    let mut group = match Group::load(&state.device, &remote.group_id) {
        Ok(group) => group,
        Err(_) => {
            // Try every Welcome: a group may add several devices, and only
            // one message matches this device's key package.
            let mut joined = None;
            let mut last_error = None;
            for welcome in remote
                .messages
                .iter()
                .filter(|message| message.kind == "welcome")
            {
                match Group::join(&state.device, &welcome.payload) {
                    Ok(group) => {
                        joined = Some(group);
                        break;
                    }
                    Err(error) => last_error = Some(format!("MLS join: {error}")),
                }
            }
            let group = joined.ok_or_else(|| {
                last_error
                    .unwrap_or_else(|| "this share has no MLS Welcome for this device".to_string())
            })?;
            if !state.groups.contains(&remote.group_id) {
                state.groups.push(remote.group_id.clone());
            }
            state.pending_commits.remove(&remote.group_id);
            save_state(master, state).await?;
            group
        }
    };
    if !group.has_pending_commit() {
        state.pending_commits.remove(&remote.group_id);
    }
    // A response may have been lost after the server accepted our commit.
    // If the server never advanced, the staged commit never won; drop it.
    if let Some(pending_epoch) = group.pending_epoch()
        && remote.epoch < pending_epoch
    {
        group.discard_pending(&state.device)?;
        state.pending_commits.remove(&remote.group_id);
        save_state(master, state).await?;
    }
    let mut progressed = true;
    while progressed {
        progressed = false;
        for message in &remote.messages {
            if message.kind != "commit" || message.epoch != group.epoch() + 1 {
                continue;
            }
            let before = group.epoch();
            let expected = state.pending_commits.get(&remote.group_id).cloned();
            let processed =
                group.process_commit(&state.device, &message.payload, expected.as_deref());
            if processed.is_err() && group.has_pending_commit() {
                group
                    .discard_pending(&state.device)
                    .map_err(|error| format!("MLS discard commit: {error}"))?;
                state.pending_commits.remove(&remote.group_id);
                save_state(master, state).await?;
                if group
                    .process_commit(&state.device, &message.payload, None)
                    .is_ok()
                    && group.epoch() > before
                {
                    progressed = true;
                    save_state(master, state).await?;
                }
                continue;
            }
            if processed.is_ok() {
                if group.epoch() == before {
                    return Err(format!(
                        "MLS commit at epoch {} did not advance the local group",
                        message.epoch
                    ));
                }
                state.pending_commits.remove(&remote.group_id);
                progressed = true;
                save_state(master, state).await?;
            }
        }
    }
    if group.epoch() != remote.epoch {
        return Err(format!(
            "MLS group is at epoch {} locally but {} on the server; reset this device's MLS state and ask a member to re-share",
            group.epoch(),
            remote.epoch
        ));
    }
    if !state.groups.contains(&remote.group_id) {
        state.groups.push(remote.group_id.clone());
        save_state(master, state).await?;
    }
    // Advisory: lets the server prune history without blocking the UI if
    // the endpoint is unavailable or the server is older.
    let _ = api::send_json(
        "POST",
        &format!("/api/mls/epoch?path={}", encode(path)),
        &json!({
            "device_id": state.device.device_id(),
            "epoch": group.epoch(),
        }),
    )
    .await;
    Ok(group)
}

fn exporter(group: &Group, device: &Device) -> Result<[u8; 32], String> {
    group
        .export(device, SHARE_KEYRING_EXPORTER, 32)
        .map_err(|error| format!("MLS exporter: {error}"))?
        .try_into()
        .map_err(|_| "MLS exporter length".to_string())
}

fn open_keyring(
    group: &Group,
    device: &Device,
    remote: &RemoteGroup,
) -> Result<(ShareKeyring, i64), String> {
    let blob = remote
        .keyring
        .as_ref()
        .ok_or_else(|| "this share has no keyring yet".to_string())?;
    if blob.epoch != group.epoch() {
        return Err("the share keyring is for a different epoch".to_string());
    }
    let key = exporter(group, device)?;
    let keyring = decrypt_keyring(&key, &remote.group_id, group.epoch(), &blob.payload)
        .map_err(|error| format!("share keyring: {error}"))?;
    Ok((keyring, blob.revision))
}

/// Decrypts a shared file through its MLS keyring (if the share uses one).
pub async fn decrypt_shared_file(
    master: &MasterKey,
    server_path: &str,
    display_name: &str,
) -> Result<(String, Vec<u8>), String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let mounts = mounts().await?;
    let Some(mount) = mount_for(&mounts, server_path) else {
        return Err("not a received share".to_string());
    };
    let Some(remote) = fetch_group(&mount.mount).await? else {
        return Err("this share has no MLS group".to_string());
    };
    let mut state = load_or_create(master).await?;
    let group = join_or_load(&mut state, master, server_path, &remote).await?;
    let (keyring, _revision) = open_keyring(&group, &state.device, &remote)?;
    let rel = server_path
        .strip_prefix(&mount.mount)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the share".to_string())?;
    let rel = if rel.is_empty() { ".".to_string() } else { rel };
    let key = keyring
        .get(&rel)
        .ok_or_else(|| "this file has no key in the MLS keyring".to_string())?;
    let file_key = kolimi_crypto::FileKey::from_bytes(key);
    let manifest = api::get(&format!("/api/files/manifest?path={}", encode(server_path))).await?;
    if manifest.status != 200 {
        return Err("Could not load the file manifest".to_string());
    }
    crate::e2ee::decrypt_manifest(&file_key, server_path, &manifest.body, display_name).await
}

/// Decrypts a received shared file: MLS keyring first, then the legacy
/// per-file X25519 wrap for shares created before MLS.
pub async fn decrypt_shared_or_legacy(
    master: &MasterKey,
    server_path: &str,
    display_name: &str,
) -> Result<(String, Vec<u8>), String> {
    match decrypt_shared_file(master, server_path, display_name).await {
        Ok(value) => Ok(value),
        Err(mls_error) => {
            match crate::e2ee::decrypt_shared_file(master, server_path, display_name).await {
                Ok(value) => Ok(value),
                Err(_) => Err(mls_error),
            }
        }
    }
}

/// Finds the MLS group governing an owned path (the path or an ancestor).
async fn ancestor_group(
    master: &MasterKey,
    server_path: &str,
) -> Result<Option<(String, Group, RemoteGroup)>, String> {
    let mut current = server_path.trim_end_matches('/').to_string();
    loop {
        if let Some(remote) = fetch_group(&current).await? {
            let mut state = load_or_create(master).await?;
            let group = join_or_load(&mut state, master, &current, &remote).await?;
            return Ok(Some((current, group, remote)));
        }
        let Some((parent, _)) = current.rsplit_once('/') else {
            return Ok(None);
        };
        if parent.is_empty() {
            return Ok(None);
        }
        current = parent.to_string();
    }
}

/// Reads a file key from the MLS keyring governing an owned path. Used when
/// the node's wrapped key was written by a write recipient and is not ours.
pub async fn owned_file_key(
    master: &MasterKey,
    server_path: &str,
) -> Result<Option<[u8; 32]>, String> {
    let Some((root, group, remote)) = ancestor_group(master, server_path).await? else {
        return Ok(None);
    };
    let mut state = load_or_create(master).await?;
    let (keyring, _revision) = open_keyring(&group, &state.device, &remote)?;
    let rel = server_path
        .strip_prefix(&root)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the group".to_string())?;
    let _ = &mut state;
    Ok(keyring.get(&rel))
}

/// Adds/updates an owned file key in the governing MLS keyring, if any.
pub async fn record_owned_file_key(
    master: &MasterKey,
    server_path: &str,
    file_key: &[u8; 32],
) -> Result<(), String> {
    let Some((root, mut group, mut remote)) = ancestor_group(master, server_path).await? else {
        return Ok(());
    };
    let mut state = load_or_create(master).await?;
    let rel = server_path
        .strip_prefix(&root)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the group".to_string())?;
    for _ in 0..4 {
        let (mut keyring, revision) = open_keyring(&group, &state.device, &remote)?;
        keyring.insert(&rel, file_key);
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={revision}",
                encode(&root),
                group.epoch()
            ),
            &blob,
        )
        .await?;
        if response.status == 204 {
            save_state(master, &state).await?;
            return Ok(());
        }
        if response.status != 409 {
            return Err(response
                .error()
                .unwrap_or("could not update the share keyring")
                .to_string());
        }
        let Some(fresh) = fetch_group(&root).await? else {
            return Err("the MLS group disappeared".to_string());
        };
        remote = fresh;
        group = join_or_load(&mut state, master, &root, &remote).await?;
    }
    Err("share keyring stayed busy after retries".to_string())
}

/// Removes every key under a deleted directory prefix.
pub async fn remove_path_prefix(master: &MasterKey, server_path: &str) -> Result<(), String> {
    let _ = take_path_prefix(master, server_path).await?;
    Ok(())
}

/// Removes and returns every key under a directory prefix, keyed by the
/// path relative to the group root.
async fn take_path_prefix(
    master: &MasterKey,
    server_path: &str,
) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let Some((root, mut group, mut remote)) = ancestor_group(master, server_path).await? else {
        return Ok(BTreeMap::new());
    };
    let mut state = load_or_create(master).await?;
    let prefix = server_path
        .strip_prefix(&root)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the group".to_string())?;
    for _ in 0..4 {
        let (mut keyring, revision) = open_keyring(&group, &state.device, &remote)?;
        let mut taken = BTreeMap::new();
        let paths: Vec<String> = keyring
            .entries
            .keys()
            .filter(|path| *path == &prefix || path.starts_with(&format!("{prefix}/")))
            .cloned()
            .collect();
        for path in paths {
            if let Some(key) = keyring.get(&path) {
                taken.insert(path.clone(), key);
            }
            keyring.entries.remove(&path);
        }
        if taken.is_empty() {
            return Ok(taken);
        }
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={revision}",
                encode(&root),
                group.epoch()
            ),
            &blob,
        )
        .await?;
        if response.status == 204 {
            save_state(master, &state).await?;
            return Ok(taken);
        }
        if response.status != 409 {
            return Err(response
                .error()
                .unwrap_or("could not update the share keyring")
                .to_string());
        }
        let Some(fresh) = fetch_group(&root).await? else {
            return Err("the MLS group disappeared".to_string());
        };
        remote = fresh;
        group = join_or_load(&mut state, master, &root, &remote).await?;
    }
    Err("share keyring stayed busy after retries".to_string())
}

/// Moves keyring entries when a file or directory is renamed/moved.
pub async fn rename_path_prefix(
    master: &MasterKey,
    old_path: &str,
    new_path: &str,
) -> Result<(), String> {
    if old_path == new_path {
        return Ok(());
    }
    let Some((root, _, _)) = ancestor_group(master, old_path).await? else {
        return Ok(());
    };
    let old_prefix = old_path
        .strip_prefix(&root)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .unwrap_or_default();
    let taken = take_path_prefix(master, old_path).await?;
    for (rel, key) in taken {
        if let Some(suffix) = rel.strip_prefix(&old_prefix) {
            let target = format!("{}{}", new_path.trim_end_matches('/'), suffix);
            record_owned_file_key(master, &target, &key).await?;
        }
    }
    Ok(())
}

/// Fetches one owned file's raw key/// Fetches one owned file's raw key (used when building a share keyring).
async fn owned_wrapped_file_key(
    master: &MasterKey,
    path: &str,
) -> Result<Option<[u8; 32]>, String> {
    let response = api::get(&format!("/api/files/key?path={}", encode(path))).await?;
    if response.status != 200 {
        return Ok(None);
    }
    let wrapped = STANDARD
        .decode(response.body["wrapped_key"].as_str().unwrap_or_default())
        .map_err(|_| "malformed wrapped key".to_string())?;
    Ok(Some(
        *master
            .unwrap_file_key(&wrapped)
            .map_err(|_| "could not unwrap the file key")?
            .as_bytes(),
    ))
}

async fn collect_files(path: &str, out: &mut Vec<String>) -> Result<(), String> {
    let response = api::get(&format!("/api/browse?path={}", encode(path))).await?;
    if response.status != 200 {
        return Err("could not list the shared folder".to_string());
    }
    for entry in response.body["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let Some(entry_path) = entry["path"].as_str() else {
            continue;
        };
        if entry["kind"].as_str() == Some("dir") {
            Box::pin(collect_files(entry_path, out)).await?;
        } else if entry["encrypted"].as_bool().unwrap_or(false) {
            out.push(entry_path.to_string());
        }
    }
    Ok(())
}

fn group_id_random() -> Result<Vec<u8>, String> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|error| error.to_string())?;
    Ok(id.to_vec())
}

async fn record_revocation(path: &str, signature: &[u8]) -> Result<(), String> {
    let response = api::send_json(
        "POST",
        &format!("/api/mls/revocations?path={}", encode(path)),
        &json!({ "signature_key": STANDARD.encode(signature) }),
    )
    .await?;
    if response.status != 204 && response.status != 404 {
        return Err(response
            .error()
            .unwrap_or("could not record the MLS revocation")
            .to_string());
    }
    Ok(())
}

async fn clear_revocation(path: &str, signature: &[u8]) -> Result<(), String> {
    let encoded = STANDARD.encode(signature);
    let response = api::delete(&format!(
        "/api/mls/revocations?path={}&signature_key={}",
        encode(path),
        encode(&encoded)
    ))
    .await?;
    if response.status != 204 && response.status != 404 {
        return Err(response
            .error()
            .unwrap_or("could not clear the MLS revocation")
            .to_string());
    }
    Ok(())
}

async fn post_commit(
    path: &str,
    epoch: u64,
    commit: &[u8],
    welcome: Option<&[u8]>,
) -> Result<(), (u16, String)> {
    let mut body = json!({
        "epoch": epoch,
        "commit": STANDARD.encode(commit),
    });
    if let Some(welcome) = welcome {
        body["welcome"] = json!(STANDARD.encode(welcome));
    }
    let response = api::send_json(
        "POST",
        &format!("/api/mls/commit?path={}", encode(path)),
        &body,
    )
    .await
    .map_err(|error| (0, error))?;
    if response.status == 404 {
        // Older servers only have the separate message endpoint.
        send_message(path, epoch, "commit", commit).await?;
        if let Some(welcome) = welcome {
            send_message(path, epoch, "welcome", welcome).await?;
        }
        return Ok(());
    }
    if response.status != 200 {
        return Err((
            response.status,
            response
                .error()
                .unwrap_or("could not publish the MLS commit")
                .to_string(),
        ));
    }
    Ok(())
}

async fn send_message(
    path: &str,
    epoch: u64,
    kind: &str,
    payload: &[u8],
) -> Result<(), (u16, String)> {
    let response = api::send_json(
        "POST",
        &format!("/api/mls/messages?path={}", encode(path)),
        &json!({
            "epoch": epoch,
            "kind": kind,
            "payload": STANDARD.encode(payload),
        }),
    )
    .await
    .map_err(|error| (0, error))?;
    if response.status != 200 {
        return Err((
            response.status,
            response
                .error()
                .unwrap_or("could not publish the MLS message")
                .to_string(),
        ));
    }
    Ok(())
}

async fn publish_epoch_keyring(
    state: &State,
    group: &Group,
    path: &str,
    group_id: &[u8],
    keyring: &ShareKeyring,
) -> Result<(), String> {
    let mut merged = keyring.clone();
    let mut if_revision = 0;
    for _ in 0..3 {
        let key = exporter(group, &state.device)?;
        let blob = encrypt_keyring(&key, group_id, group.epoch(), &merged)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={if_revision}",
                encode(path),
                group.epoch()
            ),
            &blob,
        )
        .await?;
        if response.status == 204 {
            return Ok(());
        }
        if response.status != 409 {
            return Err(response
                .error()
                .unwrap_or("could not rotate the share keyring")
                .to_string());
        }
        let Some(fresh) = fetch_group(path).await? else {
            return Err("the MLS group disappeared".to_string());
        };
        let Some(existing) = fresh
            .keyring
            .as_ref()
            .filter(|blob| blob.epoch == group.epoch())
        else {
            return Err("the share keyring changed epoch during rotation".to_string());
        };
        let key = exporter(group, &state.device)?;
        let mut server_keyring = decrypt_keyring(&key, group_id, group.epoch(), &existing.payload)
            .map_err(|error| format!("share keyring: {error}"))?;
        server_keyring
            .entries
            .extend(merged.entries.iter().map(|(k, v)| (k.clone(), v.clone())));
        merged = server_keyring;
        if_revision = existing.revision;
    }
    Err("share keyring stayed busy during rotation".to_string())
}

#[allow(clippy::too_many_arguments)]
async fn add_recipients_to_group(
    master: &MasterKey,
    state: &mut State,
    group: &mut Group,
    path: &str,
    group_id: &[u8],
    recipients: &[String],
    keyring: Option<&ShareKeyring>,
    revoked: &BTreeSet<Vec<u8>>,
    best_effort: bool,
) -> Result<(), String> {
    let members = group.members();
    let mut keys: std::collections::BTreeSet<Vec<u8>> =
        members.iter().map(|m| m.signature_key.clone()).collect();
    let identities: std::collections::BTreeSet<Vec<u8>> =
        members.iter().map(|m| m.identity.clone()).collect();
    let mut consumed = Vec::new();
    for recipient in recipients {
        let packages = match api::get(&format!("/api/mls/key-packages/{}", encode(recipient))).await
        {
            Ok(packages) => packages,
            Err(_) if best_effort => continue,
            Err(error) => return Err(error),
        };
        if packages.status != 200 {
            if best_effort || identities.contains(recipient.as_bytes()) {
                continue;
            }
            return Err(format!("{recipient} has no published MLS key package"));
        }
        let mut by_device: BTreeMap<String, (i64, Vec<u8>)> = BTreeMap::new();
        for package in packages.body["packages"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let id = package["id"].as_i64().unwrap_or(0);
            let device = package["device_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let Ok(payload) = STANDARD.decode(package["payload"].as_str().unwrap_or_default())
            else {
                continue;
            };
            by_device.entry(device).or_insert((id, payload));
        }
        for (device, (id, package)) in by_device {
            if device == state.device.device_id() {
                continue;
            }
            let signature = state
                .device
                .key_package_signature_key(&package)
                .map_err(|error| format!("MLS key package: {error}"))?;
            if keys.contains(&signature) {
                continue;
            }
            if best_effort && revoked.contains(&signature) {
                // An owner-removed leaf must not return from its leftover
                // package pool during automatic refresh.
                continue;
            }
            let pending = group
                .add_pending(&state.device, &package)
                .map_err(|error| format!("MLS add {recipient}: {error}"))?;
            // Persist before posting so a crash after server acceptance can
            // be reconciled against the exact commit bytes on the next load.
            state
                .pending_commits
                .insert(group_id.to_vec(), pending.commit.clone());
            save_state(master, state).await?;
            match post_commit(
                path,
                pending.epoch,
                &pending.commit,
                pending.welcome.as_deref(),
            )
            .await
            {
                Ok(()) => {}
                Err((409, _)) => {
                    group
                        .discard_pending(&state.device)
                        .map_err(|error| format!("MLS discard commit: {error}"))?;
                    state.pending_commits.remove(group_id);
                    save_state(master, state).await?;
                    return Err("another member changed the MLS group; retry".to_string());
                }
                Err((_, error)) => {
                    // Keep the pending commit: next load reconciles a lost
                    // response against the server's message log.
                    return Err(error);
                }
            }
            group
                .merge_pending(&state.device)
                .map_err(|error| format!("MLS merge commit: {error}"))?;
            state.pending_commits.remove(group_id);
            save_state(master, state).await?;
            if let Some(keyring) = keyring {
                publish_epoch_keyring(state, group, path, group_id, keyring).await?;
            }
            if !best_effort {
                // Explicit re-sharing overrides an earlier revocation.
                let _ = clear_revocation(path, &signature).await;
            }
            keys.insert(signature);
            consumed.push(id);
        }
    }
    if !consumed.is_empty() {
        let response = api::send_json(
            "POST",
            "/api/mls/key-packages/consume",
            &json!({ "ids": consumed }),
        )
        .await?;
        if response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not consume MLS key packages")
                .to_string());
        }
    }
    save_state(master, state).await
}

/// Removes every device of the given users and rotates the keyring.
pub async fn remove_recipients(
    master: &MasterKey,
    path: &str,
    usernames: &[String],
) -> Result<usize, String> {
    let mut state = load_or_create(master).await?;
    for _ in 0..3 {
        let Some(remote) = fetch_group(path).await? else {
            return Ok(0);
        };
        let mut group = join_or_load(&mut state, master, path, &remote).await?;
        let removals: Vec<(u32, Vec<u8>)> = group
            .members()
            .into_iter()
            .filter(|member| {
                usernames
                    .iter()
                    .any(|name| member.identity == name.as_bytes())
            })
            .map(|member| (member.index, member.signature_key))
            .collect();
        let indices: Vec<u32> = removals.iter().map(|(index, _)| *index).collect();
        if indices.is_empty() {
            return Ok(0);
        }
        let old_exporter = exporter(&group, &state.device)?;
        let keyring = match &remote.keyring {
            Some(blob) if blob.epoch == group.epoch() => Some(
                decrypt_keyring(
                    &old_exporter,
                    &remote.group_id,
                    group.epoch(),
                    &blob.payload,
                )
                .map_err(|error| format!("share keyring: {error}"))?,
            ),
            _ => None,
        };
        let pending = group.remove_pending(&state.device, &indices)?;
        state
            .pending_commits
            .insert(remote.group_id.clone(), pending.commit.clone());
        save_state(master, &state).await?;
        for (_, signature) in &removals {
            if let Err(error) = record_revocation(path, signature).await {
                let _ = group.discard_pending(&state.device);
                state.pending_commits.remove(&remote.group_id);
                let _ = save_state(master, &state).await;
                return Err(error);
            }
        }
        match post_commit(path, pending.epoch, &pending.commit, None).await {
            Ok(()) => {
                group
                    .merge_pending(&state.device)
                    .map_err(|error| format!("MLS merge commit: {error}"))?;
                state.pending_commits.remove(&remote.group_id);
                save_state(master, &state).await?;
                if let Some(keyring) = keyring {
                    publish_epoch_keyring(&state, &group, path, &remote.group_id, &keyring).await?;
                }
                return Ok(indices.len());
            }
            Err((409, _)) => {
                group
                    .discard_pending(&state.device)
                    .map_err(|error| format!("MLS discard commit: {error}"))?;
                state.pending_commits.remove(&remote.group_id);
                save_state(master, &state).await?;
            }
            Err((_, error)) => {
                // Keep the pending commit for reconciliation on the next load.
                return Err(error);
            }
        }
    }
    Err("another member changed the MLS group; retry".to_string())
}

/// Creates/returns the MLS group for an owned encrypted folder, adds the
/// recipients' devices, and publishes a keyring with the current file keys.
pub async fn share_folder(
    master: &MasterKey,
    path: &str,
    recipients: &[String],
    permission: &str,
) -> Result<(), String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let info = crate::e2ee::file_info(path).await?;
    let is_dir = info["kind"].as_str() == Some("dir");
    let mut files = Vec::new();
    if is_dir {
        collect_files(path, &mut files).await?;
    } else {
        files.push(path.to_string());
    }
    // Sync-created folders may not carry the server flag; encrypted files
    // are proof the tree uses client-side keys.
    if info["encrypted"].as_bool() != Some(true) && files.is_empty() {
        return Err("MLS shares are supported for encrypted content only".to_string());
    }
    publish_key_package(master).await?;
    // Recipients need the plaintext mount name and, for a folder, the name
    // key; this is independent of the MLS keyring.
    for recipient in recipients {
        crate::e2ee::share_name_with(master, path, is_dir, recipient).await?;
    }
    let mut state = load_or_create(master).await?;
    let remote = fetch_group(path).await?;
    let mut keyring = ShareKeyring::new();
    for file in &files {
        let key = match owned_wrapped_file_key(master, file).await? {
            Some(key) => Some(key),
            None => owned_file_key(master, file).await?,
        };
        if let Some(key) = key {
            let rel = file
                .strip_prefix(path)
                .map(|rest| rest.trim_start_matches('/').to_string())
                .unwrap_or_default();
            keyring.insert(if rel.is_empty() { "." } else { &rel }, &key);
        }
    }
    if let Some(remote) = remote {
        let mut group = join_or_load(&mut state, master, path, &remote).await?;
        let old_keyring = open_keyring(&group, &state.device, &remote)
            .ok()
            .map(|(keyring, _)| keyring);
        let revoked: BTreeSet<Vec<u8>> = remote.revocations.iter().cloned().collect();
        add_recipients_to_group(
            master,
            &mut state,
            &mut group,
            path,
            &remote.group_id,
            recipients,
            old_keyring.as_ref(),
            &revoked,
            false,
        )
        .await?;
        let Some(remote) = fetch_group(path).await? else {
            return Err("the MLS group disappeared".to_string());
        };
        let group = join_or_load(&mut state, master, path, &remote).await?;
        let mut revision = 0;
        if let Ok((existing, current_revision)) = open_keyring(&group, &state.device, &remote) {
            keyring = existing;
            revision = current_revision;
        }
        // Re-add the keys we can unwrap; recipient-written keys stay in the
        // merged keyring above.
        for file in &files {
            let key = match owned_wrapped_file_key(master, file).await? {
                Some(key) => Some(key),
                None => owned_file_key(master, file).await?,
            };
            if let Some(key) = key {
                let rel = file
                    .strip_prefix(path)
                    .map(|rest| rest.trim_start_matches('/').to_string())
                    .unwrap_or_default();
                keyring.insert(if rel.is_empty() { "." } else { &rel }, &key);
            }
        }
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={revision}",
                encode(path),
                group.epoch()
            ),
            &blob,
        )
        .await?;
        if response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not publish the share keyring")
                .to_string());
        }
        return Ok(());
    }
    let group_id = group_id_random()?;
    let response = api::send_json(
        "PUT",
        &format!("/api/mls/group?path={}", encode(path)),
        &json!({ "group_id": STANDARD.encode(&group_id) }),
    )
    .await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not initialize the MLS group")
            .to_string());
    }
    let mut group =
        Group::create(&state.device, &group_id).map_err(|error| format!("MLS create: {error}"))?;
    add_recipients_to_group(
        master,
        &mut state,
        &mut group,
        path,
        &group_id,
        recipients,
        None,
        &BTreeSet::new(),
        false,
    )
    .await?;
    if !state.groups.contains(&group_id) {
        state.groups.push(group_id.clone());
    }
    save_state(master, &state).await?;
    publish_epoch_keyring(&state, &group, path, &group_id, &keyring).await?;
    // Keep the requested permission visible to callers in logs/UI.
    let _ = permission;
    Ok(())
}

fn share_key_for<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mount_for(mounts, path).filter(|mount| mount.permission == "write" && mount.encrypted)
}

/// Encodes a new child name inside a writable received share.
pub async fn encode_shared_name(
    master: &MasterKey,
    dir: &str,
    name: &str,
) -> Result<Option<String>, String> {
    if !enabled() {
        return Ok(None);
    }
    let mounts = mounts().await?;
    let Some(mount) = share_key_for(&mounts, dir) else {
        return Ok(None);
    };
    let wrapped = mount
        .wrapped_name
        .as_deref()
        .ok_or_else(|| "the share has no name key".to_string())?;
    let wrapped = STANDARD
        .decode(wrapped)
        .map_err(|_| "malformed share name".to_string())?;
    let identity = crate::e2ee::own_identity(master).await?;
    let payload = kolimi_crypto::unwrap_share_metadata(&identity.private_bytes(), &wrapped)
        .map_err(|_| "could not unwrap the share name".to_string())?;
    #[derive(Deserialize)]
    struct NamePayload {
        v: u8,
        #[serde(default)]
        key: Option<String>,
    }
    let payload: NamePayload =
        serde_json::from_slice(&payload).map_err(|_| "malformed share name".to_string())?;
    if payload.v != 1 {
        return Err("unsupported share name".to_string());
    }
    let mut key = payload
        .key
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(kolimi_crypto::NameKey::from_bytes)
        .ok_or_else(|| "the share has no folder name key".to_string())?;
    // Derive the key for `dir` from the mount's child key.
    let rest = dir
        .strip_prefix(&mount.mount)
        .map(|rest| rest.trim_start_matches('/'))
        .unwrap_or_default();
    for segment in rest.split('/').filter(|segment| !segment.is_empty()) {
        let plain = key
            .decode(segment)
            .ok_or_else(|| "could not decode a shared folder name".to_string())?;
        key = key
            .child(&plain)
            .map_err(|_| "could not derive the share name key".to_string())?;
    }
    key.encode(name)
        .map(Some)
        .map_err(|_| "could not encrypt the shared file name".to_string())
}

/// Uploads a new/updated encrypted file into a writable MLS share.
pub async fn upload_shared(
    master: &MasterKey,
    dir: &str,
    name: &str,
    data: &[u8],
) -> Result<(), String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let mounts = mounts().await?;
    let Some(mount) = share_key_for(&mounts, dir) else {
        return Err("this share is not writable".to_string());
    };
    let encoded = encode_shared_name(master, dir, name)
        .await?
        .ok_or_else(|| "this share is not writable".to_string())?;
    let target = format!("{}/{}", dir.trim_end_matches('/'), encoded);
    let Some(remote) = fetch_group(&mount.mount).await? else {
        return Err("this share has no MLS group".to_string());
    };
    let mut state = load_or_create(master).await?;
    let group = join_or_load(&mut state, master, &target, &remote).await?;
    let (keyring, _revision) = open_keyring(&group, &state.device, &remote)?;
    let rel = target
        .strip_prefix(&mount.mount)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the share".to_string())?;
    let file_key = match keyring.get(&rel) {
        Some(bytes) => kolimi_crypto::FileKey::from_bytes(bytes),
        None => kolimi_crypto::FileKey::generate()
            .map_err(|_| "could not generate the file key".to_string())?,
    };
    let padded = kolimi_crypto::pad_file(data);
    let mut chunks = Vec::new();
    let mut total = 0u64;
    for chunk in kolimi_chunk::chunker::split(&padded) {
        let ciphertext = file_key
            .encrypt_chunk(chunk.data)
            .map_err(|_| "could not encrypt the file".to_string())?;
        total += ciphertext.len() as u64;
        let hash = kolimi_chunk::Hash::of(&ciphertext);
        chunks.push(kolimi_chunk::ChunkRef {
            hash,
            len: ciphertext.len() as u32,
        });
        let response = api::put_bytes(
            &format!("/api/chunks/{}?path={}", hash.to_hex(), encode(&target)),
            &ciphertext,
        )
        .await?;
        if response.status != 201 && response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not upload the file")
                .to_string());
        }
    }
    let wrapped = master
        .wrap_file_key(&file_key)
        .map_err(|_| "could not wrap the file key".to_string())?;
    let mut manifest = serde_json::to_value(&kolimi_chunk::Manifest {
        version: kolimi_chunk::Manifest::VERSION,
        size: total,
        chunks,
    })
    .map_err(|_| "could not build the file manifest".to_string())?;
    manifest["wrapped_key"] = json!(STANDARD.encode(&wrapped));
    // Optimistic concurrency: if the file already exists, require the
    // manifest we just read to still be current.
    let mut url = format!("/api/files?path={}", encode(&target));
    if let Ok(current) = api::get(&format!("/api/files/manifest?path={}", encode(&target))).await
        && current.status == 200
        && let Ok(manifest) = serde_json::from_value::<kolimi_chunk::Manifest>(current.body.clone())
    {
        url.push_str(&format!(
            "&if_content_id={}",
            manifest.content_id().to_hex()
        ));
    }
    let response = api::send_json("PUT", &url, &manifest).await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not save the file")
            .to_string());
    }
    let response = api::put_bytes(
        &format!("/api/files/key?path={}", encode(&target)),
        &wrapped,
    )
    .await?;
    if response.status != 204 {
        return Err(response
            .error()
            .unwrap_or("could not store the file key")
            .to_string());
    }
    record_owned_file_key(master, &target, file_key.as_bytes()).await
}

/// Promotes existing encrypted folder shares to MLS groups/keyrings.
pub async fn migrate_shares(master: &MasterKey) -> Result<Vec<String>, String> {
    if !enabled() {
        return Err("MLS shares are disabled in this browser".to_string());
    }
    let response = api::get("/api/shares/owned").await?;
    if response.status != 200 {
        return Err("could not list owned shares".to_string());
    }
    let mut nodes: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
    for share in response.body["shares"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) else {
            continue;
        };
        let mut members = Vec::new();
        match share["kind"].as_str() {
            Some("user") => {
                if let Some(name) = share["recipient"].as_str() {
                    members.push(name.to_string());
                }
            }
            Some("group") => {
                if let Some(name) = share["recipient"].as_str() {
                    members.extend(crate::e2ee::group_members(name).await.unwrap_or_default());
                }
            }
            _ => continue,
        }
        nodes.entry(path.to_string()).or_default().extend(members);
    }
    let mut migrated = Vec::new();
    for (path, recipients) in nodes {
        let info = crate::e2ee::file_info(&path).await?;
        if info["kind"].as_str() != Some("dir") {
            continue;
        }
        let recipients: Vec<String> = recipients.into_iter().collect();
        share_folder(master, &path, &recipients, "read").await?;
        migrated.push(path);
    }
    Ok(migrated)
}

/// The decoded display path helper for shared names is in `e2ee`; this
/// returns whether a folder is a writable MLS share.
pub async fn is_writable_shared(dir: &str) -> bool {
    let Ok(mounts) = mounts().await else {
        return false;
    };
    share_key_for(&mounts, dir).is_some()
}

/// Keeps the linter honest about the storage type on non-wasm builds.
#[allow(dead_code)]
fn _storage_type(_: Option<web_sys::Storage>) {}
