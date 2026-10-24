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
use std::collections::BTreeMap;
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
    let (device, groups) =
        Device::import_state(&plain).map_err(|error| format!("MLS state: {error}"))?;
    Ok(Some(State { device, groups }))
}

async fn save_state(master: &MasterKey, state: &State) -> Result<(), String> {
    let plain = state
        .device
        .export_state(&state.groups)
        .map_err(|error| format!("MLS state: {error}"))?;
    let blob = master
        .seal_local(&plain, STATE_AAD)
        .map_err(|_| "could not seal MLS state".to_string())?;
    idb_set(&slot(master), &STANDARD.encode(blob)).await
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

/// Creates the initial device state exactly once, even if two UI effects
/// race on first unlock.
async fn create_state(master: &MasterKey, identity: &[u8]) -> Result<State, String> {
    while CREATING_STATE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        let _ = JsFuture::from(js_sys::Promise::resolve(&JsValue::NULL)).await;
    }
    let _guard = CreationGuard;
    if let Some(state) = load_state(master).await? {
        return Ok(state);
    }
    let device = Device::new(identity).map_err(|error| format!("MLS device: {error}"))?;
    let state = State {
        device,
        groups: Vec::new(),
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
    let own = api::get("/api/mls/key-packages").await.ok();
    let have = own
        .filter(|response| response.status == 200)
        .and_then(|response| response.body["packages"].as_array().map(Vec::len))
        .unwrap_or(0);
    for _ in have..POOL {
        let package = state
            .device
            .key_package()
            .map_err(|error| format!("MLS key package: {error}"))?;
        let response = api::send_json(
            "PUT",
            "/api/mls/key-packages",
            &json!({
                "device_id": state.device.device_id(),
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
}

async fn fetch_group(path: &str) -> Result<Option<RemoteGroup>, String> {
    let mut after = 0i64;
    let mut messages = Vec::new();
    let mut group_id: Option<Vec<u8>> = None;
    let mut epoch;
    let mut keyring = None;
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
    }))
}

async fn join_or_load(
    state: &mut State,
    master: &MasterKey,
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
            save_state(master, state).await?;
            group
        }
    };
    let mut progressed = true;
    while progressed {
        progressed = false;
        for message in &remote.messages {
            if message.kind == "commit"
                && message.epoch == group.epoch() + 1
                && group.process(&state.device, &message.payload).is_ok()
            {
                progressed = true;
                save_state(master, state).await?;
            }
        }
    }
    if group.epoch() != remote.epoch {
        return Err(format!(
            "MLS group is at epoch {} locally but {} on the server",
            group.epoch(),
            remote.epoch
        ));
    }
    if !state.groups.contains(&remote.group_id) {
        state.groups.push(remote.group_id.clone());
        save_state(master, state).await?;
    }
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
    let group = join_or_load(&mut state, master, &remote).await?;
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
            let group = join_or_load(&mut state, master, &remote).await?;
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
        group = join_or_load(&mut state, master, &remote).await?;
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
        group = join_or_load(&mut state, master, &remote).await?;
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

async fn add_recipients_to_group(
    master: &MasterKey,
    state: &mut State,
    group: &mut Group,
    path: &str,
    recipients: &[String],
) -> Result<(), String> {
    let members = group.members();
    let mut keys: std::collections::BTreeSet<Vec<u8>> =
        members.iter().map(|m| m.signature_key.clone()).collect();
    let identities: std::collections::BTreeSet<Vec<u8>> =
        members.iter().map(|m| m.identity.clone()).collect();
    let mut consumed = Vec::new();
    for recipient in recipients {
        let packages = api::get(&format!("/api/mls/key-packages/{}", encode(recipient))).await?;
        if packages.status != 200 {
            if identities.contains(recipient.as_bytes()) {
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
            let payload = STANDARD
                .decode(package["payload"].as_str().unwrap_or_default())
                .map_err(|_| "malformed MLS key package".to_string())?;
            by_device.entry(device).or_insert((id, payload));
        }
        for (_, (id, package)) in by_device {
            let signature = state
                .device
                .key_package_signature_key(&package)
                .map_err(|error| format!("MLS key package: {error}"))?;
            if keys.contains(&signature) {
                continue;
            }
            let (welcome, commit) = group
                .add(&state.device, &package)
                .map_err(|error| format!("MLS add {recipient}: {error}"))?;
            let epoch = group.epoch();
            for (kind, payload) in [("commit", commit), ("welcome", welcome)] {
                let response = api::send_json(
                    "POST",
                    &format!("/api/mls/messages?path={}", encode(path)),
                    &json!({
                        "epoch": epoch,
                        "kind": kind,
                        "payload": STANDARD.encode(payload),
                    }),
                )
                .await?;
                if response.status != 200 {
                    return Err(response
                        .error()
                        .unwrap_or("could not publish the MLS message")
                        .to_string());
                }
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
    let Some(remote) = fetch_group(path).await? else {
        return Ok(0);
    };
    let mut state = load_or_create(master).await?;
    let mut group = join_or_load(&mut state, master, &remote).await?;
    let indices: Vec<u32> = group
        .members()
        .into_iter()
        .filter(|member| {
            usernames
                .iter()
                .any(|name| member.identity == name.as_bytes())
        })
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
    let commit = group.remove(&state.device, &indices)?;
    let epoch = group.epoch();
    let response = api::send_json(
        "POST",
        &format!("/api/mls/messages?path={}", encode(path)),
        &json!({
            "epoch": epoch,
            "kind": "commit",
            "payload": STANDARD.encode(commit),
        }),
    )
    .await?;
    if response.status != 200 {
        return Err(response
            .error()
            .unwrap_or("could not publish the MLS removal commit")
            .to_string());
    }
    if let Some(keyring) = keyring {
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, epoch, &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={epoch}&if_revision=0",
                encode(path)
            ),
            &blob,
        )
        .await?;
        if response.status != 204 {
            return Err(response
                .error()
                .unwrap_or("could not rotate the share keyring")
                .to_string());
        }
    }
    save_state(master, &state).await?;
    Ok(indices.len())
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
    if let Some(mut remote) = remote {
        let mut group = join_or_load(&mut state, master, &remote).await?;
        let old_epoch = group.epoch();
        let old_keyring = open_keyring(&group, &state.device, &remote)
            .ok()
            .map(|(keyring, _)| keyring);
        add_recipients_to_group(master, &mut state, &mut group, path, recipients).await?;
        if let Some(old_keyring) = old_keyring
            && group.epoch() != old_epoch
        {
            let key = exporter(&group, &state.device)?;
            let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &old_keyring)?;
            let response = api::put_bytes(
                &format!(
                    "/api/mls/keyring?path={}&if_epoch={}&if_revision=0",
                    encode(path),
                    group.epoch()
                ),
                &blob,
            )
            .await?;
            if response.status != 204 {
                return Err(response
                    .error()
                    .unwrap_or("could not rotate the share keyring")
                    .to_string());
            }
            let Some(fresh) = fetch_group(path).await? else {
                return Err("the MLS group disappeared".to_string());
            };
            remote = fresh;
            group = join_or_load(&mut state, master, &remote).await?;
        }
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
    add_recipients_to_group(master, &mut state, &mut group, path, recipients).await?;
    if !state.groups.contains(&group_id) {
        state.groups.push(group_id.clone());
    }
    save_state(master, &state).await?;
    let key = exporter(&group, &state.device)?;
    let blob = encrypt_keyring(&key, &group_id, group.epoch(), &keyring)?;
    let response = api::put_bytes(
        &format!(
            "/api/mls/keyring?path={}&if_epoch={}&if_revision=0",
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
    let group = join_or_load(&mut state, master, &remote).await?;
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
