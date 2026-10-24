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

fn slot(master: &MasterKey) -> String {
    // A short, non-secret account fingerprint so several accounts in one
    // browser don't overwrite each other's state.
    let digest = blake3::hash(&master.as_bytes()[..8]);
    format!("{STATE_KEY}:{}", &digest.to_hex()[..16])
}

fn load_state(master: &MasterKey) -> Result<Option<State>, String> {
    let Some(storage) = storage() else {
        return Ok(None);
    };
    let Some(raw) = storage
        .get_item(&slot(master))
        .map_err(|_| "browser storage")?
    else {
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

fn save_state(master: &MasterKey, state: &State) -> Result<(), String> {
    let Some(storage) = storage() else {
        return Err("browser storage is unavailable".to_string());
    };
    let plain = state
        .device
        .export_state(&state.groups)
        .map_err(|error| format!("MLS state: {error}"))?;
    let blob = master
        .seal_local(&plain, STATE_AAD)
        .map_err(|_| "could not seal MLS state".to_string())?;
    storage
        .set_item(&slot(master), &STANDARD.encode(blob))
        .map_err(|_| "could not save MLS state".to_string())
}

fn load_or_create(master: &MasterKey) -> Result<State, String> {
    if let Some(state) = load_state(master)? {
        return Ok(state);
    }
    let device = Device::new(b"kolimi-web").map_err(|error| format!("MLS device: {error}"))?;
    let state = State {
        device,
        groups: Vec::new(),
    };
    save_state(master, &state)?;
    Ok(state)
}

/// Publishes a fresh key package for this browser device.
pub async fn publish_key_package(master: &MasterKey) -> Result<(), String> {
    let state = load_or_create(master)?;
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
    // Persist the private init key created by the builder.
    save_state(master, &state)
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
struct RemoteGroup {
    group_id: Vec<u8>,
    epoch: u64,
    messages: Vec<GroupMessage>,
    keyring: Option<(u64, Vec<u8>)>,
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
                Some((
                    keyring["epoch"].as_u64()?,
                    STANDARD.decode(keyring["payload"].as_str()?).ok()?,
                ))
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

fn join_or_load(
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
            save_state(master, state)?;
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
                save_state(master, state)?;
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
        save_state(master, state)?;
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
) -> Result<ShareKeyring, String> {
    let (epoch, payload) = remote
        .keyring
        .as_ref()
        .ok_or_else(|| "this share has no keyring yet".to_string())?;
    if *epoch != group.epoch() {
        return Err("the share keyring is for a different epoch".to_string());
    }
    let key = exporter(group, device)?;
    decrypt_keyring(&key, &remote.group_id, group.epoch(), payload)
        .map_err(|error| format!("share keyring: {error}"))
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
    let mut state = load_or_create(master)?;
    let group = join_or_load(&mut state, master, &remote)?;
    let keyring = open_keyring(&group, &state.device, &remote)?;
    let rel = server_path
        .strip_prefix(&mount.mount)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the share".to_string())?;
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
            let mut state = load_or_create(master)?;
            let group = join_or_load(&mut state, master, &remote)?;
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
    let mut state = load_or_create(master)?;
    let keyring = open_keyring(&group, &state.device, &remote)?;
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
    let mut state = load_or_create(master)?;
    let rel = server_path
        .strip_prefix(&root)
        .map(|rest| rest.trim_start_matches('/').to_string())
        .ok_or_else(|| "path is outside the group".to_string())?;
    for _ in 0..3 {
        let mut keyring = open_keyring(&group, &state.device, &remote)?;
        keyring.insert(&rel, file_key);
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}",
                encode(&root),
                group.epoch()
            ),
            &blob,
        )
        .await?;
        if response.status == 204 {
            save_state(master, &state)?;
            return Ok(());
        }
        if response.status != 409 {
            return Err(response
                .error()
                .unwrap_or("could not update the share keyring")
                .to_string());
        }
        // Another writer changed the epoch/keyring; retry from the server.
        let Some(fresh) = fetch_group(&root).await? else {
            return Err("the MLS group disappeared".to_string());
        };
        remote = fresh;
        group = join_or_load(&mut state, master, &remote)?;
    }
    Err("share keyring stayed busy after retries".to_string())
}

/// Fetches one owned file's raw key (used when building a share keyring).
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
    if info["kind"].as_str() != Some("dir") {
        return Err("MLS shares are supported for folders only".to_string());
    }
    let mut files = Vec::new();
    collect_files(path, &mut files).await?;
    // Sync-created folders may not carry the server flag; encrypted files
    // are proof the tree uses client-side keys.
    if info["encrypted"].as_bool() != Some(true) && files.is_empty() {
        return Err("MLS shares are supported for encrypted folders only".to_string());
    }
    publish_key_package(master).await?;
    // Recipients need the plaintext mount name and the folder name key;
    // this is independent of the MLS keyring.
    for recipient in recipients {
        crate::e2ee::share_name_with(master, path, true, recipient).await?;
    }
    let mut state = load_or_create(master)?;
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
            if !rel.is_empty() {
                keyring.insert(&rel, &key);
            }
        }
    }
    if let Some(remote) = remote {
        let group = join_or_load(&mut state, master, &remote)?;
        if let Ok(existing) = open_keyring(&group, &state.device, &remote) {
            keyring = existing;
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
                if !rel.is_empty() {
                    keyring.insert(&rel, &key);
                }
            }
        }
        let key = exporter(&group, &state.device)?;
        let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &keyring)?;
        let response = api::put_bytes(
            &format!(
                "/api/mls/keyring?path={}&if_epoch={}",
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
    for recipient in recipients {
        let packages = api::get(&format!("/api/mls/key-packages/{}", encode(recipient))).await?;
        if packages.status != 200 {
            return Err(format!("{recipient} has no published MLS key package"));
        }
        let payloads = packages.body["packages"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for package in payloads {
            let package = STANDARD
                .decode(package["payload"].as_str().unwrap_or_default())
                .map_err(|_| "malformed MLS key package".to_string())?;
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
        }
    }
    if !state.groups.contains(&group_id) {
        state.groups.push(group_id.clone());
    }
    save_state(master, &state)?;
    let key = exporter(&group, &state.device)?;
    let blob = encrypt_keyring(&key, &group_id, group.epoch(), &keyring)?;
    let response = api::put_bytes(
        &format!(
            "/api/mls/keyring?path={}&if_epoch={}",
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
    let mut state = load_or_create(master)?;
    let group = join_or_load(&mut state, master, &remote)?;
    let keyring = open_keyring(&group, &state.device, &remote)?;
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
    let response = api::send_json(
        "PUT",
        &format!("/api/files?path={}", encode(&target)),
        &manifest,
    )
    .await?;
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
    let mut updated = keyring;
    updated.insert(&rel, file_key.as_bytes());
    let key = exporter(&group, &state.device)?;
    let blob = encrypt_keyring(&key, &remote.group_id, group.epoch(), &updated)?;
    let response = api::put_bytes(
        &format!(
            "/api/mls/keyring?path={}&if_epoch={}",
            encode(&mount.mount),
            group.epoch()
        ),
        &blob,
    )
    .await?;
    if response.status != 204 {
        return Err(response
            .error()
            .unwrap_or("could not update the share keyring")
            .to_string());
    }
    save_state(master, &state)
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
