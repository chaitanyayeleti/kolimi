//! MLS group state for sync/desktop encrypted shares.
//!
//! The server stores opaque key packages, commits/Welcomes and one
//! epoch-bound keyring per shared folder. This module owns the client side:
//! device bootstrap, group create/join, commit processing, and reading or
//! updating the share keyring. Group secrets never leave the sealed
//! [`MlsStore`](crate::mls_store::MlsStore).

use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_crypto::{FileKey, MasterKey};
use kolimi_mls::SHARE_KEYRING_EXPORTER;
use kolimi_mls::client::{Device, Group};
use kolimi_mls::keyring::{ShareKeyring, decrypt as decrypt_keyring, encrypt as encrypt_keyring};
use serde::Deserialize;

use crate::mls_store::MlsStore;
use crate::{Http, SyncConfig, SyncError, encode};

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
}

#[derive(Debug, Clone)]
struct RemoteGroup {
    group_id: Vec<u8>,
    epoch: u64,
    messages: Vec<GroupMessage>,
    keyring: Option<KeyringBlob>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReceivedMount {
    pub mount: String,
}

/// A loaded MLS device plus the groups it has joined.
pub(crate) struct MlsClient {
    store: MlsStore,
    device: Device,
    groups: BTreeSet<Vec<u8>>,
    keyrings: BTreeMap<Vec<u8>, (u64, ShareKeyring)>,
    mounts: Option<Vec<ReceivedMount>>,
}

impl MlsClient {
    /// Loads the sealed device state, or creates a fresh device.
    pub(crate) fn load(config: &SyncConfig, master: &MasterKey) -> Result<Self, SyncError> {
        let store = MlsStore::new(&config.local_dir);
        let (device, groups, created) = match store.load(master)? {
            Some((device, groups)) => (device, groups, false),
            None => (
                Device::new(config.username.as_bytes())
                    .map_err(|error| SyncError::E2ee(format!("MLS device: {error}")))?,
                Vec::new(),
                true,
            ),
        };
        if created {
            // Persist before publishing a key package: the private half is
            // needed to process the Welcome after a later sync pass.
            store.save(master, &device, &[])?;
        }
        Ok(Self {
            store,
            device,
            groups: groups.into_iter().collect(),
            keyrings: BTreeMap::new(),
            mounts: None,
        })
    }

    fn save(&self, master: &MasterKey) -> Result<(), SyncError> {
        let groups: Vec<Vec<u8>> = self.groups.iter().cloned().collect();
        self.store.save(master, &self.device, &groups)
    }

    fn device(&self) -> &Device {
        &self.device
    }

    /// Publishes a fresh key package for this device (idempotent per
    /// device id; openmls key packages are single-use).
    pub(crate) async fn publish_key_package(
        &mut self,
        http: &Http,
        master: &MasterKey,
    ) -> Result<(), SyncError> {
        let package = self
            .device
            .key_package()
            .map_err(|error| SyncError::E2ee(format!("MLS key package: {error}")))?;
        let (status, body) = http
            .put_json(
                "/api/mls/key-packages",
                &serde_json::json!({
                    "device_id": self.device.device_id(),
                    "payload": STANDARD.encode(package),
                }),
            )
            .await?;
        if status != 204 {
            return Err(SyncError::Server {
                status,
                path: format!("/api/mls/key-packages ({body})"),
            });
        }
        // The builder stored the private init key in the provider; persist
        // it or the Welcome cannot be processed after a later sync pass.
        self.save(master)
    }

    async fn received_mounts(&mut self, http: &Http) -> Result<&[ReceivedMount], SyncError> {
        if self.mounts.is_none() {
            let (status, body) = http.get_json("/api/shares/received").await?;
            if status != 200 {
                return Err(SyncError::Server {
                    status,
                    path: "/api/shares/received".to_string(),
                });
            }
            let mounts = body["mounts"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| serde_json::from_value(item.clone()).ok())
                        .collect()
                })
                .unwrap_or_default();
            self.mounts = Some(mounts);
        }
        Ok(self.mounts.as_deref().unwrap_or_default())
    }

    /// The received-share mount containing `server_path`, if any.
    async fn mount_for(
        &mut self,
        http: &Http,
        server_path: &str,
    ) -> Result<Option<ReceivedMount>, SyncError> {
        let mounts = self.received_mounts(http).await?;
        Ok(mounts
            .iter()
            .filter(|mount| {
                server_path == mount.mount
                    || server_path
                        .strip_prefix(&mount.mount)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
            .max_by_key(|mount| mount.mount.len())
            .cloned())
    }

    /// Finds the MLS group for a stored path by checking the path and its
    /// ancestors (a group belongs to a shared folder, not every file).
    async fn group_for_path(
        &mut self,
        http: &Http,
        server_path: &str,
    ) -> Result<Option<(String, RemoteGroup)>, SyncError> {
        // Received shares are mounted at `/Shared with me/<name>`; the
        // group is attached to the owner's node, resolved through the mount.
        if let Some(mount) = self.mount_for(http, server_path).await? {
            if let Some(group) = fetch_group(http, &mount.mount).await? {
                return Ok(Some((mount.mount, group)));
            }
            return Ok(None);
        }
        // Owned path: check the path itself, then each parent folder.
        let mut current = server_path.trim_end_matches('/').to_string();
        loop {
            if let Some(group) = fetch_group(http, &current).await? {
                return Ok(Some((current, group)));
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

    /// Ensures the local group is joined and at the server's epoch.
    async fn ensure_group(
        &mut self,
        _http: &Http,
        master: &MasterKey,
        server_path: &str,
        remote: &RemoteGroup,
    ) -> Result<Group, SyncError> {
        let group_id = remote.group_id.clone();
        let mut group = match Group::load(self.device(), &group_id).map_err(|_| ()) {
            Ok(group) => group,
            Err(_) => {
                // A group can contain Welcomes for several devices; only
                // one matches this device's key package.
                let mut joined = None;
                let mut last_error = None;
                for welcome in remote
                    .messages
                    .iter()
                    .filter(|message| message.kind == "welcome")
                {
                    match Group::join(self.device(), &welcome.payload) {
                        Ok(group) => {
                            if group.epoch() != welcome.epoch {
                                last_error = Some(SyncError::E2ee(
                                    "MLS Welcome epoch does not match the commit".to_string(),
                                ));
                                continue;
                            }
                            joined = Some(group);
                            break;
                        }
                        Err(error) => {
                            last_error = Some(SyncError::E2ee(format!("MLS join: {error}")));
                        }
                    }
                }
                let joined = joined.ok_or_else(|| {
                    last_error.unwrap_or_else(|| {
                        SyncError::E2ee(format!(
                            "MLS group for {server_path} has no Welcome for this device"
                        ))
                    })
                })?;
                self.groups.insert(group_id.clone());
                self.save(master)?;
                joined
            }
        };

        // Process commits this device has not seen. A commit's `epoch` is
        // the epoch it creates; skip anything already merged.
        let mut progressed = true;
        while progressed {
            progressed = false;
            for message in &remote.messages {
                if message.kind != "commit" || message.epoch != group.epoch() + 1 {
                    continue;
                }
                match group.process(self.device(), &message.payload) {
                    Ok(()) => {
                        progressed = true;
                        self.save(master)?;
                    }
                    Err(_) => continue,
                }
            }
        }
        if group.epoch() != remote.epoch {
            return Err(SyncError::E2ee(format!(
                "MLS group for {server_path} is at epoch {} locally but {} on the server",
                group.epoch(),
                remote.epoch
            )));
        }
        self.groups.insert(group_id);
        self.save(master)?;
        Ok(group)
    }

    /// Loads and decrypts the current share keyring for a path, if the
    /// path belongs to an MLS group.
    pub(crate) async fn keyring_for(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
    ) -> Result<Option<(String, ShareKeyring)>, SyncError> {
        let Some((root, remote)) = self.group_for_path(http, server_path).await? else {
            return Ok(None);
        };
        let group = self
            .ensure_group(http, master, server_path, &remote)
            .await?;
        let Some(blob) = remote.keyring else {
            return Ok(None);
        };
        if blob.epoch != group.epoch() {
            return Err(SyncError::E2ee(format!(
                "share keyring for {root} is at epoch {} but the group is at {}",
                blob.epoch,
                group.epoch()
            )));
        }
        if let Some((epoch, keyring)) = self.keyrings.get(&remote.group_id)
            && *epoch == group.epoch()
        {
            return Ok(Some((root, keyring.clone())));
        }
        let exporter = group
            .export(self.device(), SHARE_KEYRING_EXPORTER, 32)
            .map_err(|error| SyncError::E2ee(format!("MLS exporter: {error}")))?;
        let exporter: [u8; 32] = exporter
            .try_into()
            .map_err(|_| SyncError::E2ee("MLS exporter length".to_string()))?;
        let keyring = decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
            .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
        self.keyrings
            .insert(remote.group_id.clone(), (group.epoch(), keyring.clone()));
        Ok(Some((root, keyring)))
    }

    /// Looks up one file key in the path's share keyring.
    pub(crate) async fn file_key(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
    ) -> Result<Option<FileKey>, SyncError> {
        let Some((root, keyring)) = self.keyring_for(http, master, server_path).await? else {
            return Ok(None);
        };
        let Some(rel) = relative_to_share(server_path, &root) else {
            return Ok(None);
        };
        Ok(keyring.get(&rel).map(FileKey::from_bytes))
    }

    /// Adds/updates one file key in the path's share keyring.
    ///
    /// Returns `false` when the path is not inside an MLS share (the caller
    /// should keep the legacy per-file wrap).
    pub(crate) async fn record_file_key(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        file_key: &FileKey,
    ) -> Result<bool, SyncError> {
        for attempt in 0..4 {
            let Some((root, remote)) = self.group_for_path(http, server_path).await? else {
                return Ok(false);
            };
            let group = self
                .ensure_group(http, master, server_path, &remote)
                .await?;
            let Some(rel) = relative_to_share(server_path, &root) else {
                return Ok(false);
            };
            let mut keyring = match remote.keyring {
                Some(blob) if blob.epoch == group.epoch() => {
                    let exporter = group
                        .export(self.device(), SHARE_KEYRING_EXPORTER, 32)
                        .map_err(|error| SyncError::E2ee(format!("MLS exporter: {error}")))?;
                    let exporter: [u8; 32] = exporter
                        .try_into()
                        .map_err(|_| SyncError::E2ee("MLS exporter length".to_string()))?;
                    decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
                        .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?
                }
                _ => ShareKeyring::new(),
            };
            keyring.insert(&rel, file_key.as_bytes());
            let exporter = group
                .export(self.device(), SHARE_KEYRING_EXPORTER, 32)
                .map_err(|error| SyncError::E2ee(format!("MLS exporter: {error}")))?;
            let exporter: [u8; 32] = exporter
                .try_into()
                .map_err(|_| SyncError::E2ee("MLS exporter length".to_string()))?;
            let blob = encrypt_keyring(&exporter, &remote.group_id, group.epoch(), &keyring)
                .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
            let path = format!(
                "/api/mls/keyring?path={}&if_epoch={}",
                encode(&root),
                group.epoch()
            );
            let status = http.put_bytes(&path, &blob).await?;
            if status == 204 {
                self.keyrings
                    .insert(remote.group_id, (group.epoch(), keyring));
                return Ok(true);
            }
            if status == 409 && attempt < 3 {
                continue;
            }
            return Err(SyncError::Server { status, path });
        }
        Err(SyncError::Protocol(
            "MLS keyring stayed busy after retries".to_string(),
        ))
    }

    /// Creates the group for an owned encrypted folder and adds the listed
    /// recipients. Returns the current epoch.
    pub(crate) async fn create_group(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        recipients: &[String],
    ) -> Result<u64, SyncError> {
        // Re-sharing an already initialized folder reuses the group; the
        // caller will publish a fresh keyring below.
        if let Some((root, remote)) = self.group_for_path(http, server_path).await? {
            let group = self
                .ensure_group(http, master, server_path, &remote)
                .await?;
            let _ = root;
            return Ok(group.epoch());
        }
        let group_id = random_group_id()?;
        let mut group = Group::create(self.device(), &group_id)
            .map_err(|error| SyncError::E2ee(format!("MLS create: {error}")))?;
        let (status, body) = http
            .put_json(
                &format!("/api/mls/group?path={}", encode(server_path)),
                &serde_json::json!({ "group_id": STANDARD.encode(&group_id) }),
            )
            .await?;
        if status != 200 {
            return Err(SyncError::Server {
                status,
                path: format!("/api/mls/group ({body})"),
            });
        }
        for recipient in recipients {
            let packages = recipient_key_packages(http, recipient).await?;
            if packages.is_empty() {
                return Err(SyncError::E2ee(format!(
                    "{recipient} has no MLS key package; ask them to sync once with MLS enabled"
                )));
            }
            for package in packages {
                let (welcome, commit) = group
                    .add(self.device(), &package)
                    .map_err(|error| SyncError::E2ee(format!("MLS add {recipient}: {error}")))?;
                let epoch = group.epoch();
                post_message(http, server_path, epoch, "commit", &commit).await?;
                post_message(http, server_path, epoch, "welcome", &welcome).await?;
            }
        }
        self.groups.insert(group_id);
        self.save(master)?;
        Ok(group.epoch())
    }

    /// Publishes a full keyring for a newly-created group.
    pub(crate) async fn publish_keyring(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        keyring: &ShareKeyring,
    ) -> Result<(), SyncError> {
        let Some((root, remote)) = self.group_for_path(http, server_path).await? else {
            return Err(SyncError::E2ee(format!("no MLS group for {server_path}")));
        };
        let group = self
            .ensure_group(http, master, server_path, &remote)
            .await?;
        let exporter = group
            .export(self.device(), SHARE_KEYRING_EXPORTER, 32)
            .map_err(|error| SyncError::E2ee(format!("MLS exporter: {error}")))?;
        let exporter: [u8; 32] = exporter
            .try_into()
            .map_err(|_| SyncError::E2ee("MLS exporter length".to_string()))?;
        // Merge into the current keyring: a re-share/migration must not drop
        // keys that write recipients added (their per-node key is not wrapped
        // for the owner).
        let mut merged = match &remote.keyring {
            Some(blob) if blob.epoch == group.epoch() => {
                decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
                    .unwrap_or_else(|_| ShareKeyring::new())
            }
            _ => ShareKeyring::new(),
        };
        merged
            .entries
            .extend(keyring.entries.iter().map(|(k, v)| (k.clone(), v.clone())));
        let blob = encrypt_keyring(&exporter, &remote.group_id, group.epoch(), &merged)
            .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
        let path = format!(
            "/api/mls/keyring?path={}&if_epoch={}",
            encode(&root),
            group.epoch()
        );
        let status = http.put_bytes(&path, &blob).await?;
        if status != 204 {
            return Err(SyncError::Server { status, path });
        }
        Ok(())
    }
}

fn relative_to_share(server_path: &str, root: &str) -> Option<String> {
    let rest = server_path.strip_prefix(root)?;
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

fn random_group_id() -> Result<Vec<u8>, SyncError> {
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id)
        .map_err(|error| SyncError::E2ee(format!("MLS group id: {error}")))?;
    Ok(id.to_vec())
}

async fn recipient_key_packages(http: &Http, username: &str) -> Result<Vec<Vec<u8>>, SyncError> {
    let path = format!("/api/mls/key-packages/{}", encode(username));
    let (status, body) = http.get_json(&path).await?;
    if status == 404 {
        return Ok(Vec::new());
    }
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    Ok(body["packages"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["payload"].as_str())
                .filter_map(|payload| STANDARD.decode(payload).ok())
                .collect()
        })
        .unwrap_or_default())
}

async fn post_message(
    http: &Http,
    server_path: &str,
    epoch: u64,
    kind: &str,
    payload: &[u8],
) -> Result<(), SyncError> {
    let path = format!("/api/mls/messages?path={}", encode(server_path));
    let (status, body) = http
        .post_json(
            &path,
            &serde_json::json!({
                "epoch": epoch,
                "kind": kind,
                "payload": STANDARD.encode(payload),
            }),
        )
        .await?;
    if status != 200 {
        return Err(SyncError::Server {
            status,
            path: format!("{path} ({body})"),
        });
    }
    Ok(())
}

async fn fetch_group(http: &Http, server_path: &str) -> Result<Option<RemoteGroup>, SyncError> {
    let mut messages = Vec::new();
    let mut keyring = None;
    let mut group_id: Option<Vec<u8>> = None;
    let mut epoch: Option<u64> = None;
    let mut after = 0i64;
    loop {
        let path = format!(
            "/api/mls/group?path={}&after={after}&limit=1000",
            encode(server_path)
        );
        let (status, body) = http.get_json(&path).await?;
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(SyncError::Server { status, path });
        }
        group_id = match group_id {
            Some(group_id) => Some(group_id),
            None => Some(
                STANDARD
                    .decode(body["group_id"].as_str().unwrap_or_default())
                    .map_err(|_| SyncError::E2ee("malformed MLS group id".to_string()))?,
            ),
        };
        if epoch.is_none() {
            epoch = Some(body["epoch"].as_u64().unwrap_or(0));
        }
        if keyring.is_none() {
            keyring = body["keyring"].as_object().and_then(|keyring| {
                Some(KeyringBlob {
                    epoch: keyring["epoch"].as_u64()?,
                    payload: STANDARD.decode(keyring["payload"].as_str()?).ok()?,
                })
            });
        }
        let page = body["messages"].as_array().cloned().unwrap_or_default();
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
        group_id: group_id.ok_or_else(|| SyncError::E2ee("MLS group id missing".to_string()))?,
        epoch: epoch.unwrap_or(0),
        messages,
        keyring,
    }))
}
