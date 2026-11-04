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
use kolimi_mls::client::{Device, Group, MemberInfo};
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
    revision: i64,
}

#[derive(Debug, Clone)]
struct RemoteGroup {
    group_id: Vec<u8>,
    epoch: u64,
    messages: Vec<GroupMessage>,
    keyring: Option<KeyringBlob>,
    /// Client-asserted revoked signatures; auto-refresh must skip these.
    revocations: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddOutcome {
    Done,
    Conflict,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReceivedMount {
    pub mount: String,
    #[serde(default)]
    pub permission: String,
}

/// A share root that may carry an MLS group, with the caller's write access.
#[derive(Debug, Clone)]
struct GroupRoot {
    path: String,
    writable: bool,
}

/// One MLS device known to the server, with group membership discovered
/// from this client's local group state.
#[derive(Debug, Clone)]
pub struct MlsDevice {
    /// Opaque device id from the server roster.
    pub device_id: String,
    /// Best-effort label reported by the device (may be empty).
    pub device_name: String,
    /// Public signature key, if the device published one.
    pub signature_key: Option<Vec<u8>>,
    /// First time this device published a package.
    pub created_at: i64,
    /// Last package upload / roster activity.
    pub last_seen_at: i64,
    /// Share roots where this client found the device's leaf.
    pub groups: Vec<String>,
    /// Whether this is the device running the command.
    pub current: bool,
}

/// Result of listing the roster. `warnings` names groups that could not be
/// inspected because this client has no usable local state for them.
#[derive(Debug, Clone, Default)]
pub struct MlsDeviceList {
    pub devices: Vec<MlsDevice>,
    pub warnings: Vec<String>,
}

/// Result of revoking one device.
#[derive(Debug, Clone, Default)]
pub struct MlsRevokeReport {
    /// Share roots where at least one leaf was removed.
    pub groups: Vec<String>,
    /// Number of MLS leaves removed across those groups.
    pub leaves: usize,
    /// Whether the server roster row and its packages were removed.
    pub roster_removed: bool,
}

/// A stable, human-readable label for this sync device.
fn local_device_name() -> String {
    std::env::var("KOLIMI_DEVICE_NAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|name| name.trim().chars().take(128).collect::<String>())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "kolimi-sync".to_string())
}

/// A loaded MLS device plus the groups it has joined.
pub(crate) struct MlsClient {
    store: MlsStore,
    device: Device,
    groups: BTreeSet<Vec<u8>>,
    keyrings: BTreeMap<Vec<u8>, (u64, ShareKeyring)>,
    groups_cache: BTreeMap<String, RemoteGroup>,
    mounts: Option<Vec<ReceivedMount>>,
    /// Highest epoch reported to the server in this pass, per group.
    reported_epochs: BTreeMap<Vec<u8>, u64>,
    /// Serialized commits posted but not yet merged locally, per group id.
    pending_commits: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MlsClient {
    /// Loads the sealed device state, or creates a fresh device.
    pub(crate) fn load(config: &SyncConfig, master: &MasterKey) -> Result<Self, SyncError> {
        let store = MlsStore::new(&config.local_dir);
        let (device, groups, pending_commits, created) = match store.load(master)? {
            Some((device, groups, pending)) => (device, groups, pending, false),
            None => (
                Device::new(config.username.as_bytes())
                    .map_err(|error| SyncError::E2ee(format!("MLS device: {error}")))?,
                Vec::new(),
                BTreeMap::new(),
                true,
            ),
        };
        if created {
            // Persist before publishing a key package: the private half is
            // needed to process the Welcome after a later sync pass.
            store.save(master, &device, &[], &BTreeMap::new())?;
        }
        Ok(Self {
            store,
            device,
            groups: groups.into_iter().collect(),
            keyrings: BTreeMap::new(),
            groups_cache: BTreeMap::new(),
            mounts: None,
            reported_epochs: BTreeMap::new(),
            pending_commits,
        })
    }

    fn save(&self, master: &MasterKey) -> Result<(), SyncError> {
        let groups: Vec<Vec<u8>> = self.groups.iter().cloned().collect();
        self.store
            .save(master, &self.device, &groups, &self.pending_commits)
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
        const POOL: i64 = 4;
        // Keep a small pool so two groups can be shared before the next
        // pass. The server filters consumed/expired packages.
        let (status, body) = http.get_json("/api/mls/key-packages").await?;
        let device_id = self.device.device_id();
        let have = if status == 200 {
            body["packages"]
                .as_array()
                .map(|packages| {
                    packages
                        .iter()
                        .filter(|package| package["device_id"].as_str() == Some(&device_id))
                        .count()
                })
                .unwrap_or(0) as i64
        } else {
            0
        };
        let mut target = POOL;
        if have >= POOL {
            // Devices upgraded from a build that did not report a name or
            // signature key need one metadata-bearing package. Stay within
            // the server's per-device cap.
            let metadata_missing = match http.get_json("/api/mls/devices").await {
                Ok((200, body)) => body["devices"]
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
                // A transient roster error must not force another package.
                _ => false,
            };
            if !metadata_missing {
                return Ok(());
            }
            // Add one metadata-bearing package; the server's per-device cap
            // remains authoritative if the pool is already at its limit.
            target = have + 1;
        }
        let device_name = local_device_name();
        for _ in have..target {
            let package = self
                .device
                .key_package()
                .map_err(|error| SyncError::E2ee(format!("MLS key package: {error}")))?;
            let signature_key = self
                .device
                .key_package_signature_key(&package)
                .map_err(SyncError::E2ee)?;
            let (status, body) = http
                .put_json(
                    "/api/mls/key-packages",
                    &serde_json::json!({
                        "device_id": self.device.device_id(),
                        "device_name": device_name,
                        "signature_key": STANDARD.encode(signature_key),
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
        }
        // The builder stored the private init keys in the provider; persist
        // them or a Welcome cannot be processed after a later sync pass.
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
            if let Some(group) = self.groups_cache.get(&current) {
                return Ok(Some((current, group.clone())));
            }
            if let Some(group) = fetch_group(http, &current).await? {
                self.groups_cache.insert(current.clone(), group.clone());
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
        http: &Http,
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
                self.pending_commits.remove(&group_id);
                self.save(master)?;
                joined
            }
        };

        if !group.has_pending_commit() {
            self.pending_commits.remove(&group_id);
        }
        // If the server never advanced, the staged commit was rejected or
        // never reached the server; drop it and continue from the old epoch.
        if group.has_pending_commit() && remote.epoch <= group.epoch() {
            group
                .discard_pending(self.device())
                .map_err(SyncError::E2ee)?;
            self.pending_commits.remove(&group_id);
            self.save(master)?;
        }
        // A previous pass may have crashed after the server accepted a commit
        // but before the local merge. The server echo is surfaced by openmls
        // as `OwnPendingCommit`, which `Group::process` merges.
        if group.epoch() > remote.epoch {
            return Err(SyncError::E2ee(format!(
                "MLS group for {server_path} is ahead of the server (local epoch {}, server epoch {}); reset this device's MLS state and ask a member to re-share",
                group.epoch(),
                remote.epoch
            )));
        }

        // Process commits this device has not seen. A commit's `epoch` is
        // the epoch it creates; skip anything already merged.
        let mut progressed = true;
        while progressed {
            progressed = false;
            for message in &remote.messages {
                if message.kind != "commit" || message.epoch != group.epoch() + 1 {
                    continue;
                }
                let before = group.epoch();
                let expected = self.pending_commits.get(&group_id).cloned();
                let processed =
                    group.process_commit(self.device(), &message.payload, expected.as_deref());
                if processed.is_err() && group.has_pending_commit() {
                    // Our staged commit lost the epoch race. Drop it and
                    // process the winning commit from the same parent epoch.
                    group
                        .discard_pending(self.device())
                        .map_err(SyncError::E2ee)?;
                    self.pending_commits.remove(&group_id);
                    self.save(master)?;
                    if group
                        .process_commit(self.device(), &message.payload, None)
                        .is_ok()
                        && group.epoch() > before
                    {
                        progressed = true;
                        self.save(master)?;
                    }
                    continue;
                }
                if processed.is_ok() {
                    if group.epoch() == before {
                        return Err(SyncError::E2ee(format!(
                            "MLS commit at epoch {} did not advance the local group",
                            message.epoch
                        )));
                    }
                    self.pending_commits.remove(&group_id);
                    progressed = true;
                    self.save(master)?;
                }
            }
        }
        if group.epoch() != remote.epoch {
            return Err(SyncError::E2ee(format!(
                "MLS group for {server_path} is at epoch {} locally but {} on the server; reset this device's MLS state and ask a member to re-share",
                group.epoch(),
                remote.epoch
            )));
        }
        self.report_epoch(http, server_path, &group_id, group.epoch())
            .await;
        self.groups.insert(group_id);
        self.save(master)?;
        Ok(group)
    }

    /// Reports the processed epoch so the server can prune old messages.
    ///
    /// Advisory: a missing endpoint or a rejected report must not break
    /// syncing. The next pass retries if the server still needs it.
    async fn report_epoch(&mut self, http: &Http, server_path: &str, group_id: &[u8], epoch: u64) {
        if self
            .reported_epochs
            .get(group_id)
            .is_some_and(|reported| *reported >= epoch)
        {
            return;
        }
        let path = format!("/api/mls/epoch?path={}", encode(server_path));
        match http
            .post_json(
                &path,
                &serde_json::json!({
                    "device_id": self.device.device_id(),
                    "epoch": epoch,
                }),
            )
            .await
        {
            Ok((204, _)) => {
                self.reported_epochs.insert(group_id.to_vec(), epoch);
            }
            Ok((404, _)) => {}
            Ok((status, body)) => {
                eprintln!(
                    "kolimi-sync: epoch report for {server_path} failed ({status}): {}",
                    body["error"].as_str().unwrap_or_default()
                );
            }
            Err(error) => {
                eprintln!("kolimi-sync: epoch report for {server_path} failed: {error}");
            }
        }
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

    /// Current epoch and members of the group governing a stored path.
    pub(crate) async fn status(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
    ) -> Result<Option<(u64, Vec<kolimi_mls::client::MemberInfo>)>, SyncError> {
        let Some((_root, remote)) = self.group_for_path(http, server_path).await? else {
            return Ok(None);
        };
        let group = self
            .ensure_group(http, master, server_path, &remote)
            .await?;
        Ok(Some((group.epoch(), group.members())))
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
        self.mutate_keyring(http, master, server_path, |root, keyring| {
            if let Some(rel) = relative_to_share(server_path, root) {
                keyring.insert(&rel, file_key.as_bytes());
            }
        })
        .await
    }

    /// Removes a deleted file's key from the governing keyring.
    pub(crate) async fn remove_file_key(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
    ) -> Result<(), SyncError> {
        let _ = self
            .mutate_keyring(http, master, server_path, |root, keyring| {
                if let Some(rel) = relative_to_share(server_path, root) {
                    keyring.entries.remove(&rel);
                }
            })
            .await?;
        Ok(())
    }

    /// Applies a mutation to the current keyring with epoch + revision
    /// optimistic concurrency, retrying after a concurrent writer.
    async fn mutate_keyring(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        mut mutate: impl FnMut(&str, &mut ShareKeyring),
    ) -> Result<bool, SyncError> {
        for _ in 0..4 {
            let Some((root, remote)) = self.group_for_path(http, server_path).await? else {
                return Ok(false);
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
            let (mut keyring, revision) = match &remote.keyring {
                Some(blob) if blob.epoch == group.epoch() => (
                    decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
                        .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?,
                    blob.revision,
                ),
                _ => (ShareKeyring::new(), 0),
            };
            mutate(&root, &mut keyring);
            let blob = encrypt_keyring(&exporter, &remote.group_id, group.epoch(), &keyring)
                .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
            let path = format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={revision}",
                encode(&root),
                group.epoch()
            );
            let status = http.put_bytes(&path, &blob).await?;
            if status == 204 {
                self.keyrings
                    .insert(remote.group_id, (group.epoch(), keyring));
                self.groups_cache.remove(&root);
                return Ok(true);
            }
            if status != 409 {
                return Err(SyncError::Server { status, path });
            }
            self.groups_cache.remove(&root);
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
        if let Some((root, remote)) = self.group_for_path(http, server_path).await? {
            let mut group = self
                .ensure_group(http, master, server_path, &remote)
                .await?;
            self.add_recipients_to_group(
                http,
                master,
                server_path,
                &root,
                &remote,
                &mut group,
                recipients,
                false,
            )
            .await?;
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
        self.add_recipients_to_group(
            http,
            master,
            server_path,
            server_path,
            &RemoteGroup {
                group_id: group_id.clone(),
                epoch: group.epoch(),
                messages: Vec::new(),
                keyring: None,
                revocations: Vec::new(),
            },
            &mut group,
            recipients,
            false,
        )
        .await?;
        self.groups.insert(group_id);
        self.save(master)?;
        Ok(group.epoch())
    }

    /// Adds users/devices that are not yet members and consumes the packages
    /// that were actually used.
    ///
    /// A losing concurrent committer discards its staged commit and replays
    /// the winning epoch before retrying, so the local group never forks.
    #[allow(clippy::too_many_arguments)]
    async fn add_recipients_to_group(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        root: &str,
        remote: &RemoteGroup,
        group: &mut Group,
        recipients: &[String],
        best_effort: bool,
    ) -> Result<(), SyncError> {
        let mut remote = remote.clone();
        for _ in 0..3 {
            let keyring = self.current_keyring(group, &remote)?;
            let revoked: BTreeSet<Vec<u8>> = remote.revocations.iter().cloned().collect();
            match self
                .add_recipients_once(
                    http,
                    master,
                    root,
                    &remote.group_id,
                    group,
                    recipients,
                    keyring.as_ref(),
                    &revoked,
                    best_effort,
                )
                .await?
            {
                AddOutcome::Done => return Ok(()),
                AddOutcome::Conflict => {
                    self.groups_cache.remove(root);
                    self.save(master)?;
                    let Some(fresh) = fetch_group(http, root).await? else {
                        return Err(SyncError::E2ee(format!(
                            "MLS group for {root} disappeared during a concurrent commit"
                        )));
                    };
                    *group = self.ensure_group(http, master, server_path, &fresh).await?;
                    remote = fresh;
                }
            }
        }
        Err(SyncError::Protocol(
            "MLS group stayed busy after retries".to_string(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_recipients_once(
        &mut self,
        http: &Http,
        master: &MasterKey,
        root: &str,
        group_id: &[u8],
        group: &mut Group,
        recipients: &[String],
        keyring: Option<&ShareKeyring>,
        revoked: &BTreeSet<Vec<u8>>,
        best_effort: bool,
    ) -> Result<AddOutcome, SyncError> {
        let members = group.members();
        let mut keys: BTreeSet<Vec<u8>> = members.iter().map(|m| m.signature_key.clone()).collect();
        let identities: BTreeSet<Vec<u8>> = members.iter().map(|m| m.identity.clone()).collect();
        let mut consumed = Vec::new();
        for recipient in recipients {
            let packages = match recipient_key_packages(http, recipient).await {
                Ok(packages) => packages,
                Err(error) if best_effort => {
                    eprintln!("kolimi-sync: cannot fetch MLS packages for {recipient}: {error}");
                    continue;
                }
                Err(error) => return Err(error),
            };
            if packages.is_empty() && !identities.contains(recipient.as_bytes()) {
                if best_effort {
                    continue;
                }
                return Err(SyncError::E2ee(format!(
                    "{recipient} has no MLS key package; ask them to sync once with MLS enabled"
                )));
            }
            for package in packages {
                if package.device_id == self.device.device_id() {
                    continue;
                }
                let signature = self
                    .device
                    .key_package_signature_key(&package.payload)
                    .map_err(SyncError::E2ee)?;
                if keys.contains(&signature) {
                    // Already a member (re-share/new group with a stale
                    // unconsumed package); leave it for another group.
                    continue;
                }
                if best_effort && revoked.contains(&signature) {
                    // The owner removed this leaf on purpose. Its remaining
                    // key packages must not silently re-add it.
                    continue;
                }
                let pending = group
                    .add_pending(self.device(), &package.payload)
                    .map_err(|error| SyncError::E2ee(format!("MLS add {recipient}: {error}")))?;
                // Persist before posting: a crash after the server accepts
                // the commit must leave enough state to reconcile it.
                self.pending_commits
                    .insert(group_id.to_vec(), pending.commit.clone());
                self.save(master)?;
                match post_commit(
                    http,
                    root,
                    pending.epoch,
                    &pending.commit,
                    pending.welcome.as_deref(),
                )
                .await
                {
                    Ok(()) => {}
                    Err(SyncError::Server { status: 409, .. }) => {
                        group
                            .discard_pending(self.device())
                            .map_err(SyncError::E2ee)?;
                        self.pending_commits.remove(group_id);
                        let _ = self.consume_packages(http, &consumed).await;
                        return Ok(AddOutcome::Conflict);
                    }
                    Err(error) => {
                        // Keep the staged commit: the response may have been
                        // lost after the server accepted it. The next pass
                        // reconciles it against the message log.
                        return Err(error);
                    }
                }
                group
                    .merge_pending(self.device())
                    .map_err(SyncError::E2ee)?;
                self.pending_commits.remove(group_id);
                self.save(master)?;
                self.groups_cache.remove(root);
                // Rotate the keyring for every new epoch, not only at the
                // end: a concurrent committer may reach this epoch first.
                if let Some(keyring) = keyring {
                    self.publish_keyring(http, master, root, keyring).await?;
                }
                if !best_effort {
                    // An explicit re-share overrides an earlier revocation.
                    if let Err(error) = clear_revocation(http, root, &signature).await {
                        eprintln!(
                            "kolimi-sync: could not clear MLS revocation for {recipient}: {error}"
                        );
                    }
                }
                keys.insert(signature);
                consumed.push(package.id);
            }
        }
        self.consume_packages(http, &consumed).await?;
        self.groups_cache.remove(root);
        Ok(AddOutcome::Done)
    }

    fn current_keyring(
        &self,
        group: &Group,
        remote: &RemoteGroup,
    ) -> Result<Option<ShareKeyring>, SyncError> {
        let Some(blob) = remote.keyring.as_ref() else {
            return Ok(None);
        };
        if blob.epoch != group.epoch() {
            return Ok(None);
        }
        let exporter = group
            .export(self.device(), SHARE_KEYRING_EXPORTER, 32)
            .map_err(|error| SyncError::E2ee(format!("MLS exporter: {error}")))?;
        let exporter: [u8; 32] = exporter
            .try_into()
            .map_err(|_| SyncError::E2ee("MLS exporter length".to_string()))?;
        let keyring = decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
            .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
        Ok(Some(keyring))
    }

    async fn consume_packages(&self, http: &Http, ids: &[i64]) -> Result<(), SyncError> {
        if ids.is_empty() {
            return Ok(());
        }
        let (status, body) = http
            .post_json(
                "/api/mls/key-packages/consume",
                &serde_json::json!({ "ids": ids }),
            )
            .await?;
        if status != 204 {
            return Err(SyncError::Server {
                status,
                path: format!("/api/mls/key-packages/consume ({body})"),
            });
        }
        Ok(())
    }

    /// Re-adds devices that published a fresh key package after losing MLS
    /// state.
    ///
    /// Only groups this user already owns are touched; legacy shares without
    /// an MLS group are skipped. Best-effort by design: one broken share must
    /// not block the rest of the sync pass.
    pub(crate) async fn refresh_owned_groups(
        &mut self,
        http: &Http,
        master: &MasterKey,
        root: &str,
    ) -> Result<(), SyncError> {
        let root = root.trim_end_matches('/');
        let root = root.to_string();
        let (status, body) = http.get_json("/api/shares/owned").await?;
        if status != 200 {
            return Err(SyncError::Server {
                status,
                path: "/api/shares/owned".to_string(),
            });
        }
        let mut nodes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for share in body["shares"].as_array().cloned().unwrap_or_default() {
            let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) else {
                continue;
            };
            // A scoped sync must not mutate MLS groups outside its mirror.
            if !under_root(path, &root) {
                continue;
            }
            let mut members = Vec::new();
            match share["kind"].as_str() {
                Some("user") => {
                    if let Some(user) = share["recipient"].as_str() {
                        members.push(user.to_string());
                    }
                }
                Some("group") => {
                    if let Some(group) = share["recipient"].as_str() {
                        let path = format!("/api/groups/{}/members", encode(group));
                        if let Ok((200, body)) = http.get_json(&path).await {
                            members.extend(
                                body["members"]
                                    .as_array()
                                    .map(|list| {
                                        list.iter()
                                            .filter_map(|name| name.as_str().map(str::to_string))
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default(),
                            );
                        }
                    }
                }
                _ => continue,
            }
            let entry = nodes.entry(path.to_string()).or_default();
            entry.extend(members);
        }
        for (path, recipients) in nodes {
            if recipients.is_empty() {
                continue;
            }
            let Some((root, remote)) = (match self.group_for_path(http, &path).await {
                Ok(group) => group,
                Err(error) => {
                    eprintln!("kolimi-sync: cannot refresh MLS group for {path}: {error}");
                    continue;
                }
            }) else {
                continue;
            };
            // Only refresh a share's own root. Adding a child-share recipient
            // to an ancestor group would widen membership beyond that share.
            if root != path.trim_end_matches('/') {
                continue;
            }
            let mut group = match self.ensure_group(http, master, &path, &remote).await {
                Ok(group) => group,
                Err(error) => {
                    eprintln!("kolimi-sync: cannot re-add devices for {path}: {error}");
                    continue;
                }
            };
            let recipients: Vec<String> = recipients.into_iter().collect();
            if let Err(error) = self
                .add_recipients_to_group(
                    http,
                    master,
                    &path,
                    &root,
                    &remote,
                    &mut group,
                    &recipients,
                    true,
                )
                .await
            {
                eprintln!("kolimi-sync: cannot re-add devices for {path}: {error}");
            }
        }
        Ok(())
    }

    /// Removes every device of the given users and rotates the keyring to
    /// the new epoch.
    pub(crate) async fn remove_recipients(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        usernames: &[String],
    ) -> Result<usize, SyncError> {
        self.remove_matching(http, master, server_path, &|member: &MemberInfo| {
            usernames
                .iter()
                .any(|name| member.identity == name.as_bytes())
        })
        .await
    }

    /// Removes leaves matching `matches` from the group that exactly governs
    /// `server_path`, rotating the share keyring for each new epoch.
    ///
    /// Refuses to commit from a device that is no longer a member: after a
    /// lost/reset state there may be no remaining member able to advance the
    /// group, in which case the share must be recreated.
    async fn remove_matching(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        matches: &(impl Fn(&MemberInfo) -> bool + ?Sized),
    ) -> Result<usize, SyncError> {
        let Some((root, mut remote)) = self.group_for_path(http, server_path).await? else {
            return Ok(0);
        };
        // Never remove a child-share recipient from an ancestor group: that
        // would also revoke their access to the parent share.
        if root != server_path.trim_end_matches('/') {
            return Ok(0);
        }
        for _ in 0..3 {
            let mut group = self
                .ensure_group(http, master, server_path, &remote)
                .await?;
            if !group
                .members()
                .iter()
                .any(|member| member.signature_key == self.device.signature_key())
            {
                return Err(SyncError::E2ee(format!(
                    "this device is no longer a member of {root}; if no member can open the share, recreate it"
                )));
            }
            let removals: Vec<(u32, Vec<u8>)> = group
                .members()
                .into_iter()
                .filter(|member| matches(member))
                .map(|member| (member.index, member.signature_key))
                .collect();
            let indices: Vec<u32> = removals.iter().map(|(index, _)| *index).collect();
            if indices.is_empty() {
                return Ok(0);
            }
            let keyring = self.current_keyring(&group, &remote)?;
            let pending = group
                .remove_pending(self.device(), &indices)
                .map_err(SyncError::E2ee)?;
            self.pending_commits
                .insert(remote.group_id.clone(), pending.commit.clone());
            self.save(master)?;
            if let Err(error) = record_revocations(http, &root, &removals).await {
                // Do not post a removal whose revocation record failed: an
                // automatic re-add could otherwise undo it on the next pass.
                let _ = group.discard_pending(self.device());
                self.pending_commits.remove(&remote.group_id);
                let _ = self.save(master);
                return Err(error);
            }
            match post_commit(http, &root, pending.epoch, &pending.commit, None).await {
                Ok(()) => {
                    group
                        .merge_pending(self.device())
                        .map_err(SyncError::E2ee)?;
                    self.pending_commits.remove(&remote.group_id);
                    self.save(master)?;
                    self.groups_cache.remove(server_path);
                    self.groups_cache.remove(&root);
                    if let Some(keyring) = keyring {
                        self.publish_keyring(http, master, &root, &keyring).await?;
                    }
                    return Ok(indices.len());
                }
                Err(SyncError::Server { status: 409, .. }) => {
                    group
                        .discard_pending(self.device())
                        .map_err(SyncError::E2ee)?;
                    self.pending_commits.remove(&remote.group_id);
                    self.save(master)?;
                    self.groups_cache.remove(server_path);
                    let Some(fresh) = fetch_group(http, &root).await? else {
                        return Err(SyncError::E2ee(format!(
                            "MLS group for {root} disappeared during a concurrent commit"
                        )));
                    };
                    remote = fresh;
                }
                Err(error) => {
                    // Keep the staged commit for reconciliation; see the add
                    // path above.
                    return Err(error);
                }
            }
        }
        Err(SyncError::Protocol(
            "MLS group stayed busy after retries".to_string(),
        ))
    }

    /// Every share root that may carry an MLS group: owned shares plus
    /// received mounts. Paths are exact roots, not arbitrary descendants.
    async fn group_roots(&mut self, http: &Http) -> Result<Vec<GroupRoot>, SyncError> {
        let mut roots: BTreeMap<String, bool> = BTreeMap::new();
        let (status, body) = http.get_json("/api/shares/owned").await?;
        if status != 200 {
            return Err(SyncError::Server {
                status,
                path: "/api/shares/owned".to_string(),
            });
        }
        for share in body["shares"].as_array().cloned().unwrap_or_default() {
            if let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) {
                // The owner can always commit to their own node group.
                roots.insert(path.trim_end_matches('/').to_string(), true);
            }
        }
        let mounts = self.received_mounts(http).await?.to_vec();
        for mount in mounts {
            let path = mount.mount.trim_end_matches('/').to_string();
            let writable = mount.permission == "write";
            roots
                .entry(path)
                .and_modify(|existing| *existing |= writable)
                .or_insert(writable);
        }
        Ok(roots
            .into_iter()
            .map(|(path, writable)| GroupRoot { path, writable })
            .collect())
    }

    /// Maps each MLS signature key to the share roots where this client can
    /// see it. Groups that cannot be opened are returned as warnings rather
    /// than failing the whole listing.
    async fn signature_groups(
        &mut self,
        http: &Http,
        master: &MasterKey,
    ) -> Result<(BTreeMap<Vec<u8>, Vec<String>>, Vec<String>), SyncError> {
        let roots = self.group_roots(http).await?;
        let mut groups: BTreeMap<Vec<u8>, Vec<String>> = BTreeMap::new();
        let mut warnings = Vec::new();
        for root in roots {
            let Some(remote) = fetch_group(http, &root.path).await? else {
                continue;
            };
            let group = match self.ensure_group(http, master, &root.path, &remote).await {
                Ok(group) => group,
                Err(error) => {
                    warnings.push(format!("{}: {error}", root.path));
                    continue;
                }
            };
            for member in group.members() {
                let paths = groups.entry(member.signature_key).or_default();
                if !paths.contains(&root.path) {
                    paths.push(root.path.clone());
                }
            }
        }
        Ok((groups, warnings))
    }

    /// Lists this account's roster and annotates each device with the share
    /// roots this client can currently see it in.
    pub(crate) async fn devices(
        &mut self,
        http: &Http,
        master: &MasterKey,
    ) -> Result<MlsDeviceList, SyncError> {
        self.device_list(http, master, None).await
    }

    /// Lists another account's public roster, annotated with the groups this
    /// client can inspect. Used by a share owner removing a recipient
    /// device.
    pub(crate) async fn devices_for(
        &mut self,
        http: &Http,
        master: &MasterKey,
        username: &str,
    ) -> Result<MlsDeviceList, SyncError> {
        self.device_list(http, master, Some(username)).await
    }

    async fn device_list(
        &mut self,
        http: &Http,
        master: &MasterKey,
        username: Option<&str>,
    ) -> Result<MlsDeviceList, SyncError> {
        let own = username.is_none();
        let mut devices = fetch_device_roster(http, username).await?;
        let (groups, warnings) = self.signature_groups(http, master).await?;
        let current_id = self.device.device_id();
        let current_signature = self.device.signature_key().to_vec();
        if own && !devices.iter().any(|device| device.device_id == current_id) {
            devices.push(MlsDevice {
                device_id: current_id.clone(),
                device_name: local_device_name(),
                signature_key: Some(current_signature.clone()),
                created_at: 0,
                last_seen_at: 0,
                groups: Vec::new(),
                current: true,
            });
        }
        for device in &mut devices {
            device.current = own && device.device_id == current_id;
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

    /// Removes one device's leaves from every group this client can inspect,
    /// rotates each keyring, and only then removes the server roster row.
    ///
    /// If the device is still in a read-only share, nothing is removed: the
    /// caller cannot commit there, so the share owner must remove it first
    /// (or the share must be recreated). This keeps the roster entry until
    /// every reachable group is actually clean.
    pub(crate) async fn revoke_device(
        &mut self,
        http: &Http,
        master: &MasterKey,
        device_id: &str,
    ) -> Result<MlsRevokeReport, SyncError> {
        let devices = fetch_device_roster(http, None).await?;
        let target = devices
            .iter()
            .find(|device| device.device_id == device_id)
            .ok_or_else(|| SyncError::E2ee("unknown MLS device".to_string()))?;
        if target.device_id == self.device.device_id() {
            return Err(SyncError::E2ee(
                "refusing to revoke the current device; use --mls-reset and enroll this device again"
                    .to_string(),
            ));
        }
        let Some(signature) = target.signature_key.clone() else {
            return Err(SyncError::E2ee(format!(
                "device {} has not reported a signature key; run one sync on it with this release, then retry",
                target.device_id
            )));
        };
        let report = self
            .revoke_signature(http, master, device_id, &signature, true)
            .await?;
        let path = format!("/api/mls/devices?device_id={}", encode(device_id));
        let status = http.delete(&path).await?;
        if status != 204 {
            return Err(SyncError::Server { status, path });
        }
        Ok(MlsRevokeReport {
            roster_removed: true,
            ..report
        })
    }

    /// Removes a recipient's device from every writable group. Used by a
    /// share owner; it never deletes the recipient's roster row.
    pub(crate) async fn revoke_recipient_device(
        &mut self,
        http: &Http,
        master: &MasterKey,
        username: &str,
        device_id: &str,
    ) -> Result<MlsRevokeReport, SyncError> {
        let devices = fetch_device_roster(http, Some(username)).await?;
        let target = devices
            .iter()
            .find(|device| device.device_id == device_id)
            .ok_or_else(|| SyncError::E2ee(format!("{username} has no MLS device {device_id}")))?;
        let Some(signature) = target.signature_key.clone() else {
            return Err(SyncError::E2ee(format!(
                "device {device_id} has not reported a signature key; ask {username} to sync it once with this release"
            )));
        };
        self.revoke_signature(http, master, device_id, &signature, false)
            .await
    }

    async fn revoke_signature(
        &mut self,
        http: &Http,
        master: &MasterKey,
        device_id: &str,
        signature: &[u8],
        include_read_only: bool,
    ) -> Result<MlsRevokeReport, SyncError> {
        // Inspect every relevant group first. A single unreadable group is a
        // hard stop: we cannot prove the target has no leaf there.
        let mut affected = Vec::new();
        let mut read_only = Vec::new();
        for root in self.group_roots(http).await? {
            if !include_read_only && !root.writable {
                continue;
            }
            let Some(remote) = fetch_group(http, &root.path).await? else {
                continue;
            };
            let group = self
                .ensure_group(http, master, &root.path, &remote)
                .await
                .map_err(|error| {
                    SyncError::E2ee(format!(
                        "cannot inspect MLS group {}: {error}; if no remaining member can open it, recreate the share",
                        root.path
                    ))
                })?;
            if !group
                .members()
                .iter()
                .any(|member| member.signature_key == self.device.signature_key())
            {
                return Err(SyncError::E2ee(format!(
                    "this device is no longer a member of {}; recreate the share instead of revoking from it",
                    root.path
                )));
            }
            if group
                .members()
                .iter()
                .any(|member| member.signature_key == signature)
            {
                if root.writable {
                    affected.push(root.path);
                } else {
                    read_only.push(root.path);
                }
            }
        }
        if !read_only.is_empty() {
            return Err(SyncError::E2ee(format!(
                "device {device_id} is still a member of read-only share(s) {}; ask each owner to run --mls-revoke-device {device_id} --with <your username>, or recreate the share",
                read_only.join(", ")
            )));
        }

        let mut report = MlsRevokeReport::default();
        for root in affected {
            let removed = self
                .remove_matching(http, master, &root, &|member: &MemberInfo| {
                    member.signature_key == signature
                })
                .await?;
            if removed > 0 {
                report.groups.push(root);
                report.leaves += removed;
            }
        }
        Ok(report)
    }

    /// Publishes a full keyring for a newly-created group, merging the
    /// current entries so a re-share does not drop writer-added keys.
    pub(crate) async fn publish_keyring(
        &mut self,
        http: &Http,
        master: &MasterKey,
        server_path: &str,
        keyring: &ShareKeyring,
    ) -> Result<(), SyncError> {
        for _ in 0..4 {
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
            let (mut merged, revision) = match &remote.keyring {
                Some(blob) if blob.epoch == group.epoch() => (
                    decrypt_keyring(&exporter, &remote.group_id, group.epoch(), &blob.payload)
                        .unwrap_or_else(|_| ShareKeyring::new()),
                    blob.revision,
                ),
                _ => (ShareKeyring::new(), 0),
            };
            merged
                .entries
                .extend(keyring.entries.iter().map(|(k, v)| (k.clone(), v.clone())));
            let blob = encrypt_keyring(&exporter, &remote.group_id, group.epoch(), &merged)
                .map_err(|error| SyncError::E2ee(format!("share keyring: {error}")))?;
            let path = format!(
                "/api/mls/keyring?path={}&if_epoch={}&if_revision={revision}",
                encode(&root),
                group.epoch()
            );
            let status = http.put_bytes(&path, &blob).await?;
            if status == 204 {
                self.groups_cache.remove(&root);
                return Ok(());
            }
            if status != 409 {
                return Err(SyncError::Server { status, path });
            }
            self.groups_cache.remove(&root);
        }
        Err(SyncError::Protocol(
            "MLS keyring stayed busy after retries".to_string(),
        ))
    }
}

fn under_root(path: &str, root: &str) -> bool {
    root.is_empty() || path == root || path.starts_with(&format!("{root}/"))
}

fn relative_to_share(server_path: &str, root: &str) -> Option<String> {
    let rest = server_path.strip_prefix(root)?;
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        // A group attached directly to a shared file uses the root key.
        Some(".".to_string())
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

async fn fetch_device_roster(
    http: &Http,
    username: Option<&str>,
) -> Result<Vec<MlsDevice>, SyncError> {
    let path = match username {
        Some(username) => format!("/api/mls/devices/{}", encode(username)),
        None => "/api/mls/devices".to_string(),
    };
    let (status, body) = http.get_json(&path).await?;
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    Ok(body["devices"]
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
            created_at: device["created_at"].as_i64().unwrap_or(0),
            last_seen_at: device["last_seen_at"].as_i64().unwrap_or(0),
            groups: Vec::new(),
            current: false,
        })
        .collect())
}

struct KeyPackageEntry {
    id: i64,
    device_id: String,
    payload: Vec<u8>,
}

async fn recipient_key_packages(
    http: &Http,
    username: &str,
) -> Result<Vec<KeyPackageEntry>, SyncError> {
    let path = format!("/api/mls/key-packages/{}", encode(username));
    let (status, body) = http.get_json(&path).await?;
    if status == 404 {
        return Ok(Vec::new());
    }
    if status != 200 {
        return Err(SyncError::Server { status, path });
    }
    let mut by_device: BTreeMap<String, KeyPackageEntry> = BTreeMap::new();
    for item in body["packages"].as_array().cloned().unwrap_or_default() {
        let Some(payload) = item["payload"]
            .as_str()
            .and_then(|value| STANDARD.decode(value).ok())
        else {
            continue;
        };
        let device_id = item["device_id"].as_str().unwrap_or_default().to_string();
        // A device has one leaf/signature key per group; adding two packages
        // from the same device would be a DuplicateSignatureKey. Packages
        // for different groups are still distinct init keys.
        by_device
            .entry(device_id.clone())
            .or_insert(KeyPackageEntry {
                id: item["id"].as_i64().unwrap_or(0),
                device_id,
                payload,
            });
    }
    Ok(by_device.into_values().collect())
}

async fn record_revocations(
    http: &Http,
    server_path: &str,
    removals: &[(u32, Vec<u8>)],
) -> Result<(), SyncError> {
    for (_, signature) in removals {
        let path = format!("/api/mls/revocations?path={}", encode(server_path));
        let (status, body) = http
            .post_json(
                &path,
                &serde_json::json!({
                    "signature_key": STANDARD.encode(signature),
                }),
            )
            .await?;
        if status == 404 {
            // Older servers have no revocation table. Removal still works;
            // they simply cannot suppress automatic re-add.
            continue;
        }
        if status != 204 {
            return Err(SyncError::Server {
                status,
                path: format!("{path} ({body})"),
            });
        }
    }
    Ok(())
}

async fn clear_revocation(
    http: &Http,
    server_path: &str,
    signature: &[u8],
) -> Result<(), SyncError> {
    let encoded = STANDARD.encode(signature);
    let path = format!(
        "/api/mls/revocations?path={}&signature_key={}",
        encode(server_path),
        encode(&encoded)
    );
    let status = http.delete(&path).await?;
    if status != 204 && status != 404 {
        return Err(SyncError::Server { status, path });
    }
    Ok(())
}

async fn post_commit(
    http: &Http,
    server_path: &str,
    epoch: u64,
    commit: &[u8],
    welcome: Option<&[u8]>,
) -> Result<(), SyncError> {
    let path = format!("/api/mls/commit?path={}", encode(server_path));
    let mut body = serde_json::json!({
        "epoch": epoch,
        "commit": STANDARD.encode(commit),
    });
    if let Some(welcome) = welcome {
        body["welcome"] = serde_json::Value::String(STANDARD.encode(welcome));
    }
    let (status, body) = http.post_json(&path, &body).await?;
    if status == 404 {
        // Older servers do not have the atomic endpoint. Fall back to the
        // separate message appends so a new client can still talk to one.
        post_message(http, server_path, epoch, "commit", commit).await?;
        if let Some(welcome) = welcome {
            post_message(http, server_path, epoch, "welcome", welcome).await?;
        }
        return Ok(());
    }
    if status != 200 {
        return Err(SyncError::Server {
            status,
            path: format!("{path} ({body})"),
        });
    }
    Ok(())
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
    let mut revocations = Vec::new();
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
                    revision: keyring["revision"].as_i64().unwrap_or(0),
                })
            });
        }
        if revocations.is_empty() {
            revocations = body["revocations"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| STANDARD.decode(item["signature_key"].as_str()?).ok())
                        .collect()
                })
                .unwrap_or_default();
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
        revocations,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::under_root;

    #[test]
    fn scoped_refresh_stays_under_its_root() {
        assert!(under_root("/Documents", ""));
        assert!(under_root("/Documents", "/Documents"));
        assert!(under_root("/Documents/Team", "/Documents"));
        assert!(!under_root("/Private/Team", "/Documents"));
        assert!(!under_root("/Documents-old", "/Documents"));
    }
}
