//! Thin, state-in-memory client helpers around openmls.
//!
//! Persistence (OS keystore / IndexedDB) is the next integration slice;
//! this module gives the sync/desktop/web layers one place for device
//! key packages, group creation, Welcome joins and the epoch exporter.

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

use crate::CIPHERSUITE;

/// Restored device, group ids and unmerged commits.
pub type RestoredState = (Device, Vec<Vec<u8>>, BTreeMap<Vec<u8>, Vec<u8>>);

/// A device credential and its local MLS provider.
pub struct Device {
    identity: Vec<u8>,
    device_id: [u8; 16],
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

/// Serialized device state: signer, identity and the openmls key-value
/// storage (including all group secrets). Encrypt this with the UMK before
/// writing it to disk/IndexedDB.
#[derive(SerdeSerialize, SerdeDeserialize)]
struct PersistedDevice {
    v: u8,
    identity: Vec<u8>,
    device_id: String,
    signer: serde_json::Value,
    storage: BTreeMap<String, String>,
    groups: Vec<String>,
    /// Serialized, unmerged commits keyed by group id. Kept so a client can
    /// verify a server echo byte-for-byte after a crash or lost response.
    #[serde(default)]
    pending_commits: BTreeMap<String, String>,
}

impl Device {
    /// Creates a fresh credential/signature key pair for a device.
    pub fn new(identity: &[u8]) -> Result<Self, String> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity.to_vec());
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|error| format!("mls signature key: {error:?}"))?;
        signer
            .store(provider.storage())
            .map_err(|error| format!("mls key store: {error:?}"))?;
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        let mut device_id = [0u8; 16];
        getrandom::getrandom(&mut device_id).map_err(|error| format!("mls device id: {error}"))?;
        Ok(Self {
            identity: identity.to_vec(),
            device_id,
            provider,
            signer,
            credential,
        })
    }

    /// The credential identity this device was created with.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The stable id this device publishes its key packages under.
    pub fn device_id(&self) -> String {
        STANDARD.encode(self.device_id)
    }

    /// This device's public MLS signature key (the same key that appears on
    /// its group leaf). Public material; used to map a roster device to the
    /// leaves a revoke commit must remove.
    pub fn signature_key(&self) -> &[u8] {
        self.credential.signature_key.as_slice()
    }

    /// Reads a serialized key package's leaf signature key. Used to avoid
    /// adding the same device twice to one group.
    pub fn key_package_signature_key(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let package = KeyPackageIn::tls_deserialize_exact(bytes)
            .map_err(|error| format!("mls key package decode: {error:?}"))?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| format!("mls key package validate: {error:?}"))?;
        Ok(package.leaf_node().signature_key().as_slice().to_vec())
    }

    /// Serializes the device and the listed group ids.
    ///
    /// The output contains every MLS secret; callers **must** seal it with
    /// [`kolimi_crypto::MasterKey::seal_local`] (or equivalent) before
    /// persisting it.
    pub fn export_state(
        &self,
        groups: &[Vec<u8>],
        pending_commits: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        let storage = self.provider.storage();
        let values = storage
            .values
            .read()
            .map_err(|_| "mls storage lock".to_string())?;
        let storage: BTreeMap<String, String> = values
            .iter()
            .map(|(key, value)| (STANDARD.encode(key), STANDARD.encode(value)))
            .collect();
        let signer = serde_json::to_value(&self.signer)
            .map_err(|error| format!("mls signer encoding: {error}"))?;
        serde_json::to_vec(&PersistedDevice {
            v: 1,
            identity: self.identity.clone(),
            device_id: self.device_id(),
            signer,
            storage,
            groups: groups.iter().map(|group| STANDARD.encode(group)).collect(),
            pending_commits: pending_commits
                .iter()
                .map(|(group, commit)| (STANDARD.encode(group), STANDARD.encode(commit)))
                .collect(),
        })
        .map_err(|error| format!("mls state encoding: {error}"))
    }

    /// Restores a device from [`Self::export_state`].
    pub fn import_state(bytes: &[u8]) -> Result<RestoredState, String> {
        let persisted: PersistedDevice =
            serde_json::from_slice(bytes).map_err(|error| format!("mls state decode: {error}"))?;
        if persisted.v != 1 {
            return Err("unsupported MLS state version".to_string());
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| "mls storage lock".to_string())?;
            for (key, value) in persisted.storage {
                let key = STANDARD
                    .decode(key)
                    .map_err(|_| "bad MLS storage key".to_string())?;
                let value = STANDARD
                    .decode(value)
                    .map_err(|_| "bad MLS storage value".to_string())?;
                values.insert(key, value);
            }
        }
        let device_id: [u8; 16] = STANDARD
            .decode(&persisted.device_id)
            .map_err(|_| "bad MLS device id".to_string())?
            .try_into()
            .map_err(|_| "bad MLS device id length".to_string())?;
        let signer: SignatureKeyPair = serde_json::from_value(persisted.signer)
            .map_err(|error| format!("mls signer decode: {error}"))?;
        signer
            .store(provider.storage())
            .map_err(|error| format!("mls signer store: {error:?}"))?;
        let credential = BasicCredential::new(persisted.identity.clone());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        let groups = persisted
            .groups
            .into_iter()
            .map(|group| {
                STANDARD
                    .decode(group)
                    .map_err(|_| "bad MLS group id".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pending_commits = persisted
            .pending_commits
            .into_iter()
            .map(|(group, commit)| {
                let group = STANDARD
                    .decode(group)
                    .map_err(|_| "bad MLS pending group id".to_string())?;
                let commit = STANDARD
                    .decode(commit)
                    .map_err(|_| "bad MLS pending commit".to_string())?;
                Ok((group, commit))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        Ok((
            Self {
                identity: persisted.identity,
                device_id,
                provider,
                signer,
                credential,
            },
            groups,
            pending_commits,
        ))
    }

    /// The serialized public key package to publish/upload.
    pub fn key_package(&self) -> Result<Vec<u8>, String> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|error| format!("mls key package: {error:?}"))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| format!("mls key package encoding: {error:?}"))
    }
}

/// One member of a group.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    /// Leaf index in the ratchet tree.
    pub index: u32,
    /// Credential identity (the account username in Kolimi's clients).
    pub identity: Vec<u8>,
    /// Public signature key, unique per device within a group.
    pub signature_key: Vec<u8>,
}

/// A commit staged locally but not merged yet.
///
/// Post it to the server first, then call [`Group::merge_pending`] only after
/// the server accepts it. If another committer wins the epoch, call
/// [`Group::discard_pending`] and process the winning commit.
#[derive(Debug, Clone)]
pub struct PendingCommit {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub epoch: u64,
}

/// An in-memory MLS group.
pub struct Group {
    group: MlsGroup,
}

impl Group {
    /// Creates a group. `group_id` is the random id shared with the server.
    pub fn create(device: &Device, group_id: &[u8]) -> Result<Self, String> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &device.provider,
            &device.signer,
            &config,
            GroupId::from_slice(group_id),
            device.credential.clone(),
        )
        .map_err(|error| format!("mls group create: {error:?}"))?;
        Ok(Self { group })
    }

    /// Loads a group from the device's persisted storage.
    pub fn load(device: &Device, group_id: &[u8]) -> Result<Self, String> {
        let group = MlsGroup::load(device.provider.storage(), &GroupId::from_slice(group_id))
            .map_err(|error| format!("mls group load: {error:?}"))?
            .ok_or_else(|| "MLS group not found in local state".to_string())?;
        Ok(Self { group })
    }

    /// Adds one member from a serialized key package, leaving the commit
    /// pending until the caller confirms the server accepted it.
    pub fn add_pending(
        &mut self,
        device: &Device,
        key_package: &[u8],
    ) -> Result<PendingCommit, String> {
        let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|error| format!("mls key package decode: {error:?}"))?
            .validate(device.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| format!("mls key package validate: {error:?}"))?;
        let (commit, welcome, _) = self
            .group
            .add_members(&device.provider, &device.signer, &[key_package])
            .map_err(|error| format!("mls add member: {error:?}"))?;
        let epoch = self
            .pending_epoch()
            .ok_or_else(|| "mls add did not stage a commit".to_string())?;
        Ok(PendingCommit {
            commit: commit
                .to_bytes()
                .map_err(|error| format!("mls commit encoding: {error:?}"))?,
            welcome: Some(
                welcome
                    .to_bytes()
                    .map_err(|error| format!("mls welcome encoding: {error:?}"))?,
            ),
            epoch,
        })
    }

    /// Adds one member and immediately merges the commit locally.
    ///
    /// Prefer [`Self::add_pending`] when the commit must be accepted by a
    /// server first; this convenience method is for local callers/tests.
    pub fn add(
        &mut self,
        device: &Device,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let pending = self.add_pending(device, key_package)?;
        self.merge_pending(device)?;
        let welcome = pending
            .welcome
            .ok_or_else(|| "mls add did not produce a Welcome".to_string())?;
        Ok((welcome, pending.commit))
    }

    /// Merges the locally staged commit after the server accepted it.
    pub fn merge_pending(&mut self, device: &Device) -> Result<(), String> {
        self.group
            .merge_pending_commit(&device.provider)
            .map_err(|error| format!("mls merge commit: {error:?}"))
    }

    /// Drops a locally staged commit that the server rejected.
    pub fn discard_pending(&mut self, device: &Device) -> Result<(), String> {
        self.group
            .clear_pending_commit(device.provider.storage())
            .map_err(|error| format!("mls clear pending commit: {error:?}"))
    }

    /// The epoch of the staged commit, if one is pending.
    pub fn pending_epoch(&self) -> Option<u64> {
        self.group
            .pending_commit()
            .map(|commit| commit.epoch().as_u64())
    }

    /// Whether this group has an unmerged commit.
    pub fn has_pending_commit(&self) -> bool {
        self.group.pending_commit().is_some()
    }

    /// Joins from a serialized Welcome (ratchet tree is in the extension).
    pub fn join(device: &Device, welcome: &[u8]) -> Result<Self, String> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome)
            .map_err(|error| format!("mls welcome decode: {error:?}"))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err("expected an MLS Welcome message".to_string()),
        };
        let config = MlsGroupJoinConfig::builder().build();
        let group = StagedWelcome::new_from_welcome(&device.provider, &config, welcome, None)
            .map_err(|error| format!("mls welcome stage: {error:?}"))?
            .into_group(&device.provider)
            .map_err(|error| format!("mls group join: {error:?}"))?;
        Ok(Self { group })
    }

    /// The group's current members, with the credential identity and leaf
    /// index used for removals.
    pub fn members(&self) -> Vec<MemberInfo> {
        self.group
            .members()
            .map(|member| MemberInfo {
                index: member.index.u32(),
                identity: member.credential.serialized_content().to_vec(),
                signature_key: member.signature_key.clone(),
            })
            .collect()
    }

    /// Removes members by leaf index, leaving the commit pending until the
    /// caller confirms the server accepted it.
    pub fn remove_pending(
        &mut self,
        device: &Device,
        indices: &[u32],
    ) -> Result<PendingCommit, String> {
        let leaves: Vec<LeafNodeIndex> = indices
            .iter()
            .map(|index| LeafNodeIndex::new(*index))
            .collect();
        let (commit, _welcome, _group_info) = self
            .group
            .remove_members(&device.provider, &device.signer, &leaves)
            .map_err(|error| format!("mls remove member: {error:?}"))?;
        let epoch = self
            .pending_epoch()
            .ok_or_else(|| "mls remove did not stage a commit".to_string())?;
        Ok(PendingCommit {
            commit: commit
                .to_bytes()
                .map_err(|error| format!("mls commit encoding: {error:?}"))?,
            welcome: None,
            epoch,
        })
    }

    /// Removes members and immediately merges the commit locally.
    ///
    /// Prefer [`Self::remove_pending`] when the commit must be accepted by a
    /// server first.
    pub fn remove(&mut self, device: &Device, indices: &[u32]) -> Result<Vec<u8>, String> {
        let pending = self.remove_pending(device, indices)?;
        self.merge_pending(device)?;
        Ok(pending.commit)
    }

    /// Processes a commit/proposal/application message from another member.
    pub fn process(&mut self, device: &Device, message: &[u8]) -> Result<(), String> {
        let message = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|error| format!("mls message decode: {error:?}"))?;
        let protocol = message
            .try_into_protocol_message()
            .map_err(|error| format!("mls protocol message: {error:?}"))?;
        let processed = self
            .group
            .process_message(&device.provider, protocol)
            .map_err(|error| format!("mls process message: {error:?}"))?;
        match processed.into_content() {
            // A received commit is staged; merge it so the epoch advances.
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&device.provider, *staged)
                    .map_err(|error| format!("mls merge staged commit: {error:?}"))?;
            }
            // The server echoed our own pending commit. Merging it recovers
            // the case where the commit was accepted but the client crashed
            // or lost the response before merging locally.
            ProcessedMessageContent::OwnPendingCommit => {
                self.group
                    .merge_pending_commit(&device.provider)
                    .map_err(|error| format!("mls merge pending commit: {error:?}"))?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Processes a message that the caller knows is a commit.
    ///
    /// Unlike [`Self::process`], this handles an own Commit framed as a
    /// PrivateMessage (openmls returns `OwnPrivateMessage`) by merging the
    /// locally staged pending commit **only when the received bytes exactly
    /// match** `expected_pending`. Private-message framing is unauthenticated,
    /// so the caller must pass the persisted commit it previously posted.
    /// That is the recovery path after a lost HTTP response or a crash after
    /// server acceptance.
    pub fn process_commit(
        &mut self,
        device: &Device,
        message: &[u8],
        expected_pending: Option<&[u8]>,
    ) -> Result<(), String> {
        let parsed = MlsMessageIn::tls_deserialize_exact(message)
            .map_err(|error| format!("mls message decode: {error:?}"))?;
        let protocol = parsed
            .try_into_protocol_message()
            .map_err(|error| format!("mls protocol message: {error:?}"))?;
        if protocol.content_type() != ContentType::Commit {
            return Err("expected an MLS commit".to_string());
        }
        let processed = self
            .group
            .process_message(&device.provider, protocol)
            .map_err(|error| format!("mls process message: {error:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.group
                    .merge_staged_commit(&device.provider, *staged)
                    .map_err(|error| format!("mls merge staged commit: {error:?}"))?;
            }
            ProcessedMessageContent::OwnPendingCommit => {
                self.group
                    .merge_pending_commit(&device.provider)
                    .map_err(|error| format!("mls merge pending commit: {error:?}"))?;
            }
            ProcessedMessageContent::OwnPrivateMessage => {
                // Private-message framing is unauthenticated: openmls says
                // this is only a sender-data hint and cannot be decrypted or
                // signature-checked. Merge only when the exact bytes match
                // the pending commit this client persisted before posting.
                let matches = expected_pending.is_some_and(|expected| expected == message);
                if !matches || self.group.pending_commit().is_none() {
                    return Err("own private commit does not match the staged commit".to_string());
                }
                self.group
                    .merge_pending_commit(&device.provider)
                    .map_err(|error| format!("mls merge pending commit: {error:?}"))?;
            }
            _ => {}
        }
        Ok(())
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Exports a secret (e.g. the share-keyring key) for this epoch.
    pub fn export(&self, device: &Device, label: &str, len: usize) -> Result<Vec<u8>, String> {
        self.group
            .export_secret(device.provider.crypto(), label, b"kolimi", len)
            .map_err(|error| format!("mls export: {error:?}"))
    }
}
