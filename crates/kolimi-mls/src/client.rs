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

/// A device credential and its local MLS provider.
pub struct Device {
    identity: Vec<u8>,
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
    signer: serde_json::Value,
    storage: BTreeMap<String, String>,
    groups: Vec<String>,
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
        Ok(Self {
            identity: identity.to_vec(),
            provider,
            signer,
            credential,
        })
    }

    /// Serializes the device and the listed group ids.
    ///
    /// The output contains every MLS secret; callers **must** seal it with
    /// [`kolimi_crypto::MasterKey::seal_local`] (or equivalent) before
    /// persisting it.
    pub fn export_state(&self, groups: &[Vec<u8>]) -> Result<Vec<u8>, String> {
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
            signer,
            storage,
            groups: groups.iter().map(|group| STANDARD.encode(group)).collect(),
        })
        .map_err(|error| format!("mls state encoding: {error}"))
    }

    /// Restores a device from [`Self::export_state`].
    pub fn import_state(bytes: &[u8]) -> Result<(Self, Vec<Vec<u8>>), String> {
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
        Ok((
            Self {
                identity: persisted.identity,
                provider,
                signer,
                credential,
            },
            groups,
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

    /// Adds one member from a serialized key package.
    ///
    /// Returns `(welcome, commit)`, both serialized. The caller stores the
    /// commit at the new epoch and the welcome for the new device.
    pub fn add(
        &mut self,
        device: &Device,
        key_package: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let key_package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|error| format!("mls key package decode: {error:?}"))?
            .validate(device.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|error| format!("mls key package validate: {error:?}"))?;
        let (commit, welcome, _) = self
            .group
            .add_members(&device.provider, &device.signer, &[key_package])
            .map_err(|error| format!("mls add member: {error:?}"))?;
        self.group
            .merge_pending_commit(&device.provider)
            .map_err(|error| format!("mls merge commit: {error:?}"))?;
        Ok((
            welcome
                .to_bytes()
                .map_err(|error| format!("mls welcome encoding: {error:?}"))?,
            commit
                .to_bytes()
                .map_err(|error| format!("mls commit encoding: {error:?}"))?,
        ))
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
        // A received commit is staged; merge it so the epoch advances.
        if let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() {
            self.group
                .merge_staged_commit(&device.provider, *staged)
                .map_err(|error| format!("mls merge staged commit: {error:?}"))?;
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
