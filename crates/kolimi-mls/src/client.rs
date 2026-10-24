//! Thin, state-in-memory client helpers around openmls.
//!
//! Persistence (OS keystore / IndexedDB) is the next integration slice;
//! this module gives the sync/desktop/web layers one place for device
//! key packages, group creation, Welcome joins and the epoch exporter.

use openmls::prelude::tls_codec::{Deserialize, Serialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::CIPHERSUITE;

/// A device credential and its local MLS provider.
pub struct Device {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
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
            provider,
            signer,
            credential,
        })
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
        self.group
            .process_message(&device.provider, protocol)
            .map_err(|error| format!("mls process message: {error:?}"))?;
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
