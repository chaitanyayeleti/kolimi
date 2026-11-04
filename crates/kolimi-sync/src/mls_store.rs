//! Persisted MLS device/group state for the sync/desktop client.
//!
//! The openmls key-value storage contains every group secret, so it is
//! sealed with the user's master key before it touches disk. The file is
//! written `0600` via a temporary file + rename.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kolimi_crypto::MasterKey;
use kolimi_mls::client::Device;

use crate::SyncError;

const STATE_FILE: &str = "mls-state.bin";
const STATE_AAD: &[u8] = b"kolimi-mls-state-v1";

/// A restored MLS device, the group ids it manages, and any serialized
/// commits that were posted but not yet merged locally.
pub type MlsState = (Device, Vec<Vec<u8>>, BTreeMap<Vec<u8>, Vec<u8>>);

/// The on-disk MLS state for one sync pair.
pub struct MlsStore {
    path: PathBuf,
}

impl MlsStore {
    /// Creates a store under `<local_dir>/.kolimi/`.
    pub fn new(local_dir: &Path) -> Self {
        Self {
            path: local_dir.join(".kolimi").join(STATE_FILE),
        }
    }

    /// Loads and decrypts the device plus its group ids.
    pub fn load(&self, master: &MasterKey) -> Result<Option<MlsState>, SyncError> {
        let blob = match std::fs::read(&self.path) {
            Ok(blob) => blob,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let plaintext = master
            .open_local(&blob, STATE_AAD)
            .map_err(|_| SyncError::E2ee("could not decrypt MLS state".to_string()))?;
        let (device, groups, pending) = Device::import_state(&plaintext)
            .map_err(|error| SyncError::E2ee(format!("could not load MLS state: {error}")))?;
        Ok(Some((device, groups, pending)))
    }

    /// Deletes the sealed state and any interrupted-write temp file.
    ///
    /// The next sync creates a new MLS device and publishes a fresh key
    /// package. Existing group members must re-add that device (re-share the
    /// folder) before it can read the share again. Returns `true` when a
    /// state file existed.
    pub fn reset(&self) -> Result<bool, SyncError> {
        let mut removed = false;
        for path in [&self.path, &self.path.with_extension("bin.tmp")] {
            match std::fs::remove_file(path) {
                Ok(()) => removed = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(removed)
    }

    /// Seals and writes the device state (and the group ids it manages).
    pub fn save(
        &self,
        master: &MasterKey,
        device: &Device,
        groups: &[Vec<u8>],
        pending: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), SyncError> {
        let plaintext = device
            .export_state(groups, pending)
            .map_err(SyncError::E2ee)?;
        let blob = master.seal_local(&plaintext, STATE_AAD)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use kolimi_mls::SHARE_KEYRING_EXPORTER;
    use kolimi_mls::client::Group;

    use super::*;

    #[test]
    fn sealed_state_survives_disk_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let master = MasterKey::generate().unwrap();
        let device = Device::new(b"alice@laptop").unwrap();
        let group_id = [5u8; 32];
        let group = Group::create(&device, &group_id).unwrap();
        let secret = group.export(&device, SHARE_KEYRING_EXPORTER, 32).unwrap();

        let store = MlsStore::new(dir.path());
        store
            .save(
                &master,
                &device,
                &[group_id.to_vec()],
                &BTreeMap::from([(group_id.to_vec(), b"pending".to_vec())]),
            )
            .unwrap();
        let (loaded, groups, pending) = store.load(&master).unwrap().expect("state saved");
        assert_eq!(groups, vec![group_id.to_vec()]);
        assert_eq!(
            pending.get(group_id.as_slice()).map(Vec::as_slice),
            Some(b"pending".as_slice())
        );
        let reloaded = Group::load(&loaded, &groups[0]).unwrap();
        assert_eq!(
            reloaded
                .export(&loaded, SHARE_KEYRING_EXPORTER, 32)
                .unwrap(),
            secret
        );

        // A different master key must not decrypt the file.
        let other = MasterKey::generate().unwrap();
        assert!(store.load(&other).is_err());
    }

    #[test]
    fn reset_removes_state_and_reports_whether_it_existed() {
        let dir = tempfile::tempdir().unwrap();
        let master = MasterKey::generate().unwrap();
        let device = Device::new(b"alice@laptop").unwrap();
        let store = MlsStore::new(dir.path());
        store.save(&master, &device, &[], &BTreeMap::new()).unwrap();
        assert!(store.load(&master).unwrap().is_some());

        assert!(store.reset().unwrap());
        assert!(store.load(&master).unwrap().is_none());
        assert!(!store.reset().unwrap());
    }
}
