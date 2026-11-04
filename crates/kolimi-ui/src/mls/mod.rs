//! Browser MLS state for group E2EE (RFC 9420).
//!
//! MLS device/group secrets are sealed with the unlocked master key and
//! stored in IndexedDB; the server only ever sees opaque key packages,
//! commits/Welcomes and the epoch-bound share keyring.
//!
//! The implementation is split by concern: `types` holds the data shapes,
//! `state` owns the sealed local device/group state, `api` wraps the MLS
//! HTTP endpoints, and `protocol` drives group membership and keyrings.

mod api;
mod protocol;
mod state;
mod types;

pub use protocol::{
    decrypt_shared_or_legacy, devices, encode_shared_name, is_writable_shared, migrate_shares,
    owned_file_key, publish_key_package, record_owned_file_key, refresh_owned_groups,
    remove_path_prefix, remove_recipients, rename_path_prefix, revoke_device, share_folder,
    upload_shared,
};
pub use state::{enabled, reset_state};
pub use types::MlsDevice;
