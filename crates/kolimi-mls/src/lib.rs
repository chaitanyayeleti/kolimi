//! Kolimi MLS spike (RFC 9420).
//!
//! This crate is **not** wired into the server yet. It validates the
//! protocol pieces the group-E2EE milestone needs:
//!
//! - a device credential and key package,
//! - group creation and asynchronous add via Welcome,
//! - application messages and the epoch exporter,
//! - a stable exporter contract for the future share keyring
//!   (`"kolimi-share-keyring-v1"`).
//!
//! It lives under `spikes/` so the audited workspace does not pull
//! `openmls` and its dependency tree before the security review. See
//! `README.md` and `docs/rfc/0012-mls-groups.md`.

pub mod client;
pub mod keyring;

pub use openmls;
pub use openmls::prelude;

/// Exporter label used to derive the per-epoch share keyring key.
pub const SHARE_KEYRING_EXPORTER: &str = "kolimi-share-keyring-v1";

/// The ciphersuite the milestone should standardize on.
pub const CIPHERSUITE: prelude::Ciphersuite =
    prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// The RFC 9420 protocol version this spike targets.
pub fn protocol() -> &'static str {
    "MLS RFC 9420 (openmls 0.9)"
}
