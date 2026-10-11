//! UniFFI bindings for the Kolimi sync core.
//!
//! Android and iOS shells call this crate from Kotlin/Swift. The surface
//! is deliberately small: build a client from a config record, run one
//! sync pass, and set up E2EE. Platform code owns the things Rust cannot:
//! scheduling (WorkManager / BGTaskScheduler) for background upload,
//! secure credential storage, and the WebAuthn PRF ceremony whose 32-byte
//! output is passed in as `e2ee_prf_secret` (RFC 0007).

uniffi::setup_scaffolding!();

use std::sync::Arc;

use kolimi_sync::{E2eeOptions, SyncConfig, SyncReport};

/// Configuration for one sync root.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncConfig {
    /// Server base URL, e.g. `https://cloud.example.com`.
    pub server: String,
    /// Username (HTTP Basic).
    pub username: String,
    /// Password (HTTP Basic); platform code should fetch it from the
    /// OS keychain rather than hardcoding it.
    pub password: String,
    /// Absolute path of the local directory to mirror.
    pub local_dir: String,
    /// Relative paths whose files are encrypted end-to-end.
    pub encrypted_roots: Vec<String>,
    /// E2EE passphrase (one of passphrase / recovery code / PRF).
    pub e2ee_passphrase: Option<String>,
    /// E2EE recovery code.
    pub e2ee_recovery_code: Option<String>,
    /// WebAuthn PRF output (exactly 32 bytes) from the platform ceremony.
    pub e2ee_prf_secret: Option<Vec<u8>>,
}

/// What one sync pass did.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncReport {
    /// Files written locally from the server.
    pub pulled: u64,
    /// Files uploaded to the server.
    pub pushed: u64,
    /// Locally deleted files (deleted remotely).
    pub removed_local: u64,
    /// Remote files deleted because they were deleted locally.
    pub removed_remote: u64,
    /// Push conflicts (server version kept, local copy preserved).
    pub conflicts: u64,
}

impl From<SyncReport> for FfiSyncReport {
    fn from(report: SyncReport) -> Self {
        Self {
            pulled: report.pulled,
            pushed: report.pushed,
            removed_local: report.removed_local,
            removed_remote: report.removed_remote,
            conflicts: report.conflicts,
        }
    }
}

/// Errors crossing the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    /// The sync pass failed.
    #[error("sync failed: {message}")]
    Sync {
        /// Human-readable description.
        message: String,
    },
    /// The E2EE setup failed.
    #[error("e2ee setup failed: {message}")]
    E2ee {
        /// Human-readable description.
        message: String,
    },
}

/// A sync client for one root.
#[derive(uniffi::Object)]
pub struct KolimiSync {
    config: SyncConfig,
}

#[uniffi::export(async_runtime = "tokio")]
impl KolimiSync {
    /// Builds a client; no network access happens until `sync_once`.
    #[uniffi::constructor]
    pub fn new(config: FfiSyncConfig) -> Arc<Self> {
        let e2ee = if config.encrypted_roots.is_empty() {
            None
        } else {
            Some(E2eeOptions {
                passphrase: config.e2ee_passphrase,
                recovery_code: config.e2ee_recovery_code,
                prf_secret: config.e2ee_prf_secret,
                encrypted_roots: config.encrypted_roots,
            })
        };
        Arc::new(Self {
            config: SyncConfig {
                server: config.server,
                username: config.username,
                password: config.password,
                local_dir: config.local_dir.into(),
                e2ee,
            },
        })
    }

    /// Runs one full sync pass (pull, then push). Safe to call from a
    /// background worker; overlapping calls are the platform's job to
    /// prevent.
    pub async fn sync_once(&self) -> Result<FfiSyncReport, FfiError> {
        kolimi_sync::sync_once(&self.config)
            .await
            .map(FfiSyncReport::from)
            .map_err(|error| FfiError::Sync {
                message: error.to_string(),
            })
    }

    /// Creates and uploads an E2EE keyring; returns the recovery code
    /// (show it to the user once, then store it in the OS keychain).
    pub async fn e2ee_setup(&self, passphrase: String) -> Result<String, FfiError> {
        let (keyring, recovery) =
            kolimi_sync::create_keyring(&passphrase).map_err(|error| FfiError::E2ee {
                message: error.to_string(),
            })?;
        kolimi_sync::upload_keyring(&self.config, &keyring)
            .await
            .map_err(|error| FfiError::E2ee {
                message: error.to_string(),
            })?;
        // Publish the X25519 identity (unlocking with the fresh passphrase).
        let mut identity_config = self.config.clone();
        let roots = identity_config
            .e2ee
            .as_ref()
            .map(|options| options.encrypted_roots.clone())
            .unwrap_or_else(|| vec!["Private".to_string()]);
        identity_config.e2ee = Some(E2eeOptions {
            passphrase: Some(passphrase.clone()),
            recovery_code: None,
            prf_secret: None,
            encrypted_roots: roots,
        });
        kolimi_sync::publish_identity(&identity_config)
            .await
            .map_err(|error| FfiError::E2ee {
                message: error.to_string(),
            })?;
        Ok(kolimi_crypto::recovery_code_display(&recovery))
    }
}
