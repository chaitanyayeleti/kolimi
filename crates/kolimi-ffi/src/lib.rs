//! UniFFI bindings for the Kolimi sync core.
//!
//! Android and iOS shells call this crate from Kotlin/Swift. The surface
//! is deliberately small: build a client from a config record, run one
//! sync pass, and set up E2EE. Platform code owns the things Rust cannot:
//! scheduling (WorkManager / BGTaskScheduler) for background upload,
//! secure credential storage, and the WebAuthn PRF ceremony whose 32-byte
//! output is passed in as `e2ee_prf_secret` (RFC 0007).

uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex};

use kolimi_sync::{E2eeOptions, SyncConfig, SyncReport};

/// Configuration for one sync root.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSyncConfig {
    /// Server base URL, e.g. `https://cloud.example.com`.
    pub server: String,
    /// Username (HTTP Basic).
    pub username: String,
    /// Password (HTTP Basic); platform code should fetch it from the
    /// OS keychain rather than hardcoding it. Ignored when `token` is set.
    pub password: String,
    /// Bearer session/API token. When set, requests authenticate with it
    /// instead of `password` — the mobile flow logs in once (password + TOTP)
    /// and syncs with the token, without retaining the password.
    pub token: Option<String>,
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

/// A device enrollment (RFC 0008), shown for comparison.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiEnrollment {
    /// Server-side enrollment id.
    pub id: i64,
    /// Device label.
    pub name: String,
    /// Short code both devices must show. It commits to the device's public
    /// key, so a substituted key yields a different code.
    pub code: String,
    /// Fingerprint of the device's public key.
    pub fingerprint: String,
}

impl From<&kolimi_sync::Enrollment> for FfiEnrollment {
    fn from(enrollment: &kolimi_sync::Enrollment) -> Self {
        Self {
            id: enrollment.id,
            name: enrollment.name.clone(),
            code: enrollment.code.clone(),
            fingerprint: enrollment.fingerprint.clone(),
        }
    }
}

/// Maps a core E2EE/sync failure across the FFI boundary.
fn e2ee_error(error: kolimi_sync::SyncError) -> FfiError {
    FfiError::E2ee {
        message: error.to_string(),
    }
}

/// The enrollment-state mutex was poisoned by a panic.
fn lock_poisoned() -> FfiError {
    FfiError::E2ee {
        message: "enrollment state lock poisoned".to_string(),
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
    /// E2EE needs unlocking (passphrase, recovery code, or an enrolled
    /// device) before this sync can run.
    #[error("locked: {message}")]
    Locked {
        /// Human-readable description.
        message: String,
    },
}

/// A sync client for one root.
#[derive(uniffi::Object)]
pub struct KolimiSync {
    config: SyncConfig,
    /// A device enrollment started by `start_enrollment`, awaiting approval.
    pending: Mutex<Option<kolimi_sync::PendingDevice>>,
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
                token: config.token,
                local_dir: config.local_dir.into(),
                e2ee,
            },
            pending: Mutex::new(None),
        })
    }

    /// Runs one full sync pass (pull, then push). Safe to call from a
    /// background worker; overlapping calls are the platform's job to
    /// prevent.
    pub async fn sync_once(&self) -> Result<FfiSyncReport, FfiError> {
        kolimi_sync::sync_once(&self.config)
            .await
            .map(FfiSyncReport::from)
            .map_err(|error| match error {
                // A locked keyring is a first-class state, not a failure
                // (RFC 0011): the shell prompts for unlock instead of erroring.
                kolimi_sync::SyncError::Locked(message) => FfiError::Locked { message },
                other => FfiError::Sync {
                    message: other.to_string(),
                },
            })
    }

    /// Starts a device enrollment (RFC 0008): creates it and returns the code
    /// to compare on an already-unlocked device. Call `finish_enrollment` to
    /// wait for approval and persist the device key.
    pub async fn start_enrollment(&self, device_name: String) -> Result<FfiEnrollment, FfiError> {
        let pending = kolimi_sync::start_enrollment(&self.config, &device_name)
            .await
            .map_err(e2ee_error)?;
        let details = FfiEnrollment::from(&pending.details);
        *self.pending.lock().map_err(|_| lock_poisoned())? = Some(pending);
        Ok(details)
    }

    /// Waits for the in-progress enrollment to be approved and persists the
    /// device key. Returns the enrollment id.
    pub async fn finish_enrollment(&self) -> Result<i64, FfiError> {
        let pending = {
            let mut guard = self.pending.lock().map_err(|_| lock_poisoned())?;
            guard.take()
        }
        .ok_or_else(|| FfiError::E2ee {
            message: "no enrollment in progress".to_string(),
        })?;
        kolimi_sync::finish_enrollment(&self.config, &pending)
            .await
            .map_err(e2ee_error)
    }

    /// Fetches a pending enrollment's details (name, fingerprint, code) so an
    /// approving device can show them before approving.
    pub async fn pending_enrollment(&self, id: i64) -> Result<FfiEnrollment, FfiError> {
        kolimi_sync::pending_enrollment(&self.config, id)
            .await
            .map(|details| FfiEnrollment::from(&details))
            .map_err(e2ee_error)
    }

    /// Approves a pending enrollment. `code` must be the code shown on the new
    /// device; a mismatch (e.g. a substituted key) refuses the approval.
    pub async fn approve_device(&self, id: i64, code: String) -> Result<String, FfiError> {
        kolimi_sync::approve_device(&self.config, id, &code)
            .await
            .map_err(e2ee_error)
    }

    /// Forgets this device's local key material (the OS-keystore entry and
    /// the device file). Returns whether anything was removed.
    pub fn forget_device(&self) -> Result<bool, FfiError> {
        kolimi_sync::forget_device(&self.config.local_dir).map_err(|error| FfiError::E2ee {
            message: error.to_string(),
        })
    }

    /// Creates and uploads an E2EE keyring; returns the recovery code
    /// (show it to the user once, then store it in the OS keychain).
    pub async fn e2ee_setup(&self, passphrase: String) -> Result<String, FfiError> {
        if passphrase.is_empty() {
            return Err(FfiError::E2ee {
                message: "passphrase must not be empty".to_string(),
            });
        }
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
