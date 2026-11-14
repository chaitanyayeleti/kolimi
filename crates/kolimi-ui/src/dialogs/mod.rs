//! Modal dialogs and Settings sections.

mod account;
mod admin;
mod enrollment;
mod passkeys;
mod settings;
mod share;
mod vault;
mod versions;

pub(crate) use admin::AdminPage;
pub(crate) use settings::{SettingsDialog, SettingsTab};
pub(crate) use share::ShareDialog;
pub(crate) use vault::VaultSetupDialog;
pub(crate) use versions::VersionsDialog;
