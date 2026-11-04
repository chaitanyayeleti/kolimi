//! Shared MLS data shapes and pure helpers.

use base64::{Engine, engine::general_purpose::STANDARD};
use kolimi_mls::client::Device;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct Mount {
    pub(super) mount: String,
    pub(super) permission: String,
    pub(super) encrypted: bool,
    #[serde(default)]
    pub(super) wrapped_name: Option<String>,
}

pub(super) struct State {
    pub(super) device: Device,
    pub(super) groups: Vec<Vec<u8>>,
    pub(super) pending_commits: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// One MLS device in this account's server roster.
#[derive(Debug, Clone)]
pub struct MlsDevice {
    pub device_id: String,
    pub device_name: String,
    pub signature_key: Option<Vec<u8>>,
    pub last_seen_at: i64,
    /// Share roots where this browser can currently see the device's leaf.
    pub groups: Vec<String>,
    pub current: bool,
}

/// Roster listing plus groups this browser could not inspect.
#[derive(Debug, Clone, Default)]
pub struct MlsDeviceList {
    pub devices: Vec<MlsDevice>,
    pub warnings: Vec<String>,
}

/// Result of revoking one MLS device from the browser.
#[derive(Debug, Clone, Default)]
pub struct MlsRevokeReport {
    pub groups: Vec<String>,
    pub leaves: usize,
}

pub(super) fn parse_device_roster(body: &serde_json::Value) -> Vec<MlsDevice> {
    body["devices"]
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
            last_seen_at: device["last_seen_at"].as_i64().unwrap_or(0),
            groups: Vec::new(),
            current: false,
        })
        .collect()
}

pub(super) fn mount_for<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mounts
        .iter()
        .filter(|mount| {
            path == mount.mount
                || path
                    .strip_prefix(&mount.mount)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|mount| mount.mount.len())
}

#[derive(Debug, Clone)]
pub(super) struct GroupMessage {
    pub(super) seq: i64,
    pub(super) epoch: u64,
    pub(super) kind: String,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct KeyringBlob {
    pub(super) epoch: u64,
    pub(super) payload: Vec<u8>,
    pub(super) revision: i64,
}

#[derive(Debug, Clone)]
pub(super) struct RemoteGroup {
    pub(super) group_id: Vec<u8>,
    pub(super) epoch: u64,
    pub(super) messages: Vec<GroupMessage>,
    pub(super) keyring: Option<KeyringBlob>,
    /// Client-asserted revoked signatures; automatic re-add skips these.
    pub(super) revocations: Vec<Vec<u8>>,
}

pub(super) fn share_key_for<'a>(mounts: &'a [Mount], path: &str) -> Option<&'a Mount> {
    mount_for(mounts, path).filter(|mount| mount.permission == "write" && mount.encrypted)
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn parse_device_roster_decodes_reported_fields() {
        let body = serde_json::json!({
            "devices": [{
                "device_id": "device-1",
                "device_name": "Laptop",
                "signature_key": "AQID",
                "last_seen_at": 42,
            }]
        });
        let devices = parse_device_roster(&body);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "device-1");
        assert_eq!(devices[0].device_name, "Laptop");
        assert_eq!(devices[0].signature_key.as_deref(), Some(&[1, 2, 3][..]));
        assert_eq!(devices[0].last_seen_at, 42);
        assert!(devices[0].groups.is_empty());
        assert!(!devices[0].current);
    }

    #[wasm_bindgen_test]
    fn parse_device_roster_tolerates_missing_fields() {
        let devices = parse_device_roster(&serde_json::json!({ "devices": [{}] }));
        assert_eq!(devices.len(), 1);
        assert!(devices[0].device_id.is_empty());
        assert!(devices[0].signature_key.is_none());
        assert_eq!(devices[0].last_seen_at, 0);
    }

    fn mount(path: &str, permission: &str, encrypted: bool) -> Mount {
        Mount {
            mount: path.to_string(),
            permission: permission.to_string(),
            encrypted,
            wrapped_name: None,
        }
    }

    #[wasm_bindgen_test]
    fn mount_for_prefers_the_longest_prefix() {
        let mounts = vec![
            mount("/team", "read", true),
            mount("/team/docs", "write", true),
        ];
        assert_eq!(
            mount_for(&mounts, "/team/docs/report.txt").map(|m| m.mount.as_str()),
            Some("/team/docs")
        );
        assert_eq!(
            mount_for(&mounts, "/team/other.txt").map(|m| m.mount.as_str()),
            Some("/team")
        );
        assert!(mount_for(&mounts, "/other").is_none());
    }

    #[wasm_bindgen_test]
    fn writable_share_requires_write_and_encryption() {
        let mounts = vec![
            mount("/read", "read", true),
            mount("/plain", "write", false),
            mount("/write", "write", true),
        ];
        assert!(share_key_for(&mounts, "/read/file").is_none());
        assert!(share_key_for(&mounts, "/plain/file").is_none());
        assert_eq!(
            share_key_for(&mounts, "/write/file").map(|m| m.mount.as_str()),
            Some("/write")
        );
    }
}
