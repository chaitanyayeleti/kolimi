//! HTTP wrappers for the MLS endpoints.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::collections::BTreeSet;

use super::types::{GroupMessage, KeyringBlob, Mount, RemoteGroup};
use crate::api;
use crate::app::encode;

pub(super) async fn mounts() -> Result<Vec<Mount>, String> {
    let response = api::get("/api/shares/received").await?;
    if response.status != 200 {
        return Ok(Vec::new());
    }
    Ok(response.body["mounts"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| serde_json::from_value(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default())
}

/// Every root that may carry an MLS group: owned shares and received mounts.
pub(super) async fn group_roots() -> Result<Vec<String>, String> {
    let mut roots = BTreeSet::new();
    let response = api::get("/api/shares/owned").await?;
    if response.status != 200 {
        return Err("could not list owned shares".to_string());
    }
    for share in response.body["shares"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        if let Some(path) = share["path"].as_str().filter(|path| !path.is_empty()) {
            roots.insert(path.trim_end_matches('/').to_string());
        }
    }
    for mount in mounts().await? {
        roots.insert(mount.mount.trim_end_matches('/').to_string());
    }
    Ok(roots.into_iter().collect())
}

pub(super) async fn fetch_group(path: &str) -> Result<Option<RemoteGroup>, String> {
    let mut after = 0i64;
    let mut messages = Vec::new();
    let mut group_id: Option<Vec<u8>> = None;
    let mut epoch;
    let mut keyring = None;
    let mut revocations = Vec::new();
    loop {
        let response = api::get(&format!(
            "/api/mls/group?path={}&after={after}&limit=1000",
            encode(path)
        ))
        .await?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status != 200 {
            return Err(response
                .error()
                .unwrap_or("could not load the MLS group")
                .to_string());
        }
        if group_id.is_none() {
            group_id = Some(
                STANDARD
                    .decode(response.body["group_id"].as_str().unwrap_or_default())
                    .map_err(|_| "malformed MLS group id".to_string())?,
            );
        }
        epoch = response.body["epoch"].as_u64().unwrap_or(0);
        if keyring.is_none() {
            keyring = response.body["keyring"].as_object().and_then(|keyring| {
                Some(KeyringBlob {
                    epoch: keyring["epoch"].as_u64()?,
                    payload: STANDARD.decode(keyring["payload"].as_str()?).ok()?,
                    revision: keyring["revision"].as_i64().unwrap_or(0),
                })
            });
        }
        if revocations.is_empty() {
            revocations = response.body["revocations"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| STANDARD.decode(item["signature_key"].as_str()?).ok())
                        .collect()
                })
                .unwrap_or_default();
        }
        let page = response.body["messages"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut advanced = false;
        for message in page {
            let seq = message["seq"].as_i64().unwrap_or(0);
            if seq > after {
                after = seq;
                advanced = true;
            }
            messages.push(GroupMessage {
                seq,
                epoch: message["epoch"].as_u64().unwrap_or(0),
                kind: message["kind"].as_str().unwrap_or_default().to_string(),
                payload: STANDARD
                    .decode(message["payload"].as_str().unwrap_or_default())
                    .unwrap_or_default(),
            });
        }
        if !advanced || after == 0 {
            break;
        }
    }
    messages.sort_by_key(|message| message.seq);
    Ok(Some(RemoteGroup {
        group_id: group_id.ok_or_else(|| "MLS group id missing".to_string())?,
        epoch,
        messages,
        keyring,
        revocations,
    }))
}

pub(super) async fn record_revocation(path: &str, signature: &[u8]) -> Result<(), String> {
    let response = api::send_json(
        "POST",
        &format!("/api/mls/revocations?path={}", encode(path)),
        &json!({ "signature_key": STANDARD.encode(signature) }),
    )
    .await?;
    if response.status != 204 && response.status != 404 {
        return Err(response
            .error()
            .unwrap_or("could not record the MLS revocation")
            .to_string());
    }
    Ok(())
}

pub(super) async fn clear_revocation(path: &str, signature: &[u8]) -> Result<(), String> {
    let encoded = STANDARD.encode(signature);
    let response = api::delete(&format!(
        "/api/mls/revocations?path={}&signature_key={}",
        encode(path),
        encode(&encoded)
    ))
    .await?;
    if response.status != 204 && response.status != 404 {
        return Err(response
            .error()
            .unwrap_or("could not clear the MLS revocation")
            .to_string());
    }
    Ok(())
}

pub(super) async fn post_commit(
    path: &str,
    epoch: u64,
    commit: &[u8],
    welcome: Option<&[u8]>,
) -> Result<(), (u16, String)> {
    let mut body = json!({
        "epoch": epoch,
        "commit": STANDARD.encode(commit),
    });
    if let Some(welcome) = welcome {
        body["welcome"] = json!(STANDARD.encode(welcome));
    }
    let response = api::send_json(
        "POST",
        &format!("/api/mls/commit?path={}", encode(path)),
        &body,
    )
    .await
    .map_err(|error| (0, error))?;
    if response.status == 404 {
        // Older servers only have the separate message endpoint.
        send_message(path, epoch, "commit", commit).await?;
        if let Some(welcome) = welcome {
            send_message(path, epoch, "welcome", welcome).await?;
        }
        return Ok(());
    }
    if response.status != 200 {
        return Err((
            response.status,
            response
                .error()
                .unwrap_or("could not publish the MLS commit")
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn send_message(
    path: &str,
    epoch: u64,
    kind: &str,
    payload: &[u8],
) -> Result<(), (u16, String)> {
    let response = api::send_json(
        "POST",
        &format!("/api/mls/messages?path={}", encode(path)),
        &json!({
            "epoch": epoch,
            "kind": kind,
            "payload": STANDARD.encode(payload),
        }),
    )
    .await
    .map_err(|error| (0, error))?;
    if response.status != 200 {
        return Err((
            response.status,
            response
                .error()
                .unwrap_or("could not publish the MLS message")
                .to_string(),
        ));
    }
    Ok(())
}
