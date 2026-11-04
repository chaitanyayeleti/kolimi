//! Search helpers for plaintext and encrypted names.

use kolimi_crypto::MasterKey;
use serde_json::Value;

use super::types::SearchHit;
use crate::api;

/// Fetches received mounts and unwraps their display names/keys.
pub(super) async fn received_mounts(
    master: Option<&MasterKey>,
) -> (Vec<Value>, Vec<crate::e2ee::ShareDisplay>) {
    let mut mounts = Vec::new();
    if let Ok(response) = api::get("/api/shares/received").await
        && response.status == 200
    {
        mounts = response.body["mounts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
    }
    let mut shares = Vec::new();
    if let Some(master) = master {
        for mount in &mounts {
            let (Some(wrapped), Some(prefix)) =
                (mount["wrapped_name"].as_str(), mount["mount"].as_str())
            else {
                continue;
            };
            if let Ok((name, key)) = crate::e2ee::unwrap_share_name(master, wrapped).await {
                shares.push(crate::e2ee::ShareDisplay {
                    prefix: prefix.to_string(),
                    name,
                    key,
                });
            }
        }
    }
    (mounts, shares)
}

/// Client-side name search over encrypted items.
///
/// The server indexes only ciphertext (`k1_…`), so it cannot match a
/// plaintext query. This walks the tree (and received share files), decodes
/// names with the unlocked key, and returns name matches. Content search
/// inside encrypted files remains impossible by design.
pub(super) async fn encrypted_name_hits(
    master: &MasterKey,
    query: &str,
    shares: &[crate::e2ee::ShareDisplay],
) -> Vec<SearchHit> {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();
    #[allow(clippy::too_many_arguments)]
    fn add(
        hits: &mut Vec<SearchHit>,
        seen: &mut std::collections::HashSet<String>,
        master: &MasterKey,
        needle: &str,
        shares: &[crate::e2ee::ShareDisplay],
        path: &str,
        kind: &str,
        size: u64,
        modified_at: i64,
        need_encoded: bool,
    ) {
        if hits.len() >= 50 || !seen.insert(path.to_string()) {
            return;
        }
        if need_encoded
            && !path.split('/').any(kolimi_crypto::is_encoded_name)
            && !shares.iter().any(|share| path.starts_with(&share.prefix))
        {
            return;
        }
        let display = crate::e2ee::decode_display_path_with_shares(Some(master), path, shares);
        let name = display.rsplit('/').next().unwrap_or_default();
        if !name.to_lowercase().contains(needle) {
            return;
        }
        hits.push(SearchHit {
            name: name.to_string(),
            path: path.to_string(),
            is_dir: kind == "dir",
            size,
            modified_at,
            snippet: "Encrypted name match".to_string(),
            encrypted: true,
        });
    }

    let mut after = 0i64;
    loop {
        let url = format!("/api/sync/tree?after_id={after}&limit=1000");
        let Ok(response) = api::get(&url).await else {
            break;
        };
        if response.status != 200 {
            break;
        }
        for entry in response.body["entries"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let Some(path) = entry["path"].as_str() else {
                continue;
            };
            add(
                &mut hits,
                &mut seen,
                master,
                &needle,
                shares,
                path,
                entry["kind"].as_str().unwrap_or("file"),
                entry["size"].as_u64().unwrap_or(0),
                entry["modified_at"].as_i64().unwrap_or(0),
                true,
            );
        }
        if !response.body["has_more"].as_bool().unwrap_or(false) {
            break;
        }
        let last = response.body["last_id"].as_i64().unwrap_or(after);
        if last <= after {
            break;
        }
        after = last;
        if hits.len() >= 50 {
            break;
        }
    }

    // Files received through encrypted shares (folder names inside a share
    // are covered when the client has already browsed them; the shared-tree
    // API lists files).
    if let Ok(response) = api::get("/api/sync/shared-tree").await
        && response.status == 200
        && let Some(entries) = response.body["entries"].as_array()
    {
        for entry in entries {
            let Some(path) = entry["path"].as_str() else {
                continue;
            };
            add(
                &mut hits,
                &mut seen,
                master,
                &needle,
                shares,
                path,
                entry["kind"].as_str().unwrap_or("file"),
                entry["size"].as_u64().unwrap_or(0),
                entry["modified_at"].as_i64().unwrap_or(0),
                false,
            );
        }
    }
    hits
}
