//! Admin-only HTTP surface for groups and the audit log.
//!
//! Group routes control sharing rosters; they never rotate MLS keys or
//! rewrite share keyrings. Clients must re-share affected encrypted folders
//! after membership changes. Audit responses expose the visible fields only;
//! chain hashes stay server-side.

use std::collections::HashMap;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kolimi_auth::CurrentUser;
use kolimi_db::{AuditEntry, AuditPageQuery, DbError, Group};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, api, audit};

/// Rejects callers that are not administrators.
fn require_admin(user: &CurrentUser) -> Option<Response> {
    (!user.is_admin).then(|| api::forbidden("administrator access required"))
}

fn group_json(group: &Group, members: &[String]) -> Value {
    json!({
        "id": group.id,
        "name": group.name,
        "created_at": group.created_at,
        "members": members,
    })
}

/// `GET /api/groups` — admin overview with every group's members.
pub async fn list_groups(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let groups = match state.db.list_groups().await {
        Ok(groups) => groups,
        Err(_) => return api::internal_error(),
    };
    let memberships = match state.db.group_member_names().await {
        Ok(memberships) => memberships,
        Err(_) => return api::internal_error(),
    };
    let mut by_group: HashMap<i64, Vec<String>> = HashMap::new();
    for (group_id, username) in memberships {
        by_group.entry(group_id).or_default().push(username);
    }
    let groups: Vec<Value> = groups
        .iter()
        .map(|group| {
            group_json(
                group,
                by_group.get(&group.id).map_or(&[][..], Vec::as_slice),
            )
        })
        .collect();
    Json(json!({ "groups": groups })).into_response()
}

/// New-group payload.
#[derive(Deserialize)]
pub struct NewGroupRequest {
    name: String,
}

/// `POST /api/groups` — create a named group.
pub async fn create_group(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<NewGroupRequest>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let name = req.name.trim();
    if name.is_empty() {
        return api::bad_request("group name is required");
    }
    if name.len() > 64 {
        return api::bad_request("group name must be at most 64 bytes");
    }
    let group = match state.db.create_group(name).await {
        Ok(group) => group,
        Err(DbError::Conflict(message)) => {
            return (StatusCode::CONFLICT, Json(json!({ "error": message }))).into_response();
        }
        Err(_) => return api::internal_error(),
    };
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "group.add",
        &group.name,
        json!({ "id": group.id, "by": "api" }),
    )
    .await;
    (StatusCode::CREATED, Json(group_json(&group, &[]))).into_response()
}

/// `DELETE /api/groups/{name}` — delete a group and its memberships/shares.
pub async fn delete_group(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(name): Path<String>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let Some(group) = state.db.group_by_name(&name).await.ok().flatten() else {
        return api::not_found();
    };
    match state.db.delete_group(group.id).await {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "group.delete",
                &group.name,
                json!({ "id": group.id, "by": "api" }),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => api::not_found(),
        Err(_) => api::internal_error(),
    }
}

/// `POST /api/groups/{name}/members/{username}` — add a member.
pub async fn add_group_member(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path((name, username)): Path<(String, String)>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let Some(group) = state.db.group_by_name(&name).await.ok().flatten() else {
        return api::not_found();
    };
    let Some(member) = state.db.find_user(&username).await.ok().flatten() else {
        return api::not_found();
    };
    if state
        .db
        .add_group_member(group.id, member.id)
        .await
        .is_err()
    {
        return api::internal_error();
    }
    audit(
        &state,
        Some(user.user_id),
        Some(&user.username),
        "group.member_add",
        &group.name,
        json!({ "user": member.username, "by": "api" }),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `DELETE /api/groups/{name}/members/{username}` — remove a member.
///
/// Idempotent: removing someone who is not a member still succeeds.
pub async fn remove_group_member(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path((name, username)): Path<(String, String)>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let Some(group) = state.db.group_by_name(&name).await.ok().flatten() else {
        return api::not_found();
    };
    let Some(member) = state.db.find_user(&username).await.ok().flatten() else {
        return api::not_found();
    };
    match state.db.remove_group_member(group.id, member.id).await {
        Ok(true) => {
            audit(
                &state,
                Some(user.user_id),
                Some(&user.username),
                "group.member_remove",
                &group.name,
                json!({ "user": member.username, "by": "api" }),
            )
            .await;
        }
        Ok(false) => {}
        Err(_) => return api::internal_error(),
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Audit-list query parameters.
#[derive(Deserialize)]
pub struct AuditParams {
    #[serde(default)]
    limit: Option<i64>,
    /// Keyset cursor: entries with a smaller id (newest-first paging).
    #[serde(default)]
    before: Option<i64>,
    /// Exact action filter, e.g. `group.add`.
    #[serde(default)]
    action: Option<String>,
    /// Exact subject filter, usually a username or group name.
    #[serde(default)]
    subject: Option<String>,
}

fn filter_value(value: Option<&str>, max_chars: usize) -> Result<Option<&str>, ()> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    if value.is_some_and(|value| value.chars().count() > max_chars) {
        return Err(());
    }
    Ok(value)
}

fn audit_json(entry: &AuditEntry) -> Value {
    let details = serde_json::from_str::<Value>(&entry.details)
        .unwrap_or_else(|_| Value::String(entry.details.clone()));
    json!({
        "id": entry.id,
        "ts": entry.ts,
        "actor_id": entry.actor_id,
        "actor": entry.actor,
        "action": entry.action,
        "subject": entry.subject,
        "details": details,
    })
}

/// `GET /api/audit?limit=&before=&action=&subject=` — newest-first audit page.
pub async fn list_audit(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(params): Query<AuditParams>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let action = match filter_value(params.action.as_deref(), 128) {
        Ok(action) => action,
        Err(()) => return api::bad_request("action filter is too long"),
    };
    let subject = match filter_value(params.subject.as_deref(), 512) {
        Ok(subject) => subject,
        Err(()) => return api::bad_request("subject filter is too long"),
    };
    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let entries = match state
        .db
        .audit_page(AuditPageQuery {
            limit: limit + 1,
            before: params.before,
            action,
            subject,
        })
        .await
    {
        Ok(entries) => entries,
        Err(_) => return api::internal_error(),
    };
    let has_more = entries.len() as i64 > limit;
    let entries = if has_more {
        &entries[..limit as usize]
    } else {
        entries.as_slice()
    };
    let next_before = has_more
        .then(|| entries.last().map(|entry| entry.id))
        .flatten();
    let entries: Vec<Value> = entries.iter().map(audit_json).collect();
    Json(json!({
        "entries": entries,
        "has_more": has_more,
        "next_before": next_before,
    }))
    .into_response()
}

/// `GET /api/audit/verify` — recompute the hash chain, signatures, and
/// anchors. Trust comes from the server's configured signing key.
pub async fn verify_audit(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Response {
    if let Some(response) = require_admin(&user) {
        return response;
    }
    let mut trusted_keys = Vec::new();
    if let Some(signer) = state.audit_signer.as_deref()
        && let Ok(key) =
            kolimi_db::TrustedAuditKey::from_parts(signer.key_id(), signer.public_key().to_vec())
    {
        trusted_keys.push(key);
    }
    let trust_source = if trusted_keys.is_empty() {
        "none"
    } else {
        "configured-key"
    };
    let verify = state
        .db
        .audit_verify_with(kolimi_db::AuditVerifyOptions {
            trusted_keys,
            require_signatures: false,
            anchor_log: state
                .audit_anchors
                .as_deref()
                .and_then(|config| config.journal.clone())
                .filter(|path| path.exists()),
            trust_source: Some(trust_source.to_string()),
        })
        .await;
    match verify {
        Ok(verify) => {
            let anchor = state.db.audit_anchor().await.ok().flatten();
            Json(json!({
                "ok": verify.first_bad.is_none() && !verify.rollback_detected,
                "entries": verify.entries,
                "checkpoints": verify.checkpoints,
                "pruned_checkpoints": verify.pruned_checkpoints,
                "signed_checkpoints": verify.signed_checkpoints,
                "verified_signatures": verify.verified_signatures,
                "unsigned_checkpoints": verify.unsigned_checkpoints,
                "signature_errors": verify.signature_errors,
                "anchors_checked": verify.anchors_checked,
                "rollback_detected": verify.rollback_detected,
                "trust_source": verify.trust_source,
                "first_bad": verify.first_bad,
                "latest_anchor": verify.latest_anchor.map(|anchor| json!({
                    "checkpoint_id": anchor.checkpoint_id,
                    "last_entry_id": anchor.last_entry_id,
                })),
                "latest_checkpoint": verify.latest_checkpoint.map(|checkpoint| json!({
                    "id": checkpoint.id,
                    "last_entry_id": checkpoint.last_entry_id,
                    "merkle_root": checkpoint.merkle_root,
                })),
                "anchor": anchor.map(|anchor| json!({
                    "pruned_through": anchor.pruned_through,
                    "pruned_entries": anchor.pruned_entries,
                })),
            }))
            .into_response()
        }
        Err(_) => api::internal_error(),
    }
}
