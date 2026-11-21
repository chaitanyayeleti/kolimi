//! Background maintenance: trash/version retention, blob GC, and the
//! incremental scrubber.
//!
//! The janitor runs hourly. All operations are idempotent and safe to run
//! concurrently with traffic: blob deletion has a grace period so blobs
//! written by in-flight uploads are never swept, and the scrubber only
//! reads. Each pass re-verifies a bounded batch of blobs per user (BLAKE3
//! for chunks, structural content id for manifests), advancing a durable
//! cursor so every blob is checked regularly; corruption is logged and
//! audited (single-node installs have no replica to self-heal from).

use std::time::{Duration, Instant};

use crate::AppState;

/// Trashed nodes are kept for 30 days before permanent deletion.
pub const TRASH_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Superseded versions are kept for 30 days (and at most 10 per file).
pub const VERSION_RETENTION_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Unreferenced blobs younger than this are never swept.
pub const GC_GRACE: Duration = Duration::from_secs(60 * 60);
/// Janitor interval.
pub const INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Blobs re-verified per user per pass.
pub const SCRUB_BATCH: usize = 200;
/// Users with expired trash/versions handled per pass.
pub const RETENTION_BATCH: i64 = 100;
/// Accounts swept for garbage per pass.
pub const GC_BATCH: i64 = 50;
/// Legacy flat manifests moved to the fanout layout per account per pass.
pub const MIGRATE_BATCH: usize = 1000;
/// Checkpoint batches the janitor may seal in one pass.
pub const AUDIT_CHECKPOINTS_PER_PASS: u64 = 10;
/// Accounts scrubbed per pass (each checks `SCRUB_BATCH` blobs).
pub const SCRUB_USERS: i64 = 50;
/// Usage counters recomputed from disk per pass (bounded; least-recently
/// reconciled users first).
pub const RECONCILE_BATCH: i64 = 50;
/// Consumed/expired MLS key packages are retained this long for diagnostics.
pub const MLS_KEY_PACKAGE_RETENTION_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Inactive MLS device-roster entries are retained much longer than packages
/// so a recipient cannot churn new device ids every cleanup cycle.
pub const MLS_DEVICE_RETENTION_MILLIS: i64 = 180 * 24 * 60 * 60 * 1000;
/// A device that has not reported its epoch for this long is ignored when
/// calculating the safe pruning floor.
pub const MLS_EPOCH_REPORT_FRESH_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Old MLS protocol messages/keyrings are kept at least this long.
pub const MLS_MESSAGE_RETENTION_MILLIS: i64 = 7 * 24 * 60 * 60 * 1000;

/// What one janitor pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Accounts with expired trash or versions processed.
    pub retention_users: u64,
    /// Trashed nodes permanently deleted.
    pub purged_trash: u64,
    /// Old versions pruned.
    pub pruned_versions: u64,
    /// Accounts swept for unreferenced blobs.
    pub gc_users: u64,
    /// Chunk blobs reclaimed.
    pub chunks_deleted: u64,
    /// Manifest blobs reclaimed.
    pub manifests_deleted: u64,
    /// Legacy flat manifests moved into the fanout layout.
    pub manifests_migrated: u64,
    /// Accounts scrubbed.
    pub scrub_users: u64,
    /// Expired public-link unlock sessions removed.
    pub expired_link_sessions: u64,
    /// Expired device enrollments removed.
    pub expired_enrollments: u64,
    /// Consumed/expired MLS key packages removed.
    pub pruned_mls_key_packages: u64,
    /// Inactive MLS device-roster entries removed.
    pub pruned_mls_devices: u64,
    /// MLS protocol messages below the safe epoch floor.
    pub pruned_mls_messages: u64,
    /// MLS keyrings below the safe epoch floor.
    pub pruned_mls_keyrings: u64,
    /// Blobs re-verified by the scrubber.
    pub scrubbed: u64,
    /// Blobs found corrupt by the scrubber.
    pub corrupt: u64,
    /// Usage counters recomputed from disk.
    pub reconciled: u64,
    /// Audit checkpoints sealed this pass.
    pub audit_checkpoints_sealed: u64,
    /// Sealed checkpoints that were signed.
    pub audit_checkpoints_signed: u64,
    /// Sealing failed; entries remain unsealed for the next pass.
    pub audit_seal_failed: bool,
    /// Anchor records appended to the journal.
    pub audit_anchors_journaled: u64,
    /// Anchor records delivered over HTTP.
    pub audit_anchors_delivered: u64,
    /// Anchor rows that failed at least one sink.
    pub audit_anchor_failures: u64,
}

/// Errors during a janitor pass.
#[derive(Debug, thiserror::Error)]
pub enum JanitorError {
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] kolimi_db::DbError),
    /// Storage failure.
    #[error("storage: {0}")]
    Vfs(#[from] kolimi_vfs::VfsError),
    /// Blob store failure.
    #[error("blob store: {0}")]
    Store(#[from] kolimi_store::StoreError),
    /// Audit anchor delivery failure.
    #[error("audit anchor: {0}")]
    Anchor(#[from] crate::anchor::AnchorError),
}

/// Runs one maintenance pass.
///
/// Work is scheduled per account instead of scanning every account:
/// expired-retention accounts first, then accounts with uncollected deletes,
/// then the least-recently-swept and least-recently-scrubbed batches. Every
/// batch is bounded, so pass time does not grow with the total user count.
pub async fn run_once(state: &AppState, now: i64) -> Result<Report, JanitorError> {
    let mut report = Report::default();
    let trash_cutoff = now - TRASH_RETENTION_MILLIS;
    let version_cutoff = now - VERSION_RETENTION_MILLIS;

    let mut swept = std::collections::HashSet::new();

    // Accounts with expired retention get priority and a sweep immediately:
    // purging rows is what makes their blobs unreferenced.
    for user_id in state
        .db
        .users_with_expired_retention(trash_cutoff, version_cutoff, RETENTION_BATCH)
        .await?
    {
        report.retention_users += 1;
        report.purged_trash += state.db.purge_trash(user_id, trash_cutoff).await?;
        report.pruned_versions += state.db.prune_versions(user_id, version_cutoff).await?;
        sweep_user(state, user_id, now, &mut report).await?;
        swept.insert(user_id);
    }

    // Accounts with a delete or emptied trash since their last sweep.
    for user_id in state.db.users_with_pending_gc(GC_BATCH).await? {
        if swept.insert(user_id) {
            sweep_user(state, user_id, now, &mut report).await?;
        }
    }

    // Rotating sweep: never-swept and then least-recently-swept accounts.
    for user_id in state.db.users_due_for_gc(GC_BATCH).await? {
        if swept.insert(user_id) {
            sweep_user(state, user_id, now, &mut report).await?;
        }
    }

    // Rotating scrub: `SCRUB_BATCH` blobs per account.
    for user_id in state.db.users_due_for_scrub(SCRUB_USERS).await? {
        report.scrub_users += 1;
        scrub_user(state, user_id, &mut report).await?;
    }

    report.expired_link_sessions = state.db.delete_expired_link_sessions(now).await?;
    report.expired_enrollments = state.db.purge_expired_enrollments().await?;
    report.pruned_mls_key_packages = state
        .db
        .purge_mls_key_packages(now - MLS_KEY_PACKAGE_RETENTION_MILLIS)
        .await?;
    report.pruned_mls_devices = state
        .db
        .prune_mls_devices(now - MLS_DEVICE_RETENTION_MILLIS)
        .await?;
    (report.pruned_mls_messages, report.pruned_mls_keyrings) = state
        .db
        .prune_mls_messages(
            now - MLS_MESSAGE_RETENTION_MILLIS,
            now - MLS_EPOCH_REPORT_FRESH_MILLIS,
        )
        .await?;

    // Seal audit entries off the request path once enough have accumulated
    // or the oldest unsealed entry is old enough to bound the anchor gap.
    let seal_age_millis = std::env::var("KOLIMI_AUDIT_SEAL_AGE_SECS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|seconds| *seconds >= 0)
        .map(|seconds| seconds.saturating_mul(1000))
        .unwrap_or(24 * 60 * 60 * 1000);
    let enqueue_anchor = state
        .audit_anchors
        .as_deref()
        .is_some_and(crate::anchor::AnchorConfig::enabled);
    let mut signer = state.audit_signer.clone();
    if signer.is_none()
        && let Some(path) = state.audit_signing_key.as_deref()
    {
        match kolimi_db::AuditSigner::load(path) {
            Ok(loaded) => {
                tracing::info!(key_id = loaded.key_id(), "audit signing key reloaded");
                signer = Some(std::sync::Arc::new(loaded));
            }
            Err(error) => tracing::error!(%error, "audit signing key still unavailable"),
        }
    }
    if state.audit_signing_key.is_some() && signer.is_none() {
        report.audit_seal_failed = true;
        state.metrics.audit_signing_error();
        tracing::error!("refusing to seal audit checkpoints without the configured signing key");
    } else {
        match state
            .db
            .audit_seal_if_due(
                kolimi_db::AUDIT_CHECKPOINT_ENTRIES,
                seal_age_millis,
                kolimi_db::AUDIT_CHECKPOINT_BATCH,
                AUDIT_CHECKPOINTS_PER_PASS,
                signer.as_deref(),
                enqueue_anchor,
            )
            .await
        {
            Ok(sealed) => {
                report.audit_checkpoints_sealed = sealed;
                if signer.is_some() {
                    report.audit_checkpoints_signed = sealed;
                    state.metrics.audit_checkpoints_signed(sealed);
                }
            }
            Err(error) => {
                report.audit_seal_failed = true;
                if signer.is_some() {
                    state.metrics.audit_signing_error();
                }
                tracing::error!(%error, "audit checkpoint seal failed; retrying next pass");
            }
        }
    }
    if let Some(config) = state.audit_anchors.as_deref()
        && config.enabled()
    {
        match crate::anchor::drain(&state.db, config, Some(&state.metrics), 20).await {
            Ok(drain) => {
                report.audit_anchors_journaled = drain.journaled;
                report.audit_anchors_delivered = drain.delivered;
                report.audit_anchor_failures = drain.failed;
            }
            Err(error) => tracing::error!(%error, "audit anchor drain failed; retrying next pass"),
        }
    }

    // Recompute a bounded batch of usage counters from *referenced* bytes so
    // the cached numbers cannot drift; the request path never walks the tree.
    for user_id in state.db.users_for_reconcile(RECONCILE_BATCH).await? {
        state.vfs.reconcile_usage(user_id).await?;
        report.reconciled += 1;
    }
    Ok(report)
}

/// Sweeps one account's unreferenced blobs and records the sweep cursor.
async fn sweep_user(
    state: &AppState,
    user_id: i64,
    now: i64,
    report: &mut Report,
) -> Result<(), JanitorError> {
    if !state.db.legacy_manifests_migrated(user_id).await? {
        let moved = state
            .vfs
            .store()
            .migrate_legacy_manifests(user_id, MIGRATE_BATCH)
            .await?;
        report.manifests_migrated += moved;
        if moved < MIGRATE_BATCH as u64 {
            state.db.mark_legacy_manifests_migrated(user_id).await?;
        }
    }
    let swept = state.vfs.collect_garbage(user_id, GC_GRACE).await?;
    report.gc_users += 1;
    report.chunks_deleted += swept.chunks_deleted;
    report.manifests_deleted += swept.manifests_deleted;
    state.db.set_last_gc(user_id, now).await?;
    Ok(())
}

/// Re-verifies one batch of a user's blobs and advances the cursor.
async fn scrub_user(
    state: &AppState,
    user_id: i64,
    report: &mut Report,
) -> Result<(), JanitorError> {
    let cursor = state.db.scrub_cursor(user_id).await?;
    let batch = state
        .vfs
        .store()
        .scrub_batch(user_id, cursor.as_deref(), SCRUB_BATCH)
        .await?;
    report.scrubbed += batch.checked;
    for blob in &batch.corrupt {
        report.corrupt += 1;
        tracing::error!(user_id, blob, "scrub: blob corrupt");
        // An audit failure must not abort scrubbing for every user.
        if let Err(error) = state
            .db
            .audit_append(
                None,
                Some("janitor"),
                "scrub.corrupt",
                blob,
                &serde_json::json!({ "user_id": user_id }),
            )
            .await
        {
            tracing::warn!(%error, user_id, blob, "scrub: failed to audit corrupt blob");
        }
    }
    state
        .db
        .set_scrub_cursor(user_id, batch.next.as_deref())
        .await?;
    Ok(())
}

/// Runs the janitor forever on the configured interval.
pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let started = Instant::now();
        match run_once(&state, kolimi_db::now_millis()).await {
            Ok(report) => {
                state
                    .metrics
                    .janitor_pass("success", started.elapsed().as_secs_f64());
                state
                    .metrics
                    .janitor_event("retention_users", report.retention_users);
                state
                    .metrics
                    .janitor_event("trash_purged", report.purged_trash);
                state
                    .metrics
                    .janitor_event("versions_pruned", report.pruned_versions);
                state.metrics.janitor_event("gc_users", report.gc_users);
                state
                    .metrics
                    .janitor_event("chunks_deleted", report.chunks_deleted);
                state
                    .metrics
                    .janitor_event("manifests_deleted", report.manifests_deleted);
                state
                    .metrics
                    .janitor_event("manifests_migrated", report.manifests_migrated);
                state
                    .metrics
                    .janitor_event("scrub_users", report.scrub_users);
                state
                    .metrics
                    .janitor_event("link_sessions_expired", report.expired_link_sessions);
                state
                    .metrics
                    .janitor_event("enrollments_expired", report.expired_enrollments);
                state
                    .metrics
                    .janitor_event("mls_key_packages_pruned", report.pruned_mls_key_packages);
                state
                    .metrics
                    .janitor_event("mls_devices_pruned", report.pruned_mls_devices);
                state
                    .metrics
                    .janitor_event("mls_messages_pruned", report.pruned_mls_messages);
                state
                    .metrics
                    .janitor_event("mls_keyrings_pruned", report.pruned_mls_keyrings);
                state
                    .metrics
                    .janitor_event("scrub_checked", report.scrubbed);
                state.metrics.janitor_event("scrub_corrupt", report.corrupt);
                state.metrics.janitor_event("reconciled", report.reconciled);
                state
                    .metrics
                    .janitor_event("audit_checkpoints_sealed", report.audit_checkpoints_sealed);
                state
                    .metrics
                    .janitor_event("audit_checkpoints_signed", report.audit_checkpoints_signed);
                state
                    .metrics
                    .janitor_event("audit_anchors_journaled", report.audit_anchors_journaled);
                state
                    .metrics
                    .janitor_event("audit_anchors_delivered", report.audit_anchors_delivered);
                if report != Report::default() {
                    tracing::info!(
                        retention_users = report.retention_users,
                        purged_trash = report.purged_trash,
                        pruned_versions = report.pruned_versions,
                        gc_users = report.gc_users,
                        chunks_deleted = report.chunks_deleted,
                        manifests_deleted = report.manifests_deleted,
                        manifests_migrated = report.manifests_migrated,
                        scrub_users = report.scrub_users,
                        expired_link_sessions = report.expired_link_sessions,
                        expired_enrollments = report.expired_enrollments,
                        pruned_mls_key_packages = report.pruned_mls_key_packages,
                        pruned_mls_devices = report.pruned_mls_devices,
                        pruned_mls_messages = report.pruned_mls_messages,
                        pruned_mls_keyrings = report.pruned_mls_keyrings,
                        scrubbed = report.scrubbed,
                        corrupt = report.corrupt,
                        reconciled = report.reconciled,
                        audit_checkpoints_sealed = report.audit_checkpoints_sealed,
                        audit_checkpoints_signed = report.audit_checkpoints_signed,
                        audit_anchors_journaled = report.audit_anchors_journaled,
                        audit_anchors_delivered = report.audit_anchors_delivered,
                        audit_anchor_failures = report.audit_anchor_failures,
                        "janitor pass complete"
                    );
                }
            }
            Err(error) => {
                state
                    .metrics
                    .janitor_pass("error", started.elapsed().as_secs_f64());
                tracing::warn!(error = %error, "janitor pass failed");
            }
        }
    }
}
