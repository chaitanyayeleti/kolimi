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

use std::time::Duration;

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
/// Usage counters recomputed from disk per pass (bounded; least-recently
/// reconciled users first).
pub const RECONCILE_BATCH: i64 = 50;

/// What one janitor pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Trashed nodes permanently deleted.
    pub purged_trash: u64,
    /// Old versions pruned.
    pub pruned_versions: u64,
    /// Chunk blobs reclaimed.
    pub chunks_deleted: u64,
    /// Manifest blobs reclaimed.
    pub manifests_deleted: u64,
    /// Expired public-link unlock sessions removed.
    pub expired_link_sessions: u64,
    /// Expired device enrollments removed.
    pub expired_enrollments: u64,
    /// Blobs re-verified by the scrubber.
    pub scrubbed: u64,
    /// Blobs found corrupt by the scrubber.
    pub corrupt: u64,
    /// Usage counters recomputed from disk.
    pub reconciled: u64,
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
}

/// Runs one maintenance pass for every user.
pub async fn run_once(state: &AppState, now: i64) -> Result<Report, JanitorError> {
    let mut report = Report::default();
    let users = state.db.list_users().await?;
    for user in users {
        report.purged_trash += state
            .db
            .purge_trash(user.id, now - TRASH_RETENTION_MILLIS)
            .await?;
        report.pruned_versions += state
            .db
            .prune_versions(user.id, now - VERSION_RETENTION_MILLIS)
            .await?;
        let swept = state.vfs.collect_garbage(user.id, GC_GRACE).await?;
        report.chunks_deleted += swept.chunks_deleted;
        report.manifests_deleted += swept.manifests_deleted;
        scrub_user(state, user.id, &mut report).await?;
    }
    report.expired_link_sessions = state.db.delete_expired_link_sessions(now).await?;
    report.expired_enrollments = state.db.purge_expired_enrollments().await?;

    // Recompute a bounded batch of usage counters from *referenced* bytes so
    // the cached numbers cannot drift; the request path never walks the tree.
    for user_id in state.db.users_for_reconcile(RECONCILE_BATCH).await? {
        state.vfs.reconcile_usage(user_id).await?;
        report.reconciled += 1;
    }
    Ok(report)
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
        state
            .db
            .audit_append(
                None,
                Some("janitor"),
                "scrub.corrupt",
                blob,
                &serde_json::json!({ "user_id": user_id }),
            )
            .await?;
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
        match run_once(&state, kolimi_db::now_millis()).await {
            Ok(report) if report != Report::default() => {
                tracing::info!(
                    purged_trash = report.purged_trash,
                    pruned_versions = report.pruned_versions,
                    chunks_deleted = report.chunks_deleted,
                    manifests_deleted = report.manifests_deleted,
                    expired_link_sessions = report.expired_link_sessions,
                    expired_enrollments = report.expired_enrollments,
                    scrubbed = report.scrubbed,
                    corrupt = report.corrupt,
                    reconciled = report.reconciled,
                    "janitor pass complete"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "janitor pass failed"),
        }
    }
}
