//! Background maintenance: trash/version retention and blob GC.
//!
//! The janitor runs hourly. All operations are idempotent and safe to run
//! concurrently with traffic: blob deletion has a grace period so blobs
//! written by in-flight uploads are never swept.

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
    }
    report.expired_link_sessions = state.db.delete_expired_link_sessions(now).await?;
    Ok(report)
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
                    "janitor pass complete"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "janitor pass failed"),
        }
    }
}
