//! Background indexer: feeds the tantivy index from the change feed.
//!
//! Crash-safe by construction: progress is recorded *after* the index
//! commit, so a crash at any point replays idempotent upserts from the
//! last committed sequence.

use std::time::{Duration, Instant};

use kolimi_search::SearchDoc;

use crate::AppState;

/// How often the indexer runs.
pub const INTERVAL: Duration = Duration::from_secs(30);
/// Maximum change-feed entries consumed per user per pass.
pub const MAX_BATCH: i64 = 2000;
/// Maximum users indexed per pass; the least recently indexed go first, so a
/// large instance is covered over several passes instead of one long scan.
pub const MAX_USERS_PER_PASS: i64 = 100;
/// Maximum bytes of a file indexed as text.
pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;

/// What one indexing pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IndexReport {
    /// Users with pending changes processed.
    pub users: u64,
    /// Documents added or refreshed.
    pub indexed: u64,
    /// Documents removed.
    pub removed: u64,
}

/// Errors during an indexing pass.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// Database failure.
    #[error("database: {0}")]
    Db(#[from] kolimi_db::DbError),
    /// Search index failure.
    #[error("search: {0}")]
    Search(#[from] kolimi_search::SearchError),
}

/// Runs one indexing pass for users with pending changes.
pub async fn run_once(state: &AppState) -> Result<IndexReport, IndexerError> {
    let mut report = IndexReport::default();
    for user_id in state
        .db
        .users_with_pending_changes(MAX_USERS_PER_PASS)
        .await?
    {
        report.users += 1;
        let last = state.db.search_last_seq(user_id).await?;
        let changes = state.db.changes_since(user_id, last, MAX_BATCH).await?;
        if changes.is_empty() {
            continue;
        }
        let mut latest = last;
        for change in &changes {
            latest = latest.max(change.seq);
            match change.op.as_str() {
                "delete" => {
                    state.search.remove(user_id, &change.path)?;
                    report.removed += 1;
                }
                "move" => {
                    if let Some(from) = change.from_path.as_deref() {
                        state.search.remove(user_id, from)?;
                        report.removed += 1;
                    }
                    index_path(state, user_id, &change.path, &mut report).await?;
                }
                _ => index_path(state, user_id, &change.path, &mut report).await?,
            }
        }
        state.search.commit()?;
        state.db.set_search_last_seq(user_id, latest).await?;
    }
    Ok(report)
}

async fn index_path(
    state: &AppState,
    user_id: i64,
    path: &str,
    report: &mut IndexReport,
) -> Result<(), IndexerError> {
    match state.vfs.resolve(user_id, path).await {
        Ok(node) if node.is_dir() => {
            state.search.upsert(&SearchDoc {
                user_id,
                path: path.to_string(),
                name: node.name,
                is_dir: true,
                content: None,
                size: 0,
                modified_at: node.modified_at,
            })?;
            report.indexed += 1;
        }
        Ok(node) => {
            // On a DB error, treat the node as encrypted so we never index
            // ciphertext as if it were text.
            let encrypted = state.db.is_encrypted(node.id).await.unwrap_or(true);
            let content = if !encrypted && crate::preview::looks_textual(&node.name) {
                match state.vfs.read_head(user_id, path, MAX_CONTENT_BYTES).await {
                    Ok((_, bytes)) => crate::preview::extract_text(&bytes),
                    Err(_) => None,
                }
            } else {
                None
            };
            state.search.upsert(&SearchDoc {
                user_id,
                path: path.to_string(),
                name: node.name,
                is_dir: false,
                content,
                size: node.size,
                modified_at: node.modified_at,
            })?;
            report.indexed += 1;
        }
        Err(_) => {
            state.search.remove(user_id, path)?;
            report.removed += 1;
        }
    }
    Ok(())
}

/// Runs the indexer forever on the configured interval.
pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        let started = Instant::now();
        match run_once(&state).await {
            Ok(report) => {
                state.metrics.indexer_pass(
                    "success",
                    started.elapsed().as_secs_f64(),
                    report.indexed,
                    report.removed,
                );
                if report != IndexReport::default() {
                    tracing::info!(
                        users = report.users,
                        indexed = report.indexed,
                        removed = report.removed,
                        "search indexer pass complete"
                    );
                }
            }
            Err(error) => {
                state
                    .metrics
                    .indexer_pass("error", started.elapsed().as_secs_f64(), 0, 0);
                tracing::warn!(error = %error, "search indexer pass failed");
            }
        }
    }
}
