//! Background indexer: feeds the tantivy index from the change feed.
//!
//! Crash-safe by construction: progress is recorded *after* the index
//! commit, so a crash at any point replays idempotent upserts from the
//! last committed sequence.

use std::time::Duration;

use kolimi_search::SearchDoc;

use crate::AppState;

/// How often the indexer runs.
pub const INTERVAL: Duration = Duration::from_secs(30);
/// Maximum change-feed entries consumed per user per pass.
pub const MAX_BATCH: i64 = 2000;
/// Maximum bytes of a file indexed as text.
pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;

/// What one indexing pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IndexReport {
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

/// Runs one indexing pass for every user.
pub async fn run_once(state: &AppState) -> Result<IndexReport, IndexerError> {
    let mut report = IndexReport::default();
    for user in state.db.list_users().await? {
        let last = state.db.search_last_seq(user.id).await?;
        let changes = state.db.changes_since(user.id, last, MAX_BATCH).await?;
        if changes.is_empty() {
            continue;
        }
        let mut latest = last;
        for change in &changes {
            latest = latest.max(change.seq);
            match change.op.as_str() {
                "delete" => {
                    state.search.remove(user.id, &change.path)?;
                    report.removed += 1;
                }
                "move" => {
                    if let Some(from) = change.from_path.as_deref() {
                        state.search.remove(user.id, from)?;
                        report.removed += 1;
                    }
                    index_path(state, user.id, &change.path, &mut report).await?;
                }
                _ => index_path(state, user.id, &change.path, &mut report).await?,
            }
        }
        state.search.commit()?;
        state.db.set_search_last_seq(user.id, latest).await?;
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
        match run_once(&state).await {
            Ok(report) if report != IndexReport::default() => {
                tracing::info!(
                    indexed = report.indexed,
                    removed = report.removed,
                    "search indexer pass complete"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "search indexer pass failed"),
        }
    }
}
