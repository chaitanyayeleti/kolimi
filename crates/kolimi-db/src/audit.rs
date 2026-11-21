//! Append-only, hash-chained audit log.
//!
//! Every entry hashes the previous entry's hash together with its own
//! fields, so removing, reordering, or editing any row breaks
//! [`Db::audit_verify`]. Appends are serialized through an in-process
//! mutex (SQLite has a single writer anyway), which keeps the chain
//! linear. The log is tamper-evident, not fail-closed: callers decide
//! whether an append failure aborts the audited operation.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;
use sqlx::SqliteConnection;
use tokio::io::AsyncWriteExt;

use futures_util::StreamExt;

use crate::{Db, DbError, now_millis};

/// One audit entry.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    /// Primary key (also the chain position).
    pub id: i64,
    /// Unix milliseconds.
    pub ts: i64,
    /// Acting user, when the event has one.
    pub actor_id: Option<i64>,
    /// Non-user actor (`cli`, `system`) or a denormalized username.
    pub actor: Option<String>,
    /// Dotted action name, e.g. `file.upsert`, `auth.login`.
    pub action: String,
    /// Path, username, or share id the action targets.
    pub subject: String,
    /// JSON object with extra context.
    pub details: String,
    /// Hash of the previous entry (empty for the first).
    pub prev_hash: Vec<u8>,
    /// BLAKE3 of `prev_hash` plus this entry's fields.
    pub hash: Vec<u8>,
}

/// Parameters for an audit-log page.
#[derive(Debug, Clone, Copy)]
pub struct AuditPageQuery<'a> {
    /// Maximum rows to return.
    pub limit: i64,
    /// Return entries with an id lower than this (newest-first paging).
    pub before: Option<i64>,
    /// Exact action name, e.g. `group.add`.
    pub action: Option<&'a str>,
    /// Exact subject, e.g. a username or group name.
    pub subject: Option<&'a str>,
}

/// Result of verifying the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerify {
    /// Number of entries checked.
    pub entries: u64,
    /// First entry id whose hash or link does not match, if any.
    pub first_bad: Option<i64>,
}

/// The last pruned audit entry. Verification starts from this trust point.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AuditAnchor {
    /// Last entry removed by retention.
    pub pruned_through: i64,
    /// Hash of that entry; the next retained row's `prev_hash`.
    pub hash: Vec<u8>,
    /// Total entries removed by retention.
    pub pruned_entries: i64,
    /// Last prune time in Unix milliseconds.
    pub updated_at: i64,
}

/// Result of exporting and pruning an audit prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPruneReport {
    /// Entries written to the export file.
    pub exported: u64,
    /// Last pruned entry id.
    pub pruned_through: i64,
    /// Anchor hash (hex) for the export boundary.
    pub anchor_hash: String,
}

/// One JSONL line in an audit export. `details_raw` preserves the exact
/// string covered by the chain hash; `details` is a convenience view.
#[derive(Serialize)]
struct AuditExportEntry<'a> {
    id: i64,
    ts: i64,
    actor_id: Option<i64>,
    actor: Option<&'a str>,
    action: &'a str,
    subject: &'a str,
    details: Value,
    details_raw: &'a str,
    prev_hash: String,
    hash: String,
}

fn chain_hash(
    prev_hash: &[u8],
    ts: i64,
    actor_id: Option<i64>,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    details: &str,
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev_hash);
    hasher.update(b"\n");
    hasher.update(ts.to_string().as_bytes());
    hasher.update(b"\n");
    if let Some(id) = actor_id {
        hasher.update(id.to_string().as_bytes());
    }
    hasher.update(b"\n");
    hasher.update(actor.unwrap_or("").as_bytes());
    hasher.update(b"\n");
    hasher.update(action.as_bytes());
    hasher.update(b"\n");
    hasher.update(subject.as_bytes());
    hasher.update(b"\n");
    hasher.update(details.as_bytes());
    hasher.finalize().as_bytes().to_vec()
}

impl Db {
    /// Appends an entry to the audit log, chaining it onto the previous one.
    pub async fn audit_append(
        &self,
        actor_id: Option<i64>,
        actor: Option<&str>,
        action: &str,
        subject: &str,
        details: &Value,
    ) -> Result<(), DbError> {
        let _guard = self.audit_lock.lock().await;
        let mut conn = self.pool.acquire().await?;
        append_chained(&mut conn, actor_id, actor, action, subject, details).await
    }

    /// Appends an audit entry on an existing connection (used to make a
    /// multi-statement operation atomic — see [`Db::record_change`]).
    pub(crate) async fn audit_append_on(
        &self,
        conn: &mut SqliteConnection,
        actor_id: Option<i64>,
        actor: Option<&str>,
        action: &str,
        subject: &str,
        details: &Value,
    ) -> Result<(), DbError> {
        append_chained(conn, actor_id, actor, action, subject, details).await
    }
}

/// Chains and inserts an audit row on `conn` (the caller owns the transaction).
async fn append_chained(
    conn: &mut SqliteConnection,
    actor_id: Option<i64>,
    actor: Option<&str>,
    action: &str,
    subject: &str,
    details: &Value,
) -> Result<(), DbError> {
    let details = details.to_string();
    let ts = now_millis();
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    let prev_hash = prev.unwrap_or_default();
    let hash = chain_hash(&prev_hash, ts, actor_id, actor, action, subject, &details);
    sqlx::query(
        "INSERT INTO audit_log (ts, actor_id, actor, action, subject, details, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(ts)
    .bind(actor_id)
    .bind(actor)
    .bind(action)
    .bind(subject)
    .bind(&details)
    .bind(&prev_hash)
    .bind(&hash)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

impl Db {
    /// Lists audit entries newest first, optionally before `before` (id).
    pub async fn audit_list(
        &self,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Vec<AuditEntry>, DbError> {
        self.audit_page(AuditPageQuery {
            limit,
            before,
            action: None,
            subject: None,
        })
        .await
    }

    /// Lists audit entries newest first with optional exact-match filters.
    pub async fn audit_page(&self, query: AuditPageQuery<'_>) -> Result<Vec<AuditEntry>, DbError> {
        let limit = query.limit.clamp(1, 1000);
        Ok(sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log
             WHERE (? IS NULL OR id < ?)
               AND (? IS NULL OR action = ?)
               AND (? IS NULL OR subject = ?)
             ORDER BY id DESC LIMIT ?",
        )
        .bind(query.before)
        .bind(query.before)
        .bind(query.action)
        .bind(query.action)
        .bind(query.subject)
        .bind(query.subject)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The current retention anchor, if entries have been pruned.
    pub async fn audit_anchor(&self) -> Result<Option<AuditAnchor>, DbError> {
        Ok(sqlx::query_as::<_, AuditAnchor>(
            "SELECT pruned_through, hash, pruned_entries, updated_at
             FROM audit_anchor WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Exports entries up to `before` as JSONL and prunes them, recording an
    /// anchor so the retained tail still verifies.
    ///
    /// The export is written and fsynced before the delete commits. At least
    /// the newest entry is always retained, so SQLite cannot reuse its id
    /// after the table becomes empty.
    pub async fn audit_export_and_prune(
        &self,
        before: i64,
        to: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let _guard = self.audit_lock.lock().await;
        if before <= 0 {
            return Err(DbError::Audit(
                "--before must be a positive entry id".into(),
            ));
        }
        if tokio::fs::try_exists(to).await? {
            return Err(DbError::Audit(format!(
                "refusing to overwrite existing export {}",
                to.display()
            )));
        }
        if let Some(parent) = to.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }
        let Some(file_name) = to.file_name().and_then(|name| name.to_str()) else {
            return Err(DbError::Audit("export path has no filename".into()));
        };
        let temp = to.with_file_name(format!(".{file_name}.tmp-{}", now_millis()));
        let result = self.audit_export_and_prune_inner(before, to, &temp).await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temp).await;
        }
        result
    }

    async fn audit_export_and_prune_inner(
        &self,
        before: i64,
        to: &Path,
        temp: &Path,
    ) -> Result<AuditPruneReport, DbError> {
        let mut tx = self.pool.begin().await?;
        let anchor = sqlx::query_as::<_, AuditAnchor>(
            "SELECT pruned_through, hash, pruned_entries, updated_at
             FROM audit_anchor WHERE id = 1",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let from = anchor.as_ref().map(|a| a.pruned_through).unwrap_or(0);
        if before <= from {
            return Err(DbError::Audit(format!(
                "entries through {from} were already pruned"
            )));
        }
        let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
            .fetch_one(&mut *tx)
            .await?;
        let Some(max_id) = max_id else {
            return Err(DbError::Audit("the audit log is empty".into()));
        };
        if before >= max_id {
            return Err(DbError::Audit(format!(
                "refusing to prune the newest entry; use --before less than {max_id}"
            )));
        }

        let mut expected_prev = anchor
            .as_ref()
            .map(|anchor| anchor.hash.clone())
            .unwrap_or_default();
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .await?;
        let mut exported = 0u64;
        let mut last_id = 0i64;
        let mut last_hash = Vec::new();
        {
            let mut rows = sqlx::query_as::<_, AuditEntry>(
                "SELECT * FROM audit_log WHERE id > ? AND id <= ? ORDER BY id",
            )
            .bind(from)
            .bind(before)
            .fetch(&mut *tx);
            while let Some(row) = rows.next().await {
                let row = row?;
                let expected = chain_hash(
                    &expected_prev,
                    row.ts,
                    row.actor_id,
                    row.actor.as_deref(),
                    &row.action,
                    &row.subject,
                    &row.details,
                );
                if row.prev_hash != expected_prev || row.hash != expected {
                    return Err(DbError::Audit(format!(
                        "chain mismatch at audit entry {}; refusing to prune",
                        row.id
                    )));
                }
                let details = serde_json::from_str(&row.details)
                    .unwrap_or_else(|_| Value::String(row.details.clone()));
                let export = AuditExportEntry {
                    id: row.id,
                    ts: row.ts,
                    actor_id: row.actor_id,
                    actor: row.actor.as_deref(),
                    action: &row.action,
                    subject: &row.subject,
                    details,
                    details_raw: &row.details,
                    prev_hash: hex::encode(&row.prev_hash),
                    hash: hex::encode(&row.hash),
                };
                let mut line = serde_json::to_vec(&export)
                    .map_err(|error| DbError::Audit(error.to_string()))?;
                line.push(b'\n');
                file.write_all(&line).await?;
                exported += 1;
                last_id = row.id;
                last_hash = row.hash.clone();
                expected_prev = row.hash;
            }
        }
        if exported == 0 {
            return Err(DbError::Audit(format!(
                "no audit entries found between {from} and {before}"
            )));
        }
        // The retained tail must link to the anchor we are about to write.
        let next_prev: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT prev_hash FROM audit_log WHERE id > ? ORDER BY id LIMIT 1")
                .bind(before)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(next_prev) = next_prev
            && next_prev != last_hash
        {
            return Err(DbError::Audit(
                "retained audit tail does not link to the pruned prefix".into(),
            ));
        }

        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(temp, to).await?;

        sqlx::query("DELETE FROM audit_log WHERE id <= ?")
            .bind(last_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_anchor (id, pruned_through, hash, pruned_entries, updated_at)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 pruned_through = excluded.pruned_through,
                 hash = excluded.hash,
                 pruned_entries = audit_anchor.pruned_entries + excluded.pruned_entries,
                 updated_at = excluded.updated_at",
        )
        .bind(last_id)
        .bind(&last_hash)
        .bind(exported as i64)
        .bind(now_millis())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(AuditPruneReport {
            exported,
            pruned_through: last_id,
            anchor_hash: hex::encode(last_hash),
        })
    }

    /// Recomputes the retained chain, starting at the retention anchor.
    pub async fn audit_verify(&self) -> Result<AuditVerify, DbError> {
        let anchor = self.audit_anchor().await?;
        let from = anchor.as_ref().map(|a| a.pruned_through).unwrap_or(0);
        let mut expected_prev = anchor.map(|a| a.hash).unwrap_or_default();
        let mut rows =
            sqlx::query_as::<_, AuditEntry>("SELECT * FROM audit_log WHERE id > ? ORDER BY id")
                .bind(from)
                .fetch(&self.pool);
        let mut entries = 0;
        while let Some(row) = rows.next().await {
            let row = row?;
            entries += 1;
            let expected = chain_hash(
                &expected_prev,
                row.ts,
                row.actor_id,
                row.actor.as_deref(),
                &row.action,
                &row.subject,
                &row.details,
            );
            if row.prev_hash != expected_prev || row.hash != expected {
                return Ok(AuditVerify {
                    entries,
                    first_bad: Some(row.id),
                });
            }
            expected_prev = row.hash.clone();
        }
        Ok(AuditVerify {
            entries,
            first_bad: None,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use serde_json::{Value, json};

    use crate::Db;

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn appends_chain_and_verify() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        db.audit_append(
            Some(user.id),
            None,
            "file.upsert",
            "/a.txt",
            &json!({"size": 3}),
        )
        .await
        .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "bob", &json!({}))
            .await
            .unwrap();
        db.audit_append(Some(user.id), None, "auth.login", "alice", &json!({}))
            .await
            .unwrap();

        let verify = db.audit_verify().await.unwrap();
        assert_eq!(
            verify,
            crate::audit::AuditVerify {
                entries: 3,
                first_bad: None
            }
        );

        let list = db.audit_list(10, None).await.unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].action, "auth.login");
        assert_eq!(list[2].action, "file.upsert");
        assert!(list[0].prev_hash == list[1].hash);

        let older = db.audit_list(10, Some(list[1].id)).await.unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].action, "file.upsert");
    }

    #[tokio::test]
    async fn pages_can_filter_by_action_and_subject() {
        let (_dir, db) = db().await;
        db.audit_append(None, Some("cli"), "group.add", "team", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "group.add", "ops", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "team", &json!({}))
            .await
            .unwrap();

        let groups = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: None,
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|entry| entry.action == "group.add"));

        let team = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: None,
                action: None,
                subject: Some("team"),
            })
            .await
            .unwrap();
        assert_eq!(team.len(), 2);
        assert!(team.iter().all(|entry| entry.subject == "team"));

        let first_page = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 1,
                before: None,
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].subject, "ops");
        let second_page = db
            .audit_page(crate::audit::AuditPageQuery {
                limit: 10,
                before: Some(first_page[0].id),
                action: Some("group.add"),
                subject: None,
            })
            .await
            .unwrap();
        assert_eq!(second_page.len(), 1);
        assert_eq!(second_page[0].subject, "team");
    }

    #[tokio::test]
    async fn tampering_breaks_the_chain() {
        let (_dir, db) = db().await;
        db.audit_append(None, Some("cli"), "user.add", "alice", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "bob", &json!({}))
            .await
            .unwrap();
        db.audit_append(None, Some("cli"), "user.add", "carol", &json!({}))
            .await
            .unwrap();
        assert_eq!(db.audit_verify().await.unwrap().first_bad, None);

        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(2));
        assert_eq!(verify.entries, 2);
    }

    #[tokio::test]
    async fn deleting_an_entry_breaks_the_chain() {
        let (_dir, db) = db().await;
        for name in ["a", "b", "c"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM audit_log WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(db.audit_verify().await.unwrap().first_bad, Some(3));
    }

    #[tokio::test]
    async fn export_and_prune_records_an_anchor_that_verifies() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c", "d", "e"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        let report = db.audit_export_and_prune(3, &path).await.unwrap();
        assert_eq!(report.exported, 3);
        assert_eq!(report.pruned_through, 3);
        assert_eq!(report.anchor_hash.len(), 64);

        let export = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(export.lines().count(), 3);
        let first: Value = serde_json::from_str(export.lines().next().unwrap()).unwrap();
        assert_eq!(first["subject"], "a");
        assert_eq!(first["hash"].as_str().unwrap().len(), 64);
        assert!(first["details_raw"].is_string());

        let anchor = db.audit_anchor().await.unwrap().unwrap();
        assert_eq!(anchor.pruned_through, 3);
        assert_eq!(anchor.pruned_entries, 3);
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.entries, 2);
        assert_eq!(verify.first_bad, None);

        db.audit_append(None, Some("cli"), "user.add", "f", &json!({}))
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.entries, 3);
        assert_eq!(verify.first_bad, None);
    }

    #[tokio::test]
    async fn prune_refuses_newest_entry_and_existing_export() {
        let (dir, db) = db().await;
        for name in ["a", "b"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "keep me").unwrap();
        assert!(db.audit_export_and_prune(1, &path).await.is_err());
        std::fs::remove_file(&path).unwrap();

        // Keeping the newest row is mandatory.
        assert!(db.audit_export_and_prune(2, &path).await.is_err());
        assert!(db.audit_anchor().await.unwrap().is_none());
        assert_eq!(db.audit_list(10, None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn prune_refuses_a_tampered_prefix() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 2")
            .execute(db.pool())
            .await
            .unwrap();
        let path = dir.path().join("audit.jsonl");
        assert!(db.audit_export_and_prune(2, &path).await.is_err());
        assert!(db.audit_anchor().await.unwrap().is_none());
        assert_eq!(db.audit_list(10, None).await.unwrap().len(), 3);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn verify_checks_the_tail_against_the_anchor() {
        let (dir, db) = db().await;
        for name in ["a", "b", "c", "d"] {
            db.audit_append(None, Some("cli"), "user.add", name, &json!({}))
                .await
                .unwrap();
        }
        let path = dir.path().join("audit.jsonl");
        db.audit_export_and_prune(2, &path).await.unwrap();
        sqlx::query("UPDATE audit_log SET subject = 'mallory' WHERE id = 3")
            .execute(db.pool())
            .await
            .unwrap();
        let verify = db.audit_verify().await.unwrap();
        assert_eq!(verify.first_bad, Some(3));
    }
}
