//! Append-only, hash-chained audit log.
//!
//! Every entry hashes the previous entry's hash together with its own
//! fields, so removing, reordering, or editing any row breaks
//! [`Db::audit_verify`]. Appends are serialized through an in-process
//! mutex (SQLite has a single writer anyway), which keeps the chain
//! linear. The log is tamper-evident, not fail-closed: callers decide
//! whether an append failure aborts the audited operation.

use serde::Serialize;
use serde_json::Value;

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

/// Result of verifying the whole chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerify {
    /// Number of entries checked.
    pub entries: u64,
    /// First entry id whose hash or link does not match, if any.
    pub first_bad: Option<i64>,
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
        let details = details.to_string();
        let _guard = self.audit_lock.lock().await;
        let ts = now_millis();
        let prev: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_optional(&self.pool)
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists audit entries newest first, optionally before `before` (id).
    pub async fn audit_list(
        &self,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Vec<AuditEntry>, DbError> {
        let limit = limit.clamp(1, 1000);
        Ok(sqlx::query_as::<_, AuditEntry>(
            "SELECT * FROM audit_log
             WHERE (? IS NULL OR id < ?)
             ORDER BY id DESC LIMIT ?",
        )
        .bind(before)
        .bind(before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Recomputes the whole chain and reports the first inconsistency.
    pub async fn audit_verify(&self) -> Result<AuditVerify, DbError> {
        let rows: Vec<AuditEntry> = sqlx::query_as("SELECT * FROM audit_log ORDER BY id")
            .fetch_all(&self.pool)
            .await?;
        let mut expected_prev: Vec<u8> = Vec::new();
        let mut entries = 0;
        for row in &rows {
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

    use serde_json::json;

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
}
