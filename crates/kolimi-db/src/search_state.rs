//! Indexer progress tracking (M5).

use crate::{Db, DbError, now_millis};

impl Db {
    /// The last change-feed sequence the search indexer consumed for a
    /// user (0 when the index has never been built).
    pub async fn search_last_seq(&self, user_id: i64) -> Result<i64, DbError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT last_seq FROM search_state WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(seq,)| seq).unwrap_or(0))
    }

    /// Records the indexer's progress for a user.
    pub async fn set_search_last_seq(&self, user_id: i64, seq: i64) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO search_state (user_id, last_seq, updated_at) VALUES (?, ?, ?)
             ON CONFLICT (user_id) DO UPDATE SET last_seq = excluded.last_seq,
                                                 updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(seq)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Users with change-feed rows past their indexing cursor, least recently
    /// indexed first. The per-user `MAX(seq)` lookup uses the
    /// `(user_id, seq)` index, so this stays cheap even on a large feed.
    pub async fn users_with_pending_changes(&self, limit: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT u.id FROM users u
             LEFT JOIN search_state s ON s.user_id = u.id
             WHERE (SELECT MAX(seq) FROM changes c WHERE c.user_id = u.id)
                   > COALESCE(s.last_seq, 0)
             ORDER BY s.updated_at IS NOT NULL, s.updated_at ASC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_indexer_progress() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let user = db.create_user("alice", "hash").await.unwrap();
        assert_eq!(db.search_last_seq(user.id).await.unwrap(), 0);
        db.set_search_last_seq(user.id, 42).await.unwrap();
        assert_eq!(db.search_last_seq(user.id).await.unwrap(), 42);
        db.set_search_last_seq(user.id, 7).await.unwrap();
        assert_eq!(db.search_last_seq(user.id).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn only_users_with_pending_changes_are_scheduled() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let alice = db.create_user("alice", "hash-a").await.unwrap();
        let bob = db.create_user("bob", "hash-b").await.unwrap();
        assert!(db.users_with_pending_changes(10).await.unwrap().is_empty());

        db.record_change(alice.id, "/a.txt", "upsert", None, 1, 0, None)
            .await
            .unwrap();
        assert_eq!(
            db.users_with_pending_changes(10).await.unwrap(),
            vec![alice.id]
        );

        db.set_search_last_seq(alice.id, 1).await.unwrap();
        assert!(db.users_with_pending_changes(10).await.unwrap().is_empty());

        db.record_change(bob.id, "/b.txt", "upsert", None, 1, 0, None)
            .await
            .unwrap();
        assert_eq!(
            db.users_with_pending_changes(10).await.unwrap(),
            vec![bob.id]
        );
    }
}
