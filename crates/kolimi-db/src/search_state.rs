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
}
