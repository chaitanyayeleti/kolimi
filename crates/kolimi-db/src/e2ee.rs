//! E2EE key storage (RFC 0007): keyrings and per-file wrapped keys.
//!
//! Everything stored here is opaque to the server: a keyring is the
//! client's JSON of wrapped master-key copies, and a file key is a
//! wrapped per-file key. Neither can be used without the user's secret.

use crate::{Db, DbError, now_millis};

/// Maximum keyring size accepted by [`Db::set_keyring`].
pub const MAX_KEYRING_BYTES: usize = 16 * 1024;
/// Maximum wrapped file key size accepted by [`Db::set_file_key`].
pub const MAX_WRAPPED_KEY_BYTES: usize = 1024;

impl Db {
    /// Stores (or replaces) a user's keyring.
    pub async fn set_keyring(&self, user_id: i64, keyring: &str) -> Result<(), DbError> {
        if keyring.is_empty() || keyring.len() > MAX_KEYRING_BYTES {
            return Err(DbError::Conflict("keyring size".to_string()));
        }
        sqlx::query(
            "INSERT INTO e2ee_keyrings (user_id, keyring, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET keyring = excluded.keyring,
                 updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(keyring)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns a user's keyring, if one exists.
    pub async fn keyring(&self, user_id: i64) -> Result<Option<String>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT keyring FROM e2ee_keyrings WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Stores (or replaces) the wrapped key of an encrypted node.
    pub async fn set_file_key(
        &self,
        user_id: i64,
        node_id: i64,
        wrapped_key: &[u8],
    ) -> Result<(), DbError> {
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES {
            return Err(DbError::Conflict("wrapped key size".to_string()));
        }
        sqlx::query(
            "INSERT INTO e2ee_file_keys (node_id, user_id, wrapped_key, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(node_id) DO UPDATE SET wrapped_key = excluded.wrapped_key,
                 updated_at = excluded.updated_at",
        )
        .bind(node_id)
        .bind(user_id)
        .bind(wrapped_key)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the wrapped key of a node, if it is encrypted.
    pub async fn file_key(&self, node_id: i64) -> Result<Option<Vec<u8>>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT wrapped_key FROM e2ee_file_keys WHERE node_id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// All encrypted node ids of a user (for tree flags and guards).
    pub async fn encrypted_node_ids(&self, user_id: i64) -> Result<Vec<i64>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT node_id FROM e2ee_file_keys WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Whether a node is encrypted.
    pub async fn is_encrypted(&self, node_id: i64) -> Result<bool, DbError> {
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM e2ee_file_keys WHERE node_id = ?")
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(exists.is_some())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use crate::Db;

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn keyring_roundtrip_and_replace() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        assert!(db.keyring(user.id).await.unwrap().is_none());
        db.set_keyring(user.id, r#"{"version":1}"#).await.unwrap();
        assert_eq!(
            db.keyring(user.id).await.unwrap().as_deref(),
            Some(r#"{"version":1}"#)
        );
        db.set_keyring(user.id, r#"{"version":1,"wraps":[]}"#)
            .await
            .unwrap();
        assert_eq!(
            db.keyring(user.id).await.unwrap().as_deref(),
            Some(r#"{"version":1,"wraps":[]}"#)
        );
    }

    #[tokio::test]
    async fn file_keys_are_per_node_and_cascade() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let root = db.root_node(user.id).await.unwrap();
        let file = db
            .insert_node(user.id, Some(root.id), "secret.txt", "file", None, 0, 0)
            .await
            .unwrap();
        assert!(!db.is_encrypted(file.id).await.unwrap());
        db.set_file_key(user.id, file.id, &[1, 2, 3]).await.unwrap();
        assert!(db.is_encrypted(file.id).await.unwrap());
        assert_eq!(
            db.file_key(file.id).await.unwrap().as_deref(),
            Some(&[1u8, 2, 3][..])
        );
        assert_eq!(db.encrypted_node_ids(user.id).await.unwrap(), vec![file.id]);

        db.delete_node(user.id, file.id).await.unwrap();
        assert!(!db.is_encrypted(file.id).await.unwrap());
    }
}
