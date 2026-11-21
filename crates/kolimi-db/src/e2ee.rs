//! E2EE key storage (RFC 0007): keyrings and per-file wrapped keys.
//!
//! Everything stored here is opaque to the server: a keyring is the
//! client's JSON of wrapped master-key copies, and a file key is a
//! wrapped per-file key. Neither can be used without the user's secret.

use std::collections::HashMap;

use crate::{Db, DbError, now_millis};

/// Maximum keyring size accepted by [`Db::set_keyring`].
pub const MAX_KEYRING_BYTES: usize = 16 * 1024;
/// Maximum wrapped file key size accepted by [`Db::set_file_key`].
pub const MAX_WRAPPED_KEY_BYTES: usize = 1024;

impl Db {
    /// Stores (or replaces) a user's keyring without concurrency checks.
    ///
    /// Used by tests and internal seeding; HTTP callers use
    /// [`Db::set_keyring_checked`].
    pub async fn set_keyring(&self, user_id: i64, keyring: &str) -> Result<(), DbError> {
        if keyring.is_empty() || keyring.len() > MAX_KEYRING_BYTES {
            return Err(DbError::Conflict("keyring size".to_string()));
        }
        sqlx::query(
            "INSERT INTO e2ee_keyrings (user_id, keyring, updated_at, epoch) VALUES (?, ?, ?, 0)
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

    /// Stores a keyring, enforcing create-or-replace concurrency.
    ///
    /// `if_epoch = None` means "create only": it fails if a keyring already
    /// exists, which closes the race between two first-time setups. Otherwise
    /// it must equal the current epoch (optimistic concurrency), and the new
    /// epoch must not move backwards, so replaying an old keyring cannot
    /// resurrect a rotated-away secret.
    pub async fn set_keyring_checked(
        &self,
        user_id: i64,
        keyring: &str,
        epoch: u64,
        if_epoch: Option<u64>,
    ) -> Result<(), DbError> {
        if keyring.is_empty() || keyring.len() > MAX_KEYRING_BYTES {
            return Err(DbError::Conflict("keyring size".to_string()));
        }
        let mut tx = self.begin_write().await?;
        let current: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM e2ee_keyrings WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        match current {
            None => {
                if if_epoch.is_some() {
                    return Err(DbError::Conflict(
                        "keyring does not exist; reload before saving".to_string(),
                    ));
                }
                sqlx::query(
                    "INSERT INTO e2ee_keyrings (user_id, keyring, updated_at, epoch)
                     VALUES (?, ?, ?, ?)",
                )
                .bind(user_id)
                .bind(keyring)
                .bind(now_millis())
                .bind(i64::try_from(epoch).unwrap_or(i64::MAX))
                .execute(&mut *tx)
                .await?;
            }
            Some(current) => {
                let current = u64::try_from(current).unwrap_or(0);
                let Some(expected) = if_epoch else {
                    return Err(DbError::Conflict(
                        "keyring already exists; reload before saving".to_string(),
                    ));
                };
                if expected != current {
                    return Err(DbError::Conflict(
                        "keyring changed since it was loaded; reload before saving".to_string(),
                    ));
                }
                if epoch < current {
                    return Err(DbError::Conflict(
                        "stale keyring epoch; refusing to roll back".to_string(),
                    ));
                }
                let result = sqlx::query(
                    "UPDATE e2ee_keyrings SET keyring = ?, updated_at = ?, epoch = ?
                     WHERE user_id = ? AND epoch = ?",
                )
                .bind(keyring)
                .bind(now_millis())
                .bind(i64::try_from(epoch).unwrap_or(i64::MAX))
                .bind(user_id)
                .bind(i64::try_from(current).unwrap_or(i64::MAX))
                .execute(&mut *tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(DbError::Conflict(
                        "keyring changed while saving; reload before saving".to_string(),
                    ));
                }
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The stored keyring epoch, if a keyring exists.
    pub async fn keyring_epoch(&self, user_id: i64) -> Result<Option<u64>, DbError> {
        let epoch: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM e2ee_keyrings WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(epoch.and_then(|value| u64::try_from(value).ok()))
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
        // The wrapped blob is a marker for "this node is encrypted", not a
        // second copy of the file key: a write recipient re-wraps the key
        // under their own master on every edit, while group members decrypt
        // through the MLS keyring. Overwriting is therefore expected.
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

    /// Stores the wrapped share metadata (display name + optional folder
    /// name key) of `node_id` for one recipient.
    pub async fn set_share_name(
        &self,
        node_id: i64,
        recipient_id: i64,
        wrapped: &[u8],
    ) -> Result<(), DbError> {
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_KEY_BYTES {
            return Err(DbError::Conflict("share name size".to_string()));
        }
        sqlx::query(
            "INSERT INTO e2ee_share_names (node_id, recipient_id, wrapped, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(node_id, recipient_id) DO UPDATE SET wrapped = excluded.wrapped,
                 created_at = excluded.created_at",
        )
        .bind(node_id)
        .bind(recipient_id)
        .bind(wrapped)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns the wrapped share metadata of `node_id` for one recipient.
    pub async fn share_name(
        &self,
        node_id: i64,
        recipient_id: i64,
    ) -> Result<Option<Vec<u8>>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT wrapped FROM e2ee_share_names WHERE node_id = ? AND recipient_id = ?",
        )
        .bind(node_id)
        .bind(recipient_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Returns wrapped share metadata for many nodes at once.
    pub async fn share_names(
        &self,
        recipient_id: i64,
        node_ids: &[i64],
    ) -> Result<HashMap<i64, Vec<u8>>, DbError> {
        let mut out = HashMap::new();
        for chunk in node_ids.chunks(500) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT node_id, wrapped FROM e2ee_share_names
                 WHERE recipient_id = ? AND node_id IN ({placeholders})"
            );
            let mut query =
                sqlx::query_as::<_, (i64, Vec<u8>)>(sqlx::AssertSqlSafe(sql)).bind(recipient_id);
            for node_id in chunk {
                query = query.bind(node_id);
            }
            for (node_id, wrapped) in query.fetch_all(&self.pool).await? {
                out.insert(node_id, wrapped);
            }
        }
        Ok(out)
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

    /// Stores a user's X25519 identity.
    ///
    /// The identity is created once: a session alone must not be able to
    /// replace the key that other users wrap file keys to. An identical
    /// retry is accepted; any other change is a conflict. Rotation needs a
    /// separate recovery flow that proves possession of the old key.
    pub async fn set_identity(
        &self,
        user_id: i64,
        public_key: &[u8],
        wrapped_private: &[u8],
    ) -> Result<(), DbError> {
        if public_key.len() != 32 || wrapped_private.is_empty() || wrapped_private.len() > 1024 {
            return Err(DbError::Conflict("identity size".to_string()));
        }
        let inserted = sqlx::query(
            "INSERT INTO e2ee_identities (user_id, public_key, wrapped_private, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(user_id) DO NOTHING",
        )
        .bind(user_id)
        .bind(public_key)
        .bind(wrapped_private)
        .bind(now_millis())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(());
        }
        let existing: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT public_key, wrapped_private FROM e2ee_identities WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        match existing {
            Some((stored_public, stored_wrapped))
                if stored_public == public_key && stored_wrapped == wrapped_private =>
            {
                Ok(())
            }
            Some(_) => Err(DbError::Conflict(
                "identity is already set; rotation requires recovery".to_string(),
            )),
            None => Err(DbError::Conflict(
                "identity changed concurrently; retry".to_string(),
            )),
        }
    }

    /// A user's identity: (public key, wrapped private key).
    pub async fn identity(&self, user_id: i64) -> Result<Option<(Vec<u8>, Vec<u8>)>, DbError> {
        Ok(sqlx::query_as(
            "SELECT public_key, wrapped_private FROM e2ee_identities WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// A user's published public key.
    pub async fn public_key(&self, user_id: i64) -> Result<Option<Vec<u8>>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT public_key FROM e2ee_identities WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Stores (or replaces) a wrapped file key for one recipient.
    pub async fn set_share_key(
        &self,
        node_id: i64,
        recipient_id: i64,
        wrapped_key: &[u8],
    ) -> Result<(), DbError> {
        if wrapped_key.is_empty() || wrapped_key.len() > 1024 {
            return Err(DbError::Conflict("share key size".to_string()));
        }
        sqlx::query(
            "INSERT INTO e2ee_share_keys (node_id, recipient_id, wrapped_key, created_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(node_id, recipient_id) DO UPDATE SET wrapped_key = excluded.wrapped_key,
                 created_at = excluded.created_at",
        )
        .bind(node_id)
        .bind(recipient_id)
        .bind(wrapped_key)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The wrapped file key stored for one recipient.
    pub async fn share_key(
        &self,
        node_id: i64,
        recipient_id: i64,
    ) -> Result<Option<Vec<u8>>, DbError> {
        Ok(sqlx::query_scalar(
            "SELECT wrapped_key FROM e2ee_share_keys WHERE node_id = ? AND recipient_id = ?",
        )
        .bind(node_id)
        .bind(recipient_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Removes the share keys for one (node, recipient) pair.
    pub async fn delete_share_keys(&self, node_id: i64, recipient_id: i64) -> Result<u64, DbError> {
        let result =
            sqlx::query("DELETE FROM e2ee_share_keys WHERE node_id = ? AND recipient_id = ?")
                .bind(node_id)
                .bind(recipient_id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected())
    }

    /// Removes every wrapped key for a node (e.g. a revoked group share).
    pub async fn delete_share_keys_for_node(&self, node_id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM e2ee_share_keys WHERE node_id = ?")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Removes a member's wrapped keys for every node shared to a group
    /// (called when the member leaves the group).
    pub async fn delete_share_keys_for_group_member(
        &self,
        group_id: i64,
        user_id: i64,
    ) -> Result<u64, DbError> {
        let result = sqlx::query(
            "DELETE FROM e2ee_share_keys
             WHERE recipient_id = ?
               AND node_id IN (
                   SELECT node_id FROM shares
                   WHERE kind = 'group' AND recipient_group_id = ?
               )",
        )
        .bind(user_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
    async fn share_names_load_in_one_batch() {
        let (_dir, db) = db().await;
        let alice = db.create_user("alice", "hash-a").await.unwrap();
        let bob = db.create_user("bob", "hash-b").await.unwrap();
        let root = db.root_node(alice.id).await.unwrap();
        let first = db
            .insert_node(alice.id, Some(root.id), "one.txt", "file", None, 0, 0)
            .await
            .unwrap();
        let second = db
            .insert_node(alice.id, Some(root.id), "two.txt", "file", None, 0, 0)
            .await
            .unwrap();
        db.set_share_name(first.id, bob.id, &[1, 2, 3])
            .await
            .unwrap();
        db.set_share_name(second.id, bob.id, &[4, 5, 6])
            .await
            .unwrap();

        let names = db
            .share_names(bob.id, &[first.id, second.id])
            .await
            .unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(names[&first.id], vec![1, 2, 3]);
        assert_eq!(names[&second.id], vec![4, 5, 6]);
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

        // Write recipients re-wrap the opaque marker on every edit.
        db.set_file_key(user.id, file.id, &[4, 5, 6]).await.unwrap();
        assert_eq!(
            db.file_key(file.id).await.unwrap().as_deref(),
            Some(&[4u8, 5, 6][..])
        );

        db.delete_node(user.id, file.id).await.unwrap();
        assert!(!db.is_encrypted(file.id).await.unwrap());
    }
}
