//! MLS group state (RFC 9420) for encrypted share roots.
//!
//! Everything here is opaque to the server: key packages, protocol
//! messages and the encrypted share keyring. The only logic is ordering,
//! epoch monotonicity and optimistic concurrency for the keyring.

use sqlx::FromRow;

use crate::{Db, DbError, now_millis};

/// A published device key package.
#[derive(Debug, Clone, FromRow)]
pub struct MlsKeyPackage {
    pub id: i64,
    pub user_id: i64,
    pub device_id: String,
    pub payload: Vec<u8>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// The MLS group attached to a node.
#[derive(Debug, Clone, FromRow)]
pub struct MlsGroup {
    pub node_id: i64,
    pub mls_group_id: Vec<u8>,
    pub epoch: i64,
    pub updated_at: i64,
}

/// One ordered protocol message.
#[derive(Debug, Clone, FromRow)]
pub struct MlsMessage {
    pub seq: i64,
    pub epoch: i64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub sender_id: i64,
    pub created_at: i64,
}

/// The current encrypted share keyring.
#[derive(Debug, Clone, FromRow)]
pub struct MlsKeyring {
    pub epoch: i64,
    pub payload: Vec<u8>,
    pub updated_by: i64,
    pub updated_at: i64,
    pub revision: i64,
}

impl Db {
    /// Publishes (or replaces) one device's key package.
    pub async fn set_mls_key_package(
        &self,
        user_id: i64,
        device_id: &str,
        payload: &[u8],
        expires_at: Option<i64>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO mls_key_packages (user_id, device_id, payload, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(payload)
        .bind(now_millis())
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists one user's unconsumed, unexpired key packages (public material).
    pub async fn mls_key_packages(&self, user_id: i64) -> Result<Vec<MlsKeyPackage>, DbError> {
        Ok(sqlx::query_as::<_, MlsKeyPackage>(
            "SELECT id, user_id, device_id, payload, created_at, expires_at
             FROM mls_key_packages
             WHERE user_id = ? AND consumed_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)
             ORDER BY id",
        )
        .bind(user_id)
        .bind(now_millis())
        .fetch_all(&self.pool)
        .await?)
    }

    /// Records the epoch this device has successfully processed.
    ///
    /// Reports are monotonic: a stale report cannot lower the recorded epoch.
    /// A report for an epoch beyond the group's current epoch is rejected.
    pub async fn report_mls_epoch(
        &self,
        node_id: i64,
        user_id: i64,
        device_id: &str,
        epoch: i64,
    ) -> Result<bool, DbError> {
        let Some(group) = self.mls_group(node_id).await? else {
            return Err(DbError::NotFound("mls group".to_string()));
        };
        if epoch < 0 || epoch > group.epoch {
            return Err(DbError::Conflict(format!(
                "epoch {epoch} is outside the group epoch 0..={}",
                group.epoch
            )));
        }
        let result = sqlx::query(
            "INSERT INTO mls_member_epochs (node_id, user_id, device_id, last_epoch, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(node_id, user_id, device_id) DO UPDATE SET
                 last_epoch = MAX(mls_member_epochs.last_epoch, excluded.last_epoch),
                 updated_at = excluded.updated_at",
        )
        .bind(node_id)
        .bind(user_id)
        .bind(device_id)
        .bind(epoch)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Prunes MLS protocol messages and old keyrings.
    ///
    /// `message_cutoff` is the age floor (messages newer than this are kept),
    /// and `report_cutoff` ignores stale device reports so an abandoned
    /// device cannot block pruning forever. A node is pruned only when at
    /// least one fresh report exists and every fresh reporter is past the
    /// deleted epochs.
    pub async fn prune_mls_messages(
        &self,
        message_cutoff: i64,
        report_cutoff: i64,
    ) -> Result<(u64, u64), DbError> {
        let messages = sqlx::query(
            "DELETE FROM mls_messages
             WHERE created_at < ?
               AND epoch < COALESCE((
                   SELECT MIN(e.last_epoch) FROM mls_member_epochs e
                   WHERE e.node_id = mls_messages.node_id
                     AND e.updated_at >= ?
               ), 0)",
        )
        .bind(message_cutoff)
        .bind(report_cutoff)
        .execute(&self.pool)
        .await?
        .rows_affected();
        let keyrings = sqlx::query(
            "DELETE FROM mls_share_keyrings
             WHERE updated_at < ?
               AND epoch < COALESCE((
                   SELECT MIN(e.last_epoch) FROM mls_member_epochs e
                   WHERE e.node_id = mls_share_keyrings.node_id
                     AND e.updated_at >= ?
               ), 0)",
        )
        .bind(message_cutoff)
        .bind(report_cutoff)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok((messages, keyrings))
    }

    /// Removes consumed or expired key packages older than `cutoff`.
    ///
    /// Consumed packages are never served again; expired ones are already
    /// filtered from reads. Keeping a short grace period preserves useful
    /// diagnostics without letting the pool grow forever.
    pub async fn purge_mls_key_packages(&self, cutoff: i64) -> Result<u64, DbError> {
        let result = sqlx::query(
            "DELETE FROM mls_key_packages
             WHERE (consumed_at IS NOT NULL AND consumed_at < ?)
                OR (expires_at IS NOT NULL AND expires_at < ?)",
        )
        .bind(cutoff)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Marks key packages as used so they are never added to another group.
    pub async fn consume_mls_key_packages(&self, ids: &[i64]) -> Result<u64, DbError> {
        let mut consumed = 0u64;
        let now = now_millis();
        for id in ids {
            let result = sqlx::query(
                "UPDATE mls_key_packages SET consumed_at = ?
                 WHERE id = ? AND consumed_at IS NULL",
            )
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
            consumed += result.rows_affected();
        }
        Ok(consumed)
    }

    /// Creates the MLS group for a node, or returns the existing one.
    ///
    /// A different group id for an already-initialized node is a conflict:
    /// two clients must never race into two incompatible groups.
    pub async fn init_mls_group(
        &self,
        node_id: i64,
        mls_group_id: &[u8],
    ) -> Result<MlsGroup, DbError> {
        let now = now_millis();
        sqlx::query(
            "INSERT INTO mls_node_groups (node_id, mls_group_id, epoch, updated_at)
             VALUES (?, ?, 0, ?)
             ON CONFLICT(node_id) DO NOTHING",
        )
        .bind(node_id)
        .bind(mls_group_id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        let group = self
            .mls_group(node_id)
            .await?
            .ok_or_else(|| DbError::NotFound("mls group".to_string()))?;
        if group.mls_group_id != mls_group_id {
            return Err(DbError::Conflict(
                "mls group is already initialized with a different id".to_string(),
            ));
        }
        Ok(group)
    }

    /// Returns the node's MLS group, if initialized.
    pub async fn mls_group(&self, node_id: i64) -> Result<Option<MlsGroup>, DbError> {
        Ok(sqlx::query_as::<_, MlsGroup>(
            "SELECT node_id, mls_group_id, epoch, updated_at
             FROM mls_node_groups WHERE node_id = ?",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Appends a protocol message and returns its sequence number.
    ///
    /// Epochs may not go backwards. A `commit` at a newer epoch advances
    /// the group's stored epoch atomically with the insert.
    pub async fn append_mls_message(
        &self,
        node_id: i64,
        epoch: i64,
        kind: &str,
        payload: &[u8],
        sender_id: i64,
    ) -> Result<i64, DbError> {
        if !matches!(kind, "proposal" | "commit" | "welcome" | "application") {
            return Err(DbError::Conflict("invalid mls message kind".to_string()));
        }
        // Serialize writers before reading the epoch. A deferred transaction
        // could read epoch N, lose the write race, and then commit against a
        // snapshot that has already advanced.
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current: Option<(i64,)> =
            sqlx::query_as("SELECT epoch FROM mls_node_groups WHERE node_id = ?")
                .bind(node_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((current_epoch,)) = current else {
            return Err(DbError::NotFound("mls group".to_string()));
        };
        if epoch < current_epoch {
            return Err(DbError::Conflict(format!(
                "epoch {epoch} is older than the group epoch {current_epoch}"
            )));
        }
        if kind == "commit" && epoch != current_epoch + 1 {
            return Err(DbError::Conflict(
                "a commit must advance the epoch by exactly one".to_string(),
            ));
        }
        if kind != "commit" && epoch != current_epoch {
            return Err(DbError::Conflict(format!(
                "{kind} messages must use the current epoch {current_epoch}"
            )));
        }
        let (seq,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(seq), 0) + 1 FROM mls_messages WHERE node_id = ?")
                .bind(node_id)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query(
            "INSERT INTO mls_messages (node_id, seq, epoch, kind, payload, sender_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(node_id)
        .bind(seq)
        .bind(epoch)
        .bind(kind)
        .bind(payload)
        .bind(sender_id)
        .bind(now_millis())
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            // `MAX(seq) + 1` is computed inside the write transaction, but a
            // unique violation can still happen if another writer commits
            // between the read and the insert. Treat it as an optimistic
            // conflict so the client retries instead of seeing a 500.
            if let sqlx::Error::Database(database) = &error
                && database.is_unique_violation()
            {
                return DbError::Conflict(
                    "another MLS message won the sequence; fetch and retry".to_string(),
                );
            }
            DbError::from(error)
        })?;
        if kind == "commit" {
            // Compare-and-swap: only the commit that advances the epoch we
            // actually read may win. A second concurrent commit at the same
            // parent epoch rolls back instead of forking the group.
            let updated = sqlx::query(
                "UPDATE mls_node_groups
                 SET epoch = ?, updated_at = ?
                 WHERE node_id = ? AND epoch = ?",
            )
            .bind(epoch)
            .bind(now_millis())
            .bind(node_id)
            .bind(current_epoch)
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(DbError::Conflict(
                    "another commit advanced the MLS epoch; fetch the group and retry".to_string(),
                ));
            }
        }
        tx.commit().await?;
        Ok(seq)
    }

    /// Messages after `after_seq` in order.
    pub async fn mls_messages(
        &self,
        node_id: i64,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<MlsMessage>, DbError> {
        Ok(sqlx::query_as::<_, MlsMessage>(
            "SELECT seq, epoch, kind, payload, sender_id, created_at
             FROM mls_messages WHERE node_id = ? AND seq > ?
             ORDER BY seq LIMIT ?",
        )
        .bind(node_id)
        .bind(after_seq)
        .bind(limit.clamp(1, 1000))
        .fetch_all(&self.pool)
        .await?)
    }

    /// Stores the share keyring for the current epoch.
    ///
    /// `if_epoch` must match the group's epoch; a concurrent writer that
    /// lost the race gets `false` instead of overwriting newer keys.
    pub async fn set_mls_keyring(
        &self,
        node_id: i64,
        epoch: i64,
        payload: &[u8],
        updated_by: i64,
        if_epoch: i64,
        if_revision: Option<i64>,
    ) -> Result<bool, DbError> {
        let Some(group) = self.mls_group(node_id).await? else {
            return Err(DbError::NotFound("mls group".to_string()));
        };
        if group.epoch != if_epoch || epoch != if_epoch {
            return Ok(false);
        }
        let now = now_millis();
        match if_revision {
            Some(0) => {
                // The caller saw no keyring. Insert revision 1 atomically;
                // a concurrent creator makes this a conflict.
                let result = sqlx::query(
                    "INSERT INTO mls_share_keyrings
                         (node_id, epoch, payload, updated_by, updated_at, revision)
                     VALUES (?, ?, ?, ?, ?, 1)
                     ON CONFLICT(node_id, epoch) DO NOTHING",
                )
                .bind(node_id)
                .bind(epoch)
                .bind(payload)
                .bind(updated_by)
                .bind(now)
                .execute(&self.pool)
                .await?;
                Ok(result.rows_affected() == 1)
            }
            Some(revision) => {
                let result = sqlx::query(
                    "UPDATE mls_share_keyrings
                     SET payload = ?, updated_by = ?, updated_at = ?, revision = revision + 1
                     WHERE node_id = ? AND epoch = ? AND revision = ?",
                )
                .bind(payload)
                .bind(updated_by)
                .bind(now)
                .bind(node_id)
                .bind(epoch)
                .bind(revision)
                .execute(&self.pool)
                .await?;
                Ok(result.rows_affected() == 1)
            }
            None => {
                // Legacy unconditional write (still bumps the revision).
                let result = sqlx::query(
                    "INSERT INTO mls_share_keyrings
                         (node_id, epoch, payload, updated_by, updated_at, revision)
                     VALUES (?, ?, ?, ?, ?, 1)
                     ON CONFLICT(node_id, epoch) DO UPDATE SET
                         payload = excluded.payload,
                         updated_by = excluded.updated_by,
                         updated_at = excluded.updated_at,
                         revision = mls_share_keyrings.revision + 1",
                )
                .bind(node_id)
                .bind(epoch)
                .bind(payload)
                .bind(updated_by)
                .bind(now)
                .execute(&self.pool)
                .await?;
                Ok(result.rows_affected() == 1)
            }
        }
    }

    /// The **current epoch's** encrypted share keyring.
    ///
    /// Keyrings from older epochs are never served after a commit: the
    /// group's epoch and the keyring epoch must match, so a client cannot
    /// accidentally use a stale key set.
    pub async fn mls_keyring(&self, node_id: i64) -> Result<Option<MlsKeyring>, DbError> {
        Ok(sqlx::query_as::<_, MlsKeyring>(
            "SELECT k.epoch, k.payload, k.updated_by, k.updated_at, k.revision
             FROM mls_share_keyrings k
             JOIN mls_node_groups g ON g.node_id = k.node_id
             WHERE k.node_id = ? AND k.epoch = g.epoch",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    async fn test_db() -> (tempfile::TempDir, Db, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let user = db.create_user("alice", "hash").await.unwrap();
        (dir, db, user.id)
    }

    #[tokio::test]
    async fn purge_removes_only_old_key_packages() {
        let (_dir, db, user) = test_db().await;
        db.set_mls_key_package(user, "old", b"old", Some(1_000))
            .await
            .unwrap();
        db.set_mls_key_package(user, "live", b"live", None)
            .await
            .unwrap();

        assert_eq!(db.purge_mls_key_packages(2_000).await.unwrap(), 1);
        let left = db.mls_key_packages(user).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].device_id, "live");
    }

    #[tokio::test]
    async fn epoch_reports_allow_safe_message_pruning() {
        let (_dir, db, user) = test_db().await;
        let root = db.root_node(user).await.unwrap();
        db.init_mls_group(root.id, b"group-id").await.unwrap();
        for epoch in 1..=4 {
            db.append_mls_message(root.id, epoch, "commit", b"commit", user)
                .await
                .unwrap();
        }

        // Without reports, nothing is pruned.
        let now = now_millis();
        let (messages, _) = db
            .prune_mls_messages(now + 1_000, now - 1_000)
            .await
            .unwrap();
        assert_eq!(messages, 0);
        assert_eq!(db.mls_messages(root.id, 0, 10).await.unwrap().len(), 4);

        // A device at epoch 2 protects everything from epoch 2 onward.
        assert!(
            db.report_mls_epoch(root.id, user, "device-a", 2)
                .await
                .unwrap()
        );
        assert!(matches!(
            db.report_mls_epoch(root.id, user, "device-a", 5).await,
            Err(DbError::Conflict(_))
        ));
        assert!(matches!(
            db.report_mls_epoch(root.id, user, "device-a", -1).await,
            Err(DbError::Conflict(_))
        ));

        let (messages, keyrings) = db
            .prune_mls_messages(now + 1_000, now - 1_000)
            .await
            .unwrap();
        assert_eq!(messages, 1, "only the epoch below the minimum report goes");
        assert_eq!(keyrings, 0);
        let left = db.mls_messages(root.id, 0, 10).await.unwrap();
        assert_eq!(left.len(), 3);
        assert_eq!(left[0].epoch, 2);
    }

    #[tokio::test]
    async fn concurrent_commits_cannot_fork_the_epoch() {
        let (_dir, db, user) = test_db().await;
        let root = db.root_node(user).await.unwrap();
        db.init_mls_group(root.id, b"group-id").await.unwrap();

        let (first, second) = tokio::join!(
            db.append_mls_message(root.id, 1, "commit", b"first", user),
            db.append_mls_message(root.id, 1, "commit", b"second", user),
        );
        let success = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(success, 1, "exactly one commit may advance the epoch");
        assert!(
            matches!(first, Err(DbError::Conflict(_)))
                || matches!(second, Err(DbError::Conflict(_)))
        );

        let group = db.mls_group(root.id).await.unwrap().unwrap();
        assert_eq!(group.epoch, 1);
        let messages = db.mls_messages(root.id, 0, 10).await.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].epoch, 1);
    }
}
