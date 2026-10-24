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
        let mut tx = self.pool.begin().await?;
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
        .await?;
        if kind == "commit" && epoch > current_epoch {
            sqlx::query("UPDATE mls_node_groups SET epoch = ?, updated_at = ? WHERE node_id = ?")
                .bind(epoch)
                .bind(now_millis())
                .bind(node_id)
                .execute(&mut *tx)
                .await?;
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
