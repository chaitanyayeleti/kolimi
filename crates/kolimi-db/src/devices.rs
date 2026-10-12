//! Multi-device E2EE storage (RFC 0008): registered devices and the
//! enrollment handshake that transfers the (opaque) wrapped master key.
//!
//! The server stores the wrapped master key verbatim and cannot derive the
//! master key, the device keys, or any file key.

use crate::{Db, DbError, now_millis};

/// Maximum accepted device-enrollment wrapped key size.
pub const MAX_DEVICE_KEY_BYTES: usize = 1024;
/// An enrollment that is not approved within this window expires.
pub const ENROLLMENT_TTL_MILLIS: i64 = 15 * 60 * 1000;
/// Most pending enrollments one account may have at once.
pub const MAX_PENDING_ENROLLMENTS: i64 = 8;

/// A device registered to an account.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Device {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// Operator-visible label.
    pub name: String,
    /// X25519 public key of the device.
    pub public_key: Vec<u8>,
    /// Registration time in Unix milliseconds.
    pub created_at: i64,
    /// Last time the device was seen.
    pub last_seen_at: Option<i64>,
}

/// A pending (or approved) device enrollment.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Enrollment {
    /// Primary key (shown to the user as the enrollment code).
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// Label of the device requesting enrollment.
    pub device_name: String,
    /// X25519 public key of the new device.
    pub device_public_key: Vec<u8>,
    /// Master key wrapped for the new device; `None` until approved.
    pub wrapped_master_key: Option<Vec<u8>>,
    /// When an approving device uploaded the wrapped key.
    pub approved_at: Option<i64>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at: i64,
}

impl Db {
    /// Creates a pending enrollment, returning its id (the code).
    pub async fn create_enrollment(
        &self,
        user_id: i64,
        device_name: &str,
        device_public_key: &[u8],
    ) -> Result<i64, DbError> {
        if device_public_key.len() != 32 {
            return Err(DbError::Conflict("device public key length".to_string()));
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM e2ee_enrollments
             WHERE user_id = ? AND approved_at IS NULL AND expires_at > ?",
        )
        .bind(user_id)
        .bind(now_millis())
        .fetch_one(&self.pool)
        .await?;
        if pending >= MAX_PENDING_ENROLLMENTS {
            return Err(DbError::Conflict(
                "too many pending enrollments".to_string(),
            ));
        }
        let now = now_millis();
        let result = sqlx::query(
            "INSERT INTO e2ee_enrollments
                 (user_id, device_name, device_public_key, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(device_name)
        .bind(device_public_key)
        .bind(now)
        .bind(now + ENROLLMENT_TTL_MILLIS)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    /// Pending (unapproved, unexpired) enrollments for a user.
    pub async fn pending_enrollments(&self, user_id: i64) -> Result<Vec<Enrollment>, DbError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, device_name, device_public_key, wrapped_master_key,
                    approved_at, created_at, expires_at
             FROM e2ee_enrollments
             WHERE user_id = ? AND approved_at IS NULL AND expires_at > ?
             ORDER BY id",
        )
        .bind(user_id)
        .bind(now_millis())
        .fetch_all(&self.pool)
        .await?)
    }

    /// Fetches one enrollment belonging to the user.
    pub async fn enrollment(&self, user_id: i64, id: i64) -> Result<Option<Enrollment>, DbError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, device_name, device_public_key, wrapped_master_key,
                    approved_at, created_at, expires_at
             FROM e2ee_enrollments WHERE id = ? AND user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Records the wrapped master key for a pending enrollment. Returns
    /// `false` if it was already approved, expired, or does not exist.
    pub async fn approve_enrollment(
        &self,
        user_id: i64,
        id: i64,
        wrapped_master_key: &[u8],
    ) -> Result<bool, DbError> {
        if wrapped_master_key.is_empty() || wrapped_master_key.len() > MAX_DEVICE_KEY_BYTES {
            return Err(DbError::Conflict("wrapped key size".to_string()));
        }
        let result = sqlx::query(
            "UPDATE e2ee_enrollments
             SET wrapped_master_key = ?, approved_at = ?
             WHERE id = ? AND user_id = ? AND approved_at IS NULL AND expires_at > ?",
        )
        .bind(wrapped_master_key)
        .bind(now_millis())
        .bind(id)
        .bind(user_id)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Removes an enrollment (after the new device has collected the key).
    pub async fn delete_enrollment(&self, user_id: i64, id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM e2ee_enrollments WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Registers a device (idempotent on the same public key).
    pub async fn register_device(
        &self,
        user_id: i64,
        name: &str,
        public_key: &[u8],
    ) -> Result<i64, DbError> {
        if public_key.len() != 32 {
            return Err(DbError::Conflict("device public key length".to_string()));
        }
        let existing: Option<i64> =
            sqlx::query_scalar("SELECT id FROM e2ee_devices WHERE user_id = ? AND public_key = ?")
                .bind(user_id)
                .bind(public_key)
                .fetch_optional(&self.pool)
                .await?;
        if let Some(existing) = existing {
            sqlx::query("UPDATE e2ee_devices SET name = ?, last_seen_at = ? WHERE id = ?")
                .bind(name)
                .bind(now_millis())
                .bind(existing)
                .execute(&self.pool)
                .await?;
            return Ok(existing);
        }
        let result = sqlx::query(
            "INSERT INTO e2ee_devices (user_id, name, public_key, created_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(name)
        .bind(public_key)
        .bind(now_millis())
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    /// Lists a user's registered devices, newest first.
    pub async fn devices(&self, user_id: i64) -> Result<Vec<Device>, DbError> {
        Ok(sqlx::query_as(
            "SELECT id, user_id, name, public_key, created_at, last_seen_at
             FROM e2ee_devices WHERE user_id = ? ORDER BY id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Removes a device record.
    pub async fn delete_device(&self, user_id: i64, id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM e2ee_devices WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes expired enrollments (called by the janitor).
    pub async fn purge_expired_enrollments(&self) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM e2ee_enrollments WHERE expires_at < ?")
            .bind(now_millis())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
