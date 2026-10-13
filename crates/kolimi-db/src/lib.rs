//! SQLite persistence for Kolimi: users, sessions, and the file tree.

use std::{path::Path, sync::Arc, time::Duration};

use serde::Serialize;
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

mod audit;
mod dav;
mod devices;
mod e2ee;
mod search_state;
mod sharing;
pub use audit::{AuditEntry, AuditVerify};
pub use dav::{DavChange, DavCollection, DavObject, DavObjectMeta};
pub use devices::{Device, Enrollment, MAX_DEVICE_KEY_BYTES};
pub use e2ee::{MAX_KEYRING_BYTES, MAX_WRAPPED_KEY_BYTES};
pub use sharing::{Group, LinkSession, ReceivedShare, ShareRow};

/// Current wall-clock time in Unix milliseconds.
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Errors returned by the database layer.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Underlying SQL error.
    #[error("sql error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// Migration failure.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// A uniqueness constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),
    /// The requested row does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The username is not acceptable.
    #[error("invalid username: {0}")]
    InvalidUsername(String),
}

/// A user account.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    /// Primary key.
    pub id: i64,
    /// Unique login name (case-insensitive).
    pub username: String,
    /// Argon2id PHC string; never exposed to clients.
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// Whether the user may manage other users.
    pub is_admin: bool,
    /// Whether the account is disabled.
    pub disabled: bool,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Per-user storage quota in bytes (`None` = server default, `0` = unlimited).
    pub quota_bytes: Option<i64>,
    /// Used storage bytes, maintained incrementally and reconciled by the janitor.
    pub used_bytes: i64,
    /// When `used_bytes` was last reconciled from disk.
    pub usage_updated_at: Option<i64>,
}

/// Sort key for the admin user list (`GET /api/users`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserSort {
    /// Account id (default).
    Id,
    /// Username.
    Username,
    /// Used storage bytes.
    UsedBytes,
    /// Per-user quota bytes.
    QuotaBytes,
}

/// Sort direction for the admin user list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Ascending (default).
    Asc,
    /// Descending.
    Desc,
}

/// Filter for the admin user list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserFilter {
    /// No filter (default).
    None,
    /// Only users at or above their effective quota.
    OverQuota,
    /// Only disabled accounts.
    Disabled,
    /// Only administrators.
    Admin,
}

/// A login session.
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// BLAKE3 hash of the session token.
    pub token_hash: Vec<u8>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at: i64,
    /// Last time the session was used.
    pub last_seen_at: i64,
}

/// A file or directory in a user's tree.
#[derive(Debug, Clone, FromRow)]
pub struct Node {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// Parent directory (`None` for the root).
    pub parent_id: Option<i64>,
    /// File or directory name (empty for the root).
    pub name: String,
    /// `"dir"` or `"file"`.
    pub kind: String,
    /// BLAKE3 content hash for files.
    pub content_id: Option<Vec<u8>>,
    /// Content size in bytes.
    pub size: i64,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
    /// When the node was moved to the trash (`None` = live).
    pub trashed_at: Option<i64>,
    /// Path the node had when it was trashed (for the trash view).
    pub original_path: Option<String>,
}

/// A historical version of a file.
#[derive(Debug, Clone, FromRow)]
pub struct VersionRow {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// The file this version belongs to.
    pub node_id: i64,
    /// BLAKE3 manifest identity of this version.
    pub content_id: Vec<u8>,
    /// Size in bytes.
    pub size: i64,
    /// When this version was superseded.
    pub created_at: i64,
}

/// One entry of a user's change feed.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ChangeRow {
    /// Monotonic per-user sequence number.
    pub seq: i64,
    /// Affected path.
    pub path: String,
    /// Previous path for moves.
    pub from_path: Option<String>,
    /// `upsert`, `delete`, or `move`.
    pub op: String,
    /// Content identity for files.
    #[serde(skip_serializing)]
    pub content_id: Option<Vec<u8>>,
    /// Size in bytes.
    pub size: i64,
    /// Event time in Unix milliseconds.
    pub modified_at: i64,
}

/// A registered passkey (WebAuthn credential).
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct PasskeyRow {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// User-chosen label.
    pub name: String,
    /// Serialized `webauthn_rs::Passkey`; never exposed via JSON.
    #[serde(skip_serializing)]
    pub credential: String,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last successful authentication time.
    pub last_used_at: Option<i64>,
}

/// A dead (user-defined) WebDAV property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadProp {
    /// XML namespace (empty string for no namespace).
    pub namespace: String,
    /// Local name.
    pub name: String,
    /// Text value (inner markup for non-text values).
    pub value: String,
}

/// One PROPPATCH operation, applied in document order.
#[derive(Debug, Clone)]
pub enum DeadPropOp {
    /// Set or replace a property.
    Set {
        /// XML namespace (empty string for no namespace).
        namespace: String,
        /// Local name.
        name: String,
        /// Value to store.
        value: String,
    },
    /// Remove a property if present.
    Remove {
        /// XML namespace (empty string for no namespace).
        namespace: String,
        /// Local name.
        name: String,
    },
}

/// Handle to the SQLite database.
#[derive(Debug, Clone)]
pub struct Db {
    pool: SqlitePool,
    audit_lock: Arc<tokio::sync::Mutex<()>>,
}

fn map_sqlx(e: sqlx::Error, what: &str) -> DbError {
    if let sqlx::Error::Database(db) = &e
        && db.is_unique_violation()
    {
        return DbError::Conflict(what.to_string());
    }
    DbError::Sqlx(e)
}

/// Validates a username: 1-64 chars of `[A-Za-z0-9._-]`.
pub fn validate_username(username: &str) -> Result<(), DbError> {
    if username.is_empty() || username.len() > 64 {
        return Err(DbError::InvalidUsername(username.to_string()));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(DbError::InvalidUsername(username.to_string()));
    }
    Ok(())
}

impl Db {
    /// Opens the database at `path`, creating it if needed, and runs migrations.
    pub async fn connect(path: &Path) -> Result<Self, DbError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            audit_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Raw pool access for tests and low-level helpers.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Stores (or replaces) a user's TOTP secret, resetting replay state.
    pub async fn set_totp_secret(&self, user_id: i64, secret: &str) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO totp_secrets (user_id, secret, created_at, last_step)
             VALUES (?, ?, ?, NULL)
             ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret,
                 created_at = excluded.created_at, last_step = NULL",
        )
        .bind(user_id)
        .bind(secret)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The user's TOTP secret and last consumed step, if enrolled.
    pub async fn totp_secret(
        &self,
        user_id: i64,
    ) -> Result<Option<(String, Option<i64>)>, DbError> {
        Ok(
            sqlx::query_as("SELECT secret, last_step FROM totp_secrets WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Consumes a TOTP time step; returns false if it was already used.
    pub async fn consume_totp_step(&self, user_id: i64, step: u64) -> Result<bool, DbError> {
        let result = sqlx::query(
            "UPDATE totp_secrets SET last_step = ?
             WHERE user_id = ? AND (last_step IS NULL OR last_step < ?)",
        )
        .bind(step as i64)
        .bind(user_id)
        .bind(step as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Disables TOTP: removes the secret and all recovery codes.
    pub async fn clear_totp(&self, user_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM totp_secrets WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Replaces all recovery codes with a fresh set of hashes.
    pub async fn replace_recovery_codes(
        &self,
        user_id: i64,
        hashes: &[Vec<u8>],
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        for hash in hashes {
            sqlx::query(
                "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
            )
            .bind(user_id)
            .bind(hash)
            .bind(now_millis())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Number of unused recovery codes.
    pub async fn count_recovery_codes(&self, user_id: i64) -> Result<i64, DbError> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(count)
    }

    /// Consumes one recovery code by hash; returns false if unknown/used.
    pub async fn consume_recovery_code(&self, user_id: i64, hash: &[u8]) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ? AND code_hash = ?")
            .bind(user_id)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The scrub cursor for a user (`None` = cycle finished / not started).
    pub async fn scrub_cursor(&self, user_id: i64) -> Result<Option<String>, DbError> {
        Ok(
            sqlx::query_scalar("SELECT cursor FROM scrub_state WHERE user_id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten(),
        )
    }

    /// Persists the scrub cursor (or clears it when the cycle finished).
    pub async fn set_scrub_cursor(
        &self,
        user_id: i64,
        cursor: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO scrub_state (user_id, cursor, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET cursor = excluded.cursor,
                 updated_at = excluded.updated_at",
        )
        .bind(user_id)
        .bind(cursor)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates a user plus their root directory. The first user becomes admin.
    pub async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, DbError> {
        validate_username(username)?;
        let now = now_millis();
        let mut tx = self.pool.begin().await?;
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await?;
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, password_hash, is_admin, created_at)
             VALUES (?, ?, ?, ?)
             RETURNING *",
        )
        .bind(username)
        .bind(password_hash)
        .bind(count == 0)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| map_sqlx(e, "username already exists"))?;
        sqlx::query(
            "INSERT INTO nodes (user_id, parent_id, name, kind, size, created_at, modified_at)
             VALUES (?, NULL, '', 'dir', 0, ?, ?)",
        )
        .bind(user.id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(user)
    }

    /// Finds a user by username (case-insensitively).
    pub async fn find_user(&self, username: &str) -> Result<Option<User>, DbError> {
        Ok(
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Fetches a user by id.
    pub async fn get_user(&self, user_id: i64) -> Result<Option<User>, DbError> {
        Ok(
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// A page of users with an admin-chosen sort, order, and filter.
    ///
    /// Keyset pagination (`after_id`) only applies to the default `Id`
    /// order; other orders return the first `limit` rows. `default_quota`
    /// is the server-wide quota in bytes (`0` = unlimited), used to decide
    /// which users are over quota when they have no per-user override.
    pub async fn users_page_sorted(
        &self,
        after_id: i64,
        limit: i64,
        sort: UserSort,
        order: SortOrder,
        filter: UserFilter,
        default_quota: u64,
    ) -> Result<Vec<User>, DbError> {
        let column = match sort {
            UserSort::Id => "id",
            UserSort::Username => "username",
            UserSort::UsedBytes => "used_bytes",
            UserSort::QuotaBytes => "COALESCE(quota_bytes, 0)",
        };
        let direction = match order {
            SortOrder::Asc => "ASC",
            SortOrder::Desc => "DESC",
        };
        let mut clauses: Vec<String> = Vec::new();
        if sort == UserSort::Id {
            clauses.push(match order {
                SortOrder::Asc => "id > ?".to_string(),
                SortOrder::Desc => "id < ?".to_string(),
            });
        }
        match filter {
            UserFilter::OverQuota => {
                // Effective quota: per-user override, else the server
                // default; `0` means unlimited (never over quota).
                let fallback = if default_quota == 0 {
                    i64::MAX
                } else {
                    default_quota as i64
                };
                clauses.push(format!(
                    "used_bytes >= (CASE WHEN quota_bytes IS NULL THEN {fallback} \
                     WHEN quota_bytes <= 0 THEN 9223372036854775807 ELSE quota_bytes END)"
                ));
            }
            UserFilter::Disabled => clauses.push("disabled = 1".to_string()),
            UserFilter::Admin => clauses.push("is_admin = 1".to_string()),
            UserFilter::None => {}
        }
        let mut sql = String::from("SELECT * FROM users");
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(&format!(" ORDER BY {column} {direction}, id ASC LIMIT ?"));

        let mut query = sqlx::query_as::<_, User>(sqlx::AssertSqlSafe(sql));
        if sort == UserSort::Id {
            query = query.bind(after_id);
        }
        query
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Lists all users ordered by name.
    pub async fn list_users(&self) -> Result<Vec<User>, DbError> {
        Ok(
            sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY username")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Removes the password hash, making the account passkey-only.
    ///
    /// Password login is rejected for accounts whose hash is empty; the
    /// caller must ensure at least one passkey is registered first.
    pub async fn clear_password(&self, username: &str) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE users SET password_hash = '' WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {username}")));
        }
        Ok(())
    }

    /// Replaces a user's password hash.
    pub async fn set_password(&self, username: &str, password_hash: &str) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
            .bind(password_hash)
            .bind(username)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {username}")));
        }
        Ok(())
    }

    /// Grants or revokes administrator rights.
    ///
    /// Revoking the last enabled administrator is refused so the server
    /// cannot be locked out of administration.
    pub async fn set_admin(&self, user_id: i64, is_admin: bool) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let Some(target) = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Err(DbError::NotFound(format!("user {user_id}")));
        };
        if !is_admin && target.is_admin && !target.disabled {
            let (others,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE id != ? AND is_admin = 1 AND disabled = 0",
            )
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
            if others == 0 {
                return Err(DbError::Conflict(
                    "cannot revoke the last administrator".to_string(),
                ));
            }
        }
        sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
            .bind(is_admin)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Enables or disables an account.
    ///
    /// Disabling drops the account's sessions immediately and is refused
    /// for the last enabled administrator.
    pub async fn set_disabled(&self, username: &str, disabled: bool) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let Some(target) = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Err(DbError::NotFound(format!("user {username}")));
        };
        if disabled && target.is_admin && !target.disabled {
            let (others,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE id != ? AND is_admin = 1 AND disabled = 0",
            )
            .bind(target.id)
            .fetch_one(&mut *tx)
            .await?;
            if others == 0 {
                return Err(DbError::Conflict(
                    "cannot disable the last administrator".to_string(),
                ));
            }
        }
        sqlx::query("UPDATE users SET disabled = ? WHERE id = ?")
            .bind(disabled)
            .bind(target.id)
            .execute(&mut *tx)
            .await?;
        if disabled {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(target.id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Deletes a user and everything they own.
    ///
    /// Foreign keys cascade to sessions, passkeys, nodes, shares, DAV
    /// collections, E2EE keys, TOTP and group memberships; audit entries
    /// keep their history with a null actor. The per-user blob directory
    /// must be removed by the caller (`BlobStore::remove_user`); garbage
    /// collection cannot reclaim it later because the janitor only visits
    /// users that still exist. Refused for the last enabled admin.
    pub async fn delete_user(&self, username: &str) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let Some(target) = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&mut *tx)
            .await?
        else {
            return Err(DbError::NotFound(format!("user {username}")));
        };
        if target.is_admin && !target.disabled {
            let (others,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE id != ? AND is_admin = 1 AND disabled = 0",
            )
            .bind(target.id)
            .fetch_one(&mut *tx)
            .await?;
            if others == 0 {
                return Err(DbError::Conflict(
                    "cannot delete the last administrator".to_string(),
                ));
            }
        }
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(target.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Adjusts a user's usage counter by `delta` bytes (clamped at zero).
    pub async fn add_used_bytes(&self, user_id: i64, delta: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET used_bytes = MAX(0, used_bytes + ?) WHERE id = ?")
            .bind(delta)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Overwrites a user's usage counter (reconciliation) and stamps the
    /// time it was measured.
    pub async fn set_used_bytes(&self, user_id: i64, bytes: u64, now: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET used_bytes = ?, usage_updated_at = ? WHERE id = ?")
            .bind(bytes.min(i64::MAX as u64) as i64)
            .bind(now)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Sets or clears a user's per-user quota (`None` = server default).
    pub async fn set_quota_bytes(&self, user_id: i64, quota: Option<i64>) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE users SET quota_bytes = ? WHERE id = ?")
            .bind(quota)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {user_id}")));
        }
        Ok(())
    }

    /// Ids of the users whose usage is least recently reconciled (never-
    /// reconciled first), for the janitor to recompute in bounded batches.
    pub async fn users_for_reconcile(&self, limit: i64) -> Result<Vec<i64>, DbError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT id FROM users
             ORDER BY usage_updated_at IS NOT NULL, usage_updated_at ASC
             LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Creates a login session.
    pub async fn create_session(
        &self,
        user_id: i64,
        token_hash: &[u8],
        expires_at: i64,
    ) -> Result<(), DbError> {
        let now = now_millis();
        sqlx::query(
            "INSERT INTO sessions (user_id, token_hash, created_at, expires_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(now)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Looks up a session by token hash.
    pub async fn find_session(&self, token_hash: &[u8]) -> Result<Option<Session>, DbError> {
        Ok(
            sqlx::query_as::<_, Session>("SELECT * FROM sessions WHERE token_hash = ?")
                .bind(token_hash)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Updates a session's last-seen timestamp.
    pub async fn touch_session(&self, session_id: i64, now: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE id = ?")
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deletes a session by token hash.
    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<(), DbError> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Drops every session belonging to a user, returning how many were
    /// removed. Used by account recovery so a lost/compromised credential
    /// cannot keep an existing session alive.
    pub async fn delete_user_sessions(&self, user_id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Deletes expired sessions, returning how many were removed.
    pub async fn delete_expired_sessions(&self, now: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Stores a new passkey for a user.
    pub async fn add_passkey(
        &self,
        user_id: i64,
        name: &str,
        credential: &str,
        now: i64,
    ) -> Result<PasskeyRow, DbError> {
        sqlx::query_as::<_, PasskeyRow>(
            "INSERT INTO passkeys (user_id, name, credential, created_at)
             VALUES (?, ?, ?, ?)
             RETURNING *",
        )
        .bind(user_id)
        .bind(name)
        .bind(credential)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "a passkey with that name already exists"))
    }

    /// Lists a user's passkeys, oldest first.
    pub async fn list_passkeys(&self, user_id: i64) -> Result<Vec<PasskeyRow>, DbError> {
        Ok(sqlx::query_as::<_, PasskeyRow>(
            "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at, id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Counts a user's passkeys.
    pub async fn count_passkeys(&self, user_id: i64) -> Result<i64, DbError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM passkeys WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Deletes one of a user's passkeys.
    pub async fn delete_passkey(&self, user_id: i64, passkey_id: i64) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM passkeys WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(passkey_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("passkey {passkey_id}")));
        }
        Ok(())
    }

    /// Persists an updated credential (sign counter, backup state) after login.
    pub async fn update_passkey(
        &self,
        user_id: i64,
        passkey_id: i64,
        credential: &str,
        last_used_at: i64,
    ) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE passkeys SET credential = ?, last_used_at = ? WHERE user_id = ? AND id = ?",
        )
        .bind(credential)
        .bind(last_used_at)
        .bind(user_id)
        .bind(passkey_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lists the dead (user-defined) properties of a node.
    pub async fn dead_props(&self, user_id: i64, node_id: i64) -> Result<Vec<DeadProp>, DbError> {
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT p.namespace, p.name, p.value FROM dead_props p
             JOIN nodes n ON n.id = p.node_id
             WHERE n.user_id = ? AND p.node_id = ?
             ORDER BY p.namespace, p.name",
        )
        .bind(user_id)
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(namespace, name, value)| DeadProp {
                namespace,
                name,
                value,
            })
            .collect())
    }

    /// Applies PROPPATCH operations in document order to a node.
    ///
    /// Returns `false` if the node does not exist or belongs to another user.
    pub async fn apply_dead_prop_ops(
        &self,
        user_id: i64,
        node_id: i64,
        ops: &[DeadPropOp],
    ) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        let (exists,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM nodes WHERE id = ? AND user_id = ?")
                .bind(node_id)
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await?;
        if exists == 0 {
            return Ok(false);
        }
        for op in ops {
            match op {
                DeadPropOp::Set {
                    namespace,
                    name,
                    value,
                } => {
                    sqlx::query(
                        "INSERT INTO dead_props (node_id, namespace, name, value)
                         VALUES (?, ?, ?, ?)
                         ON CONFLICT (node_id, namespace, name) DO UPDATE SET value = excluded.value",
                    )
                    .bind(node_id)
                    .bind(namespace)
                    .bind(name)
                    .bind(value)
                    .execute(&mut *tx)
                    .await?;
                }
                DeadPropOp::Remove { namespace, name } => {
                    sqlx::query(
                        "DELETE FROM dead_props WHERE node_id = ? AND namespace = ? AND name = ?",
                    )
                    .bind(node_id)
                    .bind(namespace)
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Returns the root directory node for a user.
    pub async fn root_node(&self, user_id: i64) -> Result<Node, DbError> {
        sqlx::query_as::<_, Node>("SELECT * FROM nodes WHERE user_id = ? AND parent_id IS NULL")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| DbError::NotFound("root node".to_string()))
    }

    /// Finds a direct child by name (excluding trashed nodes).
    pub async fn find_child(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
    ) -> Result<Option<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes
             WHERE user_id = ? AND parent_id = ? AND name = ? AND trashed_at IS NULL",
        )
        .bind(user_id)
        .bind(parent_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Fetches a node by id, scoped to the user.
    pub async fn node_by_id(&self, user_id: i64, node_id: i64) -> Result<Option<Node>, DbError> {
        Ok(
            sqlx::query_as::<_, Node>("SELECT * FROM nodes WHERE user_id = ? AND id = ?")
                .bind(user_id)
                .bind(node_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Lists the children of a directory, ordered by name (excluding trashed).
    pub async fn children(&self, user_id: i64, parent_id: i64) -> Result<Vec<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes
             WHERE user_id = ? AND parent_id = ? AND trashed_at IS NULL
             ORDER BY name",
        )
        .bind(user_id)
        .bind(parent_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Updates a file's content, pushing the old content into the version
    /// history first. Touching identical content only bumps `modified_at`.
    pub async fn update_file_versioned(
        &self,
        user_id: i64,
        node: &Node,
        content_id: &[u8],
        size: i64,
        now: i64,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        let changed = node.content_id.as_deref() != Some(content_id);
        if changed {
            if let Some(old) = &node.content_id {
                sqlx::query(
                    "INSERT INTO versions (user_id, node_id, content_id, size, created_at)
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(user_id)
                .bind(node.id)
                .bind(old.as_slice())
                .bind(node.size)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "DELETE FROM versions WHERE node_id = ?1 AND id NOT IN (
                         SELECT id FROM versions WHERE node_id = ?1
                         ORDER BY created_at DESC, id DESC LIMIT 10
                     )",
                )
                .bind(node.id)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "UPDATE nodes SET content_id = ?, size = ?, modified_at = ?
                 WHERE user_id = ? AND id = ?",
            )
            .bind(content_id)
            .bind(size)
            .bind(now)
            .bind(user_id)
            .bind(node.id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("UPDATE nodes SET modified_at = ? WHERE user_id = ? AND id = ?")
                .bind(now)
                .bind(user_id)
                .bind(node.id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Lists a file's versions, newest first.
    pub async fn list_versions(
        &self,
        user_id: i64,
        node_id: i64,
    ) -> Result<Vec<VersionRow>, DbError> {
        Ok(sqlx::query_as::<_, VersionRow>(
            "SELECT * FROM versions WHERE user_id = ? AND node_id = ?
             ORDER BY created_at DESC, id DESC",
        )
        .bind(user_id)
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Fetches one version by id.
    pub async fn version_by_id(
        &self,
        user_id: i64,
        version_id: i64,
    ) -> Result<Option<VersionRow>, DbError> {
        Ok(
            sqlx::query_as::<_, VersionRow>("SELECT * FROM versions WHERE user_id = ? AND id = ?")
                .bind(user_id)
                .bind(version_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Deletes versions older than `cutoff`.
    pub async fn prune_versions(&self, user_id: i64, cutoff: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM versions WHERE user_id = ? AND created_at < ?")
            .bind(user_id)
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Moves a node to the trash.
    pub async fn trash_node(
        &self,
        user_id: i64,
        node_id: i64,
        original_path: &str,
        now: i64,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "UPDATE nodes SET trashed_at = ?, original_path = ?
             WHERE user_id = ? AND id = ? AND trashed_at IS NULL",
        )
        .bind(now)
        .bind(original_path)
        .bind(user_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("node {node_id}")));
        }
        Ok(())
    }

    /// Lists trashed nodes, newest first.
    pub async fn list_trash(&self, user_id: i64) -> Result<Vec<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes WHERE user_id = ? AND trashed_at IS NOT NULL
             ORDER BY trashed_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Clears the trash flag on a node (caller resolves name conflicts first).
    pub async fn restore_node(&self, user_id: i64, node_id: i64) -> Result<(), DbError> {
        let result = sqlx::query(
            "UPDATE nodes SET trashed_at = NULL, original_path = NULL
             WHERE user_id = ? AND id = ? AND trashed_at IS NOT NULL",
        )
        .bind(user_id)
        .bind(node_id)
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "a node with that name already exists"))?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("trashed node {node_id}")));
        }
        Ok(())
    }

    /// Permanently deletes trashed nodes older than `cutoff`.
    pub async fn purge_trash(&self, user_id: i64, cutoff: i64) -> Result<u64, DbError> {
        let result = sqlx::query(
            "DELETE FROM nodes WHERE user_id = ? AND trashed_at IS NOT NULL AND trashed_at < ?",
        )
        .bind(user_id)
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Records a change-feed event.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_change(
        &self,
        user_id: i64,
        path: &str,
        op: &str,
        content_id: Option<&[u8]>,
        size: i64,
        modified_at: i64,
        from_path: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO changes (user_id, path, from_path, op, content_id, size, modified_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(path)
        .bind(from_path)
        .bind(op)
        .bind(content_id)
        .bind(size)
        .bind(modified_at)
        .execute(&self.pool)
        .await?;
        let mut details = serde_json::Map::new();
        details.insert("size".to_string(), serde_json::json!(size));
        if let Some(from) = from_path {
            details.insert("from".to_string(), serde_json::json!(from));
        }
        if let Some(content) = content_id {
            details.insert(
                "content_id".to_string(),
                serde_json::json!(hex::encode(content)),
            );
        }
        self.audit_append(
            Some(user_id),
            None,
            &format!("file.{op}"),
            path,
            &serde_json::Value::Object(details),
        )
        .await?;
        Ok(())
    }

    /// Returns change-feed events after `since`, oldest first.
    pub async fn changes_since(
        &self,
        user_id: i64,
        since: i64,
        limit: i64,
    ) -> Result<Vec<ChangeRow>, DbError> {
        Ok(sqlx::query_as::<_, ChangeRow>(
            "SELECT * FROM changes WHERE user_id = ? AND seq > ?
             ORDER BY seq LIMIT ?",
        )
        .bind(user_id)
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Latest change sequence for a user (0 if the feed is empty).
    pub async fn latest_change_seq(&self, user_id: i64) -> Result<i64, DbError> {
        let (seq,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(seq), 0) FROM changes WHERE user_id = ?")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(seq)
    }

    /// Computes the full path of a node by walking its ancestors.
    pub async fn node_path(&self, user_id: i64, node_id: i64) -> Result<Option<String>, DbError> {
        let names: Vec<(String,)> = sqlx::query_as(
            "WITH RECURSIVE ancestors(id, parent_id, name, lvl) AS (
                 SELECT id, parent_id, name, 0 FROM nodes WHERE user_id = ? AND id = ?
                 UNION ALL
                 SELECT n.id, n.parent_id, n.name, a.lvl + 1
                 FROM nodes n JOIN ancestors a ON n.id = a.parent_id
             )
             SELECT name FROM ancestors ORDER BY lvl DESC",
        )
        .bind(user_id)
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?;
        if names.is_empty() {
            return Ok(None);
        }
        let mut path = String::from("/");
        let parts: Vec<&str> = names
            .iter()
            .map(|(name,)| name.as_str())
            .filter(|name| !name.is_empty())
            .collect();
        path.push_str(&parts.join("/"));
        Ok(Some(path))
    }

    /// Lists every live node of a user (used to build sync tree paths).
    pub async fn all_live_nodes(&self, user_id: i64) -> Result<Vec<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes WHERE user_id = ? AND trashed_at IS NULL ORDER BY id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// All content ids referenced by live nodes or their versions.
    pub async fn referenced_content_ids(&self, user_id: i64) -> Result<Vec<Vec<u8>>, DbError> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT content_id FROM nodes WHERE user_id = ? AND content_id IS NOT NULL
             UNION
             SELECT content_id FROM versions WHERE user_id = ?",
        )
        .bind(user_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(content_id,)| content_id).collect())
    }

    /// Writes a consistent snapshot of the database to `path` (`VACUUM INTO`).
    ///
    /// `VACUUM INTO` takes a string literal rather than a bind parameter, so
    /// the single-quoted literal is escaped here and audited for injection.
    pub async fn backup_to(&self, path: &Path) -> Result<(), DbError> {
        let escaped = path.to_string_lossy().replace('\'', "''");
        let statement = format!("VACUUM INTO '{escaped}'");
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Inserts a new node.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_node(
        &self,
        user_id: i64,
        parent_id: Option<i64>,
        name: &str,
        kind: &str,
        content_id: Option<&[u8]>,
        size: i64,
        now: i64,
    ) -> Result<Node, DbError> {
        sqlx::query_as::<_, Node>(
            "INSERT INTO nodes (user_id, parent_id, name, kind, content_id, size, created_at, modified_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING *",
        )
        .bind(user_id)
        .bind(parent_id)
        .bind(name)
        .bind(kind)
        .bind(content_id)
        .bind(size)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "a node with that name already exists"))
    }

    /// Updates a file node's content reference.
    pub async fn update_file(
        &self,
        user_id: i64,
        node_id: i64,
        content_id: &[u8],
        size: i64,
        now: i64,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "UPDATE nodes SET content_id = ?, size = ?, modified_at = ? WHERE user_id = ? AND id = ?",
        )
        .bind(content_id)
        .bind(size)
        .bind(now)
        .bind(user_id)
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("node {node_id}")));
        }
        Ok(())
    }

    /// Renames and/or reparents a node.
    pub async fn move_node(
        &self,
        user_id: i64,
        node_id: i64,
        new_parent_id: i64,
        new_name: &str,
        now: i64,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "UPDATE nodes SET parent_id = ?, name = ?, modified_at = ? WHERE user_id = ? AND id = ?",
        )
        .bind(new_parent_id)
        .bind(new_name)
        .bind(now)
        .bind(user_id)
        .bind(node_id)
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "a node with that name already exists"))?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("node {node_id}")));
        }
        Ok(())
    }

    /// Deletes a node and, via cascade, its whole subtree.
    pub async fn delete_node(&self, user_id: i64, node_id: i64) -> Result<(), DbError> {
        sqlx::query("DELETE FROM nodes WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deep-copies a subtree, returning the new root node.
    pub async fn copy_subtree(
        &self,
        user_id: i64,
        src: &Node,
        dst_parent_id: i64,
        dst_name: &str,
        now: i64,
    ) -> Result<Node, DbError> {
        let mut tx = self.pool.begin().await?;
        let root = insert_copy(&mut tx, user_id, src, dst_parent_id, dst_name, now)
            .await
            .map_err(|e| map_sqlx(e, "a node with that name already exists"))?;
        let mut stack = vec![(src.id, root.id)];
        while let Some((orig_parent, new_parent)) = stack.pop() {
            let kids = sqlx::query_as::<_, Node>(
                "SELECT * FROM nodes WHERE user_id = ? AND parent_id = ?",
            )
            .bind(user_id)
            .bind(orig_parent)
            .fetch_all(&mut *tx)
            .await?;
            for kid in kids {
                let copy = insert_copy(&mut tx, user_id, &kid, new_parent, &kid.name, now)
                    .await
                    .map_err(|e| map_sqlx(e, "a node with that name already exists"))?;
                if kid.kind == "dir" {
                    stack.push((kid.id, copy.id));
                }
            }
        }
        tx.commit().await?;
        Ok(root)
    }
}

async fn insert_copy(
    conn: &mut sqlx::SqliteConnection,
    user_id: i64,
    src: &Node,
    dst_parent_id: i64,
    dst_name: &str,
    now: i64,
) -> Result<Node, sqlx::Error> {
    let copy = sqlx::query_as::<_, Node>(
        "INSERT INTO nodes (user_id, parent_id, name, kind, content_id, size, created_at, modified_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING *",
    )
    .bind(user_id)
    .bind(dst_parent_id)
    .bind(dst_name)
    .bind(&src.kind)
    .bind(&src.content_id)
    .bind(src.size)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query(
        "INSERT INTO dead_props (node_id, namespace, name, value)
         SELECT ?, namespace, name, value FROM dead_props WHERE node_id = ?",
    )
    .bind(copy.id)
    .bind(src.id)
    .execute(&mut *conn)
    .await?;

    Ok(copy)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn creates_user_with_root_and_admin_flags() {
        let (_dir, db) = db().await;
        let alice = db.create_user("alice", "hash-a").await.unwrap();
        let bob = db.create_user("bob", "hash-b").await.unwrap();
        assert!(alice.is_admin);
        assert!(!bob.is_admin);

        let root = db.root_node(alice.id).await.unwrap();
        assert_eq!(root.kind, "dir");
        assert_eq!(root.parent_id, None);
    }

    #[tokio::test]
    async fn rejects_duplicate_and_invalid_usernames() {
        let (_dir, db) = db().await;
        db.create_user("alice", "hash").await.unwrap();
        assert!(matches!(
            db.create_user("ALICE", "hash").await,
            Err(DbError::Conflict(_))
        ));
        assert!(matches!(
            db.create_user("bad name", "hash").await,
            Err(DbError::InvalidUsername(_))
        ));
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let token = [7u8; 32];
        db.create_session(user.id, &token, now_millis() + 60_000)
            .await
            .unwrap();

        let session = db.find_session(&token).await.unwrap().unwrap();
        assert_eq!(session.user_id, user.id);

        db.touch_session(session.id, now_millis()).await.unwrap();
        db.delete_session(&token).await.unwrap();
        assert!(db.find_session(&token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_sessions_are_purged() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        db.create_session(user.id, &[1u8; 32], now_millis() - 1)
            .await
            .unwrap();
        assert_eq!(db.delete_expired_sessions(now_millis()).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn node_tree_operations() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let root = db.root_node(user.id).await.unwrap();
        let now = now_millis();

        let dir = db
            .insert_node(user.id, Some(root.id), "docs", "dir", None, 0, now)
            .await
            .unwrap();
        let file = db
            .insert_node(
                user.id,
                Some(dir.id),
                "notes.txt",
                "file",
                Some(&[9u8; 32]),
                5,
                now,
            )
            .await
            .unwrap();

        assert_eq!(db.children(user.id, root.id).await.unwrap().len(), 1);
        assert_eq!(db.children(user.id, dir.id).await.unwrap().len(), 1);

        db.move_node(user.id, file.id, root.id, "renamed.txt", now)
            .await
            .unwrap();
        let moved = db.node_by_id(user.id, file.id).await.unwrap().unwrap();
        assert_eq!(moved.name, "renamed.txt");
        assert_eq!(moved.parent_id, Some(root.id));

        db.delete_node(user.id, dir.id).await.unwrap();
        assert!(db.node_by_id(user.id, dir.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_cascades_to_children() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let root = db.root_node(user.id).await.unwrap();
        let now = now_millis();
        let dir = db
            .insert_node(user.id, Some(root.id), "a", "dir", None, 0, now)
            .await
            .unwrap();
        let sub = db
            .insert_node(user.id, Some(dir.id), "b", "dir", None, 0, now)
            .await
            .unwrap();
        let file = db
            .insert_node(
                user.id,
                Some(sub.id),
                "c.txt",
                "file",
                Some(&[1u8; 32]),
                1,
                now,
            )
            .await
            .unwrap();

        db.delete_node(user.id, dir.id).await.unwrap();
        assert!(db.node_by_id(user.id, sub.id).await.unwrap().is_none());
        assert!(db.node_by_id(user.id, file.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn copy_subtree_duplicates_recursively() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let root = db.root_node(user.id).await.unwrap();
        let now = now_millis();
        let dir = db
            .insert_node(user.id, Some(root.id), "src", "dir", None, 0, now)
            .await
            .unwrap();
        db.insert_node(user.id, Some(dir.id), "inner", "dir", None, 0, now)
            .await
            .unwrap();

        let copy = db
            .copy_subtree(user.id, &dir, root.id, "dst", now)
            .await
            .unwrap();
        let children = db.children(user.id, copy.id).await.unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name, "inner");
    }

    #[tokio::test]
    async fn cannot_duplicate_names_in_same_directory() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        let root = db.root_node(user.id).await.unwrap();
        let now = now_millis();
        db.insert_node(user.id, Some(root.id), "a", "dir", None, 0, now)
            .await
            .unwrap();
        assert!(matches!(
            db.insert_node(user.id, Some(root.id), "a", "dir", None, 0, now)
                .await,
            Err(DbError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn users_cannot_see_each_others_nodes() {
        let (_dir, db) = db().await;
        let alice = db.create_user("alice", "hash").await.unwrap();
        let bob = db.create_user("bob", "hash").await.unwrap();
        let root = db.root_node(alice.id).await.unwrap();
        let node = db
            .insert_node(
                alice.id,
                Some(root.id),
                "secret",
                "file",
                Some(&[2u8; 32]),
                1,
                0,
            )
            .await
            .unwrap();
        assert!(db.node_by_id(bob.id, node.id).await.unwrap().is_none());
        assert!(db.children(bob.id, root.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn passkey_lifecycle() {
        let (_dir, db) = db().await;
        let user = db.create_user("alice", "hash").await.unwrap();
        assert_eq!(db.count_passkeys(user.id).await.unwrap(), 0);

        let row = db
            .add_passkey(user.id, "laptop", "{\"cred\":1}", now_millis())
            .await
            .unwrap();
        assert_eq!(db.count_passkeys(user.id).await.unwrap(), 1);

        let listed = db.list_passkeys(user.id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "laptop");

        db.update_passkey(user.id, row.id, "{\"cred\":2}", now_millis())
            .await
            .unwrap();
        assert_eq!(
            db.list_passkeys(user.id).await.unwrap()[0].credential,
            "{\"cred\":2}"
        );

        db.delete_passkey(user.id, row.id).await.unwrap();
        assert!(db.list_passkeys(user.id).await.unwrap().is_empty());
        assert!(matches!(
            db.delete_passkey(user.id, row.id).await,
            Err(DbError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn passkey_names_are_unique_per_user() {
        let (_dir, db) = db().await;
        let alice = db.create_user("alice", "hash").await.unwrap();
        let bob = db.create_user("bob", "hash").await.unwrap();
        db.add_passkey(alice.id, "key", "{}", 0).await.unwrap();
        assert!(matches!(
            db.add_passkey(alice.id, "key", "{}", 0).await,
            Err(DbError::Conflict(_))
        ));
        db.add_passkey(bob.id, "key", "{}", 0).await.unwrap();
    }
}
