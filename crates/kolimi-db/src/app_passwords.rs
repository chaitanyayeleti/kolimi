//! Per-device app passwords (API tokens) for sync, WebDAV/CalDAV, and
//! clients that cannot complete an interactive TOTP/passkey login.
//!
//! Only the BLAKE3 digest of the token is stored. Tokens are high-entropy
//! (256 bits), so lookup is a direct hash match rather than Argon2.
//!
//! Every token carries protocol-level scopes (`*` = full account access) and
//! an optional expiry. Rows created before scopes existed default to `*`.

use crate::{Db, DbError, now_millis};

use serde::Serialize;

/// A stored app password. The plaintext token is returned only at creation.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AppPassword {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    #[serde(skip)]
    pub user_id: i64,
    /// Operator-visible label, e.g. "Laptop sync".
    pub name: String,
    /// BLAKE3 hash of the token.
    #[serde(skip)]
    pub token_hash: Vec<u8>,
    /// Comma-separated scopes, or `*` for full access.
    pub scopes: String,
    /// Expiry time in Unix milliseconds (`None` = never).
    pub expires_at: Option<i64>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last successful use, if any.
    pub last_used_at: Option<i64>,
}

impl Db {
    /// Creates an app password. The caller generates and hashes the token.
    pub async fn create_app_password(
        &self,
        user_id: i64,
        name: &str,
        token_hash: &[u8],
        scopes: &str,
        expires_at: Option<i64>,
    ) -> Result<AppPassword, DbError> {
        let now = now_millis();
        let result = sqlx::query(
            "INSERT INTO app_passwords (user_id, name, token_hash, scopes, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(scopes)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await;
        match result {
            Ok(result) => Ok(AppPassword {
                id: result.last_insert_rowid(),
                user_id,
                name: name.to_string(),
                token_hash: token_hash.to_vec(),
                scopes: scopes.to_string(),
                expires_at,
                created_at: now,
                last_used_at: None,
            }),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
                DbError::Conflict("an app password with that name already exists".to_string()),
            ),
            Err(error) => Err(error.into()),
        }
    }

    /// Lists a user's app passwords, newest first.
    pub async fn list_app_passwords(&self, user_id: i64) -> Result<Vec<AppPassword>, DbError> {
        Ok(sqlx::query_as::<_, AppPassword>(
            "SELECT * FROM app_passwords WHERE user_id = ? ORDER BY created_at DESC, id DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Updates the mutable fields of one app password.
    ///
    /// `None` leaves a field unchanged. `expires_at` is `Some(None)` to clear
    /// an expiry and `Some(Some(ms))` to set one.
    pub async fn update_app_password(
        &self,
        user_id: i64,
        id: i64,
        name: Option<&str>,
        scopes: Option<&str>,
        expires_at: Option<Option<i64>>,
    ) -> Result<AppPassword, DbError> {
        let existing = sqlx::query_as::<_, AppPassword>(
            "SELECT * FROM app_passwords WHERE user_id = ? AND id = ?",
        )
        .bind(user_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| DbError::NotFound(format!("app password {id}")))?;
        let name = name.unwrap_or(&existing.name);
        let scopes = scopes.unwrap_or(&existing.scopes);
        let expires_at = expires_at.unwrap_or(existing.expires_at);
        let result = sqlx::query(
            "UPDATE app_passwords SET name = ?, scopes = ?, expires_at = ?
             WHERE user_id = ? AND id = ?",
        )
        .bind(name)
        .bind(scopes)
        .bind(expires_at)
        .bind(user_id)
        .bind(id)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(AppPassword {
                name: name.to_string(),
                scopes: scopes.to_string(),
                expires_at,
                ..existing
            }),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(
                DbError::Conflict("an app password with that name already exists".to_string()),
            ),
            Err(error) => Err(error.into()),
        }
    }

    /// Deletes one app password owned by `user_id`.
    pub async fn delete_app_password(&self, user_id: i64, id: i64) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM app_passwords WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("app password {id}")));
        }
        Ok(())
    }

    /// Deletes the app password matching `token_hash` for `user_id`. Used by a
    /// device to revoke the credential it authenticated with.
    pub async fn delete_app_password_hash(
        &self,
        user_id: i64,
        token_hash: &[u8],
    ) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM app_passwords WHERE user_id = ? AND token_hash = ?")
            .bind(user_id)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Looks up an app password by username and token hash.
    pub async fn find_app_password(
        &self,
        username: &str,
        token_hash: &[u8],
    ) -> Result<Option<AppPassword>, DbError> {
        Ok(sqlx::query_as::<_, AppPassword>(
            "SELECT ap.*
             FROM app_passwords ap
             JOIN users u ON u.id = ap.user_id
             WHERE u.username = ? AND ap.token_hash = ?",
        )
        .bind(username)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Records a successful app-password use.
    pub async fn touch_app_password(&self, id: i64, now: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE app_passwords SET last_used_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Drops every app password for a user (admin recovery / disable).
    pub async fn delete_user_app_passwords(&self, user_id: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM app_passwords WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
