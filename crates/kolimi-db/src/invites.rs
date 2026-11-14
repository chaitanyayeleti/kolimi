//! One-time invite links for onboarding.
//!
//! The plaintext token is never stored: callers hash it with BLAKE3 and keep
//! only the digest. Accepting an invite creates the account and consumes the
//! row in one transaction, so a token can never create two users.

use serde::Serialize;

use crate::{Db, DbError, User, create_user_on, map_sqlx, now_millis, validate_username};

/// A pending or consumed invite.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Invite {
    /// Primary key.
    pub id: i64,
    /// Account name reserved by this invite.
    pub username: String,
    /// BLAKE3 of the plaintext token; never exposed.
    #[serde(skip_serializing)]
    pub token_hash: Vec<u8>,
    /// Administrator that created the invite, when still present.
    pub created_by: Option<i64>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at: i64,
    /// Optional profile fields carried onto the new account.
    pub display_name: Option<String>,
    /// Optional contact address carried onto the new account.
    pub email: Option<String>,
    /// When the invite was accepted, if it has been consumed.
    pub used_at: Option<i64>,
}

/// Fields for [`Db::create_invite`].
#[derive(Debug, Clone, Copy)]
pub struct NewInvite<'a> {
    /// Account name to reserve.
    pub username: &'a str,
    /// BLAKE3 digest of the plaintext token.
    pub token_hash: &'a [u8],
    /// Creating administrator.
    pub created_by: Option<i64>,
    /// Expiry time in Unix milliseconds.
    pub expires_at: i64,
    /// Optional display name.
    pub display_name: Option<&'a str>,
    /// Optional email.
    pub email: Option<&'a str>,
}

impl Db {
    /// Creates an invite, first clearing expired pending invites so a name
    /// can be invited again after its previous link expired.
    pub async fn create_invite(&self, invite: NewInvite<'_>) -> Result<Invite, DbError> {
        validate_username(invite.username)?;
        let now = now_millis();
        if invite.expires_at <= now {
            return Err(DbError::Conflict(
                "invite expiry is in the past".to_string(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM invites WHERE used_at IS NULL AND expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM users WHERE username = ? COLLATE NOCASE")
                .bind(invite.username)
                .fetch_optional(&mut *tx)
                .await?;
        if existing.is_some() {
            return Err(DbError::Conflict("username already exists".to_string()));
        }
        let created = sqlx::query_as::<_, Invite>(
            "INSERT INTO invites
                 (username, token_hash, created_by, created_at, expires_at, display_name, email)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             RETURNING *",
        )
        .bind(invite.username)
        .bind(invite.token_hash)
        .bind(invite.created_by)
        .bind(now)
        .bind(invite.expires_at)
        .bind(invite.display_name)
        .bind(invite.email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| map_sqlx(error, "username already has a pending invite"))?;
        tx.commit().await?;
        Ok(created)
    }

    /// Lists unused invites newest first. Expired rows remain visible so an
    /// administrator can revoke them; callers compute `expired` from the
    /// timestamp.
    pub async fn list_pending_invites(&self) -> Result<Vec<Invite>, DbError> {
        Ok(sqlx::query_as::<_, Invite>(
            "SELECT * FROM invites WHERE used_at IS NULL
             ORDER BY created_at DESC, id DESC",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Finds an unused, unexpired invite by token digest.
    pub async fn find_valid_invite(&self, token_hash: &[u8]) -> Result<Option<Invite>, DbError> {
        Ok(sqlx::query_as::<_, Invite>(
            "SELECT * FROM invites
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(now_millis())
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Fetches an invite by id (including consumed rows).
    pub async fn invite_by_id(&self, id: i64) -> Result<Option<Invite>, DbError> {
        Ok(
            sqlx::query_as::<_, Invite>("SELECT * FROM invites WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Revokes an unused invite. Returns whether a row was removed.
    pub async fn revoke_invite(&self, id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM invites WHERE id = ? AND used_at IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Creates the account and marks the invite used in one transaction.
    pub async fn consume_invite(
        &self,
        token_hash: &[u8],
        password_hash: &str,
    ) -> Result<User, DbError> {
        let now = now_millis();
        let mut tx = self.pool.begin().await?;
        let Some(invite) = sqlx::query_as::<_, Invite>(
            "SELECT * FROM invites
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Err(DbError::NotFound("invite".to_string()));
        };
        let mut user = create_user_on(&mut tx, &invite.username, password_hash).await?;
        if invite.display_name.is_some() || invite.email.is_some() {
            sqlx::query("UPDATE users SET display_name = ?, email = ? WHERE id = ?")
                .bind(invite.display_name.as_deref())
                .bind(invite.email.as_deref())
                .bind(user.id)
                .execute(&mut *tx)
                .await?;
            user.display_name.clone_from(&invite.display_name);
            user.email.clone_from(&invite.email);
        }
        let result = sqlx::query("UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL")
            .bind(now)
            .bind(invite.id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() != 1 {
            return Err(DbError::Conflict("invite already used".to_string()));
        }
        tx.commit().await?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use crate::{Db, DbError, NewInvite, now_millis};

    async fn db() -> (tempfile::TempDir, Db) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        (dir, db)
    }

    fn hash(token: &str) -> [u8; 32] {
        *blake3::hash(token.as_bytes()).as_bytes()
    }

    #[tokio::test]
    async fn invite_is_created_consumed_and_single_use() {
        let (_dir, db) = db().await;
        let created = db
            .create_invite(NewInvite {
                username: "carol",
                token_hash: &hash("token-one"),
                created_by: None,
                expires_at: now_millis() + 60_000,
                display_name: Some("Carol"),
                email: Some("carol@example.test"),
            })
            .await
            .unwrap();
        assert_eq!(created.username, "carol");
        assert_eq!(created.display_name.as_deref(), Some("Carol"));

        let found = db
            .find_valid_invite(&hash("token-one"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, created.id);

        let user = db.consume_invite(&hash("token-one"), "hash").await.unwrap();
        assert_eq!(user.username, "carol");
        assert!(
            db.find_valid_invite(&hash("token-one"))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.consume_invite(&hash("token-one"), "hash2")
                .await
                .unwrap_err()
                .to_string(),
            "not found: invite"
        );
    }

    #[tokio::test]
    async fn expired_invites_do_not_reserve_the_username() {
        let (_dir, db) = db().await;
        db.create_invite(NewInvite {
            username: "carol",
            token_hash: &hash("old"),
            created_by: None,
            expires_at: now_millis() - 1,
            display_name: None,
            email: None,
        })
        .await
        .unwrap_err();
        // Insert directly to model a link that expired after creation.
        sqlx::query(
            "INSERT INTO invites (username, token_hash, created_at, expires_at)
             VALUES ('carol', ?, ?, ?)",
        )
        .bind(hash("old").as_slice())
        .bind(now_millis() - 120_000)
        .bind(now_millis() - 60_000)
        .execute(db.pool())
        .await
        .unwrap();
        let fresh = db
            .create_invite(NewInvite {
                username: "carol",
                token_hash: &hash("new"),
                created_by: None,
                expires_at: now_millis() + 60_000,
                display_name: None,
                email: None,
            })
            .await
            .unwrap();
        assert_eq!(fresh.username, "carol");
        assert!(db.find_valid_invite(&hash("old")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn existing_users_and_duplicate_pending_names_conflict() {
        let (_dir, db) = db().await;
        db.create_user("alice", "hash").await.unwrap();
        let error = db
            .create_invite(NewInvite {
                username: "alice",
                token_hash: &hash("a"),
                created_by: None,
                expires_at: now_millis() + 60_000,
                display_name: None,
                email: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(error, DbError::Conflict(_)));

        db.create_invite(NewInvite {
            username: "carol",
            token_hash: &hash("b"),
            created_by: None,
            expires_at: now_millis() + 60_000,
            display_name: None,
            email: None,
        })
        .await
        .unwrap();
        db.create_invite(NewInvite {
            username: "CAROL",
            token_hash: &hash("c"),
            created_by: None,
            expires_at: now_millis() + 60_000,
            display_name: None,
            email: None,
        })
        .await
        .unwrap_err();
    }
}
