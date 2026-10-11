//! Groups, shares, and public-link sessions (M3).

use serde::Serialize;

use crate::{Db, DbError, User, map_sqlx, now_millis};

/// A named group of users.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Group {
    /// Primary key.
    pub id: i64,
    /// Unique name (case-insensitive).
    pub name: String,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
}

/// A share row: user-to-user, user-to-group, or public link.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ShareRow {
    /// Primary key.
    pub id: i64,
    /// User whose tree contains the shared node.
    pub owner_id: i64,
    /// Shared node.
    pub node_id: i64,
    /// `"user"`, `"group"`, or `"link"`.
    pub kind: String,
    /// Recipient for user shares.
    pub recipient_user_id: Option<i64>,
    /// Recipient group for group shares.
    pub recipient_group_id: Option<i64>,
    /// `"read"` or `"write"` (write implies read).
    pub permission: String,
    /// Opaque token for public links.
    pub token: Option<String>,
    /// Argon2id PHC string for password-protected links.
    pub password_hash: Option<String>,
    /// Expiry time in Unix milliseconds (`None` = never).
    pub expires_at: Option<i64>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
}

/// A share received by a user, joined with node and owner details.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ReceivedShare {
    /// Share primary key.
    pub share_id: i64,
    /// Owner of the underlying node.
    pub owner_id: i64,
    /// Owner's username.
    pub owner_username: String,
    /// Shared node id (in the owner's tree).
    pub node_id: i64,
    /// Node name.
    pub name: String,
    /// `"dir"` or `"file"`.
    pub kind: String,
    /// BLAKE3 content id for files.
    #[serde(skip_serializing)]
    pub content_id: Option<Vec<u8>>,
    /// Content size in bytes.
    pub size: i64,
    /// Node modification time in Unix milliseconds.
    pub modified_at: i64,
    /// `"read"` or `"write"`.
    pub permission: String,
    /// Share creation time in Unix milliseconds.
    pub created_at: i64,
}

/// A logged-in public-link unlock session.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LinkSession {
    /// Primary key.
    pub id: i64,
    /// Unlocked share.
    pub share_id: i64,
    /// BLAKE3 hash of the cookie token.
    pub token_hash: Vec<u8>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Expiry time in Unix milliseconds.
    pub expires_at: i64,
}

impl Db {
    // ---- groups --------------------------------------------------------

    /// Creates a group. Names are unique, case-insensitively.
    pub async fn create_group(&self, name: &str) -> Result<Group, DbError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 64 {
            return Err(DbError::Conflict("invalid group name".to_string()));
        }
        sqlx::query_as::<_, Group>(
            "INSERT INTO groups (name, created_at) VALUES (?, ?) RETURNING *",
        )
        .bind(name)
        .bind(now_millis())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "group name already exists"))
    }

    /// Lists groups by name.
    pub async fn list_groups(&self) -> Result<Vec<Group>, DbError> {
        Ok(
            sqlx::query_as::<_, Group>("SELECT * FROM groups ORDER BY name COLLATE NOCASE")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Fetches a group by exact (case-insensitive) name.
    pub async fn group_by_name(&self, name: &str) -> Result<Option<Group>, DbError> {
        Ok(
            sqlx::query_as::<_, Group>("SELECT * FROM groups WHERE name = ? COLLATE NOCASE")
                .bind(name)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Fetches a group by id.
    pub async fn group_by_id(&self, group_id: i64) -> Result<Option<Group>, DbError> {
        Ok(
            sqlx::query_as::<_, Group>("SELECT * FROM groups WHERE id = ?")
                .bind(group_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Deletes a group (memberships and group shares cascade).
    pub async fn delete_group(&self, group_id: i64) -> Result<bool, DbError> {
        // Drop wrapped keys for the group's shares before the share rows
        // cascade away.
        sqlx::query(
            "DELETE FROM e2ee_share_keys
             WHERE node_id IN (
                 SELECT node_id FROM shares
                 WHERE kind = 'group' AND recipient_group_id = ?
             )",
        )
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        let result = sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(group_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Adds a member to a group. Idempotent.
    pub async fn add_group_member(&self, group_id: i64, user_id: i64) -> Result<(), DbError> {
        sqlx::query(
            "INSERT OR IGNORE INTO group_members (group_id, user_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(group_id)
        .bind(user_id)
        .bind(now_millis())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Removes a member from a group. Returns whether the row existed.
    pub async fn remove_group_member(&self, group_id: i64, user_id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM group_members WHERE group_id = ? AND user_id = ?")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() > 0 {
            // The member can no longer resolve the shared paths, so their
            // wrapped keys are dead weight; remove them.
            self.delete_share_keys_for_group_member(group_id, user_id)
                .await?;
        }
        Ok(result.rows_affected() > 0)
    }

    /// Lists a group's members.
    pub async fn group_members(&self, group_id: i64) -> Result<Vec<User>, DbError> {
        Ok(sqlx::query_as::<_, User>(
            "SELECT u.* FROM users u
             JOIN group_members m ON m.user_id = u.id
             WHERE m.group_id = ? ORDER BY u.username",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Lists the groups a user belongs to.
    pub async fn user_groups(&self, user_id: i64) -> Result<Vec<Group>, DbError> {
        Ok(sqlx::query_as::<_, Group>(
            "SELECT g.* FROM groups g
             JOIN group_members m ON m.group_id = g.id
             WHERE m.user_id = ? ORDER BY g.name COLLATE NOCASE",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    // ---- shares --------------------------------------------------------

    /// Creates a share row.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_share(
        &self,
        owner_id: i64,
        node_id: i64,
        kind: &str,
        recipient_user_id: Option<i64>,
        recipient_group_id: Option<i64>,
        permission: &str,
        token: Option<&str>,
        password_hash: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<ShareRow, DbError> {
        sqlx::query_as::<_, ShareRow>(
            "INSERT INTO shares (owner_id, node_id, kind, recipient_user_id, recipient_group_id,
                                 permission, token, password_hash, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(owner_id)
        .bind(node_id)
        .bind(kind)
        .bind(recipient_user_id)
        .bind(recipient_group_id)
        .bind(permission)
        .bind(token)
        .bind(password_hash)
        .bind(expires_at)
        .bind(now_millis())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "this item is already shared with that recipient"))
    }

    /// Fetches a share by id.
    pub async fn share_by_id(&self, share_id: i64) -> Result<Option<ShareRow>, DbError> {
        Ok(
            sqlx::query_as::<_, ShareRow>("SELECT * FROM shares WHERE id = ?")
                .bind(share_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Fetches a public link by token.
    pub async fn share_by_token(&self, token: &str) -> Result<Option<ShareRow>, DbError> {
        Ok(
            sqlx::query_as::<_, ShareRow>("SELECT * FROM shares WHERE token = ? AND kind = 'link'")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Lists the shares an owner created for a node.
    pub async fn shares_for_node(
        &self,
        owner_id: i64,
        node_id: i64,
    ) -> Result<Vec<ShareRow>, DbError> {
        Ok(sqlx::query_as::<_, ShareRow>(
            "SELECT * FROM shares WHERE owner_id = ? AND node_id = ? ORDER BY id",
        )
        .bind(owner_id)
        .bind(node_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Lists all shares created by an owner.
    pub async fn shares_owned(&self, owner_id: i64) -> Result<Vec<ShareRow>, DbError> {
        Ok(
            sqlx::query_as::<_, ShareRow>("SELECT * FROM shares WHERE owner_id = ? ORDER BY id")
                .bind(owner_id)
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Lists shares received by a user (directly or through a group).
    pub async fn received_shares(&self, user_id: i64) -> Result<Vec<ReceivedShare>, DbError> {
        Ok(sqlx::query_as::<_, ReceivedShare>(
            "SELECT s.id AS share_id, s.owner_id, u.username AS owner_username, s.node_id,
                    n.name, n.kind, n.content_id, n.size, n.modified_at, s.permission, s.created_at
             FROM shares s
             JOIN nodes n ON n.id = s.node_id
             JOIN users u ON u.id = s.owner_id
             WHERE s.kind IN ('user', 'group')
               AND (s.recipient_user_id = ?1
                    OR s.recipient_group_id IN
                       (SELECT group_id FROM group_members WHERE user_id = ?1))
               AND n.trashed_at IS NULL
               AND s.owner_id != ?1
             ORDER BY s.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The strongest permission granted to `caller` on `node` by any live
    /// share (direct or group). `None` when no share applies.
    ///
    /// Inheritance is by mount: a share on an ancestor exposes its whole
    /// subtree at the recipient's mount point, so per-node evaluation only
    /// has to consider shares on the node itself.
    pub async fn effective_permission(
        &self,
        node_id: i64,
        caller_id: i64,
    ) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT permission FROM shares
             WHERE node_id = ?1
               AND (recipient_user_id = ?2
                    OR recipient_group_id IN
                       (SELECT group_id FROM group_members WHERE user_id = ?2))
             ORDER BY (permission = 'write') DESC
             LIMIT 1",
        )
        .bind(node_id)
        .bind(caller_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(permission,)| permission))
    }

    /// Updates a share's permission.
    pub async fn update_share_permission(
        &self,
        share_id: i64,
        permission: &str,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE shares SET permission = ? WHERE id = ?")
            .bind(permission)
            .bind(share_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Updates a link's password hash (`None` clears the password).
    pub async fn update_share_password(
        &self,
        share_id: i64,
        password_hash: Option<&str>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE shares SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(share_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Updates a link's expiry (`None` clears it).
    pub async fn update_share_expiry(
        &self,
        share_id: i64,
        expires_at: Option<i64>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("UPDATE shares SET expires_at = ? WHERE id = ?")
            .bind(expires_at)
            .bind(share_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes a share (its link sessions cascade).
    pub async fn delete_share(&self, share_id: i64) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM shares WHERE id = ?")
            .bind(share_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ---- public-link sessions -----------------------------------------

    /// Records an unlock session for a password-protected link.
    pub async fn create_link_session(
        &self,
        share_id: i64,
        token_hash: &[u8],
        expires_at: i64,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO link_sessions (share_id, token_hash, created_at, expires_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(share_id)
        .bind(token_hash)
        .bind(now_millis())
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finds a live unlock session by cookie-token hash.
    pub async fn find_link_session(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<LinkSession>, DbError> {
        Ok(sqlx::query_as::<_, LinkSession>(
            "SELECT * FROM link_sessions WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(token_hash)
        .bind(now_millis())
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Deletes expired unlock sessions.
    pub async fn delete_expired_link_sessions(&self, now: i64) -> Result<u64, DbError> {
        let result = sqlx::query("DELETE FROM link_sessions WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> (tempfile::TempDir, Db, User, User) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let alice = db.create_user("alice", "hash-a").await.unwrap();
        let bob = db.create_user("bob", "hash-b").await.unwrap();
        (dir, db, alice, bob)
    }

    async fn file(db: &Db, user_id: i64, name: &str) -> i64 {
        let root = db.root_node(user_id).await.unwrap();
        db.insert_node(
            user_id,
            Some(root.id),
            name,
            "file",
            Some(&[7u8; 32]),
            1,
            now_millis(),
        )
        .await
        .unwrap()
        .id
    }

    #[tokio::test]
    async fn group_lifecycle() {
        let (_dir, db, alice, bob) = db().await;
        let group = db.create_group("Team").await.unwrap();
        assert!(matches!(
            db.create_group("team").await,
            Err(DbError::Conflict(_))
        ));
        assert_eq!(
            db.group_by_name("TEAM").await.unwrap().unwrap().id,
            group.id
        );

        db.add_group_member(group.id, bob.id).await.unwrap();
        db.add_group_member(group.id, bob.id).await.unwrap();
        assert_eq!(db.group_members(group.id).await.unwrap().len(), 1);
        assert_eq!(db.user_groups(bob.id).await.unwrap().len(), 1);

        assert!(db.remove_group_member(group.id, bob.id).await.unwrap());
        assert!(!db.remove_group_member(group.id, bob.id).await.unwrap());
        assert!(db.delete_group(group.id).await.unwrap());
        assert!(!db.delete_group(group.id).await.unwrap());
        let _ = alice;
    }

    #[tokio::test]
    async fn user_share_and_permission_merge() {
        let (_dir, db, alice, bob) = db().await;
        let node = file(&db, alice.id, "doc.txt").await;
        db.create_share(
            alice.id,
            node,
            "user",
            Some(bob.id),
            None,
            "read",
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let received = db.received_shares(bob.id).await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].owner_username, "alice");
        assert_eq!(
            db.effective_permission(node, bob.id)
                .await
                .unwrap()
                .as_deref(),
            Some("read")
        );
        assert!(
            db.effective_permission(node, alice.id)
                .await
                .unwrap()
                .is_none()
        );

        // A group share with write wins over the direct read share.
        let group = db.create_group("Team").await.unwrap();
        db.add_group_member(group.id, bob.id).await.unwrap();
        db.create_share(
            alice.id,
            node,
            "group",
            None,
            Some(group.id),
            "write",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            db.effective_permission(node, bob.id)
                .await
                .unwrap()
                .as_deref(),
            Some("write")
        );
        // Both shares surface as separate received rows; callers dedupe.
        assert_eq!(db.received_shares(bob.id).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn duplicate_shares_are_rejected_but_links_are_not() {
        let (_dir, db, alice, bob) = db().await;
        let node = file(&db, alice.id, "doc.txt").await;
        db.create_share(
            alice.id,
            node,
            "user",
            Some(bob.id),
            None,
            "read",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            db.create_share(
                alice.id,
                node,
                "user",
                Some(bob.id),
                None,
                "write",
                None,
                None,
                None
            )
            .await,
            Err(DbError::Conflict(_))
        ));
        db.create_share(
            alice.id,
            node,
            "link",
            None,
            None,
            "read",
            Some("tok1"),
            None,
            None,
        )
        .await
        .unwrap();
        db.create_share(
            alice.id,
            node,
            "link",
            None,
            None,
            "read",
            Some("tok2"),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(db.shares_for_node(alice.id, node).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn trashed_nodes_disappear_from_received_shares() {
        let (_dir, db, alice, bob) = db().await;
        let node = file(&db, alice.id, "doc.txt").await;
        db.create_share(
            alice.id,
            node,
            "user",
            Some(bob.id),
            None,
            "read",
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.trash_node(alice.id, node, "/doc.txt", now_millis())
            .await
            .unwrap();
        assert!(db.received_shares(bob.id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn link_lookup_and_sessions() {
        let (_dir, db, alice, _bob) = db().await;
        let node = file(&db, alice.id, "doc.txt").await;
        let share = db
            .create_share(
                alice.id,
                node,
                "link",
                None,
                None,
                "read",
                Some("tok"),
                Some("$argon2id$..."),
                Some(now_millis() + 1000),
            )
            .await
            .unwrap();
        assert_eq!(
            db.share_by_token("tok").await.unwrap().unwrap().id,
            share.id
        );
        assert!(db.share_by_token("nope").await.unwrap().is_none());

        let hash = [9u8; 32];
        db.create_link_session(share.id, &hash, now_millis() + 1000)
            .await
            .unwrap();
        let session = db.find_link_session(&hash).await.unwrap().unwrap();
        assert_eq!(session.share_id, share.id);

        db.create_link_session(share.id, &[8u8; 32], now_millis() - 1)
            .await
            .unwrap();
        assert!(db.find_link_session(&[8u8; 32]).await.unwrap().is_none());
        assert_eq!(
            db.delete_expired_link_sessions(now_millis()).await.unwrap(),
            1
        );

        assert!(db.delete_share(share.id).await.unwrap());
        assert!(db.find_link_session(&hash).await.unwrap().is_none());
    }
}
