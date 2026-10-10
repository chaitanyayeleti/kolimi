//! SQLite persistence for Kolimi: users, sessions, and the file tree.

use std::{path::Path, time::Duration};

use serde::Serialize;
use sqlx::{
    FromRow, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

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
        Ok(Self { pool })
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

    /// Lists all users ordered by name.
    pub async fn list_users(&self) -> Result<Vec<User>, DbError> {
        Ok(
            sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY username")
                .fetch_all(&self.pool)
                .await?,
        )
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
    pub async fn set_admin(&self, user_id: i64, is_admin: bool) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE users SET is_admin = ? WHERE id = ?")
            .bind(is_admin)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("user {user_id}")));
        }
        Ok(())
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

    /// Finds a direct child by name.
    pub async fn find_child(
        &self,
        user_id: i64,
        parent_id: i64,
        name: &str,
    ) -> Result<Option<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes WHERE user_id = ? AND parent_id = ? AND name = ?",
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

    /// Lists the children of a directory, ordered by name.
    pub async fn children(&self, user_id: i64, parent_id: i64) -> Result<Vec<Node>, DbError> {
        Ok(sqlx::query_as::<_, Node>(
            "SELECT * FROM nodes WHERE user_id = ? AND parent_id = ? ORDER BY name",
        )
        .bind(user_id)
        .bind(parent_id)
        .fetch_all(&self.pool)
        .await?)
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
