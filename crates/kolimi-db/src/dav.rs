//! CalDAV/CardDAV collections, objects, and per-collection change log (M4).
//!
//! Calendar and address-book data lives beside the file tree rather than
//! inside it: objects are small, versioned by clients via ETags, and
//! tracked in their own change log for RFC 6578 `sync-collection`.

use serde::Serialize;

use crate::{Db, DbError, map_sqlx, now_millis};

/// A calendar or address-book collection.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DavCollection {
    /// Primary key.
    pub id: i64,
    /// Owning user.
    pub user_id: i64,
    /// `"calendar"` or `"addressbook"`.
    pub kind: String,
    /// URL name (slug).
    pub name: String,
    /// Human-readable display name.
    pub displayname: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Optional calendar color (`#RRGGBB` or `#RRGGBBAA`).
    pub color: Option<String>,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
}

/// A calendar object resource or vCard.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DavObject {
    /// Primary key.
    pub id: i64,
    /// Owning collection.
    pub collection_id: i64,
    /// Resource name (URL segment).
    pub name: String,
    /// Extracted UID.
    pub uid: String,
    /// Media type (`text/calendar` or `text/vcard`).
    pub content_type: String,
    /// Raw payload.
    pub data: Vec<u8>,
    /// Entity tag (BLAKE3 hex, unquoted).
    pub etag: String,
    /// Size in bytes.
    pub size: i64,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
}

/// Object metadata without the payload (for listings).
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DavObjectMeta {
    /// Resource name.
    pub name: String,
    /// Extracted UID.
    pub uid: String,
    /// Media type.
    pub content_type: String,
    /// Entity tag (unquoted).
    pub etag: String,
    /// Size in bytes.
    pub size: i64,
    /// Creation time in Unix milliseconds.
    pub created_at: i64,
    /// Last modification time in Unix milliseconds.
    pub modified_at: i64,
}

/// One entry of a collection's change log.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DavChange {
    /// Monotonic per-collection sequence number.
    pub seq: i64,
    /// Affected resource name.
    pub object_name: String,
    /// `"upsert"` or `"delete"`.
    pub op: String,
    /// Event time in Unix milliseconds.
    pub modified_at: i64,
}

impl Db {
    // ---- collections ---------------------------------------------------

    /// Creates a calendar or address book. Names are unique per kind.
    pub async fn create_dav_collection(
        &self,
        user_id: i64,
        kind: &str,
        name: &str,
        displayname: Option<&str>,
    ) -> Result<DavCollection, DbError> {
        if !matches!(kind, "calendar" | "addressbook") {
            return Err(DbError::Conflict("invalid collection kind".to_string()));
        }
        let now = now_millis();
        sqlx::query_as::<_, DavCollection>(
            "INSERT INTO dav_collections (user_id, kind, name, displayname, created_at, modified_at)
             VALUES (?, ?, ?, ?, ?, ?) RETURNING *",
        )
        .bind(user_id)
        .bind(kind)
        .bind(name)
        .bind(displayname)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx(e, "a collection with that name already exists"))
    }

    /// Lists a user's collections of one kind, by name.
    pub async fn list_dav_collections(
        &self,
        user_id: i64,
        kind: &str,
    ) -> Result<Vec<DavCollection>, DbError> {
        Ok(sqlx::query_as::<_, DavCollection>(
            "SELECT * FROM dav_collections WHERE user_id = ? AND kind = ? ORDER BY name",
        )
        .bind(user_id)
        .bind(kind)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Fetches a collection by URL name.
    pub async fn dav_collection(
        &self,
        user_id: i64,
        kind: &str,
        name: &str,
    ) -> Result<Option<DavCollection>, DbError> {
        Ok(sqlx::query_as::<_, DavCollection>(
            "SELECT * FROM dav_collections WHERE user_id = ? AND kind = ? AND name = ?",
        )
        .bind(user_id)
        .bind(kind)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Fetches a collection by id, scoped to its owner.
    pub async fn dav_collection_by_id(
        &self,
        user_id: i64,
        collection_id: i64,
    ) -> Result<Option<DavCollection>, DbError> {
        Ok(sqlx::query_as::<_, DavCollection>(
            "SELECT * FROM dav_collections WHERE user_id = ? AND id = ?",
        )
        .bind(user_id)
        .bind(collection_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Sets (or clears) a collection property. `field` is one of
    /// `displayname`, `description`, `color`.
    pub async fn set_dav_collection_prop(
        &self,
        user_id: i64,
        collection_id: i64,
        field: &str,
        value: Option<&str>,
    ) -> Result<bool, DbError> {
        let column = match field {
            "displayname" => "displayname",
            "description" => "description",
            "color" => "color",
            _ => return Err(DbError::Conflict("unknown property".to_string())),
        };
        let statement = format!(
            "UPDATE dav_collections SET {column} = ?, modified_at = ? WHERE user_id = ? AND id = ?"
        );
        let result = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(value)
            .bind(now_millis())
            .bind(user_id)
            .bind(collection_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes a collection; its objects and change log cascade.
    pub async fn delete_dav_collection(
        &self,
        user_id: i64,
        collection_id: i64,
    ) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM dav_collections WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(collection_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ---- objects -------------------------------------------------------

    /// Creates or replaces an object, recording a change.
    ///
    /// A UID already used by a different resource in the collection is a
    /// conflict (CalDAV `no-uid-conflict`).
    #[allow(clippy::too_many_arguments)]
    pub async fn put_dav_object(
        &self,
        collection_id: i64,
        name: &str,
        uid: &str,
        content_type: &str,
        data: &[u8],
        etag: &str,
        size: i64,
        now: i64,
    ) -> Result<DavObject, DbError> {
        let mut tx = self.pool.begin().await?;
        let object = sqlx::query_as::<_, DavObject>(
            "INSERT INTO dav_objects
                 (collection_id, name, uid, content_type, data, etag, size, created_at, modified_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (collection_id, name) DO UPDATE SET
                 uid = excluded.uid,
                 content_type = excluded.content_type,
                 data = excluded.data,
                 etag = excluded.etag,
                 size = excluded.size,
                 modified_at = excluded.modified_at
             RETURNING *",
        )
        .bind(collection_id)
        .bind(name)
        .bind(uid)
        .bind(content_type)
        .bind(data)
        .bind(etag)
        .bind(size)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            map_sqlx(
                e,
                "another resource in this collection already uses that UID",
            )
        })?;

        sqlx::query(
            "INSERT INTO dav_changes (collection_id, object_name, op, modified_at)
             VALUES (?, ?, 'upsert', ?)",
        )
        .bind(collection_id)
        .bind(name)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE dav_collections SET modified_at = ? WHERE id = ?")
            .bind(now)
            .bind(collection_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(object)
    }

    /// Deletes an object, recording a change. Returns whether it existed.
    pub async fn delete_dav_object(&self, collection_id: i64, name: &str) -> Result<bool, DbError> {
        let now = now_millis();
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("DELETE FROM dav_objects WHERE collection_id = ? AND name = ?")
            .bind(collection_id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() > 0 {
            sqlx::query(
                "INSERT INTO dav_changes (collection_id, object_name, op, modified_at)
                 VALUES (?, ?, 'delete', ?)",
            )
            .bind(collection_id)
            .bind(name)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE dav_collections SET modified_at = ? WHERE id = ?")
                .bind(now)
                .bind(collection_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

    /// Fetches one object with its payload.
    pub async fn dav_object(
        &self,
        collection_id: i64,
        name: &str,
    ) -> Result<Option<DavObject>, DbError> {
        Ok(sqlx::query_as::<_, DavObject>(
            "SELECT * FROM dav_objects WHERE collection_id = ? AND name = ?",
        )
        .bind(collection_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Lists a collection's objects (metadata only), by name.
    pub async fn list_dav_objects(
        &self,
        collection_id: i64,
    ) -> Result<Vec<DavObjectMeta>, DbError> {
        Ok(sqlx::query_as::<_, DavObjectMeta>(
            "SELECT name, uid, content_type, etag, size, created_at, modified_at
             FROM dav_objects WHERE collection_id = ? ORDER BY name",
        )
        .bind(collection_id)
        .fetch_all(&self.pool)
        .await?)
    }

    // ---- change log ----------------------------------------------------

    /// Returns change-log entries after `since`, oldest first.
    pub async fn dav_changes_since(
        &self,
        collection_id: i64,
        since: i64,
        limit: i64,
    ) -> Result<Vec<DavChange>, DbError> {
        Ok(sqlx::query_as::<_, DavChange>(
            "SELECT * FROM dav_changes WHERE collection_id = ? AND seq > ?
             ORDER BY seq LIMIT ?",
        )
        .bind(collection_id)
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The collection's current change sequence (0 when untouched); this
    /// doubles as its CTag.
    pub async fn dav_latest_seq(&self, collection_id: i64) -> Result<i64, DbError> {
        let (seq,): (i64,) =
            sqlx::query_as("SELECT COALESCE(MAX(seq), 0) FROM dav_changes WHERE collection_id = ?")
                .bind(collection_id)
                .fetch_one(&self.pool)
                .await?;
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> (tempfile::TempDir, Db, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(&dir.path().join("test.db")).await.unwrap();
        let user = db.create_user("alice", "hash").await.unwrap();
        (dir, db, user.id)
    }

    #[tokio::test]
    async fn collection_lifecycle_and_props() {
        let (_dir, db, alice) = setup().await;
        let calendar = db
            .create_dav_collection(alice, "calendar", "work", Some("Work"))
            .await
            .unwrap();
        assert_eq!(calendar.kind, "calendar");
        assert_eq!(calendar.displayname.as_deref(), Some("Work"));

        assert!(matches!(
            db.create_dav_collection(alice, "calendar", "work", None)
                .await,
            Err(DbError::Conflict(_))
        ));
        // Same name in a different kind is fine.
        db.create_dav_collection(alice, "addressbook", "work", None)
            .await
            .unwrap();
        assert_eq!(
            db.list_dav_collections(alice, "calendar")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.list_dav_collections(alice, "addressbook")
                .await
                .unwrap()
                .len(),
            1
        );

        assert!(
            db.set_dav_collection_prop(alice, calendar.id, "color", Some("#ff0000"))
                .await
                .unwrap()
        );
        let fetched = db
            .dav_collection(alice, "calendar", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.color.as_deref(), Some("#ff0000"));
        db.set_dav_collection_prop(alice, calendar.id, "color", None)
            .await
            .unwrap();
        let fetched = db
            .dav_collection(alice, "calendar", "work")
            .await
            .unwrap()
            .unwrap();
        assert!(fetched.color.is_none());

        assert!(db.delete_dav_collection(alice, calendar.id).await.unwrap());
        assert!(!db.delete_dav_collection(alice, calendar.id).await.unwrap());
    }

    #[tokio::test]
    async fn object_upsert_uid_conflicts_and_changes() {
        let (_dir, db, alice) = setup().await;
        let calendar = db
            .create_dav_collection(alice, "calendar", "work", None)
            .await
            .unwrap();

        let now = now_millis();
        let object = db
            .put_dav_object(
                calendar.id,
                "event1.ics",
                "uid-1",
                "text/calendar",
                b"BEGIN:VCALENDAR",
                "etag1",
                15,
                now,
            )
            .await
            .unwrap();
        assert_eq!(object.name, "event1.ics");

        // Same name + same UID updates in place.
        let updated = db
            .put_dav_object(
                calendar.id,
                "event1.ics",
                "uid-1",
                "text/calendar",
                b"BEGIN:VCALENDAR updated",
                "etag2",
                23,
                now + 1,
            )
            .await
            .unwrap();
        assert_eq!(updated.etag, "etag2");
        assert_eq!(updated.created_at, now);

        // Same UID under a different name is a conflict.
        assert!(matches!(
            db.put_dav_object(
                calendar.id,
                "event2.ics",
                "uid-1",
                "text/calendar",
                b"x",
                "etag3",
                1,
                now,
            )
            .await,
            Err(DbError::Conflict(_))
        ));

        // The change log sees both writes; the ctag advances.
        assert_eq!(db.dav_latest_seq(calendar.id).await.unwrap(), 2);
        let changes = db.dav_changes_since(calendar.id, 1, 100).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "upsert");

        assert_eq!(db.list_dav_objects(calendar.id).await.unwrap().len(), 1);
        assert!(
            db.delete_dav_object(calendar.id, "event1.ics")
                .await
                .unwrap()
        );
        assert!(
            !db.delete_dav_object(calendar.id, "event1.ics")
                .await
                .unwrap()
        );
        let changes = db.dav_changes_since(calendar.id, 2, 100).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].op, "delete");
        assert_eq!(changes[0].object_name, "event1.ics");
    }

    #[tokio::test]
    async fn deleting_a_collection_cascades() {
        let (_dir, db, alice) = setup().await;
        let calendar = db
            .create_dav_collection(alice, "calendar", "work", None)
            .await
            .unwrap();
        db.put_dav_object(
            calendar.id,
            "a.ics",
            "uid-a",
            "text/calendar",
            b"x",
            "e",
            1,
            now_millis(),
        )
        .await
        .unwrap();
        db.delete_dav_collection(alice, calendar.id).await.unwrap();
        assert!(db.list_dav_objects(calendar.id).await.unwrap().is_empty());
        assert_eq!(db.dav_latest_seq(calendar.id).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn collections_are_user_scoped() {
        let (_dir, db, alice) = setup().await;
        let bob = db.create_user("bob", "hash").await.unwrap();
        let calendar = db
            .create_dav_collection(alice, "calendar", "work", None)
            .await
            .unwrap();
        assert!(
            db.dav_collection(bob.id, "calendar", "work")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.dav_collection_by_id(bob.id, calendar.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!db.delete_dav_collection(bob.id, calendar.id).await.unwrap());
    }
}
