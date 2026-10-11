-- M4: CalDAV/CardDAV collections, objects, and per-collection change log.

CREATE TABLE dav_collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('calendar', 'addressbook')),
    name TEXT NOT NULL,
    displayname TEXT,
    description TEXT,
    color TEXT,
    created_at INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    UNIQUE (user_id, kind, name)
);

CREATE TABLE dav_objects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_id INTEGER NOT NULL REFERENCES dav_collections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    uid TEXT NOT NULL,
    content_type TEXT NOT NULL,
    data BLOB NOT NULL,
    etag TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    modified_at INTEGER NOT NULL,
    UNIQUE (collection_id, name),
    UNIQUE (collection_id, uid)
);

CREATE TABLE dav_changes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_id INTEGER NOT NULL REFERENCES dav_collections(id) ON DELETE CASCADE,
    object_name TEXT NOT NULL,
    op TEXT NOT NULL CHECK (op IN ('upsert', 'delete')),
    modified_at INTEGER NOT NULL
);

CREATE INDEX dav_changes_collection ON dav_changes(collection_id, seq);
