ALTER TABLE nodes ADD COLUMN trashed_at INTEGER;
ALTER TABLE nodes ADD COLUMN original_path TEXT;

DROP INDEX nodes_name;
CREATE UNIQUE INDEX nodes_name ON nodes(user_id, parent_id, name) WHERE trashed_at IS NULL;
CREATE INDEX nodes_trashed ON nodes(user_id, trashed_at);

CREATE TABLE versions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    content_id BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX versions_node ON versions(node_id, created_at DESC);

CREATE TABLE changes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    from_path TEXT,
    op TEXT NOT NULL,
    content_id BLOB,
    size INTEGER NOT NULL DEFAULT 0,
    modified_at INTEGER NOT NULL
);

CREATE INDEX changes_user_seq ON changes(user_id, seq);
