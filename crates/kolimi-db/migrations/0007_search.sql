-- M5: how far the background indexer has consumed each user's change feed.

CREATE TABLE search_state (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_seq INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
