-- M2: background scrub cursor (BLAKE3 re-verification progress).

CREATE TABLE scrub_state (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    cursor TEXT,
    updated_at INTEGER NOT NULL
);
