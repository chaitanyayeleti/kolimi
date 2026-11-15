-- Per-device app passwords for sync, WebDAV/CalDAV, and passkey-only clients.
CREATE TABLE app_passwords (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE INDEX app_passwords_user ON app_passwords(user_id, created_at DESC);
