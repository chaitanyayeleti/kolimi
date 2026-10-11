-- M6: client-side E2EE (RFC 0007).
-- The server stores wrapped keys only; it cannot derive any plaintext.

CREATE TABLE e2ee_keyrings (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    keyring TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE e2ee_file_keys (
    node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX e2ee_file_keys_user ON e2ee_file_keys(user_id);
