-- M6 v2: E2EE sharing. Identities (X25519, private key wrapped under
-- the master key) and per-recipient wrapped file keys.

CREATE TABLE e2ee_identities (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    public_key BLOB NOT NULL,
    wrapped_private BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE e2ee_share_keys (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, recipient_id)
);
