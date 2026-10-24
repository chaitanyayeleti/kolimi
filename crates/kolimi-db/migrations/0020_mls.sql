-- MLS (RFC 9420) group state for encrypted share roots.
--
-- The server stores opaque key packages, protocol messages and encrypted
-- share keyrings. It never sees an MLS secret or a file key.

CREATE TABLE mls_key_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    UNIQUE(user_id, device_id)
);

CREATE INDEX mls_key_packages_user ON mls_key_packages(user_id);

-- One MLS group per shared encrypted node (folder). Node-scoped so a user
-- share and a group share of the same folder share one epoch/keyring.
CREATE TABLE mls_node_groups (
    node_id INTEGER PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    mls_group_id BLOB NOT NULL UNIQUE,
    epoch INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE mls_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('proposal', 'commit', 'welcome', 'application')),
    payload BLOB NOT NULL,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    UNIQUE (node_id, seq)
);

CREATE INDEX mls_messages_node ON mls_messages(node_id, seq);

-- The share keyring ciphertext for one epoch. Clients encrypt it under the
-- MLS exporter before upload; the server only versions and stores it.
CREATE TABLE mls_share_keyrings (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    epoch INTEGER NOT NULL,
    payload BLOB NOT NULL,
    updated_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, epoch)
);
