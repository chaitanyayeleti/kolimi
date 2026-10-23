-- Encrypted share metadata: the display name of a shared node and, for a
-- shared folder, the per-folder name key that decodes its contents. Wrapped
-- to each recipient's X25519 identity; the server cannot read it.
CREATE TABLE e2ee_share_names (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, recipient_id)
);

CREATE INDEX e2ee_share_names_recipient ON e2ee_share_names(recipient_id);
