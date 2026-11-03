-- Per-device epoch reports let the server prune MLS history safely.
--
-- Clients upsert the epoch they have successfully processed. The janitor
-- only deletes messages older than the minimum fresh report, so a member
-- that is behind (or has not reported recently) blocks pruning instead of
-- silently losing the commits it still needs.

CREATE TABLE mls_member_epochs (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    last_epoch INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, user_id, device_id)
);

CREATE INDEX mls_member_epochs_node ON mls_member_epochs(node_id, updated_at);
