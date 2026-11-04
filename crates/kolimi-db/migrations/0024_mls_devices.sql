-- MLS device roster and key-package caps.
--
-- Key packages are a consumable pool, so the old UNIQUE(user_id, device_id)
-- was removed. That left the server accepting an unbounded number of device
-- ids per user. This roster bounds distinct MLS devices and is kept for a
-- long inactivity window so a recipient cannot churn new ids every cleanup
-- cycle.

CREATE TABLE mls_devices (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    -- Public Ed25519 signature key from the device's key package. The server
    -- never parses the package; clients report it so a revoking client can
    -- map a device id to its leaf(s) in each group. Nullable for clients
    -- that predate this column and for the package-pool backfill below.
    signature_key BLOB,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX mls_devices_seen ON mls_devices(user_id, last_seen_at);
CREATE INDEX mls_devices_last_seen ON mls_devices(last_seen_at);

-- A client-asserted revocation list per group. A removed device may still
-- have unconsumed key packages; without this, automatic re-add would put it
-- back at the next owner sync. Explicit re-sharing clears the entry.
CREATE TABLE mls_group_revocations (
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    signature_key BLOB NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    revoked_at INTEGER NOT NULL,
    revoked_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (node_id, signature_key)
);

CREATE INDEX mls_group_revocations_node ON mls_group_revocations(node_id);

-- Backfill existing devices from the package pool. Names/signature keys are
-- reported by the next package upload from each device.
INSERT OR IGNORE INTO mls_devices (user_id, device_id, created_at, last_seen_at)
SELECT user_id, device_id, MIN(created_at), MAX(created_at)
FROM mls_key_packages
GROUP BY user_id, device_id;
