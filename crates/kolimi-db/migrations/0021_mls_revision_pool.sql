-- Key packages become a consumable pool instead of one row per device.
CREATE TABLE mls_key_packages_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    consumed_at INTEGER
);

INSERT INTO mls_key_packages_new (id, user_id, device_id, payload, created_at, expires_at)
SELECT id, user_id, device_id, payload, created_at, expires_at FROM mls_key_packages;

DROP TABLE mls_key_packages;
ALTER TABLE mls_key_packages_new RENAME TO mls_key_packages;
CREATE INDEX mls_key_packages_user ON mls_key_packages(user_id);
CREATE INDEX mls_key_packages_live ON mls_key_packages(user_id, consumed_at);

-- Optimistic keyring concurrency: epoch alone cannot distinguish two
-- writers updating the same epoch.
ALTER TABLE mls_share_keyrings ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;

-- Existing keyrings predate the revision column; revision 0 is reserved for
-- "no keyring", so promote existing rows to revision 1.
UPDATE mls_share_keyrings SET revision = 1;
