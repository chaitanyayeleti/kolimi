-- RFC 0008: multi-device E2EE enrollment. The server relays an opaque
-- wrapped master key and never sees the master key, device keys, or file
-- keys.

CREATE TABLE e2ee_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);

CREATE INDEX e2ee_devices_user ON e2ee_devices(user_id);

CREATE TABLE e2ee_enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    device_public_key BLOB NOT NULL,
    wrapped_master_key BLOB,
    approved_at INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX e2ee_enrollments_user ON e2ee_enrollments(user_id);
