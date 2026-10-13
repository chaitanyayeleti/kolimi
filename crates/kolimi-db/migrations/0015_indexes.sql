-- Hot-path indexes and a uniqueness guarantee for device registration.

CREATE INDEX IF NOT EXISTS idx_e2ee_enrollments_expires
    ON e2ee_enrollments(expires_at);

CREATE INDEX IF NOT EXISTS idx_link_sessions_expires
    ON link_sessions(expires_at);

-- The e2ee_share_keys primary key is (node_id, recipient_id), so lookups by
-- recipient (revocation, "what am I a recipient of") are not covered.
CREATE INDEX IF NOT EXISTS idx_e2ee_share_keys_recipient
    ON e2ee_share_keys(recipient_id);

-- The group_members primary key is (group_id, user_id); listing a user's
-- groups needs the reverse direction.
CREATE INDEX IF NOT EXISTS idx_group_members_user
    ON group_members(user_id);

-- Device registration is keyed by (user_id, public_key). Deduplicate any rows
-- created before this constraint existed (keep the earliest per key), then
-- enforce uniqueness so a concurrent register can never create a duplicate.
DELETE FROM e2ee_devices
WHERE id NOT IN (SELECT MIN(id) FROM e2ee_devices GROUP BY user_id, public_key);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2ee_devices_user_key
    ON e2ee_devices(user_id, public_key);
