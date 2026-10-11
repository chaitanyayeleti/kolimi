-- Per-user storage quotas and a cached usage counter.
--
-- `quota_bytes` NULL means "use the server default" (KOLIMI_USER_QUOTA_BYTES);
-- 0 means unlimited. `used_bytes` is maintained incrementally on writes and
-- reconciled from disk by the janitor so admin listings never walk the blob
-- tree.
ALTER TABLE users ADD COLUMN quota_bytes INTEGER;
ALTER TABLE users ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN usage_updated_at INTEGER;
CREATE INDEX users_used_bytes ON users(used_bytes);
