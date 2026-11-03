-- Key packages published before the 30-day TTL existed have no expiry.
-- Backfill one from their creation time so the janitor can reclaim packages
-- belonging to devices that never came back.
UPDATE mls_key_packages
SET expires_at = created_at + 2592000000
WHERE expires_at IS NULL;
