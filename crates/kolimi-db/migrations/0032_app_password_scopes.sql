-- Least-privilege app passwords: protocol-level scopes and optional expiry.
--
-- Existing rows keep full access (`*`) so current clients continue to work
-- after the upgrade. New UI-created tokens can choose a narrower preset.
ALTER TABLE app_passwords ADD COLUMN scopes TEXT NOT NULL DEFAULT '*';
ALTER TABLE app_passwords ADD COLUMN expires_at INTEGER;
