-- Bump a counter on every password change so an out-of-process reset (e.g.
-- `kolimi-server user recover` from the CLI) invalidates a running server's
-- in-memory credential cache without needing an IPC signal.
ALTER TABLE users ADD COLUMN credentials_version INTEGER NOT NULL DEFAULT 0;
