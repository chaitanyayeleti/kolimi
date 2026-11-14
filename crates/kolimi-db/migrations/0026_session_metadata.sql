-- Device metadata for self-service session management.
--
-- Existing sessions predate these columns and stay valid; the UI shows
-- "unknown" for them. `user_agent` is truncated by the writer.
ALTER TABLE sessions ADD COLUMN ip TEXT;
ALTER TABLE sessions ADD COLUMN user_agent TEXT;

-- The session list is queried per user and ordered by recent activity.
CREATE INDEX sessions_user_seen ON sessions(user_id, last_seen_at DESC);
