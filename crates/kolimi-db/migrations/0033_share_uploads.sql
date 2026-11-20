-- Upload-only ("file request") links: per-link caps and committed counters.
--
-- The share row already allows kind = 'link' with permission = 'write'; these
-- columns make that mode safe to expose publicly. `max_*` NULL means the
-- server default; counters only move after a successful commit.
ALTER TABLE shares ADD COLUMN max_files INTEGER;
ALTER TABLE shares ADD COLUMN max_bytes INTEGER;
ALTER TABLE shares ADD COLUMN uploaded_files INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN uploaded_bytes INTEGER NOT NULL DEFAULT 0;

CREATE INDEX shares_upload_links ON shares(kind, permission, created_at DESC);
