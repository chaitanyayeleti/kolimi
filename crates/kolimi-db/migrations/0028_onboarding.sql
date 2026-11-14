-- Phase 4 onboarding: one-time invite links, optional profile fields, and
-- server-enforced password rotation.

ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

-- An invite creates the account only when it is accepted. The token is
-- hashed; the plaintext exists once in the generated link.
CREATE TABLE invites (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE,
    token_hash BLOB NOT NULL UNIQUE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    display_name TEXT,
    email TEXT,
    used_at INTEGER
);

CREATE INDEX invites_pending ON invites(created_at DESC) WHERE used_at IS NULL;
-- Only one live invite per username. Expired rows are cleaned up when the
-- next invite is created.
CREATE UNIQUE INDEX invites_pending_username
    ON invites(username COLLATE NOCASE) WHERE used_at IS NULL;
