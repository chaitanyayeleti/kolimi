-- M6 ship-blocker: TOTP two-factor and one-time recovery codes.

CREATE TABLE totp_secrets (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- Highest consumed time step (replay protection within the window).
    last_step INTEGER
);

CREATE TABLE recovery_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX recovery_codes_user ON recovery_codes(user_id);
