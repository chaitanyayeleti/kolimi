-- M3: groups, shares (user/group/public link), and public-link sessions.

CREATE TABLE groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('user', 'group', 'link')),
    recipient_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    recipient_group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write')),
    token TEXT UNIQUE,
    password_hash TEXT,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK (
        (kind = 'user' AND recipient_user_id IS NOT NULL AND recipient_group_id IS NULL AND token IS NULL)
        OR (kind = 'group' AND recipient_group_id IS NOT NULL AND recipient_user_id IS NULL AND token IS NULL)
        OR (kind = 'link' AND recipient_user_id IS NULL AND recipient_group_id IS NULL AND token IS NOT NULL)
    )
);

CREATE INDEX shares_node ON shares(node_id);
CREATE INDEX shares_recipient_user ON shares(recipient_user_id);
CREATE INDEX shares_recipient_group ON shares(recipient_group_id);
CREATE UNIQUE INDEX shares_user_unique ON shares(node_id, recipient_user_id) WHERE kind = 'user';
CREATE UNIQUE INDEX shares_group_unique ON shares(node_id, recipient_group_id) WHERE kind = 'group';

CREATE TABLE link_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX link_sessions_share ON link_sessions(share_id);
