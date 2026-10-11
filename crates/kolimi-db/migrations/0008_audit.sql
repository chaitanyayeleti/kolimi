-- Append-only, hash-chained audit log (M6).
-- Rows are only ever inserted; the chain is verified by recomputing each
-- hash over (prev_hash, ts, actor, action, subject, details).

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor TEXT,
    action TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    prev_hash BLOB NOT NULL,
    hash BLOB NOT NULL
);

CREATE INDEX audit_log_ts ON audit_log(ts);
