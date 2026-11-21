-- Audit checkpoint signing and external anchoring (RFC 0014).
--
-- Signatures are detached: a signature covers the existing checkpoint header
-- hash, so it does not change the checkpoint chain or Merkle roots. Public
-- keys stored here are informational; verification trusts keys supplied by
-- the operator, never this table alone.
CREATE TABLE audit_signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'ed25519',
    public_key BLOB NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    retired_at INTEGER
);

CREATE TABLE audit_checkpoint_signatures (
    checkpoint_id INTEGER NOT NULL REFERENCES audit_checkpoints(id),
    key_id TEXT NOT NULL REFERENCES audit_signing_keys(key_id),
    signature BLOB NOT NULL,
    signed_at INTEGER NOT NULL,
    PRIMARY KEY (checkpoint_id, key_id)
);

-- Durable intent to publish a checkpoint to the configured anchor sinks.
-- Created in the checkpoint transaction, drained by the janitor.
CREATE TABLE audit_anchor_outbox (
    checkpoint_id INTEGER PRIMARY KEY REFERENCES audit_checkpoints(id),
    payload TEXT NOT NULL,
    journaled_at INTEGER,
    delivered_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT
);

CREATE INDEX audit_anchor_outbox_due
    ON audit_anchor_outbox(next_attempt_at)
    WHERE journaled_at IS NULL OR delivered_at IS NULL;
