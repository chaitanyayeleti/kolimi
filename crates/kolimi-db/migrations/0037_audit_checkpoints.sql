-- Sealed audit checkpoints (RFC 0013).
--
-- A checkpoint commits to a contiguous range of audit entries with an
-- RFC 6962-style Merkle root and links to the previous checkpoint header.
-- Headers are retained forever; entry bodies may be exported and pruned.
CREATE TABLE audit_checkpoints (
    id INTEGER PRIMARY KEY,
    first_entry_id INTEGER NOT NULL,
    last_entry_id INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    prev_checkpoint_hash BLOB NOT NULL,
    merkle_root BLOB NOT NULL,
    checkpoint_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    entries_pruned_at INTEGER
);

CREATE UNIQUE INDEX audit_checkpoints_range
    ON audit_checkpoints(first_entry_id, last_entry_id);

-- Serve sync tree pages without loading the whole namespace per request.
CREATE INDEX nodes_live_user_id ON nodes(user_id, id) WHERE trashed_at IS NULL;
