-- Per-user maintenance scheduling.
--
-- The janitor used to sweep every account on every pass. At scale that turns
-- one hourly job into `users × (trash purge + version prune + blob GC +
-- scrub)`. This table lets the janitor pick the least-recently-swept accounts
-- in bounded batches, while still prioritizing accounts with expired trash,
-- expired versions, or a recent delete that may have freed blobs.
CREATE TABLE maintenance_state (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Last successful blob sweep (Unix milliseconds).
    last_gc_at INTEGER,
    -- A delete happened since the last sweep; collect it on the next pass.
    dirty INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE INDEX maintenance_state_last_gc ON maintenance_state(last_gc_at);
CREATE INDEX maintenance_state_dirty ON maintenance_state(dirty, updated_at)
    WHERE dirty != 0;

-- Retention queries select expired rows across all accounts; the existing
-- per-user indexes cannot serve those scans.
CREATE INDEX nodes_trashed_at ON nodes(trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX versions_created_at ON versions(created_at);
