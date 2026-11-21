-- Anchored audit retention.
--
-- `audit_log` is append-only and hash-chained. Operators may export a prefix
-- and prune it, but verification must still work for the retained tail. This
-- table records the last pruned entry: the next retained row's `prev_hash`
-- must equal `hash`, so `audit verify` can continue from the anchor instead of
-- treating the retained tail as a fresh chain.
CREATE TABLE audit_anchor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    pruned_through INTEGER NOT NULL,
    hash BLOB NOT NULL,
    pruned_entries INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);
