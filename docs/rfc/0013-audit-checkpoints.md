# RFC 0013 — Sealed audit checkpoints

- **Status:** draft
- **Date:** 2026-11-21
- **Depends on:** the append-only audit log (`audit_log`), anchored retention
  (`audit_anchor`, migration 0034)
- **Implementation:** not started

## Summary

The audit log is already a per-entry BLAKE3 hash chain. Retention can export
and prune an old prefix and continue verification from an anchor.

This RFC adds **sealed checkpoints**: batches of audit entries with a Merkle
root and a checkpoint-chain link. A checkpoint is the useful part of a
“block” without the distributed-ledger machinery.

The goal is not consensus or global immutability. It is:

- compact verification of entry ranges,
- a permanent history of retention anchors,
- portable, independently verifiable audit exports,
- a natural place to add signatures or external publication later.

## What this is not

- No peer-to-peer network, consensus, mining, tokens, or smart contracts.
- No multi-node global ordering.
- No claim that a checkpoint is immutable against an attacker who can rewrite
  the entire database and every local file.
- No replacement for offsite backups or external monitoring.
- No per-entry signing or per-request external calls.

A local checkpoint chain improves organization and verification. It does not
create an external trust anchor. That requires a signing key held outside the
database and/or publication of checkpoint heads to a separately controlled
append-only system.

## Current state

`audit_log` stores one row per event:

- `id`, `ts`, actor, action, subject, details,
- `prev_hash` — the previous row's hash,
- `hash` — BLAKE3 over `prev_hash` and this row's fields.

Appends are serialized in-process. `audit_anchor` stores the last pruned
entry's id and hash so `audit verify` can start at the retention boundary.

Limitations:

- The anchor is one mutable row; previous anchors are not retained.
- Verification has no compact commitment to a range of entries.
- Pruning accepts an arbitrary entry id, not a sealed boundary.
- Export verification requires replaying every exported row.

## Data model

Add migration `0035_audit_checkpoints.sql`:

```sql
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
```

`checkpoint_hash` is stored so verification does not have to guess the header
serialization.

`entries_pruned_at` is set when the checkpoint's entry bodies have been
exported and deleted. **Checkpoint headers are never pruned.** They are small
and are the permanent block history.

`audit_log` is unchanged. `audit_anchor` remains the entry-chain retention
boundary for v1; checkpoints are additive. A later RFC may fold the anchor
into the latest checkpoint once the checkpoint model has shipped.

## Checkpoint coverage

A checkpoint covers a contiguous range of audit entries:

- `first_entry_id` is the first entry it seals.
- `last_entry_id` is the last entry it seals.
- `entry_count == last_entry_id - first_entry_id + 1` is required.
- The first checkpoint starts at the first retained entry, or after the
  current anchor if a prefix was already pruned.
- Later checkpoints start at `previous.last_entry_id + 1`.

Entries after the latest checkpoint are **unsealed**. They are still
hash-chained and visible; they are sealed on the next checkpoint.

## Sealing

Two triggers:

1. **Automatic:** the janitor seals when at least
   `AUDIT_CHECKPOINT_ENTRIES = 1024` entries are unsealed.
2. **Manual:** `kolimi-server audit seal` seals every currently unsealed
   entry into one checkpoint.

Sealing takes the audit append lock, chooses a stable maximum entry id, and
writes one checkpoint row. It does not rewrite or annotate individual audit
rows.

A checkpoint may contain more than 1,024 entries if the janitor was delayed;
that is allowed. Very large unsealed tails should be sealed in bounded
batches by the CLI implementation.

## Merkle tree

Use an RFC 6962-style binary Merkle tree over the sealed entry hashes:

- Leaf: `BLAKE3(0x00 || entry.hash)`
- Internal node: `BLAKE3(0x01 || left || right)`
- An odd node is promoted to the next level, not duplicated.
- An empty range is invalid.
- The root of a single-leaf range is its leaf hash.

The entry hash already commits to the previous entry and every field, so the
leaf does not need to repeat them.

Checkpoint header hash:

```text
BLAKE3(
  "kolimi-audit-checkpoint-v1" ||
  prev_checkpoint_hash ||
  first_entry_id ||
  last_entry_id ||
  entry_count ||
  merkle_root ||
  created_at
)
```

`prev_checkpoint_hash` is empty for the first checkpoint. The domain
separator prevents a checkpoint hash from being confused with an audit-entry
hash or a Merkle node.

## Verification

`audit verify` verifies, in order:

1. **Checkpoint chain** — contiguous ids/ranges, matching
   `prev_checkpoint_hash`, recomputed `checkpoint_hash`.
2. **Retained entry chain** — starting at `audit_anchor`, exactly as today.
3. **Checkpoint roots** — for each checkpoint whose entries are still
   present, recompute the Merkle root over
   `[first_entry_id, last_entry_id]` and compare.
4. **Unsealed tail** — verify entries after the last checkpoint against the
   last sealed entry hash.

For a checkpoint whose entries were pruned, verification checks the header
and its link to the neighboring checkpoints. It cannot recompute the root;
the exported bundle is the evidence for that block.

`GET /api/audit/verify` reports:

```json
{
  "ok": true,
  "entries": 2048,
  "checkpoints": 2,
  "pruned_checkpoints": 1,
  "first_bad": null,
  "latest_checkpoint": {
    "id": 2,
    "last_entry_id": 2048,
    "merkle_root": "…"
  }
}
```

The existing `anchor` fields remain for compatibility.

## Export bundles

A retention prune writes a JSONL bundle before deleting any entry:

- first line: checkpoint header (`kind: "kolimi-audit-checkpoint"`), including
  the hex `prev_checkpoint_hash`, `merkle_root`, and `checkpoint_hash`;
- one line per entry, with `details_raw` preserving the exact string covered
  by the entry hash;
- for v1, the verifier replays the entries to recompute the root.

`kolimi-server audit verify-export --file bundle.jsonl` verifies:

- checkpoint header hash,
- entry count and range,
- each entry's `prev_hash` / `hash`,
- the Merkle root,
- the checkpoint's link to the previous header included in the bundle (if
  present).

Inclusion proofs for a single entry are a later addition. The Merkle tree
shape is chosen so they can be added without changing the stored roots.

## Retention and pruning

`audit prune` changes from an arbitrary entry id to a **sealed checkpoint
boundary**:

```sh
kolimi-server audit seal
kolimi-server audit prune --checkpoint 12 --to /backups/audit-12.jsonl
```

Rules:

- The checkpoint must exist and be fully sealed.
- The bundle is written and fsynced before deletion.
- Entries through `checkpoint.last_entry_id` are deleted; the checkpoint
  header remains and gets `entries_pruned_at`.
- `audit_anchor` advances to that checkpoint's last entry hash.
- A prune cannot cross an unsealed tail or a partially sealed range.
- A checkpoint's entry bodies are exported at most once. Re-running prune
  for an already-pruned checkpoint is refused.

For compatibility, `--before <id>` may remain as an alias during the
transition, but it must resolve to a checkpoint boundary. New documentation
uses `--checkpoint`.

## CLI

```sh
kolimi-server audit seal
kolimi-server audit checkpoints [--limit N]
kolimi-server audit verify
kolimi-server audit verify-export --file audit-12.jsonl
kolimi-server audit prune --checkpoint 12 --to /backups/audit-12.jsonl
```

`audit checkpoints` prints id, range, count, root, pruned state, and
checkpoint hash.

## Signing and external anchoring — phase 2

Checkpoints are the right unit for signatures:

- an Ed25519 key signs the checkpoint header,
- the public key is printed/exported,
- `audit verify` checks signatures when a key is configured,
- the latest signed checkpoint hash can be published to an external
  append-only location.

Neither is required for v1. A signature key stored on the same server only
raises the bar against database-only tampering; it does not defeat a full
server compromise. External publication is the stronger option and should be
a separate design decision.

## Migration and compatibility

- Existing audit rows and `audit_anchor` remain valid.
- No checkpoint is required for verification; a log with no checkpoints
  behaves exactly as today.
- The first `audit seal` creates a checkpoint from the first retained entry
  through the current newest entry.
- Existing `audit prune --before` data is not rewritten. If an anchor exists,
  the first checkpoint starts after it.
- No changes to audit append latency: appends do not compute checkpoints.
- The janitor performs automatic sealing off the request path.

## Tests

- Seal creates one checkpoint with the correct range, root, and chain link.
- Seal after a previous checkpoint starts at `last_entry_id + 1`.
- `audit verify` passes with sealed entries and an unsealed tail.
- A modified entry breaks verification.
- A modified checkpoint root or header hash breaks verification.
- A missing checkpoint link breaks verification.
- Prune exports the bundle, marks the checkpoint pruned, and leaves the
  header chain verifiable.
- `audit verify-export` accepts a valid bundle and rejects a changed entry,
  root, or header.
- Prune refuses an unsealed boundary and an already-pruned checkpoint.
- Concurrent append during seal does not create a gap or overlap.
- CLI end-to-end: seal → list → export/prune → verify → verify-export.

## Open questions

1. Automatic seal threshold: 1,024 entries, one hour, or both?
   Recommendation: 1,024 entries, plus a janitor seal when any tail exists
   for more than a day.
2. Retain checkpoint headers forever, or cap them? Recommendation: retain
   forever; they are tiny and are the block history.
3. RFC 6962 tree vs a simpler pairwise tree? Recommendation: RFC 6962-style
   now; it costs little and enables inclusion proofs later.
4. Signed checkpoints in v1? Recommendation: no; design the column/format
   now, ship signatures as phase 2.
5. Does `--before` remain as a transition alias? Recommendation: yes for one
   release, requiring a checkpoint boundary.

## Acceptance criteria

- A sealed checkpoint commits to every entry in its range.
- Checkpoints form an unbroken chain.
- `audit verify` verifies both the entry chain and every available
  checkpoint root.
- A pruned checkpoint leaves a verifiable header history and a portable
  export.
- No request-path cost is added to ordinary audit appends.
- The design remains honest: local checkpoints are not a distributed ledger
  and do not replace external evidence.
