# RFC 0001 — Storage Engine

- **Status:** Draft
- **Milestone:** M2 (primitives scaffolded in M0 as `kolimi-chunk`)
- **Related:** RFC 0002 (Sync Protocol), `docs/threat-model.md`

## Summary

Kolimi stores file content in a **content-addressed blob store**. Files are
never stored whole; they are split into content-defined chunks, each chunk is
addressed by its BLAKE3-256 hash, and a file is an ordered list of chunk
references — a **manifest**.

This is the same family of design as restic and borg, applied to
filesystem semantics. It gives us dedup, delta sync, cheap version history,
atomic commits, and background self-healing without a database for content.

## Motivation

Nextcloud stores plain files and depends on the filesystem plus a database for
metadata. That design makes dedup, delta transfer, and integrity checking
bolted-on features. Kolimi inverts it: content addressing is the foundation,
and everything else (WebDAV, sharing, versions, trash) is a view over it.

## Design

### Chunking

- Algorithm: FastCDC (content-defined, gear hash).
- Parameters (v1):

  | Parameter | Value  |
  |-----------|--------|
  | min       | 256 KiB |
  | average   | 1 MiB  |
  | max       | 4 MiB  |

- The split is deterministic and edit-local: inserting bytes near the start
  of a file leaves all chunks after the disturbance byte-identical. Measured
  in tests: a 1-byte insertion into a 16 MiB file retains >50% of chunks
  (typically all but the first one or two).
- Future: parameters will be recorded per-manifest when the format is
  versioned further, so the chunker can be tuned without breaking old data.

### Hashing and identity

- Every chunk: `BLAKE3(bytes) -> [u8; 32]`, lowercase hex on the wire and in
  filenames.
- File **content id**: `BLAKE3(version || concat(chunk_hash || len_le))`.
  Two manifests with the same content id describe identical bytes.
- Empty files: zero chunks, content id of the version byte alone.

### Manifest format (v1)

JSON on the wire, versioned by a `version` byte:

```json
{
  "version": 1,
  "size": 15728640,
  "chunks": [
    { "hash": "ab12…", "len": 1048576 },
    { "hash": "cd34…", "len": 917504 }
  ]
}
```

- JSON first for debuggability; a compact binary encoding is planned for v2
  once the schema stabilizes.
- Manifests are immutable. Editing a file produces a new manifest; old
  manifests hanging off the version chain are the version history.

### Store layout (target, M2)

```
data/
  chunks/aa/bb/<hash>        # content-addressed blobs, one file per chunk
  manifests/<content-id>     # manifest blobs
  index.db                   # SQLite: paths -> manifest ids, refs, metadata
```

- Atomic commit: manifest blob is written first (temp + fsync + rename), then
  the path→manifest mapping is updated in a single SQLite transaction.
  A `kill -9` at any point leaves either the old or the new state, never a mix.
- **Dedup scope:** per-user by default (privacy- and authorization-safe).
  Global dedup is an explicit opt-in with a documented cross-user tradeoff.
- **E2EE boundary:** with client-side encryption, chunks are encrypted by the
  client and addressed by the hash of the ciphertext; the server stays a dumb
  store. The server-side dedup tradeoff is documented in the threat model.

### Lifecycle operations

- **Versions:** every rename/overwrite that changes content pushes the old
  manifest onto the version chain; retention policy (count + age) in M2.
- **Trash:** deleting marks the path trashed; manifests and chunks remain
  referenced until the retention policy expires them.
- **Garbage collection:** mark-and-sweep. Roots = all live + versioned +
  trashed manifests. Sweep deletes unreferenced blobs after a grace period.
  GC never runs concurrently with manifest writes it cannot snapshot.
- **Scrubbing:** a background worker periodically re-hashes stored chunks
  (BLAKE3) and reports/repairs mismatches. With S3 or replica backends,
  repair reads from a healthy replica.

## Security considerations

- Content addressing makes chunk existence observable. Chunk lookups are
  scoped to the requesting user's store view (no global existence oracle)
  unless global dedup is explicitly enabled.
- Manifests and chunks are verified on read (hash check) before being handed
  to the application layer. Verify-on-read is mandatory, not just scrub-time.
- Chunk boundaries leak content structure to someone with raw store access.
  This is inherent to CDC; E2EE mode encrypts chunk bytes but not boundaries.
  Document, don't pretend otherwise.

## Open questions

1. Binary manifest encoding: custom vs. `postcard` vs. CBOR?
2. Chunk size parameters for small-file-heavy workloads (many files < 256 KiB)?
3. GC concurrency: stop-the-world vs. generation-based marking?
4. Per-file vs. per-directory manifest granularity for directories with
   millions of entries?

## Prior art

- restic / borg / casync — CDC + content-addressed store
- ZFS / Btrfs — checksums, scrubbing, snapshots (without CDC)
- Nextcloud chunked upload (protocol only, not a storage model)
