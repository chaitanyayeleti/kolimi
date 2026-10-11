# RFC 0002 — Sync Protocol

- **Status:** Server side implemented (M2); client implementations pending (M5)
- **Milestone:** M2 (server), M5 (clients)
- **Related:** RFC 0001 (Storage Engine), `docs/threat-model.md`

## Summary

Kolimi speaks standard **WebDAV** for compatibility, and a **native delta
protocol** for first-party clients. The design goal is simple: a client must
never transfer or re-transfer a byte it does not need.

Three mechanisms deliver that:

1. **Change feed** — per-user monotonic log of metadata events.
2. **Chunk-level delta transfer** — clients upload/download only missing chunks.
3. **Live notifications** — SSE so clients learn about changes immediately.

WebDAV compatibility is defined by the litmus test suite plus real clients
(rclone, davfs, Thunderbird) — it is the floor, not the ceiling.

## Compatibility floor (WebDAV)

- RFC 4918: PROPFIND (Depth 0/1, with pagination), GET/HEAD, PUT, MKCOL,
  COPY, MOVE, DELETE, LOCK/UNLOCK, PROPPATCH (dead properties).
- `GET` file: `ETag = content-id` (RFC 0001), `Last-Modified` from metadata.
- `PUT` file: full replace. The server chunks the body and commits a manifest
  atomically. `If-Match` supported for optimistic concurrency.
- `HEAD`/`GET` honor `If-None-Match` — the most valuable caching primitive
  for third-party clients.
- PROPFIND with `Depth: 1` must be paginated (RFC 6578-style limit/offset
  extension) to survive directories with large entry counts.

## Native protocol

### Change feed

- Every metadata mutation appends a row to a per-user `changes` table with a
  monotonic `seq`, `path`, `op` (upsert/delete/move), `content_id`, `size`,
  `mtime`, and `etag`.
- `GET /api/sync/changes?since={seq}&limit=N` returns a page of events plus
  `next_seq`. Clients resume from their stored `seq` forever; they never
  enumerate the whole tree again after the first scan.
- Tombstones are kept until all known devices have acknowledged them past the
  retention horizon (device table tracks last-seen seq), then compacted.
- Moves and renames are first-class events; clients apply them without
  re-hashing content.

### Bootstrapping a new client

1. `GET /api/sync/tree` — paginated snapshot of the user's namespace with
   content ids and etags at snapshot `seq`.
2. Fetch manifests and chunks for files the client doesn't already have
   (checked locally by chunk hash — a re-installed client over an existing
   folder transfers nothing).
3. Subscribe to the live channel from `seq` onward.

### Delta transfer

Download:

1. `GET /api/files/{path}/manifest` → manifest JSON.
2. Client diffs chunk hashes against its local store.
3. `GET /api/chunks/{hash}` for missing chunks only (server verifies the
   requested hash before responding).

Upload (editing an existing file):

1. Client chunks locally, diffs against the server manifest.
2. `PUT /api/chunks/{hash}` for missing chunks — idempotent, no session
   needed, safe to retry.
3. `PUT /api/files/{path}?if_manifest={content_id}` with the new manifest.
   Server verifies every referenced chunk exists, then commits atomically.
   Conflict (manifest moved under the client) → 409 with the current manifest
   so the client can merge/retry.

Because steps 2–3 are idempotent and content-addressed, interrupted transfers
resume by simply retrying; partial STATE is never inconsistent.

### Live notifications

- `GET /api/sync/events?since={seq}` — Server-Sent Events stream.
- Emits `{seq}` pings (not full data) so it doubles as a wake-up channel;
  clients fetch changes from the feed on ping. `Last-Event-ID` resumes.
- Fallback: long-poll `GET /api/sync/longpoll?since={seq}&timeout=30`.
- Push to mobile via UnifiedPush/ntfy; APNs/FCM only as an opt-in bridge,
  never a dependency.

## Conflict semantics (v1)

- Last-writer-wins at file granularity; both versions are preserved:
  the losing manifest stays in the version chain and the losing device is
  told to save its copy as `name (conflicted copy YYYY-MM-DD).ext`.
- Directory/metadata conflicts resolve server-first (no split-brain trees).
- True merge (per-file strategy registry, e.g. text merge) is a later
  milestone; v1 optimizes for never losing data, not for auto-merging.

## Performance requirements

- 10k changed-metadata files must sync in < 5 s of metadata traffic
  (no chunk traffic if content ids unchanged).
- Change feed pages are keyset-paginated on `seq` (never OFFSET scans).
- Chunk endpoint supports HTTP/2 + HTTP/3, `Content-Range` range reads,
  and zero-copy paths where the OS allows.

## Security considerations

- **Chunk-access oracle:** `GET /api/chunks/{hash}` verifies the hash exists
  *and* is referenced by at least one manifest visible to the requesting
  user. A 404/200 difference must not leak cross-user existence.
- Auth on every endpoint; SSE and long-poll included (cookie or bearer).
- Rate limits per user and per IP; chunk uploads are cheap but unlimited
  garbage chunks must be GC-able even if never referenced (write-through
  garbage collection with TTL).
- Malicious manifests: reject manifests referencing absent chunks, chunk
  lengths that overflow, or sizes inconsistent with chunk sums.

## Open questions

1. Case sensitivity and Unicode normalization for paths (NFC vs NFD)?
2. ETag semantics for directories (metadata etag vs content etag)?
3. Should clients be able to pin/prioritize sync roots?
4. Durable client-side queue format is per-client (desktop, mobile), but
   shared consistency tests belong in this repo — test vectors?

## Client implementation (M5 alpha: `kolimi-sync`)

The first client implementation lives in `crates/kolimi-sync` (lib + CLI).
It follows this RFC directly:

- **Pull** walks `/api/sync/tree`, fetches manifests, and downloads only
  chunks missing from `<local>/.kolimi/chunks/` (the delta base), writing
  files atomically.
- **Push** chunks changed local files with the same FastCDC + BLAKE3
  parameters as the server, uploads missing chunks, and commits with
  `if_content_id` from its state file.
- **Deletions** propagate both ways: files that vanish locally become
  tombstones and are deleted remotely on the next push; files deleted
  remotely are removed locally on the next pull.
- **Conflicts** are resolved by keeping the server version and preserving
  the local edit as `name.conflict-<timestamp>` (the local file is then
  re-pulled to match the server).

State is a JSON file (`state.json`: path → content_id, size, mtime_ns,
tombstone). The Tauri shell and the mobile (uniffi) client are thin
wrappers over this core; the one-shot `sync_once` is intended to be
called from a timer or file watcher.
