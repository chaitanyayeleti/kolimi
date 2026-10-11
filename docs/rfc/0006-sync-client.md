# RFC 0006: Desktop sync client (`kolimi-sync`)

Status: implemented (alpha) · Depends on: RFC 0001 (storage engine),
RFC 0002 (sync protocol)

## Summary

`crates/kolimi-sync` is the first native client: a library plus a
`kolimi-sync` CLI that mirrors a local directory against a Kolimi server
using the delta protocol from RFC 0002. It is deliberately headless —
the Tauri tray app and the mobile client (uniffi bindings) are thin
wrappers that call `sync_once` from a timer or file watcher.

## Goals

- Byte-identical mirroring of a local directory and a server tree,
  including deletions, in both directions.
- Minimal network use: pull only fetches chunks missing from the local
  cache; push chunks locally and commits manifests with optimistic
  concurrency (`if_content_id`).
- Crash safety: every step is idempotent; an interrupted sync never
  corrupts local state or the server tree.
- Deterministic conflict policy that never loses data.

## Non-goals (alpha)

- Real-time filesystem watching (the caller schedules `sync_once`).
- Selective sync / sparse trees (syncs the whole user tree).
- Bandwidth limiting, resumable chunk uploads.
- E2EE (arrives with M6; the protocol supports opaque chunk bytes).

## Design

### State

All client state lives under `<local>/.kolimi/`:

- `state.json` — map of relative path →
  `{ content_id, size, mtime_ns, deleted }`. `deleted` is a tombstone
  set when a previously synced file disappears locally; push propagates
  the deletion and clears the entry.
- `chunks/aa/bb/<hash>` — the delta base. Chunk files are written
  atomically (temp + rename) and are never removed by sync; the janitor
  story for the client cache is future work.

The state file is written atomically after each phase. A lost state file
only costs a full re-hash of the tree, never correctness.

### Pull (server → local)

1. Page through `GET /api/sync/tree` to enumerate live files.
2. For each file, compare the remote `content_id` with state:
   - equal and local file exists → skip;
   - equal and local file missing → tombstone (user deleted it), skip —
     push will delete it remotely;
   - different and the local file was modified since the last sync
     (size/mtime differ from state) → skip; push resolves the conflict;
   - otherwise → fetch the manifest, download missing chunks into the
     cache, reassemble, and write atomically.
3. Paths in state that no longer exist remotely are deleted locally
   (with empty parent directories pruned).

### Push (local → server)

1. Walk the local tree (skipping `.kolimi/`), compare size + mtime
   against state; unchanged files are skipped.
2. For changed/new files: `split()` with the same FastCDC + BLAKE3
   parameters as the server, upload missing chunks
   (`PUT /api/chunks/{hash}`, 201/204), then
   `PUT /api/files?path=…&if_content_id=…` with the manifest.
3. A `409` means the server moved on: the local edit is preserved as
   `name.conflict-<unix-secs>`, the state entry is dropped, and the
   server version is pulled on the re-pull pass (`report.conflicts`).
4. State entries whose local file is gone are deleted remotely via
   `DELETE /dav/{path}` (directories are created first with `MKCOL`).

### Ordering and idempotency

`sync_once` = pull → push → re-pull (only if conflicts occurred). Each
phase is safe to re-run: pulls are content-addressed, pushes are
preconditioned, deletions are idempotent (404 tolerated). There is no
partial-commit state: a file is either fully mirrored or not at all.

### Report

`SyncReport { pulled, pushed, removed_local, removed_remote, conflicts }`
is returned to the caller (the CLI prints it; shells surface it in the
tray/UI). A second pass over an unchanged tree reports all zeros.

## Testing

Integration tests live in `crates/kolimi-server/tests/sync_client.rs`
and run against a real server (`build_app`) on an ephemeral
`127.0.0.1:0` listener:

- seed-dir push → mirror pull with byte-identical trees;
- second pass is a no-op in both directions;
- edits, additions, and deletions propagate each way;
- simultaneous edits: server version wins, local edit survives as
  `.conflict-<ts>`, `conflicts == 1`;
- delta cache: a small edit in a 6 MiB file reuses cached chunks and
  the file still arrives byte-identical.

## Alternatives considered

- **WebDAV-only client** (mount or rclone): no chunk-level delta, weak
  conflict semantics, no client-side state. Kept as an interop path,
  not the primary client.
- **Bidirectional record-level sync à la Syncthing**: stronger
  peer model than a single authoritative server needs; the server-side
  change feed already gives us ordering.
- **Storing state inside the chunk cache**: entangles GC with sync
  state; a separate JSON file is trivially inspectable and debuggable.

## Future work

- uniffi bindings and mobile background upload (M5/M6 clients).
- Tauri tray shell (status, pause/resume, selective sync).
- Watcher mode with debounce; upload batching.
- Client-side chunk cache GC (LRU by last use).
- E2EE: encrypt chunks and manifests client-side before `split()`;
  the server then stores opaque bytes and the conflict policy stays
  unchanged.
