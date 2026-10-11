# RFC 0005 — Search and Sandboxed Previews

- **Status:** Implemented (M5, server side)
- **Milestone:** M5
- **Related:** RFC 0001 (Storage), RFC 0002 (Sync), `docs/threat-model.md`

## Full-text search

One tantivy index per deployment holds every user's documents; queries
are filtered by a `user` term, so results never cross accounts. Indexed
fields: `name` and `path` (always), plus up to 1 MiB of `content` for
files that look textual (extension/MIME allowlist, binary sniff). A 4 KiB
snippet is stored per document for result excerpts.

The index is fed from the existing change feed by a background indexer:

1. read `changes_since(last_indexed_seq)` for each user
2. upsert/remove documents and `commit()`
3. persist the new sequence **after** the commit

A crash at any point therefore replays idempotent upserts; the index is
fully rebuildable and never the source of truth. Deletes and moves are
handled from the feed (`move` = remove old path + index new one).

`GET /api/search?q=&limit=` returns `{path, name, is_dir, size,
modified_at, score, snippet}`. Query syntax errors are a 400. The web UI
has a search box; hits navigate to their parent folder and can be
downloaded directly.

## Sandboxed previews

Preview *decoding* never happens in the server process. The server
re-executes its own binary as a hidden `preview-worker` subcommand; the
worker applies, in order:

1. **rlimits** — 1 GiB address space, 10 CPU seconds, 64 MiB file size,
   32 open files
2. **landlock** (ABI v1) — filesystem access restricted to reading the
   single scratch input file, with `no_new_privs`
3. **seccomp** — a syscall allowlist (I/O, memory, futex, exit…);
   everything else, including all networking and `execve`/`clone`,
   returns `EPERM`

The parent enforces a 10-second wall clock, `kill_on_drop`, and a
4-worker semaphore; scratch files live in `data/tmp` and are removed
after each run. Decoding itself is bounded by the `image` crate's limits
(16 384 px per side, 256 MiB allocation) so decompression bombs fail
instead of allocating.

Surface:

- `GET /api/preview?path=&size=` → `image/png` thumbnail for raster
  images (png/jpeg/gif/bmp), `text/plain` head for text files, 415 for
  everything else, 413 above 20 MiB input, 422 when the worker fails.
- Permission checks happen before the worker is spawned (received shares
  included); workers only ever see a scratch copy, never the blob store.

Failure isolation is a tested property: a corrupt image makes its own
request fail while the server keeps serving traffic. The decode path is
also a cargo-fuzz target (`preview_image`) run in CI.

## Deliberately out of scope (M5 server side)

- PDF/video/office previews (they need external decoders; the worker
  protocol is ready for them).
- OCR, image search, thumbnail caching.
- Per-user index sharding (one index with a user filter is plenty for the
  target scale; tantivy fast fields make it cheap).
