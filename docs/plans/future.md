# Future ideas and deferred work

Status: **unscheduled backlog** · Date: 2026-11-16

This is not a roadmap commitment. Current priorities live in
[ROADMAP.md](../../ROADMAP.md); shipped work lives in
[CHANGELOG.md](../../CHANGELOG.md). Parked UI work is already described in
[ui.md](ui.md). Nothing here should be started without first writing an RFC
or implementation plan, reviewing its security impact, and choosing a release
target.

The goal of this page is memory, not momentum: capture the idea, why it
matters, and the main risk while it is fresh.

## Parked UI work

The later phases in [ui.md](ui.md) are not started:

- Shared page for received/created shares and public links.
- Favorites and Recent.
- Command palette.
- Notifications.
- PWA / installable app shell.

## Core ideas

### A. Sharing beyond read-only

| Idea | Why it matters | Size | Main caveat |
| --- | --- | --- | --- |
| **Upload-only links / file requests** | Public links are read-only today; collecting files from clients or family is the missing half of sharing. A drop link can accept uploads with no listing or download. | M/L | Abuse and storage exhaustion; needs hard per-link file/byte caps, rate limits, expiry, and a dedicated “Requests” area. |
| **One-time / limited-download links** | Sensitive documents often need “download once” or a maximum download count. | S/M | Counting is fuzzy for folder links and range requests; start with single-file links. |
| **Link activity feed** | Owners should see when a link was opened, downloaded, or used to upload. | S once events exist | Depends on an event table (the parked notifications work). |

### B. Calendars and contacts

| Idea | Why it matters | Size | Main caveat |
| --- | --- | --- | --- |
| **Read-only ICS/vCard feed links** | A secret `/cal/<token>.ics` or `/ab/<token>.vcf` URL lets people subscribe from Apple Calendar, Thunderbird, or Google Calendar without full CalDAV sharing. | M | Token is a bearer secret: hash at rest, redact from logs, rate-limit, read-only, revocable, optional expiry. |
| **Per-collection CalDAV/CardDAV sharing** | Kolimi advertises calendars and contacts, but collections are single-user. Share a calendar or address book with a user/group, read-only or read-write. | L/XL | RFC 0004 explicitly defers this; needs collection ACLs, proxy collections in the recipient’s home, privilege properties, and client compatibility testing. |
| **CalDAV scheduling and free/busy** | iTIP invites, RSVP updates, and free-busy queries between local users — no email required. | L | Do it after collection sharing; clients expect specific scheduling properties and inbox/outbox behavior. |

### C. Data portability and durability

| Idea | Why it matters | Size | Main caveat |
| --- | --- | --- | --- |
| **Portable export and import** | `kolimi export` should produce a documented archive of files, calendars, contacts, metadata, and shares. `kolimi import` should accept a local folder or another WebDAV server. | M/L | Archive format, conflict policy, resumable import, and checksums need a spec. Import from WebDAV stays protocol-first. |
| **Incremental, encrypted, offsite backups** | `backup` currently writes a full DB snapshot plus blobs. Incremental snapshots, retention, encryption, and an optional S3/restic-compatible target make offsite protection practical. | M | Keep the local data directory the source of truth; offsite storage is a backup target, not a primary backend. |
| **`kolimi doctor`** | One command for disk space, data-directory permissions, SQLite integrity, scrub status, backup age, certificate expiry, version, and obvious config mistakes. | S/M | Builds on `verify`; avoid becoming a second configuration system. |

### D. Reliability and scale

| Idea | Why it matters | Size | Main caveat |
| --- | --- | --- | --- |
| **Resumable and streaming uploads** | Browser uploads are a single PUT; E2EE uploads read the whole file before chunking. A resumable session (tus-like or a small chunk API) improves large-file and mobile reliability and lowers memory. | L | New protocol surface, cleanup of abandoned sessions, and careful E2EE chunk handling. |
| **A real conflict model** | Sync preserves local edits as `.conflict-*` copies but only reports a count. Add conflict records, paths, and “keep local / keep remote / open folder” actions. | M | Mostly sync + desktop; the server should not guess at content. |
| **Large-folder pagination** | `/api/browse` returns every entry and the UI renders every row. Add cursor pagination and a virtualized list. | M/L | Changes the browse response shape; keep the old path working for clients during migration. |
| **PDF/Office text extraction for search** | Search currently indexes text-like files; PDFs and Office documents are name-only. Add sandboxed extraction for PDF, DOCX/ODT, PPTX/ODP, and EPUB. | M | Extraction must stay in the preview worker sandbox; OCR would require an external binary and is out of scope. |
| **Preview cache** | Thumbnails are regenerated on repeated grid views. Cache by node ETag/size with a disk-backed cache and HTTP validators. | S/M | Cache invalidation and disk usage; encrypted files stay excluded. |

### E. Security depth

| Idea | Why it matters | Size | Main caveat |
| --- | --- | --- | --- |
| **Scoped and expiring app passwords** | App passwords currently grant full account access. Add scopes such as WebDAV read/write, CalDAV/CardDAV, sync, and read-only, plus optional expiry and last-used time. | M | Existing tokens keep full access for compatibility; scope checks must be enforced in one authorization layer, not per route. |
| **Browser PRF key wrap** | Issue #16: wrap the browser’s device key with a WebAuthn PRF-derived key instead of keeping the unlocked state only for the tab session. | M | WebAuthn PRF support varies; needs a browser E2E test and review. |

## If we pick one

If the goal is maximum core value for the least risk:

1. **Upload-only links** — the clearest missing sharing primitive.
2. **Scoped app passwords** — small surface, immediate security gain.
3. **Calendar/contact feed links** — cheap, useful, and opens the calendar-sharing story without a full ACL project.

The strategic bet after those is **per-collection CalDAV/CardDAV sharing**: it is
the biggest gap between what Kolimi claims and what it currently does for more
than one person.

## Not now

These are deliberately not on the list above:

- SSO/OIDC — adds an external identity dependency and support burden.
- S3 as a primary storage backend — breaks the one-data-directory simplicity.
- Cross-user deduplication — privacy and side-channel headaches.
- A first-party calendar/contacts UI — protocol-first remains the right call.
- Comments/chat — not the product’s job.
- A plugin host — see the existing non-goals in `ROADMAP.md`.

## Promotion checklist

Before an idea becomes scheduled work:

- Write an RFC or plan with the data model, API, authorization, and failure
  modes.
- Update `docs/threat-model.md` if the trust boundary or new anonymous
  surface changes.
- Prove migrations are forward-only and test backup/restore for any schema
  change.
- Check client compatibility (WebDAV, CalDAV/CardDAV, desktop, FFI) where
  relevant.
- Keep E2EE rules intact: the server never receives plaintext names, file
  keys, or decrypted content.
- Add the release target, docs, and `CHANGELOG.md` entry only when the work
  is actually scheduled.
