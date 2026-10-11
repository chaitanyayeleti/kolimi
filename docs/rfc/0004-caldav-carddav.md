# RFC 0004 — CalDAV, CardDAV, and `sync-collection`

- **Status:** Implemented (M4)
- **Milestone:** M4
- **Related:** RFC 0001 (Storage Engine), RFC 0002 (Sync Protocol),
  RFC 0003 (Sharing), `docs/threat-model.md`

## Summary

Calendars and contacts are first-class DAV collections beside the file
tree, served from the same `/dav` endpoint that speaks WebDAV. Existing
clients (Thunderbird, iOS, macOS, DAVx⁵) discover them through RFC 6764
and synchronize incrementally through RFC 6578 `sync-collection`.

## Why separate storage

Calendar objects and vCards are small, are versioned by clients through
ETags, and have their own change semantics. Putting them in the
content-addressed file store would buy little (chunking, dedup) and cost
integration complexity (per-collection change logs, per-object UIDs).
Instead they live in three tables (migration 0006):

- `dav_collections` — one row per calendar/address book (`kind`, `name`,
  `displayname`, `description`, `color`)
- `dav_objects` — raw payloads with extracted `uid`, `etag` (BLAKE3),
  unique on `(collection_id, name)` and `(collection_id, uid)`
- `dav_changes` — a per-collection sequence; doubles as the CTag and the
  `sync-token` basis

The file tree is untouched; the root names `principals`, `calendars`, and
`addressbooks` are reserved so a file can never shadow a DAV namespace.

## URLs and discovery

```
/.well-known/caldav   -> 301 /dav/
/.well-known/carddav  -> 301 /dav/

/dav/                          current-user-principal (on every PROPFIND)
/dav/principals/{user}/        calendar-home-set, addressbook-home-set
/dav/calendars/{user}/         calendar home (Depth: 1 lists calendars)
/dav/calendars/{user}/{cal}/   one calendar (MKCALENDAR, PROPFIND, REPORT,
                               PROPPATCH, DELETE)
/dav/addressbooks/{user}/{ab}/ one address book (extended MKCOL)
.../{cal|ab}/{name}            object resources (GET/PUT/DELETE/PROPFIND)
```

Principals and homes are only visible to their owner; everything else
returns 404 (no cross-user existence leaks).

## Object rules

- **PUT** validates payloads: iCalendar is parsed with the `icalendar`
  crate and must contain at least one VEVENT/VTODO/VJOURNAL/VFREEBUSY
  with one shared UID (RFC 4791 §4.1); vCards are structurally validated
  (one card, VERSION, UID) because Apple and Thunderbird still send 3.0,
  which strict 4.0 parsers reject. Payloads are stored byte-for-byte, so
  VALARMs and unknown X-properties survive round trips exactly.
- A UID already used by a different resource in the collection is a 409
  (`no-uid-conflict`); updating the same resource is fine.
- ETags are quoted BLAKE3 hashes; `If-Match`/`If-None-Match` are honoured
  on PUT and GET (412/304).
- Maximum object size: 10 MiB.

## Reports

- `calendar-query` / `addressbook-query` — the **filter is advisory**: the
  full collection is returned and clients filter locally. Time-range
  filtering with TZID handling is deliberately deferred; correctness of
  the filter is a client-side display concern, and collections are small.
- `calendar-multiget` / `addressbook-multiget` — exact href matching;
  unknown or out-of-collection hrefs get a 404 response entry.
- `sync-collection` (calendars, address books, **and the file tree**) —
  initial sync returns everything plus a token
  (`urn:kolimi:sync:{collection}:{seq}` / `urn:kolimi:sync:user:{id}:{seq}`);
  incremental sync returns upserts, 404 entries for deletions, and a new
  token. Unknown tokens get 403 `valid-sync-token`. `sync-level: infinite`
  is rejected (403). The file-tree feed is scoped to the addressed
  directory prefix; moves report a deletion at the old path and an upsert
  at the new one.

## Properties

Calendar/address-book collections render: `resourcetype` (calendar /
addressbook), `displayname`, `getctag` (CalendarServer ns),
`sync-token`, `supported-calendar-component-set`, `supported-address-data`,
`calendar-color` (Apple ns), descriptions, privileges, and
`supported-report-set`. PROPPATCH accepts exactly the mutable ones
(displayname, color, description); everything else is 403.

## Deliberately out of scope (M4)

- Server-side alarm delivery: VALARMs sync to clients, which schedule
  reminders locally. Push/notification delivery belongs to M5.
- Time-range/RFC 5545 recurrence expansion for query filters.
- Free-busy reports, scheduling (iTIP/iMIP), calendar subscriptions.
- Per-collection sharing: CalDAV/CardDAV collections are not mountable
  through RFC 0003 yet.
