# RFC index

Design specs live here. An RFC explains the problem, protocol, data model
and non-goals; implementation status is tracked separately so a design can
be accepted before every client supports it.

Last full verification: **0.3.0** (2026-10-25).

| RFC | Design | Implementation (0.3.0) | Notes |
| --- | --- | --- | --- |
| [0001 — Storage engine](0001-storage-engine.md) | implemented | shipped | FastCDC + BLAKE3 CAS, manifests, GC |
| [0002 — Sync protocol](0002-sync-protocol.md) | implemented | shipped | Server + `kolimi-sync`/desktop; mobile uses the FFI core |
| [0003 — Sharing and permissions](0003-sharing-and-permissions.md) | implemented | shipped | Users, groups, public links; one authz engine |
| [0004 — CalDAV / CardDAV](0004-caldav-carddav.md) | implemented | shipped | Discovery, collections, filters, `sync-collection` |
| [0005 — Search and previews](0005-search-and-previews.md) | implemented | shipped | tantivy index + sandboxed preview worker |
| [0006 — Sync client](0006-sync-client.md) | implemented | shipped (alpha) | CLI, desktop tray, FFI core |
| [0007 — E2EE](0007-e2ee.md) | implemented | shipped | v1/v2 per-file keys; group sharing is RFC 0012 |
| [0008 — Device enrollment](0008-device-enrollment.md) | implemented | shipped | CLI + web Devices panel |
| [0009 — E2EE onboarding](0009-e2ee-onboarding.md) | draft | partial | Web Vault + encrypt-by-default landed; passkey-PRF browser unlock pending |
| [0010 — WebDAV / E2EE boundary](0010-webdav-e2ee-boundary.md) | draft | partial | DAV refuses encrypted nodes; marker-based dir boundary deferred |
| [0011 — Client unlock](0011-e2ee-client-unlock.md) | implemented | shipped (desktop) | `SyncError::Locked`, tray state, keychain unlock |
| [0012 — MLS groups](0012-mls-groups.md) | implemented | shipped; **audit pending** | Node-scoped groups, epochs, keyring, write shares |

## Status conventions

- **Design**: `draft` (still changing), `accepted` (agreed, not fully
  reflected in code), or `implemented` (the code follows this design).
- **Implementation**: `shipped`, `partial`, or `not started`, verified
  against the release in the heading. “Shipped” does not mean audited.
- **Security status is separate.** E2EE/MLS audit state is tracked in
  [`docs/audit/`](../audit/README.md), not inferred from an RFC status.
  MLS is not externally audited.

## Updating an RFC

1. Change the design first, then the `Status:` line and this table.
2. Add or update tests in the relevant crate; link them from the RFC when
   they are the evidence for an invariant.
3. If the change affects operations or the public API, update
   [docs/operations.md](../operations.md) or
   [docs/reference.md](../reference.md) and add a `CHANGELOG.md` entry.
4. Keep the RFC's “non-goals” section honest; move work that is now in
   scope into the design instead of silently expanding it.
