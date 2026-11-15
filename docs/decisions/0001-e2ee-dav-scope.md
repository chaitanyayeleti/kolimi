# Decision 0001: E2EE scope and WebDAV boundary

Status: **Accepted (2026-10-26) — option B implemented in 0.1.30** · Date: 2026-10-12 · Depends on:
RFC 0007 (E2EE), RFC 0008 (device enrollment), RFC 0009 (E2EE
onboarding), RFC 0010 (WebDAV/E2EE boundary)

## Context

v0.1.5 shipped Web-UI E2EE (decrypt in the browser) and public links to
encrypted files. While designing the next step, two draft RFCs were
written:

- **RFC 0009 — E2EE onboarding:** move keyring creation into the first
  browser login and make **encryption the default** for the whole
  account (opt-out folders). Crypto unchanged.
- **RFC 0010 — WebDAV/E2EE boundary:** make WebDAV a **plaintext-only**
  surface; encrypted subtrees invisible/refused. Requires a server-side
  **encrypted-root marker**.

A real bug surfaced during this: `kolimi-webdav` ignores the encryption
flag entirely, so a generic DAV client can **download ciphertext** and
**`PUT` plaintext into an encrypted path** (plaintext leak + node
corruption).

The operator's actual DAV usage is: **contacts (CardDAV)**, **calendar
(CalDAV)**, and **GrapheneOS Seedvault backups** (file WebDAV). Contacts
and calendar are a separate namespace and are **not** E2EE. Seedvault
**encrypts its own payload client-side**, so plaintext DAV is acceptable
there.

## Decision drivers

- Keep the personal setup **simple**; avoid building product features that
  are not needed.
- Fix the real DAV leak/corruption bug regardless.
- Preserve E2EE correctness (server never sees keys).
- Avoid new data-model concepts (markers, migrations) unless justified.

## Options

### A. DAV guard only — *recommended*
Refuse DAV `GET`/`PUT` on **encrypted nodes** (check
`is_encrypted(node)`; no schema change). Keep E2EE **opt-in** as today.
Document "encrypted files are client-only; DAV is plaintext."

- Effort: ~0.5 day. New concepts: none. Fixes the leak + overwrite bug.
- Gap: cannot detect a brand-new `PUT` into an encrypted *directory*
  (server has no dir-level flag), so it does not cover "create plaintext
  inside an encrypted tree."

### B. Marker + full DAV boundary (RFC 0010)
Add `nodes.encrypted_root` (migration 0015) + `is_encrypted_subtree`
helper; guard every DAV method; optional `dav_roots` allow-list.

- Effort: ~1 week. New concepts: encrypted-root marker, migrations,
  allow-list. Airtight dir-level enforcement; plaintext DAV unchanged.

### C. Full RFC 0009 + 0010
Browser keyring setup (wasm Argon2id, passkey PRF, UMK persistence),
encrypt-by-default with plaintext carve-outs, plus B.

- Effort: ~2–3 weeks. New concepts: many (see RFC 0009). A product
  feature; **not required** for the personal DAV/backup use case.

## Decision

Option **B** was chosen and implemented. A directory's existing `encrypted`
flag serves as the marker, so no separate `encrypted_root` column was
needed; `path_is_encrypted` walks ancestors and every DAV content operation
checks it. Plaintext DAV is unchanged. Option C's encrypt-by-default has
since shipped for the web `Vault/` tree; browser passkey-PRF unlock remains
future work (RFC 0009).

## Consequences

- B closed the directory-level gap: DAV refuses content reads and writes
  inside an encrypted folder. `DELETE` and `LOCK` stay metadata-only.
- Encrypted paths may still list opaque `k1_…` names; E2EE remains opt-in
  per tree, and metadata such as sizes and structure stays visible.
- The encrypt-by-default and passkey-PRF parts of RFC 0009 remain partial;
  they are tracked there rather than in this decision.

## References

- [RFC 0007 — E2EE](../rfc/0007-e2ee.md)
- [RFC 0008 — device enrollment](../rfc/0008-device-enrollment.md)
- [RFC 0009 — E2EE onboarding](../rfc/0009-e2ee-onboarding.md)
- [RFC 0010 — WebDAV/E2EE boundary](../rfc/0010-webdav-e2ee-boundary.md)
- Bug: `crates/kolimi-webdav/src/lib.rs` `put()` ignores encryption;
  `is_encrypted` used only by `preview.rs` and `search_indexer.rs`.
