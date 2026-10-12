# RFC 0010: WebDAV / E2EE boundary — a plaintext-only DAV surface

Status: draft (design) · Depends on: RFC 0007 (E2EE), RFC 0001 (storage
engine), RFC 0003 (sharing and permissions), RFC 0009 (E2EE onboarding)

## Summary

WebDAV is a **server-side** protocol and the server holds no E2EE keys, so
DAV can only ever move plaintext. This RFC draws a hard boundary:
**WebDAV is a plaintext-only surface; encrypted subtrees are walled off
from it.** DAV never encrypts, never decrypts, and never touches key
material.

Today the boundary is unenforced. `kolimi-webdav` does not consult the
encryption flag at all, so a generic DAV client can download ciphertext
(an opaque blob) and — worse — `PUT` plaintext into an encrypted path,
storing plaintext on the server while the node stays flagged `encrypted`,
which corrupts it for the sync client and breaks confidentiality. This
RFC makes the separation explicit and safe.

## Motivation

Current behavior (as shipped):

- `GET`/`PROPFIND`/ranges stream the raw CAS bytes, which for an encrypted
  file are `nonce || AEAD(plaintext)` chunks concatenated — unusable to a
  generic client, but served as if it were the file.
- `PUT` (`crates/kolimi-webdav/src/lib.rs:222`) streams the body into the
  store with **no encryption check**, so plaintext can land inside an
  encrypted tree.
- `is_encrypted` is consulted only by `preview.rs` and
  `search_indexer.rs`; the DAV crate ignores it.

Two failure modes follow: **plaintext leakage** (confidentiality) and
**ciphertext corruption** (a plaintext write to an encrypted node makes
it undecryptable). Both must be impossible by construction.

## Goals

- Encrypted content is **invisible** to DAV (not served, not writable).
- No DAV request can create plaintext inside, or move plaintext into, an
  encrypted subtree.
- No key material ever enters the DAV path.
- The boundary is enforced **server-side**, not by client goodwill.
- Plaintext trees keep working exactly as today (Finder/Explorer/rclone/
  davfs2/Office/backups).

## Non-goals

- **Encrypted DAV.** A server-side DAV endpoint cannot decrypt; it has no
  keys. Editing encrypted files from a normal desktop app is the job of a
  **local decrypting gateway** (a client-side proxy/FUSE mount that holds
  the key) — a separate v2 item, out of scope here.
- Hiding metadata of plaintext nodes (names, sizes, mtimes) — unchanged.
- Changing the E2EE crypto, keyring, sharing, or device enrollment.

## The boundary rule

For any path that **is** an encrypted node or is **inside** an encrypted
root:

| Method | Behavior |
| --- | --- |
| `PROPFIND` | omit encrypted children (or list locked stubs carrying a `kolimi-encrypted` property) |
| `GET` / `HEAD` / ranges | `403 Forbidden` (preferred) or `404` (to avoid leaking existence) — never serve ciphertext as a file |
| `PUT` / `MKCOL` | `403` — DAV cannot encrypt, so it must not create plaintext in an E2EE tree |
| `MOVE` / `COPY` | `403` if the operation would cross the boundary in either direction |
| `DELETE` | allowed (removing ciphertext is safe; optional, may also be refused for uniformity) |
| `LOCK` / `UNLOCK` | allowed only on plaintext paths |

`OPTIONS`/capability discovery should advertise the marker so clients can
render locked entries rather than silently showing garbage.

## Encrypted-root marker (the missing piece)

The server cannot currently tell that a *directory* is encrypted.
"Encrypted" is derived per-file from a wrapped key in `e2ee_file_keys`
(`crates/kolimi-db/src/e2ee.rs:79`); directories carry no flag, and the
"this subtree is E2EE" policy lives only in the client's `--e2ee-root`
config.

Add a server-side **encrypted-root marker**:

```sql
-- a directory node flagged as the root of an E2EE subtree
ALTER TABLE nodes ADD COLUMN encrypted_root INTEGER NOT NULL DEFAULT 0;
```

- A node is **encrypted** if it is a marked root or has an ancestor that
  is (ancestry check), or if it has a wrapped file key (files).
- The client sets the marker when it starts encrypting a tree
  (`--e2ee-root`), so the boundary no longer depends on client honesty at
  read time.
- `browse`, `search`, `preview`, and DAV all consult the same helper
  (`is_encrypted_subtree(node)`) instead of ad-hoc per-file lookups.

Migration for existing accounts: mark any directory that currently has
encrypted descendants as an encrypted root (one-time backfill), or keep
the per-file fallback until the client re-marks.

## Boundary-crossing operations

- `MOVE` a plaintext file **into** an encrypted root: `403` (the server
  cannot encrypt it).
- `MOVE` an encrypted file **out**: `403` (the server cannot decrypt it).
- `COPY` across the boundary: `403`.
- `MOVE`/`COPY` wholly within one side: allowed (still subject to the
  per-method rules above).
- Creating a plaintext child under an encrypted root (`PUT`/`MKCOL`):
  `403`.

These checks belong in the DAV crate, immediately after path resolution
and before any store access, alongside the existing lock checks.

## Scoping "separate"

Three ways to configure the boundary, from least to most isolated:

1. **Per-root (recommended).** Some roots are plaintext (DAV-visible),
   others encrypted (hidden). Keep a `Public/`/`Shared/` plaintext root
   for Finder/Office/rclone; `Private/` is invisible to DAV.
2. **Per-account.** An account is *either* a DAV-plaintext account *or* an
   E2EE account. Simplest mental model; no mixing.
3. **Dedicated endpoint.** A separate DAV listener (own port/subdomain,
   e.g. `dav.example.com`) mounted only on plaintext roots, so encrypted
   trees are not reachable at all. Optionally an allow-list of DAV roots
   (`dav_roots = ["Public"]`) enforced at mount time.

## Interaction with RFC 0009 (encrypt by default)

If the whole account is encrypted by default, a plaintext-only DAV surface
would be **empty**. The two RFCs must be adopted together:

> Encrypt by default **and** keep one plaintext root (or a separate DAV
> account) as the DAV zone.

The honest, documented story: *DAV is for plaintext files; encrypted
files live in the Kolimi client.* Editing encrypted files from Finder is
the local decrypting gateway, not remote DAV.

## Device integrations

The DAV surface exists mainly for device integrations. They fall into two
kinds, and only one touches the boundary:

- **CalDAV / CardDAV (contacts, calendar).** A separate namespace in
  dedicated tables (RFC 0004), not the chunked file CAS. E2EE (RFC 0007)
  only covers *file content*, so contacts and calendar are **unaffected**
  and stay plaintext. Nothing to wall off; no change here.
- **GrapheneOS Seedvault backup.** Uses the **file** WebDAV endpoint, so
  it does hit the boundary. Seedvault **encrypts its own backup payload
  client-side** (the vault is encrypted under the user's backup key before
  upload), so a plaintext DAV root is acceptable for confidentiality — the
  server stores an already-encrypted vault. Keep a dedicated **plaintext
  root** (e.g. `Backups/`) that is never encrypted and always DAV-visible.

Consequences:

- With RFC 0009 (encrypt by default) a fully encrypted account leaves DAV
  **empty**, breaking Seedvault. The plaintext carve-out is therefore
  **required**, not optional.
- Enforce it server-side with a `dav_roots` allow-list (e.g.
  `["Backups"]`) applied at mount time, so a device integration can only
  ever see its own plaintext root.
- For the strongest separation, give integrations a **dedicated DAV
  endpoint or account** (own port/subdomain or a separate user) entirely
  apart from the E2EE file account.
- **Defense in depth for the DAV zone:** E2EE does not protect it, so rely
  on disk-level encryption at rest (e.g. LUKS) for the server volume.

Net model: **DAV = plaintext zone for integrations (contacts, calendar,
Seedvault); E2EE = client-only zone for private files.** They never mix.

## Security considerations

- **Existence leak.** `403` reveals that a path exists; `404` hides it.
  Default to `404` for encrypted paths on `GET`/`HEAD`/`PUT` (consistent
  with "invisible"), and omit them from `PROPFIND` unless stub listing is
  enabled.
- **No key material in DAV.** The DAV path must never read `e2ee_*`
  tables; the boundary check uses only the node marker/ancestry.
- **No plaintext-in-encrypted-tree, ever.** This is the invariant that
  prevents both leakage and corruption; enforce it on every write path
  (`PUT`, `MKCOL`, `MOVE`, `COPY`).
- **Metadata still leaks** for plaintext nodes (unchanged from RFC 0007).
- **Backups/restore** operate on ciphertext unchanged; DAV is orthogonal.

## Alternatives considered

- **Serve ciphertext over DAV with a clear content-type/marker.**
  Rejected as the default: it invites users to save corrupt blobs and
  offers no way to edit. Could be an opt-in "raw" mode for backup tools.
- **Server-side decrypting DAV.** Impossible — the server has no keys.
- **Client-side decryption inside the DAV crate.** Wrong layer: DAV runs
  on the server; a decrypting DAV must be a client-local gateway.
- **Rely on the client to avoid encrypted paths.** Rejected: the server
  must not depend on client goodwill for confidentiality/integrity.

## Open questions

- Stub listing vs full omission in `PROPFIND` for encrypted children.
- `403` vs `404` defaults (existence-leak trade-off); make it a config?
- Do `DELETE` and `LOCK` need boundary checks for uniformity, or only the
  read/write/transfer methods?
- Backfill strategy for existing accounts without a root marker.
- Whether to ship the local decrypting gateway as part of the desktop app
  (RFC 0006 / client plan) or as a separate tool.
