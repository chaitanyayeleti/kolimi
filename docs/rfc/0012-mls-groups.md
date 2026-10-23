# RFC 0012: MLS group E2EE (RFC 9420)

Status: design (not implemented) · Depends on: RFC 0007 (E2EE), RFC 0008
(device enrollment), RFC 0010 (DAV boundary) · Requires: external audit delta

## Why

Group shares today wrap **each file key for each member** with X25519. That
is simple and works offline, but it has no forward secrecy or
post-compromise security: adding or removing a member does not rotate
anything, and a stolen device keeps every file key it ever received.

MLS replaces the per-member wrapping with a group key schedule. Membership
changes create a new epoch; the exporter secret from that epoch protects a
**share keyring**, so a removed member cannot read files added after the
removal, and a compromised device cannot decrypt future epochs without
participating in a commit.

## Goals

- Forward secrecy and post-compromise security for group shares.
- Asynchronous operation: members need not be online together.
- Multi-device: each enrolled device is an MLS member, not each user.
- Server stays blind: it stores commits, proposals, welcomes and an opaque
  share keyring; it never has the group secret.
- Works from the web (wasm), desktop and CLI.

## Non-goals

- Replacing the per-user UMK or per-file keys. MLS protects the **group
  share keyring**, not the whole account.
- Federation or cross-server groups.
- Hiding group membership from the server (the ACL already exposes it).

## Model

- A server `groups` row gets an `mls_group_id` (random 32 bytes) and a
  monotonically increasing `epoch`.
- Each **enrolled device** publishes a key package (credential: username +
  device public key; lifetime bounded).
- Membership = all devices of all users in the group. Adding a user adds
  all their devices; removing a user removes all their devices.
- One device is the committer per change (last writer wins, server orders
  by `(epoch, seq)`); a proposal queue lets other devices propose adds or
  removes and the next committer commits them.
- Existing encrypted shares stay on the v1 per-member path; a share or
  group is promoted to MLS explicitly (or on the next membership change).
  No silent migration of file keys.

## Share keyring

A shared folder needs a stable, offline-readable keyring for file keys:

```text
share_keyring = { file_id/path -> wrapped file key }
stored_blob   = AEAD(MLS exporter(epoch, "kolimi-share-keyring-v1"), share_keyring)
```

- The blob is stored server-side (it is ciphertext).
- On a membership change, the committer creates the new epoch, decrypts the
  keyring with the previous epoch secret, re-encrypts it with the new one,
  and uploads it atomically with the commit.
- Files added inside the shared folder get their file key written to the
  current keyring by the writer. This is where group-write sharing becomes
  possible; read-only shares only need the owner as writer.
- A removed member still has old file keys they already received. That is
  unavoidable; the guarantee is that **new epochs and new keyring versions**
  are unreadable to them. Document this precisely.

## Server schema

```sql
mls_key_packages (user_id, device_id, payload BLOB, expires_at, ...)
mls_groups (group_id BLOB PRIMARY KEY, epoch INTEGER, ...)
mls_messages (group_id, epoch, seq, kind, payload BLOB, ...)
mls_share_keyrings (group_id, epoch, payload BLOB, ...)
```

The server validates shapes/sizes, orders messages, prevents epoch
regression, and stores blobs. It never parses MLS plaintext.

## Client work

- **kolimi-mls** crate: `openmls` wrapper for create/add/remove/commit/
  welcome/export; key package lifecycle; encrypted group state at rest.
- **Desktop/CLI**: group state under `.kolimi/mls/<group>` encrypted with
  the UMK (or OS keystore); `kolimi-sync` becomes an MLS committer when a
  group share changes.
- **Web**: compile `openmls` to wasm (verify `getrandom` + provider
  support), persist group state in IndexedDB encrypted with the UMK, and
  use the existing device enrollment to bind a browser to an MLS credential.
- **Sync**: for MLS shares, replace the per-file `/api/e2ee/share-key`
  fetch with the epoch share keyring; keep the v1 path for legacy shares.

## Tests

- 3 members across 3 devices: create, add, remove, epoch advance.
- A removed member cannot decrypt the new share keyring or files added
  after removal (integration test).
- A stolen old epoch state cannot derive the next exporter secret (vector
  test).
- Web/desktop interop: a browser commits, the desktop follows.
- Server sees only opaque payloads; no plaintext names/keys in logs.
- Fuzz the message parser and state transitions.

## Rollout

1. `openmls` wasm/desktop spike + key-package API (no user-visible change).
2. Group state/message endpoints + epoch enforcement + tests.
3. Desktop/CLI group-share path behind a flag.
4. Web path + device credential binding.
5. Promote on new group shares; keep v1 reads forever.
6. External audit delta before recommending MLS for sensitive groups.

## Risks

- `openmls` API/version churn and wasm provider support.
- Asynchronous commits: a member can be several epochs behind; the client
  must replay commits/welcomes in order.
- Multi-device membership can make groups large; bound devices per user.
- Revocation is still not a remote wipe: a device that already holds old
  file keys retains them. Future epochs are protected.
