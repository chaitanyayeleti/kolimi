# RFC 0012: MLS group E2EE (RFC 9420)

Status: implemented (0.3.0); external audit pending · Last verified:
0.3.0 · Depends on: RFC 0007 (E2EE), RFC 0008 (device enrollment),
RFC 0010 (DAV boundary)

> **Client + server hardening (0.3.0):** `crates/kolimi-mls` (openmls 0.9)
> provides device credentials/key packages, group create/add, Welcome
> joins, the `kolimi-share-keyring-v1` epoch exporter, epoch rotation, and
> the epoch-bound encrypted share-keyring format. The server stores
> node-scoped group state (`/api/mls/*`). Sync/desktop keeps sealed
> `MlsStore` state (UMK-sealed, 0600), creates a group on an encrypted
> folder share, joins from the Welcome on the recipient, processes commits,
> reads/updates the keyring, and supports write recipients. The web client
> compiles the same crate to wasm, persists sealed state in browser storage,
> and uses the keyring for shared reads and writes. `kolimi-sync
> --mls-migrate` promotes existing encrypted folder shares; legacy v1 wraps
> still read. Write shares are opt-in in sync/desktop and on by default in
> the web UI (IndexedDB; localStorage kill switch `kolimi-mls=0`).
> Membership add/remove rotates the keyring, key packages are a consumable
> pool, keyrings carry a revision, and single-file shares use a group on the
> file node. The 89 temporary
> `cargo-vet` exemptions and the review checklist live in
> [`docs/audit/mls-delta.md`](../audit/mls-delta.md). **External review is
> still required before treating MLS as audited.**

## Why

The v1/v2 design wraps **each file key for each member** with X25519. That
is simple and works offline, but it has no forward secrecy or
post-compromise security: adding or removing a member does not rotate
anything, and a stolen device keeps every file key it ever received. MLS
replaces that path for new group shares while legacy wraps remain readable.

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

- A shared **node** (folder or single file) gets an `mls_group_id` (random
  32 bytes) and a monotonically increasing `epoch` (`mls_node_groups`).
- Each **enrolled device** publishes a key package (credential: username +
  device public key; lifetime bounded).
- Membership = all devices of all users in the group. Adding a user adds
  all their devices; removing a user removes all their devices.
- One device is the committer per change (last writer wins, server orders
  by `(epoch, seq)`); a proposal queue lets other devices propose adds or
  removes and the next committer commits them.
- Existing encrypted shares stay on the v1 per-member path until the owner
  runs an explicit promotion (`kolimi-sync --mls-migrate`, or re-sharing
  the folder). New encrypted folder shares use MLS when the client enables
  it. No silent migration of keys.

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
mls_key_packages (id, user_id, device_id, payload BLOB, expires_at,
                  consumed_at)
mls_node_groups (node_id PRIMARY KEY, mls_group_id BLOB UNIQUE, epoch,
                 updated_at)
mls_messages (id, node_id, seq, epoch, kind, payload BLOB, sender_id,
              created_at, UNIQUE(node_id, seq))
mls_share_keyrings (node_id, epoch, payload BLOB, updated_by, updated_at,
                    revision, PRIMARY KEY(node_id, epoch))
```

The server validates shapes/sizes, orders messages, prevents epoch
regression, and stores blobs. It never parses MLS plaintext.

## Client work

- **kolimi-mls** crate: `openmls` wrapper for create/add/remove/commit/
  welcome/export; key package lifecycle; encrypted group state at rest.
- **Desktop/CLI**: sealed `.kolimi/mls-state.bin` (device signer, identity
  and openmls key-value storage, UMK-sealed, 0600). `kolimi-sync` creates
  the group on share, joins from a Welcome, processes commits, and updates
  the keyring on write.
- **Web**: `openmls` compiled to wasm; sealed state in browser
  **IndexedDB** (one slot per account fingerprint, with a localStorage
  migration). The browser publishes
  a key package on unlock, creates/joins groups, and uses the keyring for
  shared downloads and uploads.
- **Sync**: for MLS shares, replace the per-file `/api/e2ee/share-key`
  fetch with the epoch share keyring; keep the v1 path for legacy shares.
- **Server**: mount-aware writes for write shares (commit, chunks, node
  keys, mkdir, move, delete) store data in the owner's blob namespace while
  enforcing the share ACL.

## Tests

- 3 members across 3 devices: create, add, remove, epoch advance.
- A removed member cannot decrypt the new share keyring or files added
  after removal (integration test).
- A stolen old epoch state cannot derive the next exporter secret (vector
  test).
- Web/desktop interop: a browser creates a group, a sync recipient reads
  and writes, and the owner reads the recipient's file (browser E2E).
- Server sees only opaque payloads; no plaintext names/keys in logs.
- Fuzz the keyring parser (landed as `fuzz/fuzz_targets/mls_keyring.rs`);
  message-parser and state-transition fuzzing are still pending.

## Rollout

1. `openmls` wasm/desktop spike + key-package API (done).
2. Group state/message endpoints + epoch enforcement + tests (done).
3. Desktop/CLI group-share path behind a flag (done, `E2eeOptions::mls`).
4. Web path + browser state + shared writes (done, default on).
5. Promote on new group shares; keep v1 reads and `--mls-migrate` (done).
6. External audit delta before recommending MLS for sensitive groups
   (**pending**).

## Risks

- `openmls` API/version churn and wasm provider support.
- Asynchronous commits: a member can be several epochs behind; the client
  must replay commits/welcomes in order.
- Two clients committing at the same epoch can fork a group. The current
  design assumes one active committer per membership change; fork
  detection/repair is still open.
- Multi-device membership can make groups large; bound devices per user.
- Revocation is still not a remote wipe: a device that already holds old
  file keys retains them. Future epochs are protected.
