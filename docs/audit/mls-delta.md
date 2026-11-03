# MLS (RFC 9420) audit delta — package

Status: prepared for review (0.3.0) · Applies to: `crates/kolimi-mls`, `/api/mls`,
sync/desktop client wiring and the web client. **External review has not
been performed.**

This is the delta an external reviewer needs for the group-E2EE milestone.
Nothing here is a substitute for the review itself.

## Scope

- `openmls` 0.9.2 with `openmls_rust_crypto` 0.6 and
  `openmls_basic_credential` 0.6 (MIT). The crate is now a workspace member;
  `cargo-vet` has **89 new exemptions** for this tree (724 total, none are
  audits). They are temporary until the review replaces them.
- Key packages, group creation/add/remove, application messages, epoch
  exporter, share-keyring encryption.
- Server storage and epoch validation in `crates/kolimi-db/src/mls.rs`
  and `crates/kolimi-server/src/api_mls.rs`.
- Desktop/sync: `crates/kolimi-sync/src/mls.rs` and `mls_store.rs`
  (device bootstrap, group create/join, commits, keyring read/update,
  sealed state).
- Web: `crates/kolimi-ui/src/mls.rs` (wasm openmls, sealed browser state,
  group share/join, shared read/write).
- Server mount-aware write paths for write shares: `commit_manifest`,
  chunk upload/existence, node keys, mkdir, move and delete.
- Membership lifecycle: re-share adds devices, unshare/revoke removes all
  of a user's leaves, rotates the keyring epoch, and permission updates.
- Key-package pool + consume endpoints; keyring `revision`/`if_revision`.
- Browser IndexedDB state, single-file node groups, keyring path updates on
  rename/delete, MLS request rate limiting and a keyring parser fuzz target.

## Server invariants

- `/api/mls` never parses MLS plaintext; payloads are opaque blobs.
- Group resources are resolved through the same VFS ACL as files. Reads
  need read access; messages and keyring writes need write access.
- A group id is bound to a node; re-initializing with a different id is a
  conflict.
- Epochs are monotonic. A commit advances exactly one epoch; proposals,
  welcomes and application messages use the current epoch. Older or future
  epochs are rejected.
- Message appends run in a `BEGIN IMMEDIATE` transaction and a commit
  advances the epoch with `UPDATE … WHERE epoch = <parent>`. Two commits at
  the same parent epoch are serialized: exactly one wins and the other gets
  a `409`, so the server never accepts a second epoch-N+1 transcript.
- The share keyring is one ciphertext per `(node, epoch)` and is accepted
  only with `if_epoch == group.epoch`, so a concurrent writer loses
  instead of overwriting newer keys.
- Unused key packages get a 30-day expiry; the janitor deletes
  consumed/expired rows after a further seven-day grace period. Protocol
  messages are retained (no per-member epoch tracking to prove they are no
  longer needed).
- Message and keyring sizes are capped (256 KiB / 1 MiB); key packages
  64 KiB.

## Client invariants

- The share keyring key is `HKDF(exporter, salt=group_id,
  info="kolimi-share-keyring-key-v1"||epoch)`; the blob is
  `nonce || XChaCha20-Poly1305(…, aad="kolimi-share-keyring-v1"||group_id||epoch)`.
- An epoch's blob cannot be replayed into another epoch or group.
- Adding/removing a member creates a new epoch; the committer decrypts the
  old keyring, re-encrypts it for the new epoch, and uploads it with the
  commit. A removed member cannot read the new blob.
- A removed member retains file keys already received. The guarantee is
  only for new epochs/new keyring versions.
- The device state carries the MLS signer and openmls key-value storage
  (group secrets). It is sealed with the UMK before persistence:
  `.kolimi/mls-state.bin` is 0600 and atomically replaced on desktop/sync;
  the web client stores a sealed blob in IndexedDB under an
  account-fingerprint slot. Wrong-key and tamper are rejected.
  `kolimi-sync --mls-reset` deletes only the sealed MLS state; the next
  sync creates a new device and the recipient must be re-added.
- Keyring updates use `if_epoch`; a losing writer refetches and retries.
- A write recipient's chunks and manifests are stored in the owner's blob
  namespace; the ACL is still enforced by the VFS before every write.

## Test evidence

- `crates/kolimi-mls`: host tests for group create/add/message/exporter/epoch
  rotation and share-keyring roundtrip, epoch binding, tamper rejection.
- `crates/kolimi-server/tests/mls_e2e.rs`: the full protocol over HTTP —
  key packages, init, commit/welcome, Bob joining, matching exporter, and a
  write recipient updating the keyring that the owner then decrypts.
- `crates/kolimi-mls/tests/persistence.rs`: device/group state export,
  import, group reload, and an epoch advance after reload.
- `crates/kolimi-sync/src/mls_store.rs`: UMK-sealed state file (0600,
  atomic rename), wrong-key and tamper rejection.
- `crates/kolimi-server/tests/mls_sync.rs`: sync owner share → recipient
  Welcome join → keyring read; write recipient creates/edits/deletes files
  that the owner decrypts; single-file write share round-trip; legacy v1
  share migration; loss/reset → fresh key package → re-share recovery.
- `crates/kolimi-server/tests/mls.rs`: owner-only init, read-vs-write
  ACLs, epoch rules, keyring conflict, key packages, non-member denial.
- `crates/kolimi-db/src/mls.rs`: a concurrent-commit test proves exactly
  one of two same-epoch commits wins; a key-package purge test covers the
  janitor.
- `crates/kolimi-ui` wasm tests and the existing integration tests cover
  browser read/write/reload logic. A full browser E2E suite (Chromium, two
  authenticated contexts) for web rename/delete/revoke/migration is **not
  committed yet**.
- `crates/kolimi-ui` compiles to wasm32 and passes clippy; `cargo test
  --workspace`, clippy, fmt, vet, audit/deny exceptions and smoke remain
  green.

## Open review questions

1. Key-package lifetime/rotation: unused packages expire after 30 days and
   expired/consumed ones are hidden. Confirm the TTL and pool size are
   appropriate for offline devices.
2. Message retention/pruning and a per-group message cap; consumed/expired
   key packages are pruned, but the server keeps every protocol message.
3. Any authenticated user can list another user's **public** key packages;
   confirm this matches the add-member threat model.
4. Device credential binding: a key package is currently bound to a
   device id string, not an attested device key. The device-enrollment
   identity should sign or authorize the package.
5. Client state persistence: desktop/sync uses a UMK-sealed 0600 file and
   the web client uses UMK-sealed IndexedDB. Both still need a rollback /
   device-cloning story (a stale state file is detected only by the epoch
   check, not by a monotonic counter).
6. Concurrent commits: the server now rejects the second same-parent
   commit. A client that advanced its local state before the rejection
   still needs reset/re-add; whether the epoch CAS is sufficient fork
   prevention for all client flows should be reviewed.
7. WebCrypto/provider differences and the wasm `getrandom` shim.
8. DoS: message/keyring upload rate limits and key-package spam.

## Promotion checklist

- [ ] cargo-vet exemptions/audits for the openmls tree
- [ ] Fuzz MLS message parsing and client state transitions
- [ ] Rate-limit `/api/mls/*` and cap per-group messages
- [x] Janitor pruning for consumed/expired key packages (messages remain)
- [x] Desktop/sync group-state wiring + tests
- [x] Web group-state wiring + tests (IndexedDB, locked state, reload persistence)
- [x] Write-share enablement behind a feature flag, with a migration path
- [ ] Browser E2E suite: web rename, delete, revoke and migration
- [x] Membership add/remove, keyring rotation, permission updates
- [x] Consumable key-package pool and same-epoch keyring revisions
- [x] Single-file MLS shares, single-file write shares, keyring path updates, web conflict guards
- [x] Server-side serialization of same-epoch commits
- [ ] External review signed off; only then treat MLS as audited
- [x] State-loss recovery via `--mls-reset` + documented re-add (guided UX still open)
- [ ] Message pruning (needs per-member epoch tracking)

## Known limitations

- Key packages are a consumable pool per `(user, device_id)`; clients
  publish several and consume the ids actually used in a commit.
- Adding a recipient uses every package currently published; a device that
  never syncs/unlocks cannot be added.
- Removing a member and re-encrypting the keyring is implemented in the
  CLI, desktop and web flows; a removed device keeps old keys/plaintext.
- Losing the sealed device state (cleared browser storage, deleted
  `.kolimi`) means losing that device's MLS membership. `--mls-reset`
  clears the state; a remaining member must re-add the new package.
