# MLS (RFC 9420) audit delta — package

Status: prepared for review · Applies to: `crates/kolimi-mls`, `/api/mls`,
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

## Server invariants

- `/api/mls` never parses MLS plaintext; payloads are opaque blobs.
- Group resources are resolved through the same VFS ACL as files. Reads
  need read access; messages and keyring writes need write access.
- A group id is bound to a node; re-initializing with a different id is a
  conflict.
- Epochs are monotonic. A commit advances exactly one epoch; proposals,
  welcomes and application messages use the current epoch. Older or future
  epochs are rejected.
- The share keyring is one ciphertext per `(node, epoch)` and is accepted
  only with `if_epoch == group.epoch`, so a concurrent writer loses
  instead of overwriting newer keys.
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
  the web client stores a sealed blob in `localStorage` under an
  account-fingerprint slot. Wrong-key and tamper are rejected.
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
  that the owner decrypts; legacy v1 share migration.
- `crates/kolimi-server/tests/mls.rs`: owner-only init, read-vs-write
  ACLs, epoch rules, keyring conflict, key packages, non-member denial.
- Browser E2E (Chromium, two authenticated contexts): web owner creates an
  encrypted folder and MLS group, a web recipient downloads/decrypts the
  file through the keyring, uploads a file into the write share, and the
  owner downloads/decrypts the recipient's file.
- `crates/kolimi-ui` compiles to wasm32 and passes clippy; `cargo test
  --workspace`, clippy, fmt, vet, audit/deny exceptions and smoke remain
  green.

## Open review questions

1. Key-package lifetime/rotation and whether expired packages should be
   hidden from the list.
2. Message retention/pruning and a per-group message cap; currently the
   server keeps every message.
3. Any authenticated user can list another user's **public** key packages;
   confirm this matches the add-member threat model.
4. Device credential binding: a key package is currently bound to a
   device id string, not an attested device key. The device-enrollment
   identity should sign or authorize the package.
5. Client state persistence: desktop/sync uses a UMK-sealed 0600 file and
   the web client uses UMK-sealed `localStorage`. Both need a rollback /
   device-cloning story (a stale state file is detected only by the epoch
   check, not by a monotonic counter).
6. Concurrent commits: server orders by sequence, but clients must
   resolve forks; the current design assumes one committer per epoch.
7. WebCrypto/provider differences and the wasm `getrandom` shim.
8. DoS: message/keyring upload rate limits and key-package spam.

## Promotion checklist

- [ ] cargo-vet exemptions/audits for the openmls tree
- [ ] Fuzz MLS message parsing and client state transitions
- [ ] Rate-limit `/api/mls/*` and cap per-group messages
- [ ] Janitor pruning for expired key packages and old messages
- [x] Desktop/sync group-state wiring + tests
- [x] Web group-state wiring + tests (sealed browser state, locked state)
- [x] Write-share enablement behind a feature flag, with a migration path
- [x] Browser E2E: owner share → recipient read → recipient write → owner read
- [ ] External review signed off; only then treat MLS as audited
- [ ] Membership removal/rotation UX and state-loss recovery
- [ ] Cross-device key-package pool (one package per device today)

## Known limitations

- `mls_key_packages` is unique per `(user, device_id)`; a device publishes
  one package at a time. Reuse across multiple groups is not modeled.
- Adding a recipient uses every package currently published; a device that
  never syncs/unlocks cannot be added.
- Removing a member and re-encrypting the keyring for the new epoch is
  implemented at the format level but has no UI/CLI workflow yet.
- Losing the sealed device state (cleared browser storage, deleted
  `.kolimi`) means losing that device's MLS membership; a remaining member
  must re-add it with a fresh package.
