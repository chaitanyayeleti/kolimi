# MLS (RFC 9420) audit delta — package

Status: prepared for review · Applies to: `crates/kolimi-mls` + `/api/mls`
(not yet used by shipped sync clients)

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
- Web feasibility: `cargo check --target wasm32-unknown-unknown` passes
  with the `js` getrandom feature.

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

## Client invariants (spike)

- The share keyring key is `HKDF(exporter, salt=group_id,
  info="kolimi-share-keyring-key-v1"||epoch)`; the blob is
  `nonce || XChaCha20-Poly1305(…, aad="kolimi-share-keyring-v1"||group_id||epoch)`.
- An epoch's blob cannot be replayed into another epoch or group.
- Adding/removing a member creates a new epoch; the committer decrypts the
  old keyring, re-encrypts it for the new epoch, and uploads it with the
  commit. A removed member cannot read the new blob.
- A removed member retains file keys already received. The guarantee is
  only for new epochs/new keyring versions.

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
- `cargo check --target wasm32-unknown-unknown` for the spike.
- `crates/kolimi-server/tests/mls.rs`: owner-only init, read-vs-write
  ACLs, epoch rules, keyring conflict, key packages, non-member denial.
- `cargo test --workspace`, clippy, fmt, vet and smoke remain green.

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
5. Client state persistence: desktop OS keystore vs web IndexedDB; both
   need encrypted-at-rest state and rollback protection.
6. Concurrent commits: server orders by sequence, but clients must
   resolve forks; the current design assumes one committer per epoch.
7. WebCrypto/provider differences and the wasm `getrandom` shim.
8. DoS: message/keyring upload rate limits and key-package spam.

## Promotion checklist

- [ ] cargo-vet exemptions/audits for the openmls tree
- [ ] Fuzz MLS message parsing and client state transitions
- [ ] Rate-limit `/api/mls/*` and cap per-group messages
- [ ] Janitor pruning for expired key packages and old messages
- [ ] Desktop group-state wiring + tests
- [ ] Web group-state wiring + tests (IndexedDB, locked state)
- [ ] Write-share enablement behind a feature flag, with a migration path
- [ ] External review signed off; only then enable by default
