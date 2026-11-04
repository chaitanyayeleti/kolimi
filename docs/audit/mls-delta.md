# MLS (RFC 9420) audit delta — package

Status: prepared for review (0.4.2) · Applies to: `crates/kolimi-mls`, `/api/mls`,
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
  of a user's leaves, single-device revoke removes one leaf from every group
  the client can write, rotates the keyring epoch, and permission updates.
- Per-group revocation records so automatic re-add cannot put a deliberately
  removed signature back from its leftover key-package pool.
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
- `POST /api/mls/commit` inserts the winning commit and its optional Welcome
  in the same transaction. A concurrent committer cannot advance the epoch
  between the two rows and leave a newly added device without a Welcome.
- The share keyring is one ciphertext per `(node, epoch)` and is accepted
  only with `if_epoch == group.epoch`, so a concurrent writer loses
  instead of overwriting newer keys.
- Unused key packages get a 30-day expiry; the janitor deletes
  consumed/expired rows after a further seven-day grace period.
- The server keeps a `mls_devices` roster: at most 16 active devices per
  account in a 180-day inactivity window, and at most 8 live packages per
  device. Over-limit requests are rejected with `409`; inactive roster entries
  are pruned by the janitor. The roster stores an optional display name and
  the public signature key reported with a package; `GET /api/mls/devices`
  returns the caller's roster and `GET /api/mls/devices/{username}` exposes
  only id/name/signature key for a recipient.
- `mls_group_revocations` is a **client-asserted** list of removed
  signatures per group. A writer records an entry before posting the remove
  commit, and automatic re-add skips matching key packages. An explicit
  re-share clears it. The server cannot verify that a removal happened; the
  record is a durable hint for honest clients, not cryptographic proof.
- Clients report the last processed epoch per device
  (`mls_member_epochs`). The janitor prunes protocol messages and keyrings
  older than seven days and below the minimum fresh report; reports older
  than 30 days are ignored so an abandoned device cannot block pruning.
  A device offline longer than 30 days must rejoin rather than replay all
  history.
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
  sync creates a new device and a working device on the same account re-adds
  it automatically. If no working member is online, it must be re-added
  manually.
- Keyring updates use `if_epoch`; a losing writer refetches and retries.
- Commits stay pending locally until the server accepts them, and the
  serialized pending commit is persisted before posting. A client that loses
  the epoch race discards the pending commit, replays the winning commit, and
  retries at the next epoch. If the response was lost after the server
  accepted the commit, the next pass merges the pending state only when the
  server echo matches the exact persisted commit bytes; unauthenticated
  private-message framing is never accepted as proof.
- A sync (or browser unlock) re-adds devices that published a fresh key
  package after losing local MLS state. Only a share's own group root is
  refreshed, never an ancestor group with wider membership, and a scoped sync
  only touches shares under its root. It skips signatures recorded in the
  group's revocation list; an explicit re-share ignores and then clears the
  entry.
- Single-device revoke is staged like any commit: inspect every affected
  group before removing anything, record the revocation, post the remove
  commit, merge it, and rotate the keyring. A device in a read-only received
  share is not removed by its owner (they cannot commit there); the share
  owner performs the removal or the share is recreated. A self-revoke clears
  the roster row only after every reachable group is clean.
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
  share migration; loss/reset → fresh key package → automatic re-add by a
  working device on the same account; owner removes one recipient device,
  the other device keeps decrypting, and the revoked device's roster entry is
  cleared only after the group is clean.
- `crates/kolimi-server/tests/mls.rs`: owner-only init, read-vs-write
  ACLs, epoch rules, keyring conflict, key packages, device roster
  metadata/removal, group revocation visibility/clearing, non-member denial.
- `crates/kolimi-db/src/mls.rs`: a concurrent-commit test proves exactly
  one of two same-epoch commits wins; an atomic commit+Welcome test; device
  and per-device package cap tests; roster-prune coverage; epoch report tests
  cover safe message pruning; a key-package purge test covers the janitor.
- `crates/kolimi-mls/tests/pending.rs`: pending commits do not advance the
  epoch until merged; a losing committer discards its staged commit, replays
  the winner, and retries; pending bytes survive a state roundtrip; an own
  commit after a lost response merges only when its bytes match the persisted
  pending commit.
- `browser-e2e/` (Playwright, Chromium): a real server with two users
  exercises web rename, delete, share, revoke, legacy-share migration to
  MLS, and the browser MLS reset flow.
- `crates/kolimi-ui` compiles to wasm32 and passes clippy; `cargo test
  --workspace`, clippy, fmt, vet, audit/deny exceptions and smoke remain
  green.

## Open review questions

1. Key-package lifetime/rotation: unused packages expire after 30 days and
   expired/consumed ones are hidden. The server caps at 16 active devices and
   8 live packages per device; confirm those numbers are appropriate for
   offline and replacement devices.
2. Message retention/pruning now uses per-device epoch reports; review the
   seven-day grace, the 30-day report freshness cutoff, and whether the
   minimum-report rule is safe for all client rollback cases.
3. Any authenticated user can list another user's **public** key packages;
   confirm this matches the add-member threat model.
4. Device credential binding: a key package is currently bound to a
   device id string, not an attested device key. The device-enrollment
   identity should sign or authorize the package.
5. Client state persistence: desktop/sync uses a UMK-sealed 0600 file and
   the web client uses UMK-sealed IndexedDB. Both still need a rollback /
   device-cloning story (a stale state file is detected only by the epoch
   check, not by a monotonic counter).
6. Concurrent commits: the server rejects the second same-parent commit;
   clients now stage commits locally and only merge after acceptance, discard
   a rejected commit, and replay the winner. Whether the epoch CAS plus
   pending-commit reconciliation covers every crash/transport-loss ordering
   should be reviewed.
7. WebCrypto/provider differences and the wasm `getrandom` shim.
8. DoS: message/keyring upload rate limits; the device/package caps bound
   key-package spam, but review the limits and whether device-id churn over
   the 180-day retention window is acceptable.
9. Revocation semantics: `mls_group_revocations` is an honest-client hint
   and can be cleared by any writer. Confirm the threat model for a malicious
   writer, whether the public per-user device roster (id/name/signature key)
   leaks more than the existing public key packages, and whether read-only
   recipients need a self-removal path that does not require the owner.
10. Roster deletion is not a cryptographic revocation. Confirm the client
    ordering (remove commit → keyring rotation → roster delete) and the
    behavior when a group cannot be inspected from any remaining device.

## Promotion checklist

- [ ] cargo-vet exemptions/audits for the openmls tree
- [ ] Fuzz MLS message parsing and client state transitions
- [ ] Rate-limit `/api/mls/*` and cap per-group messages
- [x] Janitor pruning for consumed/expired key packages
- [x] Per-account MLS device roster, device/package caps and roster pruning
- [x] Single-device listing/revoke (CLI + web), owner-side recipient revoke,
      and per-group revocations against automatic re-add
- [x] Desktop/sync group-state wiring + tests
- [x] Web group-state wiring + tests (IndexedDB, locked state, reload persistence)
- [x] Write-share enablement behind a feature flag, with a migration path
- [x] Browser E2E suite: web rename, delete, revoke and migration
- [x] Membership add/remove, keyring rotation, permission updates
- [x] Consumable key-package pool and same-epoch keyring revisions
- [x] Single-file MLS shares, single-file write shares, keyring path updates, web conflict guards
- [x] Server-side serialization of same-epoch commits
- [x] Atomic commit+Welcome append
- [x] Pending-commit merge, loser replay and lost-response recovery
- [x] Automatic re-add after device-state loss (when a working device syncs)
- [ ] External review signed off; only then treat MLS as audited
- [x] Guided state-loss recovery (`--mls-reset` and the web reset button)
- [x] Message pruning with per-device epoch reports

## Known limitations

- Key packages are a consumable pool per `(user, device_id)`; clients
  publish several and consume the ids actually used in a commit. An account
  that reaches 16 active MLS devices can free a slot by revoking an old
  device (`--mls-devices` / `--mls-revoke-device`, or the web Settings list),
  or wait for inactivity pruning.
- A single-device revoke cannot remove a leaf from a read-only received
  share from the device itself; the share owner must do it with
  `--mls-revoke-device <id> --with <user>` (or recreate the share). Roster
  cleanup waits until every reachable group is clean.
- Older clients ignore `mls_group_revocations`; until every auto-refreshing
  device is updated, a revoked recipient device can be re-added from its
  remaining key packages.
- Adding a recipient uses every package currently published; a device that
  never syncs/unlocks cannot be added.
- Removing a member and re-encrypting the keyring is implemented in the
  CLI, desktop and web flows; a removed device keeps old keys/plaintext.
- Losing the sealed device state (cleared browser storage, deleted
  `.kolimi`) means losing that device's MLS membership. `--mls-reset` or
  the web reset button clears the state and publishes a fresh package; the
  next sync/unlock by a working device on the same account re-adds it. If no
  working member is online, or the lost device was the only owner device, the
  share must be manually recovered or recreated.
- A device that does not report an epoch for 30 days is ignored when
  calculating the pruning floor. It may then be too far behind to replay
  history and must be re-added.
