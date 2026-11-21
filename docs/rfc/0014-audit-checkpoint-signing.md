# RFC 0014 — Audit checkpoint signing and external anchoring

- **Status:** implemented (unreleased)
- **Date:** 2026-11-21
- **Depends on:** RFC 0013 (sealed audit checkpoints), the checkpoint header
  chain and Merkle roots from migration `0037`
- **Implementation:** migration `0038_audit_checkpoint_signing.sql`; signer,
  signature verification, anchor outbox, journal/HTTP sinks, CLI, and
  janitor age/seal and drain

## Summary

RFC 0013 made checkpoints tamper-evident: changing an entry, a range, a root,
or a checkpoint link breaks verification. It did not make them tamper-proof
against an attacker who can rewrite the database consistently and recompute
every hash.

This RFC adds two independent layers:

1. **Detached Ed25519 signatures** over each checkpoint header, made with a
   key stored outside the data directory. This defeats database-only and
   backup-only tampering and survives a restore from an untrusted backup.
2. **Anchoring** of the signed checkpoint head to storage the server cannot
   rewrite: an append-only journal and/or an HTTPS sink. Anchoring is what
   survives a full host compromise, because a later rewrite cannot reproduce
   the checkpoint hash that was already published.

Signing is local and cheap. Anchoring is deliberately small: one JSON record
per checkpoint, no consensus, no ledger.

## What this is not

- No HSM, TPM, PKCS#11, or hardware-backed key support.
- No Sigstore/Rekor or public transparency-log integration (the anchor
  record is designed to be publishable to one later).
- No multiple-required-signer quorum in v1.
- No protection against a host compromise that happens **before** the
  checkpoint was anchored, or against an attacker who can also rewrite the
  anchor target.
- No per-entry signatures and no request-path signing.
- No confidentiality claim change: anchor records contain ids, counts,
  hashes, key ids, and timestamps, never paths, users, actions, or details.

## Threat model

| Adversary | Capability | Defeated by |
| --- | --- | --- |
| A1 — database/backup tamper | Rewrites `audit_log`, `audit_checkpoints`, anchor rows; recomputes hashes and Merkle roots; cannot read a key outside the data dir | Signatures verified against an operator-supplied public key |
| A2 — full host compromise, after anchoring | Reads the signing key, rewrites everything | Anchors published before the compromise |
| A2 — full host compromise, before anchoring | Same, and no earlier anchor exists | Nothing in this design; the unanchored window is the limit |
| A3 — rollback | Restores an older snapshot to hide recent events | Newest anchored `last_entry_id` exceeds local history |
| A4 — retention cover-up | Deletes checkpoint headers or exports to hide a range | Anchored checkpoint ids/hashes are missing locally |
| A5 — single-checkpoint rewrite | Edits one checkpoint and breaks the link | The checkpoint chain still fails at the next header |

Two honest limits:

- A key on the same host is defense in depth, not proof against root. Its
  value is that ordinary backups, database dumps, and data-dir copies do not
  contain it.
- An anchor only proves what was published. Events after the newest anchor
  are not covered; the seal-age trigger below bounds that gap.

## Signing key

### File format

A signing key is a small text file outside the data directory, for example
`/etc/kolimi/audit-signing.key`:

```text
kolimi-audit-signing-key-v1
<64 hex characters: the 32-byte Ed25519 seed>
# optional label or comment lines
```

Rules:

- The first non-empty line is the exact magic above.
- The second non-empty line is the seed, lowercase or uppercase hex.
- Remaining lines must be empty or start with `#`.
- The file must be a regular file, owned by the service user, with no group
  or other permission bits on Unix (`0600` or `0400`). Symlinks are refused.
- The private key never enters SQLite, never enters a backup, and is never
  printed by any command.

### Key id

```text
key_id = hex(BLAKE3("kolimi-audit-key-v1" || public_key)[0..8])
```

That is 16 hex characters. It identifies a key in signatures, anchor records,
and logs. The full public key remains the authority; a key-id collision is
treated as an error during verification.

### Generation and rotation

```sh
kolimi-server audit keygen --out /etc/kolimi/audit-signing.key --label main
```

`keygen` writes the file with `create_new` and mode `0600`, prints the key id
and public key, and refuses to overwrite an existing file. There is no
`--force`; rotating means generating a new path.

Rotation:

1. Generate the new key and configure it for signing.
2. Optionally countersign the last checkpoint made by the old key:
   `audit sign --key NEW --checkpoint <id>`. A checkpoint can carry one
   signature per key.
3. Keep both public keys in the verifier's trusted set. Old checkpoints keep
   their old signatures; new checkpoints use the new key.
4. Remove the old public key once every verifier has been updated. There is no
   CRL; trust is an explicit operator list.

Because each checkpoint commits to the previous checkpoint hash, a trusted
signature on any checkpoint also commits to the entire earlier chain.

## Data model

Migration `0038_audit_checkpoint_signing.sql`:

```sql
CREATE TABLE audit_signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'ed25519',
    public_key BLOB NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    retired_at INTEGER
);

CREATE TABLE audit_checkpoint_signatures (
    checkpoint_id INTEGER NOT NULL REFERENCES audit_checkpoints(id),
    key_id TEXT NOT NULL REFERENCES audit_signing_keys(key_id),
    signature BLOB NOT NULL,
    signed_at INTEGER NOT NULL,
    PRIMARY KEY (checkpoint_id, key_id)
);

CREATE TABLE audit_anchor_outbox (
    checkpoint_id INTEGER PRIMARY KEY REFERENCES audit_checkpoints(id),
    payload TEXT NOT NULL,
    journaled_at INTEGER,
    delivered_at INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error TEXT
);
```

Notes:

- `public_key` is stored for convenience and display. **Verification must
  trust an externally supplied key, not the database row.** An attacker with
  write access could otherwise replace both the row and the signature.
- `algorithm` reserves agility; only `ed25519` is accepted in v1.
- A checkpoint may have zero, one, or several signatures. The primary key
  enforces one signature per key per checkpoint.
- Checkpoint rows are never deleted, so there is no cascade path.
- `audit_anchor_outbox` is created in the same transaction as the checkpoint
  and its signature, so a crash cannot lose the intent to anchor.

`ed25519-dalek` is already in the dependency graph (through openmls) and in
`supply-chain/config.toml`; adding it as a direct dependency of `kolimi-db`
does not add a new crate version. `getrandom` supplies the seed for `keygen`.

## Signed message

```text
message = "kolimi-audit-checkpoint-signature-v1" || checkpoint_hash
```

`checkpoint_hash` is the 32-byte BLAKE3 header hash from RFC 0013, which
already commits to the previous checkpoint hash, entry range, entry count,
Merkle root, and creation time. The fixed-length suffix makes the domain
separator unambiguous. Ed25519 is used in pure mode (no prehash); the
signature is 64 bytes.

Signatures are detached: signing does not change `checkpoint_hash`, the
Merkle root, the checkpoint chain, or any existing export bundle header hash.

## Sealing and signing

`audit seal` and the janitor seal as today, with one change: when a signing
key is configured, the checkpoint row and its signature are inserted in the
same SQLite transaction.

- Success: the checkpoint exists with at least one valid signature.
- Failure to load or use the configured key: the transaction rolls back and
  **no checkpoint is written**. The janitor logs the error, increments a
  metric, and retries on the next pass.
- No key configured: checkpoints are written unsigned, exactly as in 0.7.0.

`serve` validates the configured key at startup but does not refuse to start.
It logs a prominent error, and the janitor retries loading the key on each
pass. While the key cannot be loaded, sealing is refused rather than falling
back to unsigned checkpoints; fixing a path or permission recovers without a
restart.

### Backfill and countersigning

```sh
kolimi-server audit sign --key /etc/kolimi/audit-signing.key --all
kolimi-server audit sign --key NEW --checkpoint 12
```

`audit sign` is idempotent per `(checkpoint, key)` and refuses a checkpoint
whose header hash does not verify. It can sign pruned checkpoints; their
headers are permanent.

## Seal freshness

Anchoring only commits to sealed entries. A low-volume server that never
reaches 1,024 entries would leave an unbounded unsealed tail.

The janitor therefore seals when **either**:

- at least `AUDIT_CHECKPOINT_ENTRIES` (1,024) entries are unsealed, or
- the oldest unsealed entry is older than `KOLIMI_AUDIT_SEAL_AGE_SECS`
  (default 86,400, i.e. 24 hours).

A pass still creates at most `AUDIT_CHECKPOINTS_PER_PASS` checkpoints. If no
new entries exist since the last checkpoint, no checkpoint is created. This
bounds the unanchored window to roughly the seal age plus one janitor
interval.

## Verification

### Trusted keys

```sh
kolimi-server audit verify --trusted-key <hex> [--trusted-key <hex>]...
kolimi-server audit verify --trusted-keys /etc/kolimi/audit-trusted-keys
```

The trusted-keys file has one entry per line:

```text
<key_id> <public_key_hex> [label]
```

`#` comments and blank lines are allowed.

If no explicit key is supplied and `KOLIMI_AUDIT_SIGNING_KEY` is configured,
verification uses that key's public key and reports
`trust_source: "configured-key"`. This detects database-only tampering but is
not independent evidence, because the key lives on the same host. Supplying a
public key from another system or a ticket is the independent mode.

### Signature checks

For every checkpoint:

- Existing RFC 0013 checks run first (range, link, header hash, Merkle root
  when entries are present).
- A signature from a trusted key that verifies makes the checkpoint `signed`.
- A signature from an unknown key is reported as `untrusted`, not fatal.
- A signature whose key id is trusted but whose bytes do not verify is
  fatal.
- Unsigned checkpoints are reported. They are fatal only with
  `--require-signatures`.

One valid trusted signature is sufficient in v1. Quorum is a future
extension; the schema already permits multiple signatures.

### Anchor checks

```sh
kolimi-server audit verify --trusted-keys FILE --anchor-log /mnt/audit/checkpoints.jsonl
```

The anchor log is JSONL, one record per line (format below). Verification:

- Every anchored checkpoint id must exist locally. Checkpoint headers are
  never pruned, so a missing header means the local history was truncated.
- `first_entry_id`, `last_entry_id`, `entry_count`, `merkle_root`, and
  `checkpoint_hash` must match the local header.
- Duplicate records with identical values are ignored. Two different hashes
  for the same checkpoint id are fatal.
- Let `A` be the greatest anchored `last_entry_id` and `L` the greatest local
  `audit_log.id`. If `L < A`, the local database is older than something it
  already published: report `rollback_detected` and fail.
- An anchored checkpoint with no valid trusted signature is reported as
  unsigned evidence. It is fatal only with `--require-signatures`.

Verification is offline and reads a local file. The server does not fetch the
anchor URL during `verify`; an operator exports or downloads the log from the
anchor system. This avoids making verification trust the same host and avoids
SSRF/auth complexity.

### Report

`audit verify` and `GET /api/audit/verify` add:

```json
{
  "ok": true,
  "entries": 4096,
  "checkpoints": 4,
  "pruned_checkpoints": 1,
  "signed_checkpoints": 4,
  "verified_signatures": 4,
  "unsigned_checkpoints": 0,
  "signature_errors": 0,
  "anchors_checked": 4,
  "rollback_detected": false,
  "trust_source": "trusted-keys",
  "latest_anchor": { "checkpoint_id": 4, "last_entry_id": 4096 },
  "first_bad": null
}
```

The HTTP endpoint verifies against the server's configured public key only,
and labels that source as `configured-key`. It is an operational status
check, not independent attestation. Anchor counters appear only when
`KOLIMI_AUDIT_ANCHOR_LOG` is configured.

## Export bundles

The checkpoint bundle header gains an optional `signatures` array:

```json
"signatures": [
  {
    "key_id": "0123456789abcdef",
    "algorithm": "ed25519",
    "public_key": "<hex>",
    "signature": "<hex>",
    "signed_at": 1763000000000
  }
]
```

- The header hash does not cover this array; signatures are over the header
  hash, so adding them does not invalidate the bundle.
- `audit verify-export --file BUNDLE --trusted-key <hex>` checks the
  signature against the supplied key.
- Without a trusted key, the verifier checks that the signature is valid for
  the included public key and reports it as `self-signed`, not trusted.
- Old bundles without the field still verify exactly as before.

## Anchor record

One canonical JSON object per line:

```json
{
  "kind": "kolimi-audit-anchor-v1",
  "checkpoint_id": 12,
  "first_entry_id": 11265,
  "last_entry_id": 12288,
  "entry_count": 1024,
  "merkle_root": "<64 hex>",
  "checkpoint_hash": "<64 hex>",
  "created_at": 1763000000000,
  "signatures": [
    {
      "key_id": "0123456789abcdef",
      "algorithm": "ed25519",
      "public_key": "<64 hex>",
      "signature": "<128 hex>"
    }
  ]
}
```

- The signature is over `checkpoint_hash`; the other fields let a reader
  cross-check the record against a local header.
- `public_key` is informational. A reader that needs trust uses its own key
  list.
- The record contains no audit content. Publishing it reveals audit volume,
  checkpoint timing, and key ids only.
- Unsigned checkpoints produce `"signatures": []`. Such a record proves
  nothing cryptographically and is treated as informational evidence.

## Anchor sinks

Both sinks are optional and independent. If neither is configured, behavior
matches 0.7.0.

### Append-only journal

```sh
KOLIMI_AUDIT_ANCHOR_LOG=/mnt/audit-anchors/kolimi-checkpoints.jsonl
```

After a checkpoint commits, its anchor record is appended with `O_APPEND`,
followed by `fsync`; the parent directory is fsynced when the file is first
created. Append failures leave the outbox row pending and are retried by the
janitor.

A journal on the same filesystem as the data directory adds little. It must
be a separately controlled or immutable target: a WORM/object-lock mount, an
append-only NFS export, a different host reached through the HTTP sink, or
media the service account cannot rewrite. The RFC cannot enforce that
property; operations docs must state it plainly.

### HTTPS sink

```sh
KOLIMI_AUDIT_ANCHOR_URL=https://anchors.example.net/kolimi
KOLIMI_AUDIT_ANCHOR_TOKEN=...          # optional bearer token
```

Request:

```text
POST <url>
Content-Type: application/json
Idempotency-Key: <checkpoint_hash>
Authorization: Bearer <token>          # when configured
<anchor record JSON>
```

Response handling:

- `2xx`: delivered.
- `409`: already stored; treated as delivered.
- `408`, `429`, `5xx`, network error, timeout: retry with backoff.
- Other `4xx`: permanent failure; keep the row, record `last_error`, and stop
  retrying until an operator clears or fixes it.
- TLS is required, except for a loopback address (for a local sidecar).

The sink doesn't need a Kolimi-specific protocol: anything that stores the
body keyed by the idempotency header works, including an object store with
object lock or a tiny append-only receiver on another host.

### Outbox and retries

The janitor drains at most 20 pending rows per pass:

- journal append and HTTP delivery are independent; a row is complete when
  every configured sink is done.
- Backoff: `min(24h, 30s * 2^attempts)` with jitter.
- HTTP timeout: 10 seconds; connect timeout: 5 seconds.
- The payload is a snapshot written in the checkpoint transaction, so a
  later rewrite of the header cannot change what gets published.

Completed rows are tiny (a few hundred bytes) and retained. A future janitor
pass may prune rows completed more than 90 days ago when both configured
sinks are done.

## CLI

```sh
kolimi-server audit keygen --out PATH [--label TEXT]
kolimi-server audit sign --key PATH [--checkpoint ID]... [--all]
kolimi-server audit head [--json]
kolimi-server audit verify [--trusted-key HEX]... [--trusted-keys FILE]
                           [--anchor-log PATH] [--require-signatures]
kolimi-server audit verify-export --file PATH [--trusted-key HEX]...
kolimi-server audit anchors [--limit N]
kolimi-server audit anchors flush
```

- `audit head` prints the latest checkpoint's anchor record. It is the
  manual-publication path: paste the line into a ticket, a separate system,
  or an email to yourself.
- `audit anchors` lists pending and delivered outbox rows with attempts and
  the last error. `flush` attempts a bounded drain immediately.

Configuration:

| Variable | Meaning |
| --- | --- |
| `KOLIMI_AUDIT_SIGNING_KEY` | Ed25519 key file path |
| `KOLIMI_AUDIT_ANCHOR_LOG` | Append-only JSONL journal path |
| `KOLIMI_AUDIT_ANCHOR_URL` | HTTPS anchor sink |
| `KOLIMI_AUDIT_ANCHOR_TOKEN` | Bearer token for the HTTPS sink |
| `KOLIMI_AUDIT_SEAL_AGE_SECS` | Seal-age trigger, default `86400` |

## Metrics

- `kolimi_audit_checkpoints_signed_total`
- `kolimi_audit_signing_errors_total`
- `kolimi_audit_anchor_pending` (gauge)
- `kolimi_audit_anchor_delivered_total{sink="journal"|"http"}`
- `kolimi_audit_anchor_failures_total{sink="journal"|"http"}`

Alert on a nonzero signing-error rate and on `anchor_pending` growing for
more than a day.

## Migration and compatibility

- Migration `0038` adds tables only; existing audit rows, checkpoints,
  anchors, and bundles are unchanged.
- Existing checkpoints start unsigned. `audit sign --all` backfills them.
- `checkpoint_hash` and the Merkle algorithms are untouched, so RFC 0013
  verification still passes with no key configured.
- Old export bundles remain valid; old binaries ignore the optional
  `signatures` field.
- No request-path cost: signing and anchoring run in the janitor or CLI.
- A 0.7.0 database opened by a 0.8.0 binary gets the new tables; a 0.7.0
  binary refuses the newer schema as usual. Back up before upgrading.

## Tests

- `keygen` creates a `0600` file, prints the key id/public key, and refuses
  an existing path.
- A key file with group/other bits or a symlink is refused.
- Seal with a configured key writes the key row and signature in one
  transaction; a signing error leaves no checkpoint row.
- Unsigned checkpoints still seal and verify when no key is configured.
- `audit sign --all` backfills unsigned checkpoints and is idempotent.
- Verification passes with a pinned key, fails with a different key, and
  fails when a signature byte is changed.
- Replacing the public key in `audit_signing_keys` does not fool
  verification with an externally pinned key.
- `--require-signatures` fails on an unsigned checkpoint.
- Seal-age trigger creates a checkpoint for an old, small tail.
- Bundle with signatures verifies with a trusted key, reports `self-signed`
  without one, and old bundles still verify.
- Anchor record matches the local header; a changed hash, range, or root
  fails.
- A missing anchored checkpoint id fails as truncation.
- An anchor newer than local history fails as rollback.
- Journal append is durable and idempotent across a crash/retry.
- HTTP sink: 2xx and 409 mark delivered; 5xx retries; permanent 4xx stops
  with an error; `Idempotency-Key` is the checkpoint hash.
- Backoff and bounded per-pass drain behave as specified.
- No key and no sink configured leaves 0.7.0 behavior byte-for-byte.

## Open questions

1. **Quorum.** Should operators be able to require two independent keys
   (for example server + offline operator key)? Recommendation: defer; the
   schema supports it.
2. **Transparency logs.** Add Sigsum/Rekor publication as a third sink?
   Recommendation: defer until a user asks; the anchor record is log-neutral.
3. **Online anchor fetch.** Should `audit verify` fetch the sink URL
   directly? Recommendation: no; offline export keeps verification
   independent and avoids SSRF/auth surface.
4. **Key validity windows.** Add `valid_from_checkpoint` to trusted keys so
   rotation is pinned in time? Recommendation: defer; the checkpoint chain
   already gives ordering.
5. **Anchor frequency.** Every checkpoint can be chatty on a busy server.
   Recommendation: keep every checkpoint (they are tiny) and revisit if a
   sink has volume limits.

## Acceptance criteria

- A checkpoint altered without the signing key fails verification against a
  pinned public key.
- Seal and signature are atomic; a configured key never silently produces an
  unsigned checkpoint.
- An offline verifier with an anchor log detects a rewritten, truncated, or
  rolled-back local history.
- Anchor sink failure never blocks local sealing; the outbox preserves the
  intent and retries.
- Anchor records contain no paths, usernames, actions, or details.
- Existing unsigned logs, checkpoints, and bundles keep verifying unchanged.
