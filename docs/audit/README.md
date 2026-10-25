# External crypto audit package

Status: prepared for **0.3.0**. **External review has not been performed.**
This directory is written so a reviewer can start from one commit and
reproduce every claim.

There are two E2EE surfaces:

1. **v1/v2 per-file E2EE** — covered by this package.
2. **MLS group E2EE (RFC 9420)** — covered by
   [`mls-delta.md`](mls-delta.md), which is the delta for the reviewer.
   MLS is implemented but **not audited**.

## Scope (v1/v2)

- `crates/kolimi-crypto` — keyring (passphrase/recovery/PRF wraps),
  master-key wrapping, per-file keys, deterministic chunk AEAD, X25519
  identities and recipient key wrapping, encrypted-name helpers.
- Server E2EE surface — `api_e2ee`, the `e2ee_*` tables, the `encrypted`
  node flag and its guards (search, previews, shares, chunk access).
- `kolimi-sync` and desktop integration — unlock, encrypt-then-chunk push,
  decrypt pull, conflict handling, share/unshare, shared mounts, device
  enrollment.
- Web integration — unlock in the browser, decrypt/upload through the
  WASM UI, sealed state in IndexedDB, encrypted share names and public-link
  fragments.
- Wire formats pinned by `crates/kolimi-crypto/tests/vectors.json`.

## Out of scope (documented)

- **MLS cryptography** — review [`mls-delta.md`](mls-delta.md) separately.
- TLS/transport security, server host compromise, endpoint compromise,
  and traffic analysis.
- Metadata beyond the documented leakage (sizes, timestamps, structure,
  access patterns; names are encrypted).
- Plausible deniability.
- Rollback/freshness of server responses beyond the documented checks.

## Artifacts

| Artifact | Purpose |
| --- | --- |
| [`../rfc/0007-e2ee.md`](../rfc/0007-e2ee.md) | v1/v2 protocol, sharing design, manifest decision |
| [`../rfc/0012-mls-groups.md`](../rfc/0012-mls-groups.md) | MLS design and current status |
| [`mls-delta.md`](mls-delta.md) | MLS review package: invariants, server rules, tests, open questions |
| [`../crypto-review.md`](../crypto-review.md) | Internal review of v1/v2: invariants, attacks, gaps |
| [`../threat-model.md`](../threat-model.md) | System-wide assets, adversaries and boundaries |
| `crates/kolimi-crypto/tests/vectors.json` | Committed interop vectors |
| `crates/kolimi-crypto/examples/gen_vectors.rs` | Deterministic vector regenerator |
| `fuzz/fuzz_targets/e2ee_decrypt.rs` | Decryption surface: fail closed, never panic |
| `fuzz/fuzz_targets/mls_keyring.rs` | MLS keyring parser: arbitrary ciphertext, never panic |
| `crates/kolimi-server/tests/e2ee*.rs` | End-to-end unlock, sharing, enrollment, group tests |
| `crates/kolimi-server/tests/mls*.rs` | MLS groups, sync/desktop read/write, migration |

## Reproducing

```sh
git clone https://github.com/chaitanyayeleti/kolimi && cd kolimi
git checkout <audited-commit>

# Vector stability and primitives.
cargo test -p kolimi-crypto

# E2EE end-to-end (in-process server, real HTTP handlers).
cargo test -p kolimi-server \
  --test e2ee --test e2ee_share --test e2ee_devices \
  --test e2ee_enroll --test e2ee_group

# MLS group state, membership and sync/desktop flows.
cargo test -p kolimi-server --test mls --test mls_e2e --test mls_sync

# Decryption and keyring parser fuzzing (nightly).
cargo install cargo-fuzz --locked
cd fuzz
cargo fuzz run e2ee_decrypt -- -max_total_time=300
cargo fuzz run mls_keyring -- -max_total_time=300

# One-shot bundle for review.
cd .. && scripts/audit-package.sh
```

`scripts/audit-package.sh` produces
`target/audit/kolimi-audit-<commit>.tar.gz` containing the documents,
vectors and the exact commit hash.

## What we want from a review

1. Verify the v1/v2 invariants in [`../crypto-review.md`](../crypto-review.md)
   against the code, especially nonce derivation and key-wrap AADs.
2. Attack the X25519 sharing exchange: recipient binding, ephemeral reuse,
   downgrade, and whether the server can forge or substitute keys.
3. Check the deterministic-AEAD tradeoff (chunk equality within one file's
   history) for anything worse than documented leakage.
4. Look for plaintext or key material escaping through the server surface
   (logs, audit entries, error messages, temp files, previews, search).
5. Review client state handling: `.kolimi/`, OS keychain/0600 fallback,
   browser IndexedDB, and the public-link key fragment.
6. Review the MLS delta on its own terms: key-package lifecycle, epochs
   and commits, keyring binding, device credentials, state
   persistence/rollback, and mount-aware write paths.

## Engagement notes

- The crypto surface is small and self-contained; `kolimi-crypto` has no
  I/O beyond `getrandom`, which keeps the review tractable.
- We can freeze the 0.3.0 surface for the duration of a review and land
  only fixes.
- The `openmls` tree currently carries **89 temporary `cargo-vet`
  exemptions** (724 total); none are audits. They should be replaced by
  real audit entries after remediation.
- MLS is implemented (RFC 0012) and should be reviewed as MLS, separately
  from the v1/v2 per-file design. Legacy v1/v2 shares remain readable and
  are still in scope for this package.
