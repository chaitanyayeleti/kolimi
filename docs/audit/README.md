# External crypto audit package

This directory prepares an external review of Kolimi's end-to-end
encryption. It is written so a reviewer can start from a single commit
and reproduce every claim.

## Scope

In scope:

- `crates/kolimi-crypto` — keyring (passphrase/recovery/PRF wraps),
  master-key wrapping, per-file keys, deterministic chunk AEAD,
  X25519 identities, recipient key wrapping.
- Server E2EE surface — `api_e2ee`, `e2ee_keyrings`, `e2ee_file_keys`,
  `e2ee_identities`, `e2ee_share_keys`, the `encrypted` node flag and
  its guards (search, previews, shares, chunk access).
- `kolimi-sync` E2EE integration — unlock, encrypt-then-chunk push,
  decrypt pull, conflict handling, share/unshare, shared mounts.
- The wire formats pinned by `crates/kolimi-crypto/tests/vectors.json`.

Out of scope (documented non-goals, RFC 0007): metadata confidentiality,
forward secrecy, post-compromise security, rollback protection,
multi-device key management, and the web UI (no E2EE there).

## Artifacts

| Artifact | Purpose |
| --- | --- |
| `docs/rfc/0007-e2ee.md` | Protocol specification, including the v2 sharing design and the v1 manifest decision |
| `docs/crypto-review.md` | Internal review: invariants, attack analysis, known gaps |
| `docs/threat-model.md` | System-wide threat model (A5 operator reads content) |
| `crates/kolimi-crypto/tests/vectors.json` | Committed interop vectors (KEK derivations, wraps, chunk AEAD, share wrap) |
| `crates/kolimi-crypto/examples/gen_vectors.rs` | Deterministic vector regenerator |
| `fuzz/fuzz_targets/e2ee_decrypt.rs` | Decryption surface fuzz target (must fail closed, never panic) |
| `crates/kolimi-server/tests/e2ee*.rs` | End-to-end: plaintext-never-on-server marker scan, unlock methods, sharing, independent decoders |

## Reproducing

```sh
git clone https://github.com/chaitanyayeleti/kolimi && cd kolimi
git checkout <audited-commit>

# Vector stability (wire format)
cargo test -p kolimi-crypto

# End-to-end E2EE + sharing (live in-process server)
cargo test -p kolimi-server --test e2ee --test e2ee_share

# Decryption surface fuzzing (nightly)
cargo install cargo-fuzz --locked
cd fuzz && cargo fuzz run e2ee_decrypt -- -max_total_time=300

# One-shot bundle for review
scripts/audit-package.sh
```

`scripts/audit-package.sh` produces
`target/audit/kolimi-audit-<commit>.tar.gz` containing the documents,
vectors, and the exact commit hash.

## What we want from a review

1. Verify the invariants in `docs/crypto-review.md` §Invariants against
   the code, especially nonce derivation and key-wrap AADs.
2. Attack the v2 sharing exchange (X25519 ECIES): recipient binding,
   ephemeral reuse, downgrade, and the server's inability to forge keys.
3. Check the deterministic-AEAD tradeoff (chunk equality within one
   file's history) for anything worse than documented leakage.
4. Look for plaintext or key material escaping through the server
   surface (logs, audit entries, error messages, temp files).
5. Review the sync client's state handling (`.kolimi/state.json`, chunk
   cache) for key/plaintext persistence surprises.
6. Rank the known gaps (manifest structure, no FS/PCS, no MLS) by real
   risk so the roadmap can address them in order.

## Engagement notes

- The crypto surface is small and self-contained; `kolimi-crypto` has no
  I/O beyond `getrandom`, which keeps the review tractable.
- We are happy to freeze the surface for the duration of a review and
  land only fixes.
- MLS (RFC 9420) group messaging is planned but **not implemented**;
  group sharing today uses per-member X25519 wrapping (see RFC 0007 v2)
  and should be reviewed as such, not as MLS.
