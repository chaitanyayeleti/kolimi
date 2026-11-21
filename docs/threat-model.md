# Kolimi Threat Model

- **Status:** Living document. Last reviewed for **0.7.1**.
- **Related:** RFC 0001 (Storage), RFC 0002 (Sync), ROADMAP safety gates.

## Assets

1. **File content** — user documents, photos, etc. Highest sensitivity.
2. **Metadata** — names, sizes, timestamps, folder structure, share graph.
3. **Credentials** — passwords, passkeys, sessions, TOTP seeds, app passwords.
4. **Share links** — capability URLs; anyone with the URL can read the share.
5. **Audit log** — who did what; integrity matters (append-only).
6. **Server keys** — TLS keys, at-rest encryption keys (future), signing keys.

## Adversaries

| # | Adversary | Capability |
|---|-----------|------------|
| A1 | Remote unauthenticated | Full network access, can scan/brute-force/exploit parser bugs |
| A2 | Authenticated user (attacker's own account) | Can probe authorization boundaries, upload hostile files |
| A3 | Malicious share recipient | Legitimately given access to a subset; tries to pivot |
| A4 | Malicious third-party app | No plugin model: third parties use the authenticated API/DAV surfaces |
| A5 | Malicious/curious server operator | Full access to server, DB, and raw blobs (defeated by E2EE for content) |
| A6 | Network attacker | Passive/active MITM (defeated by TLS 1.3) |
| A7 | Local attacker | On the server host; can read memory/disk |
| A8 | Supply chain attacker | Malicious crate, build tool, CI compromise |

## Trust boundaries

```
client ──(TLS, untrusted network)──> kolimi-server
                                        │
                       ┌────────────────┼────────────────┐
                       ▼                ▼                ▼
                  blob store        index DB        audit log
                  (local disk)      (SQLite)        (append-only)
                                        │
                                        ▼
                                 sandboxed preview worker
```

- Everything crossing the TLS boundary is untrusted input: paths, manifests,
  chunks, filenames, shares, headers.
- The blob store and index are *trusted but verifiable*: on-disk corruption
  must be detected (BLAKE3 verify-on-read + scrub), not trusted.
- There is no plugin model: third-party integrations use the authenticated API/DAV surfaces.

## Key scenarios and mitigations

| Scenario | Mitigation | Status |
|---|---|---|
| A1 credential stuffing | argon2id, rate limits, per-device sessions, lockout, passkeys | Implemented |
| A1 stolen app password | high-entropy per-device token, BLAKE3 digest at rest, protocol scopes, optional expiry, per-device revoke; admin recovery revokes all; TLS-only Basic auth | Implemented |
| A1 app-password scope bypass | deny-by-default route matrix after authentication; write implies read; no cookie fallback on a failed app-password scope; account/credential routes require `*` | Implemented |
| A1 parser exploits (DAV/XML/manifests) | Rust memory safety, `dav-server` + own parser fuzzing, strict size/depth limits | Implemented |
| A2 IDOR / path traversal | single server-side permission engine; every lookup goes through it; `..`/symlink normalization tests | Implemented |
| A2 chunk-existence oracle | chunk endpoint checks visibility, constant 404 for invisible chunks | Implemented |
| A2 hostile uploads (zip bomb, image exploit) | previews in a re-executed worker: rlimits (AS/CPU/FSIZE/NOFILE) → landlock (read the scratch file only) → seccomp allowlist (no network, no exec); wall-clock kill; decoder dimension/allocation limits; fuzzed | Implemented |
| A3 share escalation | shares are capability-scoped, re-checked server-side every request; no client-side trust | Implemented |
| A3 mount traversal | `/Shared with me/<mount>/...` resolution starts at the mount root; ancestors of a share are unreachable | Implemented |
| A3 link token brute force | 128-bit random tokens, exact-match lookup, per-share unlock lockout (5/15min), expiry | Implemented |
| A3 link password guessing | argon2id, same lockout machinery as logins, HttpOnly unlock cookies | Implemented |
| A3 public upload abuse | upload-only links are write links with per-link file/byte caps, short default expiry, per-IP rate limiting, and owner quota; no listing, download, or overwrite; expiry, password, trashed, missing, and encrypted targets rejected | Implemented |
| A3 plaintext into an E2EE tree | file-request creation rejects encrypted folders; the upload endpoint re-checks the target before writing | Implemented |
| A3 upload filename traversal | filenames reject `/`, `\`, NUL, control characters, `.`/`..`, and overlong names; collision suffixes never overwrite; tests cover encoded traversal | Implemented |
| A2 DAV object injection | iCalendar parsed + UID rules enforced; vCards structurally validated; raw payloads stored byte-for-byte (no re-serialization); 10 MiB cap; XML parsers size-capped | Implemented |
| A2 DAV namespace shadowing | `principals`/`calendars`/`addressbooks` reserved at the root; principals/homes are owner-only and 404 for everyone else | Implemented |
| A4 third-party app | Authenticated API/DAV only, per-user permission checks | Implemented |
| A5 operator reads content | optional client-side E2EE (v1/v2 per-file keys; MLS groups since 0.5.1, not externally audited); encrypted names supported, but sizes/timestamps/structure remain visible | Partial (E2EE alpha) |
| Operator tampers with or deletes audit records | BLAKE3 hash-chained append-only audit log with sealed Merkle checkpoints; `audit verify` detects edits, deletions, and reordering. Optional Ed25519 checkpoint signatures with a key outside the data directory defeat database/backup-only tampering; anchoring signed heads to a WORM or independently controlled sink detects a host-level rewrite or rollback. Retention exports the prefix before deleting it and records the last pruned hash as an anchor. | Implemented |
| A6 MITM | rustls, TLS 1.3 only, HSTS, no mixed content in UI | Implemented |
| A7 memory scraping | `zeroize`/`secrecy` for secrets, no keys in logs; full-disk encryption is the operator's responsibility | Partial |
| A8 malicious dependency | `cargo-deny`, `cargo-audit`, `cargo-vet`, minimal dep tree, pinned lockfile in CI | Implemented |
| Secrets in memory / swap | `zeroize` on master/file keys and KEK locals; wrapped keys only on disk; allocator copies and swap remain outside our control; internal review in `docs/crypto-review.md` | Partial |
| Silent bit-rot or tampering in the blob store | background janitor scrubber re-hashes chunks (BLAKE3) and re-derives manifest ids incrementally; corruption is logged and audited | Implemented |
| A8 build/release tampering | tagged CI builds, signed release artifacts and SBOM, cosign keyless signing | Implemented |
| Replay/CSRF | CSRF double-submit tokens, SameSite=Strict cookies, no state-changing GETs | Implemented |
| Log leakage | never log content or full URLs with tokens; structured logs with redaction | Implemented |

## Explicit non-goals / honest limitations

- **OpenSSL is in the tree** via `webauthn-rs-core` (unconditional upstream dependency) for WebAuthn signature verification. It is not used for TLS (rustls), hashing (BLAKE3), or password hashing (Argon2id). This is a tracked, documented exception in `deny.toml`; revisit when upstream offers a pure-Rust backend.
- **Metadata is only partially hidden.** Encrypted nodes can use encrypted
  names (`k1_…`), but sizes, timestamps, structure and access patterns
  remain visible. Content search over encrypted data is not possible.
- **Traffic analysis** is not defended against beyond TLS.
- **Endpoint compromise** (client malware) is out of scope.
- **Deniability**: no plausible deniability engineered; do not claim it.
- Kolimi does not defend against a fully compromised host root (A7) beyond
  making it detectable for content (verify-on-read) and non-trivial for
  secrets (zeroization). Full-disk/full-VM compromise is game over.

## Review checklist for every PR

- [ ] New endpoint: does it go through the permission engine?
- [ ] New input parser: is there a fuzz target or property test?
- [ ] New dependency: license allowed, no `openssl`, audited?
- [ ] New secret: zeroized, never logged, never serialized?
- [ ] New error path: does it leak existence or content cross-user?
- [ ] New background job: crash-safe, resumable, rate-limited?
- [ ] New share/link surface: owner-only by default, revocable, expiry honored?
