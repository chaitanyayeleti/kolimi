# Kolimi Threat Model

- **Status:** Living document. Reviewed at every milestone gate.
- **Related:** RFC 0001 (Storage), RFC 0002 (Sync), ROADMAP safety gates.

## Assets

1. **File content** — user documents, photos, etc. Highest sensitivity.
2. **Metadata** — names, sizes, timestamps, folder structure, share graph.
3. **Credentials** — passwords, passkeys, sessions, OIDC tokens, TOTP seeds.
4. **Share links** — capability URLs; anyone with the URL can read the share.
5. **Audit log** — who did what; integrity matters (append-only).
6. **Server keys** — TLS keys, at-rest encryption keys (future), signing keys.

## Adversaries

| # | Adversary | Capability |
|---|-----------|------------|
| A1 | Remote unauthenticated | Full network access, can scan/brute-force/exploit parser bugs |
| A2 | Authenticated user (attacker's own account) | Can probe authorization boundaries, upload hostile files |
| A3 | Malicious share recipient | Legitimately given access to a subset; tries to pivot |
| A4 | Malicious plugin/app | Runs inside the process today (PHP-model); in Kolimi: WASM sandbox with declared capabilities |
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
                  (disk/S3)        (SQLite)        (append-only)
                                        │
                                        ▼
                                 WASM sandbox (plugins)
```

- Everything crossing the TLS boundary is untrusted input: paths, manifests,
  chunks, filenames, shares, headers.
- The blob store and index are *trusted but verifiable*: on-disk corruption
  must be detected (BLAKE3 verify-on-read + scrub), not trusted.
- Plugins are untrusted code: sandboxed, capability-scoped, resource-limited.

## Key scenarios and mitigations

| Scenario | Mitigation | Status |
|---|---|---|
| A1 credential stuffing | argon2id, rate limits, per-device sessions, lockout, passkeys | M1 |
| A1 parser exploits (DAV/XML/manifests) | Rust memory safety, `dav-server` + own parser fuzzing, strict size/depth limits | M0–M2 |
| A2 IDOR / path traversal | single server-side permission engine; every lookup goes through it; `..`/symlink normalization tests | M1–M3 |
| A2 chunk-existence oracle | chunk endpoint checks visibility, constant 404 for invisible chunks | M2 |
| A2 hostile uploads (zip bomb, image exploit) | previews in separate process: landlock+seccomp, rlimits, timeouts, no network | M5 |
| A3 share escalation | shares are capability-scoped, re-checked server-side every request; no client-side trust | M3 |
| A4 plugin root | WASM component model, explicit capabilities (no ambient FS/net), fuel metering | M7 |
| A5 operator reads content | optional client-side E2EE (per-file keys; MLS groups in v2); metadata remains visible in v1 — documented honestly | M6 |
| A6 MITM | rustls, TLS 1.3 only, HSTS, no mixed content in UI | M1 |
| A7 memory scraping | `zeroize`/`secrecy` for secrets, no keys in logs; full-disk encryption is the operator's responsibility | M1+ |
| A8 malicious dependency | `cargo-deny`, `cargo-audit`, `cargo-vet`, minimal dep tree, pinned lockfile in CI | M0 |
| A8 build/release tampering | reproducible builds, signed release artifacts, tagged builds from CI only | M7 |
| Replay/CSRF | CSRF double-submit tokens, SameSite=Strict cookies, no state-changing GETs | M1 |
| Log leakage | never log content or full URLs with tokens; structured logs with redaction | M1 |

## Explicit non-goals / honest limitations

- **OpenSSL is in the tree** via `webauthn-rs-core` (unconditional upstream dependency) for WebAuthn signature verification. It is not used for TLS (rustls), hashing (BLAKE3), or password hashing (Argon2id). This is a tracked, documented exception in `deny.toml`; revisit when upstream offers a pure-Rust backend.
- **Metadata is not hidden** from the server operator in v1 (names, sizes,
  structure). E2EE hides content; hiding metadata needs encrypted search
  (a research problem) and is not claimed.
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
