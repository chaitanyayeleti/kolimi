# Known dependency advisories (accepted)

Both entries below are accepted, upstream-blocked risks. They are RustSec
**warnings** (unmaintained / unsound), not exploitable vulnerabilities,
and `cargo audit` allows them by default. They are listed explicitly in
`.cargo/audit.toml` and `deny.toml` so the acceptance is intentional and
`cargo audit --deny warnings` / `cargo deny` stay green.

## RUSTSEC-2024-0436 — `paste` unmaintained

- **Crate:** `paste` 1.0.15 · **Via:** Leptos 0.8
  (`either_of` / `tachys` / `reactive_graph`).
- **What it is:** `paste` is a **compile-time proc-macro**. It is
  unmaintained (the maintained fork is `pastey`); there is **no known
  vulnerability** and no runtime exposure — it only affects builds.
- **Why accepted:** stable Leptos has not yet adopted `pastey`, and
  `paste` is transitive (not a direct workspace dependency), so it is not
  even flagged by cargo-deny's `unmaintained = "workspace"` scope.
- **Revisit when:** Leptos (stable) switches to `pastey`, or when a
  `paste` advisory becomes a vulnerability.

## RUSTSEC-2026-0253 — `lru` unsound (`LruCache::pop`)

- **Crate:** `lru` 0.16.4 · **Via:** `tantivy` 0.26 (search index).
- **What it is:** a potential use-after-free when a cache **key's** `Drop`
  panics during `LruCache::pop()` under `catch_unwind`. Fixed in
  `lru >= 0.18.2`.
- **Why accepted:** `tantivy` 0.26.2 (current release) depends on
  `lru 0.16`, and the versions are not semver-compatible, so there is no
  in-range fix. In Kolimi, `tantivy`'s cache keys are plain
  `(Field, u64)` / `String` values whose `Drop` cannot panic, so the
  unsound path is not reachable here.
- **Revisit when:** `tantivy` moves to `lru >= 0.18`, then remove the
  ignore.

## Process

- CI runs both `cargo audit` (`.cargo/audit.toml`) and
  `cargo deny check advisories` (`deny.toml`).
- Every accepted advisory must have a reason and a **revisit condition**.
- Prefer an actual upgrade or removal; accept only when upstream blocks a
  fix, and document why the path is unreachable.

## RUSTSEC-2026-0387 — `crypto-bigint` timing variability

- **Crate:** `crypto-bigint` 0.5.5 · **Via:** `hpke-rs-rust-crypto` 0.7
  (P-256/P-384 HPKE) → `openmls_rust_crypto`.
- **What it is:** timing variability in operations intended to be
  constant-time. Fixed in `crypto-bigint >= 0.7.6`.
- **Why accepted:** `elliptic-curve 0.13` (used by `hpke-rs-rust-crypto`)
  requires `crypto-bigint 0.5`; there is no in-range upgrade. Kolimi’s MLS
  ciphersuite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; the
  P-curve HPKE code is linked but not exercised by the group path.
- **Revisit when:** `hpke-rs` moves to `elliptic-curve 0.14` /
  `crypto-bigint >= 0.7.6`, or when a P-curve ciphersuite is enabled.

## RUSTSEC-2026-0330 / RUSTSEC-2026-0331 — `libcrux-kem`

- **Crate:** `libcrux-kem` 0.0.9 · **Via:** the optional
  `hpke-rs-libcrux` backend.
- **What it is:** a panic on a short seed and on decoding short hybrid
  keys; fixed in `libcrux-kem >= 0.0.10`.
- **Why accepted:** the `libcrux` feature is not enabled; the crate is in
  the lockfile because Cargo resolves optional dependencies, but it is
  absent from the host build graph. The RustCrypto backend is used instead.
- **Revisit when:** `openmls`/`hpke-rs` updates the optional backend or
  Cargo prunes the unused lock entry.
