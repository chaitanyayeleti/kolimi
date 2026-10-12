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
