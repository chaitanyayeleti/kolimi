# Kolimi documentation

This page is the map. The top-level [README](../README.md) is the product
overview and quick start; everything below goes deeper.

Last full verification: **0.3.0** (2026-10-25).

## Start here

- **New installation** → [install.md](install.md)
- **Day-2 administration** → [operations.md](operations.md)
- **CLI, environment and HTTP API** → [reference.md](reference.md)
- **How the code is organized** → [architecture.md](architecture.md)
- **Security review / audit** → [audit/README.md](audit/README.md) and
  [audit/mls-delta.md](audit/mls-delta.md)
- **Contributing** → [../AGENTS.md](../AGENTS.md) and the
  [RFC index](rfc/README.md)

## Guides

| Document | What it covers |
| --- | --- |
| [install.md](install.md) | One-command install, Docker/Podman, Compose + Traefik, Helm, AUR, `.deb`, desktop client, source builds, TLS/reverse proxies, first run, upgrades, uninstall |
| [operations.md](operations.md) | Users and groups, account recovery, 2FA, backup/restore, audit log, metrics/tracing, quotas, hardening, E2EE/MLS operations, desktop/mobile clients, upgrades, troubleshooting |
| [reference.md](reference.md) | `kolimi-server` and `kolimi-sync` commands, environment variables, HTTP endpoint groups, data-directory layout |

## Design and security

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | Crate map, dependency direction, runtime shape, where coupling exists |
| [threat-model.md](threat-model.md) | Assets, adversaries, trust boundaries, mitigations, honest limitations |
| [crypto-review.md](crypto-review.md) | Internal review of the v1/v2 E2EE design: primitives, invariants, attacks, gaps |
| [known-advisories.md](known-advisories.md) | Accepted RustSec warnings with reasons and revisit conditions |
| [audit/README.md](audit/README.md) | External crypto audit package: scope, artifacts, reproduction, review asks |
| [audit/mls-delta.md](audit/mls-delta.md) | MLS delta for the reviewer: invariants, server rules, tests, open questions |

MLS is implemented but **not externally audited**. The audit package is
the source of truth for what has and has not been reviewed.

## Specifications

- [rfc/README.md](rfc/README.md) — all RFCs with design and implementation
  status. Start there rather than assuming an RFC title reflects today's
  behavior.
- [decisions/0001-e2ee-dav-scope.md](decisions/0001-e2ee-dav-scope.md) —
  E2EE / WebDAV boundary decision.
- [decisions/0002-client-stack.md](decisions/0002-client-stack.md) — desktop
  and mobile client stack.

## Plans and history

| Document | What it covers |
| --- | --- |
| [../ROADMAP.md](../ROADMAP.md) | Current state, next work, deferred items, non-goals |
| [plans/clients.md](plans/clients.md) | Desktop → mobile client roadmap |
| [plans/android.md](plans/android.md) | Android/F-Droid client plan |
| [plans/releases.md](plans/releases.md) | Release channels, tag pipeline, version-bump checklist |
| [../CHANGELOG.md](../CHANGELOG.md) | What shipped in each release |

## Conventions

- **RFCs** (`rfc/NNNN-*.md`) specify designs: problem, threat model,
  protocol, data model, non-goals. They are living documents and carry a
  `Status:` line with the last verified release.
- **Decision records** (`decisions/NNNN-*.md`) capture one decision, its
  alternatives and its status (proposed / accepted / superseded).
- **Plans** (`plans/`) look forward; [ROADMAP.md](../ROADMAP.md) is the
  authoritative backlog. Shipped history belongs in `CHANGELOG.md`, not in
  the roadmap.
- **Status words** mean:
  - *design*: `draft` (still changing), `accepted` (agreed, not fully
    built), `implemented` (the design is what the code follows);
  - *implementation*: `shipped`, `partial`, or `not started`, always with
    the release it was last verified against.
- Prefer cross-links over duplication. Update the RFC when a design
  changes and add a `CHANGELOG.md` entry when behavior changes.

## Checks

`scripts/check-docs.sh` (also run in CI) verifies that relative links
resolve, every RFC appears in the RFC index, and current-facing guides do
not reintroduce known stale claims. Run it before sending a docs change.
