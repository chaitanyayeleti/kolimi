# Kolimi documentation

This page is the map. The top-level [README](../README.md) is the product
overview and quick start; everything below goes deeper.

Current-facing guides are [install.md](install.md), [how-to.md](how-to.md),
[usage.md](usage.md), [clients.md](clients.md), [operations.md](operations.md),
[reference.md](reference.md), [metrics.md](metrics.md),
[architecture.md](architecture.md), [threat-model.md](threat-model.md),
[crypto-review.md](crypto-review.md), and
[known-advisories.md](known-advisories.md). RFCs, decision records,
plans, and audit files are design or history: they may describe deferred
work, a frozen review surface, or an earlier implementation.

Last full verification: **0.5.3** (2026-11-20); desktop client verified
against **0.4.11**.

## Start here

- **New installation** → [install.md](install.md)
- **How do I…?** → [how-to.md](how-to.md)
- **Day-to-day use** → [usage.md](usage.md)
- **Connecting WebDAV, CalDAV, desktop, or the CLI** → [clients.md](clients.md)
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
| [how-to.md](how-to.md) | Task-first recipes: first admin, invites, MFA, app passwords, sharing, encryption, desktop/DAV/CalDAV, quota, backup, upgrades, MLS recovery |
| [usage.md](usage.md) | Sign-in, mandatory first-login MFA, app passwords, files, sharing, encrypted content, desktop/sync summary, admin quick reference |
| [clients.md](clients.md) | Canonical client setup: credentials and app passwords, WebDAV/CalDAV/CardDAV URLs and mounts, desktop pairing and encryption/MLS options, `kolimi-sync`, troubleshooting |
| [operations.md](operations.md) | Users and groups, account recovery, 2FA and app passwords, backup/restore, audit log, metrics/tracing, quotas, hardening, E2EE/MLS operations, client operations, upgrades, troubleshooting |
| [metrics.md](metrics.md) | `/metrics` catalog, PromQL, alert starting points, scrape credentials and token setup, Grafana dashboard |
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
| [audit/redteam-2026-11-14.md](audit/redteam-2026-11-14.md) | Internal red-team report: server, host boundary, E2EE/MLS findings and fixes |

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
| [plans/user-management.md](plans/user-management.md) | Completed admin/self-service account plan and security decisions |
| [plans/ui.md](plans/ui.md) | Web UI improvement plan: asset performance, sharing surfaces, favorites/recents, notifications, PWA |
| [plans/future.md](plans/future.md) | Unscheduled future core ideas and deferred work; not a commitment |
| [plans/releases.md](plans/releases.md) | Release channels, tag pipeline, version-bump checklist |
| [../CHANGELOG.md](../CHANGELOG.md) | What shipped in each release |

## Conventions

- **RFCs** (`rfc/NNNN-*.md`) specify designs: problem, threat model,
  protocol, data model, non-goals. They are living documents and carry a
  `Status:` line with the last verified release.
- **Decision records** (`decisions/NNNN-*.md`) capture one decision, its
  alternatives and its status (proposed / accepted / superseded).
- **Plans** (`plans/`) describe forward work or a completed implementation;
  [ROADMAP.md](../ROADMAP.md) is the authoritative backlog. Shipped history
  belongs in `CHANGELOG.md`, not in the roadmap; completed plans remain as
  design/security history.
- **Status words** mean:
  - *design*: `draft` (still changing), `accepted` (agreed, not fully
    built), `implemented` (the design is what the code follows);
  - *implementation*: `shipped`, `partial`, or `not started`, always with
    the release it was last verified against.
- **Client setup belongs in [clients.md](clients.md).** Usage and operations
  summarize behavior and link there instead of repeating URLs, credentials,
  desktop configuration, or mount commands.
- Prefer cross-links over duplication. Update the RFC when a design
  changes and add a `CHANGELOG.md` entry when behavior changes.

## Checks

`scripts/check-docs.sh` (also run in CI) verifies that relative links
resolve, every RFC appears in the RFC index, release-facing docs match the
workspace version, and current-facing guides do not reintroduce known stale
claims. Run it before sending a docs change.

`browser-e2e/` (Playwright) drives the real web UI against a fixture server
for account/session controls, admin users/invites/groups/audit, forced
password rotation, rename/delete, share/revoke, uploads, E2EE, and the MLS
migration/reset flow. It runs in the `browser (Playwright)` CI job; build the
UI and server binaries first when running it locally.

CI is path-filtered: documentation-only changes run just this check, while
code changes run the Rust suite plus the relevant browser, UI, desktop,
packaging, perf, litmus or fuzz jobs. Use a manual `workflow_dispatch` when
you need every expensive gate on an otherwise narrow change.
