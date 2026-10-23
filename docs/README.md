# Kolimi documentation

Kolimi's docs fall into four kinds:

- **Guides** — how to install and run it.
- **Design & security** — how it works and why it is safe.
- **Plans** — what is being built next.
- **Specifications** — `rfc/` design specs and `decisions/` records (ADRs).

## Start here

| Document | What it covers |
| --- | --- |
| [../README.md](../README.md) | What Kolimi is, feature highlights, quick start |
| [install.md](install.md) | Every way to install and run the server (script, AUR, `.deb`, Docker/Podman, Helm, systemd), Docker Compose with Traefik, TLS, Caddy/nginx/Traefik proxies, first-run |
| [operations.md](operations.md) | Day-2 administration: users, groups, TOTP, passkeys, backups, scrub/verify, audit, E2EE operations, metrics/tracing, quota warnings, upgrades, troubleshooting |

## Design & security

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | Crate map, dependency rules, and why the single binary is not a code monolith |
| [threat-model.md](threat-model.md) | Assets, adversaries, and mitigations |
| [crypto-review.md](crypto-review.md) | Internal review of the E2EE design (invariants, attacks, gaps) |
| [known-advisories.md](known-advisories.md) | Accepted dependency advisories (`paste`, `lru`) with revisit conditions |
| [audit/README.md](audit/README.md) | External audit package: scope, artifacts, reproduction |

## Plans

| Document | What it covers |
| --- | --- |
| [../ROADMAP.md](../ROADMAP.md) | Milestones, ship-blockers, and pending work with plans |
| [plans/clients.md](plans/clients.md) | Client roadmap — desktop first (Linux → Windows/macOS), then mobile (Android first, F-Droid), then iOS |
| [plans/releases.md](plans/releases.md) | Release & distribution — GitHub Releases (tarballs, `.deb`, Helm, SBOM), GHCR image, Arch (AUR), `install.sh` |

## Specifications — RFCs

Design specs. Status is noted in each file (`draft` / `implemented`).

| RFC | What it covers |
| --- | --- |
| [rfc/0001-storage-engine.md](rfc/0001-storage-engine.md) | Chunked CAS storage |
| [rfc/0002-sync-protocol.md](rfc/0002-sync-protocol.md) | Delta sync protocol |
| [rfc/0003-sharing-and-permissions.md](rfc/0003-sharing-and-permissions.md) | One permission engine, shares, public links |
| [rfc/0004-caldav-carddav.md](rfc/0004-caldav-carddav.md) | CalDAV/CardDAV + sync-collection |
| [rfc/0005-search-and-previews.md](rfc/0005-search-and-previews.md) | Search index and sandboxed previews |
| [rfc/0006-sync-client.md](rfc/0006-sync-client.md) | The desktop sync client |
| [rfc/0007-e2ee.md](rfc/0007-e2ee.md) | End-to-end encryption (v1 core, v2 sharing, pre-MLS groups) |
| [rfc/0008-device-enrollment.md](rfc/0008-device-enrollment.md) | Multi-device E2EE enrollment |
| [rfc/0009-e2ee-onboarding.md](rfc/0009-e2ee-onboarding.md) | E2EE onboarding: first-login browser keyring setup, encrypt by default *(draft)* |
| [rfc/0010-webdav-e2ee-boundary.md](rfc/0010-webdav-e2ee-boundary.md) | WebDAV / E2EE boundary: a plaintext-only DAV surface *(draft)* |

## Decision records

Short ADRs capturing a decision, its alternatives, and its status.

| Decision | What it covers |
| --- | --- |
| [decisions/0001-e2ee-dav-scope.md](decisions/0001-e2ee-dav-scope.md) | E2EE scope + WebDAV boundary *(proposed)* |
| [decisions/0002-client-stack.md](decisions/0002-client-stack.md) | Desktop client stack + phase-1 plan *(proposed)* |

## Conventions

- **RFCs** (`rfc/NNNN-*.md`) specify *designs*: problem, threat model,
  protocol, data model, non-goals. They are living documents — a landed
  design keeps its RFC and marks status.
- **Decision records** (`decisions/NNNN-*.md`) capture a single *decision*
  with the alternatives considered and an explicit status
  (proposed / accepted / superseded).
- **Plans** (`plans/`) are forward-looking roadmaps; the authoritative
  backlog is [../ROADMAP.md](../ROADMAP.md).
- Prefer cross-links over duplication; when a design changes, update the
  RFC and reference it from the changelog.
