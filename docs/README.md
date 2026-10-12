# Kolimi documentation

Start here.

| Document | What it covers |
| --- | --- |
| [../README.md](../README.md) | What Kolimi is, feature highlights, quick start |
| [install.md](install.md) | Every way to install and run the server (script, AUR, .deb, Docker/Podman, Helm, systemd), Docker Compose with Traefik, TLS, Caddy/nginx/Traefik proxies, first-run |
| [operations.md](operations.md) | Day-2 administration: users, groups, TOTP, passkeys, backups, scrub/verify, audit, E2EE operations, plugins, metrics, upgrades, troubleshooting |
| [architecture.md](architecture.md) | Crate map, dependency rules, and why the single binary is not a code monolith |
| [plan-clients.md](plan-clients.md) | Client roadmap — desktop first (Linux → Windows/macOS), then mobile (Android first, F-Droid), then iOS: architecture, F-Droid requirements, week-by-week plan |
| [plan-releases.md](plan-releases.md) | Release & distribution plan — GitHub Releases (tarballs, .deb, Helm, SBOM), GHCR container image, Arch (AUR), install.sh |
| [threat-model.md](threat-model.md) | Assets, adversaries, and mitigations |
| [crypto-review.md](crypto-review.md) | Internal review of the E2EE design (invariants, attacks, gaps) |
| [audit/README.md](audit/README.md) | External audit package: scope, artifacts, reproduction |
| [rfc/0001-storage-engine.md](rfc/0001-storage-engine.md) | Chunked CAS storage |
| [rfc/0002-sync-protocol.md](rfc/0002-sync-protocol.md) | Delta sync protocol |
| [rfc/0003-sharing-and-permissions.md](rfc/0003-sharing-and-permissions.md) | One permission engine, shares, public links |
| [rfc/0004-caldav-carddav.md](rfc/0004-caldav-carddav.md) | CalDAV/CardDAV + sync-collection |
| [rfc/0005-search-and-previews.md](rfc/0005-search-and-previews.md) | Search index and sandboxed previews |
| [rfc/0006-sync-client.md](rfc/0006-sync-client.md) | The desktop sync client |
| [rfc/0007-e2ee.md](rfc/0007-e2ee.md) | End-to-end encryption (v1 core, v2 sharing, pre-MLS groups) |
| [rfc/0008-device-enrollment.md](rfc/0008-device-enrollment.md) | Multi-device E2EE enrollment |
| [rfc/0009-e2ee-onboarding.md](rfc/0009-e2ee-onboarding.md) | E2EE onboarding: first-login browser keyring setup, encrypt by default (draft) |
| [rfc/0010-webdav-e2ee-boundary.md](rfc/0010-webdav-e2ee-boundary.md) | WebDAV / E2EE boundary: a plaintext-only DAV surface (draft) |
| [decisions/0001-e2ee-dav-scope.md](decisions/0001-e2ee-dav-scope.md) | Decision record: E2EE scope + WebDAV boundary (proposed) |
| [known-advisories.md](known-advisories.md) | Accepted dependency advisories (paste, lru) with revisit conditions |
| [../ROADMAP.md](../ROADMAP.md) | Milestones, ship-blockers, pending work with plans |
