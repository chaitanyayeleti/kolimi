# Kolimi documentation

Start here.

| Document | What it covers |
| --- | --- |
| [../README.md](../README.md) | What Kolimi is, feature highlights, quick start |
| [install.md](install.md) | Every way to install and run the server (script, AUR, .deb, Docker/Podman, Helm, systemd), TLS, reverse proxies, first-run |
| [operations.md](operations.md) | Day-2 administration: users, groups, TOTP, passkeys, backups, scrub/verify, audit, E2EE operations, plugins, metrics, upgrades, troubleshooting |
| [architecture.md](architecture.md) | Crate map, dependency rules, and why the single binary is not a code monolith |
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
| [../ROADMAP.md](../ROADMAP.md) | Milestones, ship-blockers, pending work with plans |
