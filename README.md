<p align="center">
  <img src="assets/branding/logo-256.png" width="96" height="96" alt="Kolimi logo" />
</p>

<h1 align="center">Kolimi (కొలిమి)</h1>

<p align="center"><strong>A small, self-hosted server for your files, calendars, and contacts.</strong></p>

The name means *forge*: a workshop where you make and keep things. Kolimi is
built in that spirit — software you run yourself, on a machine you control,
with as few moving parts as possible.

<p align="center">
  <a href="docs/install.md">Install</a> ·
  <a href="docs/how-to.md">How-to</a> ·
  <a href="docs/README.md">Documentation</a> ·
  <a href="docs/audit/README.md">Security &amp; audit</a> ·
  <a href="ROADMAP.md">Roadmap</a>
</p>

## The idea

Your files, calendars, and contacts should not need a control panel, a
service mesh, or a vendor account. They should live in a directory you can
back up, move, and inspect.

Kolimi is one process with one SQLite database and one data directory. It
ships a browser UI, a desktop app with background sync, and a CLI, and it
speaks WebDAV, CalDAV, and CardDAV for the clients you already use. Encrypted
folders keep their keys on your devices; the server stores ciphertext.

It is intentionally not a platform. There is no plugin marketplace, no
multi-tenant control plane, and no external service to operate. Kolimi does
one job: keep a private collection of files, calendars, and contacts
available to the people you choose.

## Quick start

### Docker

```sh
docker run -d --name kolimi \
  -p 127.0.0.1:8080:8080 \
  -v kolimi-data:/data \
  -e KOLIMI_ORIGIN=http://localhost:8080 \
  ghcr.io/chaitanyayeleti/kolimi:latest

docker exec -it kolimi kolimi-server user add admin
```

Open <http://localhost:8080/app/> and sign in. Set `KOLIMI_ORIGIN` to the
public URL before exposing the server, or passkeys will not work.

### systemd host

```sh
curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
```

The installer verifies the release, installs `kolimi-server` and
`kolimi-sync`, creates the admin account, and prints the password once.

For Compose/Traefik, Helm, AUR, `.deb`, the desktop app, source builds, and
TLS, see [install.md](docs/install.md).

## What you can do

- **Keep your files.** Upload, organize, search, preview, version, and
  recover deleted items. Share with users, groups, or a read-only public link.
- **Use the clients you like.** A browser UI, a desktop app with background
  sync, `kolimi-sync`, WebDAV, and CalDAV/CardDAV.
- **Keep accounts simple.** Passkeys and passwordless accounts, TOTP,
  mandatory first-login MFA for new Admin/invited users, and revocable
  per-device app passwords.
- **Encrypt what matters.** Per-file E2EE and MLS group shares for encrypted
  folders, with encrypted names and whole-folder desktop sync.
- **Run it without a stack.** Online backup/verify, audit log, Prometheus
  metrics, OTel traces, and packages for containers, systemd, Helm, AUR,
  `.deb`, and the desktop app.

Day-to-day guides and admin workflows live in the
[documentation](docs/README.md). Common tasks have step-by-step recipes in
[how-to.md](docs/how-to.md).

## Security status

E2EE is **alpha**. The per-file v1/v2 design and the MLS group design are
implemented and tested, but **MLS has not had an external crypto audit**. The
openmls tree carries temporary `cargo-vet` exemptions; they are not audits.
The server stores ciphertext and opaque key material and never receives
plaintext file keys, but sizes, timestamps, folder structure, and access
patterns remain visible. See the [audit package](docs/audit/README.md) and
[threat model](docs/threat-model.md).

## Development

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
scripts/smoke.sh          # real server + HTTP/cookies/CSRF/WebDAV
scripts/build-ui.sh       # WASM UI; run before a release build
```

`apps/kolimi-desktop` and `fuzz` are separate workspaces with their own
lockfiles. [AGENTS.md](AGENTS.md) has the full verification matrix, workspace
boundaries, and release checklist.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
