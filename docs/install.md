# Installing Kolimi

Kolimi ships as one server binary plus an optional sync/desktop client.
Every deployment path runs the same `kolimi-server`; choose the one that
matches your host.

- [Requirements](#requirements)
- [Choose a path](#choose-a-path)
- [One-command install (systemd host)](#one-command-install-systemd-host)
- [Docker / Podman](#docker--podman)
- [Docker Compose with Traefik](#docker-compose-with-traefik)
- [Kubernetes (Helm)](#kubernetes-helm)
- [Arch Linux (AUR)](#arch-linux-aur)
- [Debian / Ubuntu (.deb)](#debian--ubuntu-deb)
- [Desktop client (Linux)](#desktop-client-linux)
- [Manual / from source](#manual--from-source)
- [TLS and reverse proxies](#tls-and-reverse-proxies)
- [First run](#first-run)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

## Requirements

- **Linux x86_64 or aarch64.** Release tarballs are published for
  `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-gnu`; the container image is multi-arch
  (`linux/amd64`, `linux/arm64`).
- **One data directory.** SQLite (WAL) and the blob store are embedded; no
  Postgres, Redis, PHP or web server is required.
- **~50 MB for the binary**, plus your data. The release binary is gated
  below 50 MB in CI.
- **Landlock 5.13+** gives the strongest preview sandbox; older kernels
  fall back to seccomp + rlimits.
- The one-command installer targets systemd hosts. Containers, Helm, AUR
  and `.deb` have their own flows below.

## Choose a path

| Environment | Recommended |
| --- | --- |
| VPS/home server with systemd | [One-command install](#one-command-install-systemd-host) |
| Docker or Podman | [Docker / Podman](#docker--podman) |
| Docker + automatic HTTPS | [Compose with Traefik](#docker-compose-with-traefik) |
| Kubernetes | [Helm](#kubernetes-helm) |
| Arch Linux | [AUR](#arch-linux-aur) |
| Debian/Ubuntu package | [`.deb`](#debian--ubuntu-deb) |
| Build from a checkout | [Manual / from source](#manual--from-source) |

## One-command install (systemd host)

The installer downloads a signed release, verifies the checksum (and the
cosign signature when `cosign` is installed), installs `kolimi-server` and
`kolimi-sync`, creates the first admin account, and prints the generated
password once.

```sh
curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
```

Run this as root on a systemd host: the installer creates
`/var/lib/kolimi` and the service user. For a non-root install, pass a
writable `--prefix` and `--data-dir`.

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--prefix DIR` | Binary prefix (default `/usr/local`) |
| `--data-dir DIR` | Server state (default `/var/lib/kolimi`) |
| `--admin NAME` | First admin username (default `admin`) |
| `--password PW` | Admin password; prefer `KOLIMI_ADMIN_PASSWORD` so it is not in `ps` |
| `--version TAG` | Release tag to install (default `latest`) |
| `--no-systemd` | Skip systemd user/tmpfiles setup (containers, non-systemd hosts) |
| `--no-verify` | Skip checksum/signature verification (not recommended) |

The generated password is shown only once. Change it after first login.

### systemd unit

The unit in this repository uses `ExecStart=/usr/bin/kolimi-server`. If you
installed with the default prefix (`/usr/local`), either install with
`--prefix /usr` or adjust `ExecStart` after copying the unit.

```sh
sudo install -Dm644 packaging/systemd/kolimi.service /etc/systemd/system/kolimi.service
sudo install -Dm644 packaging/systemd/kolimi.env.example /etc/kolimi/kolimi.env
sudoedit /etc/kolimi/kolimi.env     # set KOLIMI_ORIGIN to your public URL
sudo systemctl daemon-reload
sudo systemctl enable --now kolimi
```

Without a local checkout, fetch the two files from GitHub:

```sh
sudo install -d /etc/kolimi
sudo curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/packaging/systemd/kolimi.service \
  -o /etc/systemd/system/kolimi.service
sudo curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/packaging/systemd/kolimi.env.example \
  -o /etc/kolimi/kolimi.env
```

The example environment file sets `KOLIMI_DATA=/var/lib/kolimi` and
`KOLIMI_BIND=127.0.0.1:8080`. Put TLS in front of it (see
[TLS and reverse proxies](#tls-and-reverse-proxies)) or use the direct TLS
flags below.

## Docker / Podman

Pull the published image (no local build):

```sh
docker run -d --name kolimi \
  -p 127.0.0.1:8080:8080 \
  -v kolimi-data:/data \
  -e KOLIMI_ORIGIN=http://localhost:8080 \
  ghcr.io/chaitanyayeleti/kolimi:latest
```

Create the first admin inside the running container:

```sh
docker exec kolimi kolimi-server user add admin
```

Open <http://localhost:8080/app/>. In production, set `KOLIMI_ORIGIN` to
the exact public URL (for example `https://cloud.example.com`) and set
`KOLIMI_SECURE_COOKIES=true`.

- **Tags:** `latest`, the current minor (`X.Y`), and an exact release
  (`X.Y.Z`). Pin an exact tag in production; do not rely on `latest`.
- **Architectures:** the published manifest covers `linux/amd64` and
  `linux/arm64`.
- The image is distroless and runs as nonroot (uid 65532). The `/data`
  volume is pre-owned so named volumes inherit the right ownership.
- Build locally with `docker build -f packaging/docker/Dockerfile -t kolimi .`.
  The first build compiles the WASM UI and embeds it into the binary; later
  builds reuse BuildKit cache mounts. `docker builder prune` makes the next
  build slow again.
- **Disk:** the Rust `target/` cache and old images can grow to several GB
  on a build host. Inspect with `docker system df -v`; bound the build cache
  with `docker builder prune --keep-storage 6GB` and remove stale images
  with `docker image prune -a`. Application data lives in the
  `kolimi-data` volume, not the build cache.

## Docker Compose with Traefik

A production stack with automatic Let's Encrypt TLS. Traefik discovers
Kolimi through Docker labels; the app publishes no ports directly.

```sh
cd packaging/docker
cp .env.example .env         # set KOLIMI_DOMAIN and ACME_EMAIL
docker compose -f compose.traefik.yaml up -d

# create the first admin inside the container
docker compose -f compose.traefik.yaml exec kolimi \
  kolimi-server user add admin
```

The compose file sets `KOLIMI_ORIGIN=https://$KOLIMI_DOMAIN` and
`KOLIMI_SECURE_COOKIES=true`. **The origin must match the public URL
exactly**, or passkey registration fails. Traefik handles the HTTP→HTTPS
redirect and stores ACME state in a volume; the Docker socket is mounted
read-only for label discovery. `kolimi-data` holds the database and blobs;
back it up as described in [operations.md](operations.md#backup-and-restore).

There is a second, direct-port example in `packaging/docker/compose.yaml`
if you terminate TLS elsewhere.

## Kubernetes (Helm)

```sh
helm install kolimi packaging/helm/kolimi \
  --set origin=https://cloud.example.com \
  --set secureCookies=true \
  --set persistence.size=50Gi \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=cloud.example.com
```

Key values (`packaging/helm/kolimi/values.yaml`): `image.repository/tag`,
`origin` (must be the URL users visit), `secureCookies`, `persistence.*`,
`ingress.*`, `resources`, `extraEnv`. The deployment runs non-root with a
read-only root filesystem, probes `/healthz`, and uses a `Recreate` strategy
(SQLite on a RWO volume).

The chart pulls `ghcr.io/chaitanyayeleti/kolimi:<appVersion>` by default.
To use a custom image:

```sh
docker build -f packaging/docker/Dockerfile -t ghcr.io/you/kolimi:dev .
docker push ghcr.io/you/kolimi:dev
helm upgrade --install kolimi packaging/helm/kolimi \
  --set image.repository=ghcr.io/you/kolimi --set image.tag=dev
```

## Arch Linux (AUR)

```sh
yay -S kolimi-server        # or paru -S kolimi-server
sudoedit /etc/kolimi/kolimi.env
sudo systemctl enable --now kolimi
```

The package builds from the tagged source tarball and installs the systemd
unit, sysusers/tmpfiles entries and the example environment file. The AUR
package is updated by the release workflow on each `v*` tag.

## Debian / Ubuntu (.deb)

Each release attaches a `.deb`. To build one from a checkout:

```sh
./scripts/build-ui.sh
cargo build --release --locked -p kolimi-server -p kolimi-sync
cargo install cargo-deb --locked
cargo deb -p kolimi-server --no-build
sudo dpkg -i target/debian/kolimi-server_*.deb
```

The postinst creates the `kolimi` system user and `/var/lib/kolimi`.
Configure `/etc/kolimi/kolimi.env`, then enable `kolimi.service`.

## Desktop client (Linux)

The native desktop client lives in `apps/kolimi-desktop` (Tauri). It loads
the server's `/app/` UI, adds a tray and background sync, and keeps
credentials in the OS keychain.

Install from AUR:

```sh
yay -S kolimi-desktop       # or paru -S kolimi-desktop
```

Or use the `.deb` / AppImage attached to a **Desktop Release**
(`desktop-v*` tag):

```sh
sudo dpkg -i kolimi-desktop_*.deb
chmod +x kolimi-desktop_*.AppImage && ./kolimi-desktop_*.AppImage
```

Build from source:

```sh
cargo install tauri-cli --version "^2" --locked
cd apps/kolimi-desktop
cargo tauri build --bundles deb      # -> target/release/bundle/
```

On first run the setup window writes `~/.config/kolimi/desktop.json`
(non-secret fields only); the account password and E2EE passphrase go to
the system keychain, with a session-keyring and warned file fallback. See
[operations.md](operations.md#desktop-and-mobile-clients).

## Manual / from source

```sh
git clone https://github.com/chaitanyayeleti/kolimi
cd kolimi

# Build and stage the WASM UI before the server (release embeds it).
./scripts/build-ui.sh

cargo build --release --locked -p kolimi-server -p kolimi-sync
install -Dm755 target/release/kolimi-server ~/.local/bin/kolimi-server
install -Dm755 target/release/kolimi-sync ~/.local/bin/kolimi-sync
```

`build-ui.sh` installs the `wasm32-unknown-unknown` target if needed and the
`wasm-bindgen` CLI version pinned by `Cargo.lock`. A release built without
it serves the placeholder page.

For the CLI OS-keychain backend (Secret Service / Keychain / Credential
Manager), add `--features kolimi-sync/keystore` to the build. Without it,
the CLI uses the `0600` device file fallback.

> **Hardened distros (Arch, Gentoo):** `rustls` pulls in `aws-lc-sys`,
> whose `jitterentropy` RNG must be compiled with `-O0`. If your
> environment forces `-O2` via `CFLAGS` (for example `makepkg`), the build
> fails with a `#error`. Disable that fallback so the OS RNG is used:
> `export AWS_LC_SYS_NO_JITTER_ENTROPY=1`. The AUR package sets this
> automatically.

Run it:

```sh
KOLIMI_DATA=./kolimi-data kolimi-server serve \
  --bind 127.0.0.1:8080 \
  --origin http://localhost:8080
```

Then create the first admin:

```sh
KOLIMI_DATA=./kolimi-data kolimi-server user add admin
```

The full flag and environment table is in [reference.md](reference.md).

## TLS and reverse proxies

**Direct TLS** (no proxy):

```sh
kolimi-server serve \
  --tls-cert /etc/kolimi/tls/cert.pem \
  --tls-key /etc/kolimi/tls/key.pem \
  --secure-cookies \
  --origin https://cloud.example.com
```

**Behind a proxy** (recommended; keep the server on localhost).

Caddy:

```caddy
cloud.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name cloud.example.com;
    client_max_body_size 0;            # no body limit; Kolimi caps itself
    proxy_request_buffering off;       # stream large uploads
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;      # long delta uploads
    }
}
```

Set `KOLIMI_ORIGIN=https://cloud.example.com`,
`KOLIMI_SECURE_COOKIES=true`, and `KOLIMI_TRUST_PROXY=1` when TLS
terminates at a trusted proxy. The origin must match the URL users visit
exactly; WebAuthn binds passkeys to it. `KOLIMI_TRUST_PROXY` makes rate
limits and login lockout use the real client address from
`X-Forwarded-For`.

## First run

1. Open `https://cloud.example.com/app/` (or
   `http://localhost:8080/app/`).
2. Sign in with the admin account. The installer printed the password;
   otherwise create one with `kolimi-server user add admin`.
3. Create the **Vault** passphrase when prompted. Files inside `Vault/` are
   encrypted in the browser before upload; the recovery phrase is shown
   once.
4. Upload a file and try a share. Encrypted folder shares use MLS when both
   clients support it; legacy per-file shares remain readable.
5. Recommended:
   - Register a passkey (toolbar → **Passkeys**) and optionally run
     `kolimi-server user passkey-only <name>`.
   - Enable TOTP and store the recovery codes.
   - Point a WebDAV client at `https://cloud.example.com/dav/`, and
     CalDAV/CardDAV at `/.well-known/caldav` / `/.well-known/carddav`.

## Upgrading

```sh
# 1. Consistent online backup first.
kolimi-server backup --data /var/lib/kolimi --to /backups/kolimi-$(date +%F)

# 2. Stop, replace the binary, start.
sudo systemctl stop kolimi
sudo install -m755 kolimi-server /usr/local/bin/kolimi-server
sudo systemctl start kolimi
```

Docker:

```sh
VERSION=X.Y.Z   # the release you are deploying
docker pull ghcr.io/chaitanyayeleti/kolimi:"$VERSION"
docker stop kolimi && docker rm kolimi
docker run -d --name kolimi \
  -p 127.0.0.1:8080:8080 \
  -v kolimi-data:/data \
  -e KOLIMI_ORIGIN=http://localhost:8080 \
  ghcr.io/chaitanyayeleti/kolimi:"$VERSION"
```

Migrations run automatically at startup and are **forward-only**.
Downgrading across a migration boundary requires restoring the backup. Read
the [CHANGELOG](../CHANGELOG.md) for behavior changes before upgrading, and
verify with `kolimi-server verify --data /var/lib/kolimi` afterwards.

## Uninstalling

```sh
sudo systemctl disable --now kolimi
sudo rm /usr/local/bin/kolimi-server /usr/local/bin/kolimi-sync
sudo rm /usr/lib/systemd/system/kolimi.service
sudo rm -rf /var/lib/kolimi /etc/kolimi   # deletes all data
sudo userdel kolimi
```

Docker: stop/remove the container and delete the `kolimi-data` volume only
when you intend to destroy the data.

For login, quota, E2EE and sync problems see
[operations.md#troubleshooting](operations.md#troubleshooting).
