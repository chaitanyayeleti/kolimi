# Installing Kolimi

Kolimi ships as a single server binary. Pick whichever deployment
matches your environment; all of them run the same program.

- [One-command install (systemd host)](#one-command-install)
- [Arch Linux (AUR)](#arch-linux-aur)
- [Debian / Ubuntu (.deb)](#debian--ubuntu-deb)
- [Docker / Podman](#docker--podman)
- [Docker Compose with Traefik (automatic HTTPS)](#docker-compose-with-traefik)
- [Kubernetes (Helm)](#kubernetes-helm)
- [Manual / from source](#manual--from-source)
- [TLS and reverse proxies](#tls-and-reverse-proxies)
- [First run](#first-run)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

## Requirements

- Linux (x86_64; aarch64 builds from source). Kernels with Landlock
  (5.13+) get the strongest preview sandbox; older kernels fall back to
  seccomp + rlimits only.
- ~50 MB disk for the binary; data grows with your files.
- No database server, no Redis, no PHP: SQLite (WAL) and the filesystem
  are embedded.

## One-command install

For a systemd host (VPS, home server, Raspberry Pi). Downloads the
signed release, verifies the checksum (and cosign signature when
`cosign` is installed), installs `kolimi-server` + `kolimi-sync`,
creates the admin account and prints the generated password once:

```sh
curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
```

Useful flags:

```sh
./install.sh \
  --prefix /usr/local \        # where binaries go
  --data-dir /var/lib/kolimi \ # server state
  --admin alice \              # first admin username
  --password '…' \             # skip the generated password
  --version v0.1.0 \           # pin a release
  --no-systemd                 # containers / non-systemd hosts
```

Then install the systemd unit template + env file and enable it:

```sh
sudo install -Dm644 packaging/systemd/kolimi.service /etc/systemd/system/kolimi.service
sudo install -Dm644 packaging/systemd/kolimi.env.example /etc/kolimi/kolimi.env
sudoedit /etc/kolimi/kolimi.env     # set KOLIMI_ORIGIN to your URL
sudo systemctl daemon-reload
sudo systemctl enable --now kolimi
```

If you only used the one-liner (no local checkout), fetch the same
files from GitHub first:

```sh
sudo install -d /etc/kolimi
sudo curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/packaging/systemd/kolimi.service \
  -o /etc/systemd/system/kolimi.service
sudo curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/packaging/systemd/kolimi.env.example \
  -o /etc/kolimi/kolimi.env
```

## Arch Linux (AUR)

```sh
git clone https://aur.archlinux.org/kolimi-server.git
cd kolimi-server && makepkg -si
sudoedit /etc/kolimi/kolimi.env
sudo systemctl enable --now kolimi
```

The package builds from source and installs the systemd unit,
sysusers/tmpfiles entries, and the example environment file. The
PKGBUILD lives in `packaging/arch/PKGBUILD` in the repository.

## Debian / Ubuntu (.deb)

The release job builds a `.deb`; you can also build one locally:

```sh
cargo install cargo-deb --locked
cargo build --release -p kolimi-server -p kolimi-sync
cargo deb -p kolimi-server --no-build
sudo dpkg -i target/debian/kolimi-server_*.deb
```

The postinst creates the `kolimi` system user and `/var/lib/kolimi`.
Enable the unit as usual (`/etc/kolimi/kolimi.env`).

## Docker / Podman

```sh
docker build -f packaging/docker/Dockerfile -t kolimi .
docker run -d --name kolimi \
  -p 127.0.0.1:8080:8080 \
  -v kolimi-data:/data \
  -e KOLIMI_ORIGIN=http://localhost:8080 \
  kolimi
```

- The image is distroless and runs as nonroot (uid 65532); the `/data`
  volume is pre-owned so named volumes inherit the right ownership.
- The build compiles the web UI to WebAssembly and embeds it in the
  binary, so the first `docker build` is slow (it installs
  `wasm-bindgen-cli` and builds `kolimi-ui`). Later builds reuse
  BuildKit cache mounts for the cargo registry and target directory, so
  only changed crates recompile — expect seconds to a couple of minutes.
  Keep this in mind if you use `--no-cache` (it still reuses the cache
  mounts, so it stays fast) or `docker builder prune` (clears them; the
  next build is slow again).
- **Disk:** those cache mounts (the Rust `target/` in particular) can grow
  to several GB, and each rebuild can leave old images behind. On a small
  host this adds up. Inspect with `docker system df -v` and bound the cache
  with `docker builder prune --keep-storage 6GB` (keeps recent layers, frees
  the rest) plus `docker image prune -a` for stale images. Wiping the cache
  entirely makes the next build slow again, so prefer `--keep-storage`.
- Compose examples: `packaging/docker/compose.yaml` (direct port) and
  `packaging/docker/compose.traefik.yaml` (TLS via Traefik, below).
- Create the first admin inside the container:

```sh
docker exec kolimi kolimi-server user add admin --password '…'
```

Podman works identically (`podman build`, `podman run`).

## Docker Compose with Traefik

A production-ready stack: Traefik terminates TLS with an automatic
Let's Encrypt certificate (TLS challenge), Kolimi is discovered through
Docker labels, and the app publishes no ports at all.

```sh
cd packaging/docker
cp .env.example .env         # set KOLIMI_DOMAIN and ACME_EMAIL
docker compose -f compose.traefik.yaml up -d

# create the first admin inside the container
docker compose -f compose.traefik.yaml exec kolimi \
  kolimi-server user add admin
```

What the compose file sets up:

- `KOLIMI_ORIGIN=https://$KOLIMI_DOMAIN` and
  `KOLIMI_SECURE_COOKIES=true` — **the origin must match the public URL
  exactly**, or passkey registration will fail.
- HTTP→HTTPS redirect on port 80; the ACME account and certificates live
  in the `traefik-acme` volume.
- The Docker socket is mounted read-only (Traefik only watches labels).
- `kolimi-data` holds the database and blobs; back it up as described in
  [operations.md](operations.md#backup-and-restore).

`/metrics` is **admin-only inside the app**: a signed-in administrator can
open `https://$KOLIMI_DOMAIN/metrics` directly (no separate credential),
and a scraper authenticates with HTTP Basic using an admin's username and
password. Non-admins get `403`. No proxy middleware is required.

Requirements: DNS for `KOLIMI_DOMAIN` already pointing at the host, and
ports 80/443 reachable (the TLS challenge needs port 443). WebDAV,
CalDAV, the JSON API, `/app`, `/plugins`, and public links all share the
same host rule — no extra routing needed.

Running Traefik outside Compose works the same way; point its Docker
provider at this container and give Kolimi the labels above
(`traefik.http.routers.kolimi.*`). If you prefer file-based Traefik
configuration, the equivalent dynamic config is a router with
`rule: Host(`cloud.example.com`)`, `entryPoints: [websecure]`,
`tls.certResolver: le`, and a service pointing at `kolimi:8080`.

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
`origin` (must be the URL users visit — passkeys depend on it),
`secureCookies`, `persistence.*`, `ingress.*`, `resources`, `extraEnv`.
The deployment runs non-root with a read-only root filesystem, probes
`/healthz`, and uses a `Recreate` strategy (SQLite on a RWO volume).

Build and push the image first, e.g.:

```sh
docker build -f packaging/docker/Dockerfile -t ghcr.io/you/kolimi:0.1.0 .
docker push ghcr.io/you/kolimi:0.1.0
```

## Manual / from source

```sh
git clone https://github.com/chaitanyayeleti/kolimi
cd kolimi
cargo build --release --locked -p kolimi-server -p kolimi-sync
install -Dm755 target/release/kolimi-server ~/.local/bin/kolimi-server
install -Dm755 target/release/kolimi-sync ~/.local/bin/kolimi-sync
```

Run it (all flags also have environment variables):

```sh
KOLIMI_DATA=./kolimi-data kolimi-server serve \
  --bind 127.0.0.1:8080 \
  --origin http://localhost:8080
```

| Flag | Env | Default |
| --- | --- | --- |
| `--bind` | `KOLIMI_BIND` | `127.0.0.1:8080` |
| `--data` | `KOLIMI_DATA` | `./kolimi-data` |
| `--origin` | `KOLIMI_ORIGIN` | `http://localhost:8080` |
| `--tls-cert` | `KOLIMI_TLS_CERT` | — |
| `--tls-key` | `KOLIMI_TLS_KEY` | — |
| `--secure-cookies` | `KOLIMI_SECURE_COOKIES` | off |
| trust proxy IPs | `KOLIMI_TRUST_PROXY` | off |
| default per-user storage quota (bytes) | `KOLIMI_USER_QUOTA_BYTES` | `0` (unlimited) |
| log level | `RUST_LOG` | `info` |

Set `KOLIMI_TRUST_PROXY=1` when running behind a reverse proxy (the
sample Traefik stack does) so per-client rate limiting and login lockout
use the real client address from `X-Forwarded-For` rather than the
proxy's IP.

## TLS and reverse proxies

**Direct TLS** (no proxy):

```sh
kolimi-server serve --tls-cert /etc/kolimi/tls/cert.pem \
  --tls-key /etc/kolimi/tls/key.pem --secure-cookies
```

**Behind a proxy** (recommended; the server stays on localhost).
Traefik users can jump to
[Docker Compose with Traefik](#docker-compose-with-traefik); the
snippets below cover Caddy and nginx.

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

Set `KOLIMI_ORIGIN=https://cloud.example.com` and
`KOLIMI_SECURE_COOKIES=true` when TLS terminates at the proxy.
`KOLIMI_ORIGIN` must exactly match the URL users visit — WebAuthn
(passkeys) binds to it.

## First run

1. Open `https://cloud.example.com/app/` (or `http://localhost:8080/app/`).
2. Sign in with the admin account (`install.sh` printed the password;
   otherwise create one with `kolimi-server user add admin`).
3. Upload something, then share it: the share dialog creates a public
   link with a generated password and a 30-day expiry by default.
4. Optional but recommended:
   - Register a passkey (toolbar → **Passkeys**) and then run
     `kolimi-server user passkey-only <name>` to drop the password.
   - Enable TOTP (same dialog) and store the recovery codes.
   - Point a WebDAV client (rclone, davfs2, Finder) at
     `https://cloud.example.com/dav/`.
   - CalDAV/CardDAV discovery works from the bare domain
     (`/.well-known/caldav`, `/.well-known/carddav`).

## Upgrading

```sh
# 1. back up first (online, safe)
kolimi-server backup --data /var/lib/kolimi --to /backups/kolimi-$(date +%F)

# 2. replace the binary and restart
sudo systemctl stop kolimi
sudo install -m755 kolimi-server /usr/local/bin/kolimi-server
sudo systemctl start kolimi
```

Database migrations run automatically at startup and are forward-only;
downgrading across a migration boundary requires restoring the backup.

## Uninstalling

```sh
sudo systemctl disable --now kolimi
sudo rm /usr/local/bin/kolimi-server /usr/local/bin/kolimi-sync
sudo rm /usr/lib/systemd/system/kolimi.service
sudo rm -rf /var/lib/kolimi /etc/kolimi   # deletes all data
sudo userdel kolimi
```
