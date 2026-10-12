# Release & distribution plan

Goal: repeatable, verifiable releases of the single server binary + sync
CLI across every channel we ship: GitHub Releases (tarballs, `.deb`, Helm,
SBOM, signatures), the **container image on GHCR**, **Arch (AUR)**, and
`install.sh`.

## Versioning & trigger

- Semver `vMAJOR.MINOR.PATCH`; an annotated tag `vX.Y.Z` triggers
  `.github/workflows/release.yml`.
- Maintain a `CHANGELOG.md`; GitHub auto-generates release notes from tags.
- Before tagging: `main` is green (all CI jobs), migrations are
  forward-only, the version is bumped in `Cargo.toml`.

## Channels and current status

| Channel | Artifact | Status |
| --- | --- | --- |
| GitHub Releases | gnu/musl/aarch64 tarballs, `.deb`, Helm, CycloneDX SBOM, cosign signatures | **shipped** (v0.1.0–v0.1.2); musl vendors OpenSSL for the `webauthn-rs` → `openssl-sys` edge |
| `.deb` | cargo-deb build (metadata + postinst) | **attached** to each release |
| Container | OCI image on GHCR | **published** (`ghcr.io/chaitanyayeleti/kolimi`); `amd64` today — **arm64 pending** |
| Arch (AUR) | `packaging/arch/PKGBUILD` | **automated**: the `aur` job bumps `pkgver`/`sha256sums` and pushes (gated on the `AUR_SSH_KEY` secret); `kolimi-server` is live |
| Helm | chart (`packaging/helm/kolimi`) | packaged + **attached** on release |
| `install.sh` | one-liner from the release tarball | downloads `latest` (or `--version TAG`), verifies checksum + cosign |

## Pipeline per tag

1. **build** — `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, and
   `aarch64-unknown-linux-gnu` (native arm runner); staged wasm UI, tarball
   + `.deb`, CycloneDX SBOM, cosign.
2. **container** — `docker buildx` build + push to
   `ghcr.io/chaitanyayeleti/kolimi:{vX.Y.Z, X.Y, latest}` (currently `amd64`).
3. **helm** — `helm package` → attached `.tgz`.
4. **publish** — attaches every artifact to the GitHub release.
5. **aur** — bumps `pkgver`/`sha256sums`/`pkgrel` and pushes to
   `aur.archlinux.org/kolimi-server` (gated on `AUR_SSH_KEY`).

## Remaining

- **arm64 container image** — the `build` matrix already produces an
  `aarch64` binary, but the image is `amd64` only. Add a native
  `ubuntu-24.04-arm` image build and merge a multi-arch manifest (do **not**
  build the wasmtime tree under QEMU).
- Optional fast install: a `kolimi-bin` AUR package from the release tarball
  alongside the source-built `kolimi-server`.

## Container specifics

- `linux/amd64` is published (distroless base; the build embeds the WASM
  UI). **arm64** is the remaining work, via a native `ubuntu-24.04-arm`
  runner — building the wasmtime tree under QEMU is far too slow.
- The Helm chart's `image.repository` points at
  `ghcr.io/chaitanyayeleti/kolimi` (tag defaults to the chart appVersion);
  `docker run ghcr.io/…` works without a local build.
- Tags: `vX.Y.Z`, `X.Y`, `latest`.
- CI runners are ephemeral, so the large local build cache is a
  non-issue in CI.

## Arch (AUR)

- `packaging/arch/PKGBUILD` builds from the tagged source tarball; keep a
  `kolimi-server` package (source build) and optionally a `kolimi-bin`
  (from the release tarball) for fast installs.
- Release step: update `pkgver`, `sha256sums`, `pkgrel=1`, push.

## Debian / Ubuntu

- `cargo deb -p kolimi-server --no-build` (metadata + `postinst` already
  create the user and enable the service) → attach the `.deb` to the
  release.
- Later (if demand): a hosted apt repo with a signing key.

## First-release checklist (`v0.1.0`)

- [x] `main` green; version bumped; CHANGELOG written.
- [x] Tag `v0.1.0`; `release.yml` completes.
- [x] Container image published and pullable from GHCR.
- [x] `.deb` installs and creates the `kolimi` user + systemd unit.
- [x] AUR `PKGBUILD` updated and pushed (automated via `AUR_SSH_KEY`).
- [x] `install.sh` one-liner verified against the tag.
- [x] Helm chart points at the published image.

Releases since: **v0.1.1** (musl/aarch64 tarballs + AUR automation),
**v0.1.2** (web admin panel).

## Cadence

- **Patch** releases as needed. **Minor** releases per milestone (the next
  feature release is M8 / MLS groups). **Major** only for breaking
  protocol or migration changes.
