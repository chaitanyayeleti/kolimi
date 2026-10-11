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
| GitHub Releases | gnu + musl tarballs, CycloneDX SBOM, cosign signatures | **exists** (`release.yml`) |
| `.deb` | cargo-deb build (metadata + postinst exist) | built in the CI `packaging` job, **not attached to releases** → add to `release.yml` |
| Container | OCI image | built locally only, **never published** → add buildx push to GHCR |
| Arch (AUR) | `packaging/arch/PKGBUILD` | exists; `pkgver`/`sha256sums` updated by hand → automate |
| Helm | chart (`packaging/helm/kolimi`) | exists; package + attach on release |
| `install.sh` | one-liner from the release tarball | exists; point it at the new tag |

## Pipeline per tag (target state)

1. **build** (existing, extended) — `x86_64-unknown-linux-gnu` + `musl`,
   staged wasm UI, then package tarball + `.deb`, emit SBOM, cosign-sign.
2. **container** (new) — `docker buildx` multi-arch (`amd64`, `arm64`),
   push `ghcr.io/chaitanyayeleti/kolimi:{vX.Y.Z, X.Y, latest}`.
3. **helm** (new) — `helm package` → attach `.tgz`.
4. **publish** (existing) — attach every artifact to the GitHub release.
5. **aur** (optional) — bump `pkgver`/`sha256sums`/`pkgrel` and push to
   `aur.archlinux.org/kolimi-server` (needs an AUR SSH-key secret); until
   then, a documented manual step.

## Container specifics

- Multi-arch via buildx + QEMU, distroless base (the build already embeds
  the WASM UI).
- Publishing to GHCR makes the Helm chart's `image.repository` real
  (currently a placeholder) and lets users `docker run ghcr.io/…`.
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

- [ ] `main` green; version bumped; CHANGELOG written.
- [ ] Tag `v0.1.0`; `release.yml` completes.
- [ ] Container image published and pullable from GHCR.
- [ ] `.deb` installs and creates the `kolimi` user + systemd unit.
- [ ] AUR `PKGBUILD` updated and pushed.
- [ ] `install.sh` one-liner verified against the tag.
- [ ] Helm chart points at the published image.

## Cadence

- **Patch** releases as needed. **Minor** releases per milestone (the next
  feature release is M8 / MLS groups). **Major** only for breaking
  protocol or migration changes.
