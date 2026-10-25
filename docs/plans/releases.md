# Release and distribution

Kolimi releases are tag-driven. A server release and a desktop release are
separate workflows but should be tagged together when both changed.

## Versioning and tags

- Semantic versioning: `vMAJOR.MINOR.PATCH` (for example `v0.3.0`).
- Server/CLI/container/Helm/AUR: tag **`vX.Y.Z`** →
  `.github/workflows/release.yml`.
- Desktop app: tag **`desktop-vX.Y.Z`** →
  `.github/workflows/desktop-release.yml`.
- For a paired release, both tags point at the same commit. Push both.
- Never move or re-create a published tag; ship a new patch instead.

## Channels

| Channel | Artifact | Built by |
| --- | --- | --- |
| GitHub Releases | gnu/musl/aarch64 tarballs, `.deb`, Helm chart, CycloneDX SBOM, cosign signatures | `release.yml` |
| GHCR | `ghcr.io/chaitanyayeleti/kolimi:{X.Y.Z, X.Y, latest}`, `linux/amd64` + `linux/arm64` | `release.yml` |
| Helm | chart tarball, `version`/`appVersion` set from the tag | `release.yml` |
| AUR | `kolimi-server` source package (PKGBUILD + `.SRCINFO`) | `release.yml`, gated on `AUR_SSH_KEY` |
| One-command installer | `scripts/install.sh` downloads the release tarball and verifies it | `install.sh` against the tag |
| Desktop | `.deb` + AppImage, AUR `kolimi-desktop` | `desktop-release.yml` |

## Server release pipeline (`v*`)

1. **build** — `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-gnu` (native arm runner). Stages the WASM UI
   first, builds `kolimi-server` + `kolimi-sync`, packages tarballs, builds
   the x86_64 `.deb`, emits a CycloneDX SBOM and signs the tarballs with
   cosign (keyless).
2. **container** — builds amd64 and arm64 images by digest and merges them
   into one manifest with the `X.Y.Z`, `X.Y` and `latest` tags.
3. **helm** — sets chart `version`/`appVersion` from the tag and packages
   the chart.
4. **publish** — attaches binaries, `.deb`, Helm chart, SBOMs and
   signatures to the GitHub release.
5. **aur** — updates `pkgver`, `pkgrel`, `sha256sums` and `.SRCINFO` and
   pushes to `aur.archlinux.org/kolimi-server` (skipped when the secret is
   absent).

## Desktop release pipeline (`desktop-v*`)

1. Checks the desktop lockfile with
   `cargo metadata --locked --manifest-path apps/kolimi-desktop/Cargo.toml`.
2. Builds `.deb` and AppImage bundles with Tauri and attaches them to a
   GitHub release.
3. Updates the `kolimi-desktop` AUR package when `AUR_SSH_KEY` is present.

The desktop client has its own workspace and lockfile; it is not built by
the server workspace.

## Version bump checklist

Before tagging:

- [ ] `main` is green: CI, supply-chain, fuzz, litmus, packaging, desktop.
- [ ] `CHANGELOG.md` has an entry for the version.
- [ ] `[workspace.package] version` and every `version =` in
      `[workspace.dependencies]` are bumped in the root `Cargo.toml`
      (including `crates/kolimi-store`'s `kolimi-chunk`).
- [ ] Root lockfile refreshed: `cargo update -w`.
- [ ] Desktop bumped in `apps/kolimi-desktop/Cargo.toml` and
      `tauri.conf.json`, then `cargo update -w` in that directory.
- [ ] `fuzz/Cargo.lock` refreshed if workspace package versions changed.
- [ ] `packaging/docker/compose.yaml`, `packaging/docker/.env.example` and
      `packaging/helm/kolimi/Chart.yaml` show the new version.
- [ ] AUR PKGBUILDs: the release jobs bump `pkgver`/checksums in the tagged
      copy (server `packaging/arch`, desktop `packaging/aur/kolimi-desktop`).
      No manual edit is required for a release; update them only when testing
      a local package build.
- [ ] `scripts/check-docs.sh` passes and install examples do not pin an
      old release.
- [ ] “Last verified” in `docs/README.md` and `docs/rfc/README.md` matches
      the release being tagged.
- [ ] A backup/restore and upgrade path was tested for any new migration;
      migrations are forward-only.

## Tag and verify

```sh
git tag -a vX.Y.Z -m "Kolimi vX.Y.Z"
git tag -a desktop-vX.Y.Z -m "Kolimi Desktop vX.Y.Z"
git push origin vX.Y.Z desktop-vX.Y.Z
```

Then verify:

- [ ] Both workflows completed successfully.
- [ ] The GitHub release has the expected tarballs, `.deb`, Helm chart,
      SBOM and signatures.
- [ ] `ghcr.io/chaitanyayeleti/kolimi:X.Y.Z` pulls on amd64 and arm64 and
      reports the right `/version`.
- [ ] The Helm chart `appVersion` matches the image tag.
- [ ] The AUR package points at the new tag and its checksum matches.
- [ ] `install.sh --version vX.Y.Z` installs and starts a working server.
- [ ] A desktop `.deb`/AppImage starts and can sign in.

## Rollback

Migrations are forward-only. Rolling a server back across a migration
requires restoring the pre-upgrade backup, not just replacing the binary.
Do not retag a failed release; fix forward with a patch release and note
the problem in `CHANGELOG.md`.

## Secrets

- `GITHUB_TOKEN` is provided by Actions (release assets, GHCR).
- `AUR_SSH_KEY` enables the AUR jobs; without it they are skipped.
- cosign uses GitHub OIDC keyless signing; no long-lived signing key is
  stored in the repository.
