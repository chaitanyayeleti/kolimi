#!/usr/bin/env bash
# Documentation guardrails: relative links, RFC index completeness, and a
# small set of claims that went stale in 0.1/0.2 docs. Run in CI and before
# changing user-facing docs.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re
import sys
from pathlib import Path

root = Path(".").resolve()
files = [root / "README.md", root / "ROADMAP.md", root / "CHANGELOG.md", root / "AGENTS.md"]
files += sorted((root / "docs").rglob("*.md"))

problems = []

# 1. Relative markdown links must resolve. Skip fenced code blocks.
link_re = re.compile(r'(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
for path in files:
    if not path.exists():
        problems.append(f"missing doc: {path.relative_to(root)}")
        continue
    in_fence = False
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for match in link_re.finditer(line):
            link = match.group(1)
            if link.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = link.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                problems.append(
                    f"{path.relative_to(root)}:{lineno}: broken link {link!r}"
                )

# 2. Every RFC must be present in the RFC index and carry a Status line.
rfc_dir = root / "docs" / "rfc"
rfc_index = (rfc_dir / "README.md").read_text(encoding="utf-8")
for rfc in sorted(rfc_dir.glob("[0-9][0-9][0-9][0-9]-*.md")):
    if rfc.name not in rfc_index:
        problems.append(f"docs/rfc/README.md: missing {rfc.name}")
    text = rfc.read_text(encoding="utf-8")
    if "Status:" not in text and "**Status:**" not in text:
        problems.append(f"{rfc.relative_to(root)}: no Status line")

# 3. Release-facing docs must match the workspace version. This catches the
#    common failure mode where a release is tagged but the roadmap, RFC index,
#    packaging defaults, or changelog still name the previous version.
cargo_text = (root / "Cargo.toml").read_text(encoding="utf-8")
version_match = re.search(r'^version = "([^"]+)"', cargo_text, re.MULTILINE)
if not version_match:
    problems.append("Cargo.toml: cannot read [workspace.package] version")
    version = None
else:
    version = version_match.group(1)

if version:
    release_needles = {
        "ROADMAP.md": f"Current release: **{version}**",
        "CHANGELOG.md": f"## [{version}]",
        "docs/README.md": f"Last full verification: **{version}**",
        "docs/rfc/README.md": f"Last full verification: **{version}**",
        "packaging/docker/compose.yaml": f"kolimi:{version}",
        "packaging/docker/compose.traefik.yaml": f"kolimi:{version}",
        "packaging/docker/.env.example": f"kolimi:{version}",
        "packaging/helm/kolimi/Chart.yaml": f"version: {version}",
    }
    for name, needle in release_needles.items():
        path = root / name
        if not path.exists():
            problems.append(f"missing release doc: {name}")
        elif needle not in path.read_text(encoding="utf-8"):
            problems.append(f"{name}: missing current version {needle!r}")

    rfc_needle = f"Last verified: {version}"
    for rfc in sorted(rfc_dir.glob("*.md")):
        text = rfc.read_text(encoding="utf-8")
        if "Last verified:" in text and rfc_needle not in text:
            problems.append(f"{rfc.relative_to(root)}: {rfc_needle!r} not found")

    chart = (root / "packaging/helm/kolimi/Chart.yaml").read_text(encoding="utf-8")
    if f'appVersion: "{version}"' not in chart:
        problems.append("packaging/helm/kolimi/Chart.yaml: appVersion is stale")

# 4. Keep known stale claims out of current-facing guides. Historical files
#    (CHANGELOG, ROADMAP history, RFC bodies) are intentionally not checked.
stale = {
    "README.md": [
        "next milestone (MLS",
        "v0.1.0",
        "Images are `linux/amd64`",
        "14 crates",
    ],
    "docs/install.md": [
        "v0.1.0",
        "Images are `linux/amd64`",
        "wasm37",
    ],
    "docs/operations.md": [
        "Not implemented: MLS",
        "tray.json",
        "Single-file MLS shares are read-only",
        "Write shares are folder-only",
    ],
    "docs/reference.md": [
        "Single-file MLS shares are read-only",
    ],
    "docs/architecture.md": [
        "14 crates",
        "does not link the crypto crate",
    ],
    "docs/known-advisories.md": [
        "Both entries below",
    ],
    "ROADMAP.md": [
        "Next milestone: 0.4.5",
    ],
    "docs/plans/clients.md": [
        "released on **F-Droid**",
        "Phase 2 (mobile) is next",
    ],
    "docs/plans/android.md": [
        "Android app released on **F-Droid**",
    ],
}
for name, needles in stale.items():
    path = root / name
    if not path.exists():
        problems.append(f"missing current doc: {name}")
        continue
    text = path.read_text(encoding="utf-8")
    for needle in needles:
        if needle in text:
            problems.append(f"{name}: stale text {needle!r}")

if problems:
    print("documentation checks failed:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    sys.exit(1)

print(f"docs ok ({len(files)} files, relative links + RFC index + stale-claim checks)")
PY
