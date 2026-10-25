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

# 3. Keep known stale claims out of current-facing guides. Historical files
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
    ],
    "docs/architecture.md": [
        "14 crates",
        "does not link the crypto crate",
    ],
    "docs/known-advisories.md": [
        "Both entries below",
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
