#!/usr/bin/env bash
# Bundles everything an external reviewer needs into one tarball.
set -euo pipefail
cd "$(dirname "$0")/.."

commit="$(git rev-parse HEAD)"
short="$(git rev-parse --short HEAD)"
out="target/audit"
name="kolimi-audit-$short"
mkdir -p "$out/$name"

for f in docs/rfc/0007-e2ee.md docs/crypto-review.md docs/threat-model.md \
    docs/audit/README.md; do
    [ -f "$f" ] || { echo "error: missing $f" >&2; exit 1; }
    cp "$f" "$out/$name/"
done
mkdir -p "$out/$name/vectors"
for f in crates/kolimi-crypto/tests/vectors.json crates/kolimi-crypto/examples/gen_vectors.rs; do
    [ -f "$f" ] || { echo "error: missing $f" >&2; exit 1; }
    cp "$f" "$out/$name/vectors/"
done
[ -f fuzz/fuzz_targets/e2ee_decrypt.rs ] || { echo "error: missing fuzz/fuzz_targets/e2ee_decrypt.rs" >&2; exit 1; }
cp fuzz/fuzz_targets/e2ee_decrypt.rs "$out/$name/"
printf 'commit: %s\n' "$commit" > "$out/$name/COMMIT"
printf 'commit: %s\n' "$commit" > "$out/COMMIT"

tar -C "$out" -czf "$out/$name.tar.gz" "$name"
rm -rf "$out/$name"
echo "wrote $out/$name.tar.gz (commit $commit)"
