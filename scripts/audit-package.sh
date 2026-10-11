#!/usr/bin/env bash
# Bundles everything an external reviewer needs into one tarball.
set -euo pipefail
cd "$(dirname "$0")/.."

commit="$(git rev-parse HEAD)"
short="$(git rev-parse --short HEAD)"
out="target/audit"
name="kolimi-audit-$short"
mkdir -p "$out/$name"

cp docs/rfc/0007-e2ee.md docs/crypto-review.md docs/threat-model.md \
    docs/audit/README.md "$out/$name/"
mkdir -p "$out/$name/vectors"
cp crates/kolimi-crypto/tests/vectors.json crates/kolimi-crypto/examples/gen_vectors.rs \
    "$out/$name/vectors/"
cp fuzz/fuzz_targets/e2ee_decrypt.rs "$out/$name/"
printf 'commit: %s\n' "$commit" > "$out/$name/COMMIT"
printf 'commit: %s\n' "$commit" > "$out/COMMIT"

tar -C "$out" -czf "$out/$name.tar.gz" "$name"
rm -rf "$out/$name"
echo "wrote $out/$name.tar.gz (commit $commit)"
