#!/usr/bin/env bash
# Updates packaging/arch/PKGBUILD for a release version and its source
# checksum. .SRCINFO is generated separately (make; needs makepkg).
#
#   scripts/aur-bump.sh 0.1.1
set -euo pipefail

ver="${1:?usage: aur-bump.sh <version>  (e.g. 0.1.1)}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

url="https://github.com/chaitanyayeleti/kolimi/archive/refs/tags/v${ver}.tar.gz"
echo "fetching $url"
tmp="$(mktemp)"
curl -fsSL "$url" -o "$tmp"
sum="$(sha256sum "$tmp" | awk '{print $1}')"
rm -f "$tmp"

pkgbuild="packaging/arch/PKGBUILD"
sed -i "s/^pkgver=.*/pkgver=${ver}/" "$pkgbuild"
sed -i "s/^pkgrel=.*/pkgrel=1/" "$pkgbuild"
sed -i "s/^sha256sums=.*/sha256sums=('${sum}')/" "$pkgbuild"

# Verify the sed commands actually modified the file
grep -q "^pkgver=${ver}$" "$pkgbuild" || { echo "error: pkgver not updated" >&2; exit 1; }
grep -q "^pkgrel=1$" "$pkgbuild" || { echo "error: pkgrel not updated" >&2; exit 1; }
grep -q "^sha256sums=('${sum}')$" "$pkgbuild" || { echo "error: sha256sums not updated" >&2; exit 1; }

echo "PKGBUILD updated: pkgver=${ver} sha256sums=('${sum}')"
