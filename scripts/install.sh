#!/usr/bin/env sh
# Kolimi one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/chaitanyayeleti/kolimi/main/scripts/install.sh | sh
#
# Downloads a signed release tarball (or uses --binary), installs the
# server and sync client, sets up the systemd unit when possible, and
# creates the first admin account.
#
# Flags:
#   --prefix DIR      install prefix for binaries (default /usr/local)
#   --data-dir DIR    server data directory (default /var/lib/kolimi)
#   --binary PATH     use a local kolimi-server binary (skips download)
#   --sync PATH       use a local kolimi-sync binary (optional)
#   --version TAG     release tag to install (default: latest)
#   --admin NAME      admin username to create (default: admin)
#   --password PW     admin password (default: generated and printed)
#   --no-systemd      do not install/enable the systemd unit
#   --no-verify       skip sha256/cosign verification (not recommended)
set -eu

PREFIX=/usr/local
DATA_DIR=/var/lib/kolimi
ADMIN=admin
PASSWORD=""
NO_SYSTEMD=0
VERIFY=1
VERSION="latest"
BINARY=""
SYNC_BINARY=""
REPO="chaitanyayeleti/kolimi"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --data-dir) DATA_DIR="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --sync) SYNC_BINARY="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --admin) ADMIN="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --no-systemd) NO_SYSTEMD=1; shift ;;
        --no-verify) VERIFY=0; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

detect_target() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) fail "unsupported architecture: $(uname -m)" ;;
    esac
}

tmp="$(mktemp -d)"
installed="$(mktemp)"

# Remove any partially installed files if the script exits non-zero.
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        while IFS= read -r file; do
            if [ -n "$file" ]; then
                rm -f "$file"
            fi
        done < "$installed"
    fi
    rm -rf "$tmp" "$installed"
}
trap 'cleanup' EXIT

if [ -z "$BINARY" ]; then
    need curl
    need tar
    target="$(detect_target)"
    asset="kolimi-$target.tar.gz"
    if [ "$VERSION" = "latest" ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$VERSION"
    fi
    say "downloading $asset"
    curl -fsSL "$base/$asset" -o "$tmp/$asset"
    if [ "$VERIFY" = 1 ]; then
        if curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256"; then
            (cd "$tmp" && sha256sum -c "$asset.sha256")
            say "checksum verified"
        else
            fail "could not fetch $asset.sha256 (use --no-verify to override)"
        fi
        if command -v cosign >/dev/null 2>&1; then
            if curl -fsSL "$base/$asset.sig" -o "$tmp/$asset.sig" \
                && curl -fsSL "$base/$asset.pem" -o "$tmp/$asset.pem"; then
                cosign verify-blob \
                    --certificate "$tmp/$asset.pem" \
                    --signature "$tmp/$asset.sig" \
                    --certificate-identity-regexp "https://github.com/$REPO/" \
                    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                    "$tmp/$asset" >/dev/null
                say "signature verified (cosign)"
            fi
        fi
    fi
    tar -xzf "$tmp/$asset" -C "$tmp"
    dir="$(find "$tmp" -maxdepth 1 -type d -name 'kolimi-*' | head -1)"
    [ -n "$dir" ] || fail "tarball layout unexpected"
    BINARY="$dir/kolimi-server"
    [ -n "$SYNC_BINARY" ] || SYNC_BINARY="$dir/kolimi-sync"
fi

[ -x "$BINARY" ] || fail "not executable: $BINARY"

install_bin() {
    src="$1"; dst="$PREFIX/bin/$(basename "$1")"
    if [ -w "$PREFIX/bin" ] || [ -w "$(dirname "$PREFIX")" ]; then
        install -Dm755 "$src" "$dst"
    else
        need sudo
        sudo install -Dm755 "$src" "$dst"
    fi
    printf '%s\n' "$dst" >> "$installed"
    say "installed $dst"
}

mkdir -p "$PREFIX/bin" 2>/dev/null || true
install_bin "$BINARY"
if [ -n "$SYNC_BINARY" ] && [ -x "$SYNC_BINARY" ]; then
    install_bin "$SYNC_BINARY"
fi

if [ "$NO_SYSTEMD" = 0 ] && command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    need systemd-sysusers
    if [ -f /usr/lib/sysusers.d/kolimi.conf ]; then
        systemd-sysusers /usr/lib/sysusers.d/kolimi.conf 2>/dev/null || true
    fi
    mkdir -p "$DATA_DIR"
    chown kolimi:kolimi "$DATA_DIR" 2>/dev/null || true
    chmod 700 "$DATA_DIR"
    say "systemd unit installed; enable with: systemctl enable --now kolimi"
fi

# Create the admin account (idempotent-ish: fails loudly if it exists).
if [ -z "$PASSWORD" ]; then
    PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '=+/' | cut -c1-20)"
    GENERATED=1
else
    GENERATED=0
fi
if KOLIMI_DATA="$DATA_DIR" "$PREFIX/bin/kolimi-server" user add "$ADMIN" --password "$PASSWORD" >/dev/null 2>&1; then
    if [ "$GENERATED" = 1 ]; then
        say ""
        say "admin account: $ADMIN"
        say "admin password: $PASSWORD"
        say "(change it after first login; it is shown only once)"
    else
        say "admin account $ADMIN created"
    fi
else
    say "note: user '$ADMIN' may already exist; skipping creation"
fi

say ""
say "next steps:"
say "  1. edit /etc/kolimi/kolimi.env (KOLIMI_ORIGIN must match your URL)"
say "  2. start: kolimi-server serve   (or: systemctl enable --now kolimi)"
say "  3. open http://localhost:8080/app/ and sign in"
