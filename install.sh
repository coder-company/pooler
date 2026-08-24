#!/usr/bin/env bash
# Pooler installer — Coder Company
# https://github.com/coder-company/pooler
#
# System install (default, needs root):
#   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | sudo bash
#
# User install (no root):
#   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash -s -- --user
#
# This installs the `pooler` binary only. To run Pooler as a hardened systemd
# service, run scripts/install-system-pooler.sh from a release archive after
# this script completes.

set -Eeuo pipefail

REPO="coder-company/pooler"
SYSTEM_DIR=/usr/local/bin
USER_DIR="${HOME}/.local/bin"
INSTALL_DIR=""
MODE=system
VERSION="${POOLER_VERSION:-}"

usage() {
    cat >&2 <<'EOF'
usage: install.sh [options]

Install the Pooler binary.

Options:
  --user             Install to ~/.local/bin instead of /usr/local/bin.
  --dir DIRECTORY    Install to an explicit absolute directory.
  --version VERSION  Install an exact version (default: latest release).
  -h, --help         Show this help.
EOF
    exit 2
}

die() {
    printf 'pooler installer: %s\n' "$1" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

while (($# > 0)); do
    case "$1" in
        --user) MODE=user; shift ;;
        --dir) (($# >= 2)) || usage; MODE=explicit; INSTALL_DIR=$2; shift 2 ;;
        --version) (($# >= 2)) || usage; VERSION=$2; shift 2 ;;
        -h|--help) usage ;;
        *) die "unknown option: $1" ;;
    esac
done

case "$MODE" in
    system) INSTALL_DIR=$SYSTEM_DIR ;;
    user) INSTALL_DIR=$USER_DIR ;;
    explicit) [[ "$INSTALL_DIR" = /* ]] || die '--dir must be an absolute path' ;;
esac

need curl
need tar
need uname

detect_target() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Linux)
            case "$arch" in
                x86_64|amd64) printf 'x86_64-unknown-linux-gnu\n' ;;
                aarch64|arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
                *) die "unsupported Linux architecture: $arch" ;;
            esac
            ;;
        Darwin)
            case "$arch" in
                x86_64) printf 'x86_64-apple-darwin\n' ;;
                arm64|aarch64) printf 'aarch64-apple-darwin\n' ;;
                *) die "unsupported macOS architecture: $arch" ;;
            esac
            ;;
        *) die "unsupported operating system: $os" ;;
    esac
}

# The release workflow publishes `pooler-<version>-<target>.tar.gz` assets plus
# a signed SHA256SUMS manifest, so the exact version must be known before a
# download URL can be built.
resolve_latest_version() {
    local api="https://api.github.com/repos/$REPO/releases/latest"
    local tag
    tag=$(curl -fsSL "$api" |
        sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
        head -n 1)
    [[ -n "$tag" ]] || die "could not resolve the latest release tag from $api"
    printf '%s\n' "${tag#v}"
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf '\n'
    fi
}

target=$(detect_target)
printf '==> target: %s\n' "$target"

if [[ -z "$VERSION" ]]; then
    printf '==> resolving latest release\n'
    VERSION=$(resolve_latest_version)
fi
VERSION=${VERSION#v}
printf '==> version: %s\n' "$VERSION"

package="pooler-$VERSION-$target"
base="https://github.com/$REPO/releases/download/v$VERSION"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM

printf '==> downloading %s.tar.gz\n' "$package"
curl -fsSL "$base/$package.tar.gz" -o "$work/$package.tar.gz" ||
    die "could not download $base/$package.tar.gz (check that v$VERSION publishes a $target asset)"

# The manifest is published alongside the archives. Verify when both the
# manifest and a local digest tool are available; never silently skip a
# mismatch.
if curl -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS" 2>/dev/null; then
    expected=$(awk -v name="$package.tar.gz" '$2 == name || $2 == "*"name {print $1}' "$work/SHA256SUMS" | head -n 1)
    actual=$(sha256_of "$work/$package.tar.gz")
    if [[ -n "$expected" && -n "$actual" ]]; then
        [[ "$expected" = "$actual" ]] ||
            die "checksum mismatch for $package.tar.gz (expected $expected, got $actual)"
        printf '==> checksum verified\n'
    else
        printf '==> warning: could not verify checksum for %s\n' "$package.tar.gz" >&2
    fi
else
    printf '==> warning: SHA256SUMS not available for v%s\n' "$VERSION" >&2
fi

tar -xzf "$work/$package.tar.gz" -C "$work"

# The archive root is the package directory and the executable lives under
# bin/, matching scripts/release.sh and the release workflow.
binary="$work/$package/bin/pooler"
[[ -f "$binary" ]] || die "archive did not contain $package/bin/pooler"

if [[ "$MODE" = system && "$EUID" -ne 0 ]]; then
    die "installing to $INSTALL_DIR requires root; re-run with sudo or pass --user"
fi

mkdir -p -- "$INSTALL_DIR" || die "could not create $INSTALL_DIR"
install -m 0755 -- "$binary" "$INSTALL_DIR/pooler" ||
    die "could not install to $INSTALL_DIR/pooler"

printf '==> installed pooler %s to %s/pooler\n' "$VERSION" "$INSTALL_DIR"
"$INSTALL_DIR/pooler" --version || die 'installed binary failed to run'

cat <<EOF

Pooler $VERSION is installed.

Next, hand this prompt to your coding agent:

  Set up Pooler on my machine using
  https://raw.githubusercontent.com/coder-company/pooler/main/llms.txt

Or set it up yourself:

  pooler init --output ./pooler-starter
  pooler check --config ./pooler-starter/pooler.yaml
  pooler --config ./pooler-starter/pooler.yaml dashboard

To run Pooler as a hardened systemd service on ports 18400/18401, use
scripts/install-system-pooler.sh from the release archive.
EOF

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        printf '\nNote: %s is not on your PATH. Add it to your shell profile:\n' "$INSTALL_DIR"
        printf '  export PATH="$PATH:%s"\n' "$INSTALL_DIR"
        ;;
esac
