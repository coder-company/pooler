#!/usr/bin/env bash
# Pooler Installer (by Coder Company)
# https://github.com/coder-company/pooler
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash
#
# Or with options:
#   curl -fsSL https://raw.githubusercontent.com/coder-company/pooler/main/install.sh | bash -s -- --dir ~/.local/bin

set -euo pipefail

REPO="coder-company/pooler"
BINARY_NAME="pooler"
INSTALL_DIR="${POOLER_INSTALL_DIR:-$HOME/.local/bin}"

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Pooler Installer"
      echo ""
      echo "Options:"
      echo "  --dir <path>    Installation directory (default: ~/.local/bin or /usr/local/bin)"
      echo "  -h, --help      Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

detect_target() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    linux)
      case "$arch" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "unsupported" ;;
      esac
      ;;
    darwin)
      case "$arch" in
        x86_64) echo "x86_64-apple-darwin" ;;
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        *) echo "unsupported" ;;
      esac
      ;;
    *)
      echo "unsupported"
      ;;
  esac
}

main() {
  echo "==> Pooler Installer (Coder Company)"
  
  local target
  target="$(detect_target)"
  
  if [ "$target" = "unsupported" ]; then
    echo "Error: Unsupported operating system or architecture: $(uname -s) $(uname -m)" >&2
    exit 1
  fi

  echo "==> Detected target: $target"
  mkdir -p "$INSTALL_DIR"

  # Check for latest release archive from GitHub
  local release_url="https://github.com/$REPO/releases/latest/download/pooler-$target.tar.gz"
  local temp_dir
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT

  echo "==> Downloading Pooler binary..."
  if curl -fsSL "$release_url" -o "$temp_dir/pooler.tar.gz" 2>/dev/null; then
    tar -xzf "$temp_dir/pooler.tar.gz" -C "$temp_dir"
    if [ -f "$temp_dir/pooler" ]; then
      mv "$temp_dir/pooler" "$INSTALL_DIR/$BINARY_NAME"
      chmod +x "$INSTALL_DIR/$BINARY_NAME"
    elif [ -f "$temp_dir/bin/pooler" ]; then
      mv "$temp_dir/bin/pooler" "$INSTALL_DIR/$BINARY_NAME"
      chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
    echo "==> Successfully installed pooler to $INSTALL_DIR/$BINARY_NAME"
  else
    echo "==> Release binary not found or unreachable. Checking for Cargo..."
    if command -v cargo >/dev/null 2>&1; then
      echo "==> Building and installing pooler from source via cargo..."
      cargo install --git "https://github.com/$REPO.git" pooler-cli --bin pooler --root "${INSTALL_DIR%/bin}"
      echo "==> Successfully compiled and installed pooler"
    else
      echo "Error: Could not download binary release and Cargo is not installed." >&2
      echo "Please install Rust and Cargo from https://rustup.rs or download prebuilt binaries from:" >&2
      echo "  https://github.com/$REPO/releases" >&2
      exit 1
    fi
  fi

  echo ""
  echo "========================================================"
  echo "  Pooler is installed!"
  echo "========================================================"
  echo ""
  echo "  Next steps for AI Agents (Agent-Native Setup):"
  echo "    Ask your agent: \"Initialize a new Pooler setup with 'pooler init'\""
  echo ""
  echo "  Next steps for Humans:"
  echo "    1. pooler init --output ./pooler-starter"
  echo "    2. pooler --config ./pooler-starter/pooler.yaml dashboard"
  echo ""

  # Check PATH
  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo "Notice: Add $INSTALL_DIR to your PATH in ~/.bashrc or ~/.zshrc:"
      echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
      ;;
  esac
}

main "$@"
