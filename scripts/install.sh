#!/usr/bin/env bash
set -euo pipefail

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$OS" in
  linux*)
    bash "$SCRIPT_DIR/install_linux.sh"
    ;;
  darwin*)
    bash "$SCRIPT_DIR/install_macos.sh"
    ;;
  *)
    echo "Unsupported OS for this script: $OS"
    echo "Use scripts/install_windows.ps1 on Windows."
    exit 1
    ;;
esac
