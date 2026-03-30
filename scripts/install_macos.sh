#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[N-VIEW] macOS installer starting..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 is not installed. Install Python 3.11+ and rerun."
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Attempting installation via Homebrew..."
  if command -v brew >/dev/null 2>&1; then
    brew install git
  else
    echo "Install git manually: xcode-select --install"
  fi
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap not found. Attempting installation via Homebrew..."
  if command -v brew >/dev/null 2>&1; then
    brew install nmap
  else
    echo "Homebrew not found. Install Homebrew first: https://brew.sh"
    echo "Then run: brew install nmap"
  fi
fi

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install --user -e .
python3 -m nview.cli bootstrap
python3 -m nview.cli update || true

if ! command -v nview >/dev/null 2>&1; then
  echo "nview command is not currently on PATH. Open a new terminal session."
fi

echo "[N-VIEW] Installation complete."
echo "Open a new terminal and run: nview"
echo "Or run: n-view"
