#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[N-VIEW] Linux installer starting..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python3 is not installed. Install Python 3.11+ and rerun."
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed. Attempting installation..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update
    sudo apt install -y git
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y git
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y git
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm git
  fi
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap not found. Attempting installation..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update
    sudo apt install -y nmap
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y nmap
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y nmap
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm nmap
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper install -y nmap
  else
    echo "Auto-install unavailable. Install nmap manually for your distro."
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
