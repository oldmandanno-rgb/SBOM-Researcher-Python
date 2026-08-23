#!/usr/bin/env bash
# Install kind + kubectl into WSL2 (Linux). Run from WSL:
#   ./scripts/install-tools.sh
# Requires: WSL2 with Docker Desktop's WSL2 backend running, and network access.
# Installs to ~/.local/bin (no sudo / no password prompt) and ensures it is
# on PATH via ~/.profile (Ubuntu already adds ~/.local/bin automatically).
set -euo pipefail

TARGET="$HOME/.local/bin"
mkdir -p "$TARGET"

# --- kind ---
KIND_VER=v0.24.0
echo ">> Installing kind ${KIND_VER}"
curl -fsSL -o "$TARGET/kind" "https://kind.sigs.k8s.io/dl/${KIND_VER}/kind-linux-amd64"
chmod +x "$TARGET/kind"

# --- kubectl ---
KVER="$(curl -fsSL -s https://dl.k8s.io/release/stable.txt)"
echo ">> Installing kubectl ${KVER}"
curl -fsSL -LO "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl "$TARGET/kubectl"

# Ensure ~/.local/bin is on PATH for future non-login shells.
if ! grep -q 'local/bin' "$HOME/.bashrc" 2>/dev/null; then
  printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$HOME/.bashrc"
fi

echo ">> Installed:"
"$TARGET/kind" version
"$TARGET/kubectl" version --client
