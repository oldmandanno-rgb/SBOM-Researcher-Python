#!/usr/bin/env bash
# Regenerate the hash-pinned runtime lockfile for osv_service.
#
# Per AGENTS.md, lockfiles must be generated on Linux (WSL) so the wheel
# hashes match the ubuntu-latest CI runners and the Chainguard container
# (which runs Python 3.12 on linux/x86_64). This script pins the target
# platform explicitly (--python-platform linux) so it also works if run
# from macOS/Windows, producing correct Linux wheel hashes.
#
# Usage:
#   ./scripts/gen-osv-lock.sh
#
# Requires: uv (https://astral.sh/uv) on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PYTHON_VERSION="3.12"

uv pip compile \
  --generate-hashes \
  --python-version "$PYTHON_VERSION" \
  --python-platform linux \
  --no-header \
  -o requirements-osv-service.txt \
  requirements-osv-service.in

echo "Wrote requirements-osv-service.txt (python ${PYTHON_VERSION}, linux)"
