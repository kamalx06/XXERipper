#!/usr/bin/env bash
# Build every distribution format for XXERipper.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
mkdir -p dist

echo "======================================"
echo "  Building XXERipper distributions"
echo "======================================"

echo
echo "=== 1/4 python3 wheel + sdist ==="
python3 -m build

echo
echo "=== 2/4 Debian package ==="
bash scripts/build-deb.sh || echo "[!] .deb build failed — continuing"

echo
echo "=== 3/4 RPM package ==="
bash scripts/build-rpm.sh || echo "[!] .rpm build failed — continuing"

echo
echo "=== 4/4 Arch package ==="
bash scripts/build-arch.sh || echo "[!] Arch build failed — continuing"

echo
echo "======================================"
echo "  All artifacts in dist/:"
echo "======================================"
ls -la dist/ 2>/dev/null || echo "(nothing built)"