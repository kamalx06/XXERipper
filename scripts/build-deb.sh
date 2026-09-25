#!/usr/bin/env bash
# Build a Debian package for XXERipper.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "[*] Preparing debian/ directory..."
rm -rf debian
mkdir -p debian
cp -r packaging/debian/* debian/
chmod +x debian/rules

echo "[*] Running dpkg-buildpackage..."
dpkg-buildpackage -us -uc -b

mkdir -p dist
mv ../xxeripper_*.deb dist/ 2>/dev/null || true
mv ../xxeripper_*.buildinfo dist/ 2>/dev/null || true
mv ../xxeripper_*.changes dist/ 2>/dev/null || true

echo "[✓] Built:"
ls -la dist/*.deb