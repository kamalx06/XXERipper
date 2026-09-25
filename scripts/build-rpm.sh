#!/usr/bin/env bash
# Build an RPM package for XXERipper.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

NAME=xxeripper
VERSION=$(grep -m1 '^version' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')

echo "[*] Building source tarball..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

mkdir -p "$TMPDIR/$NAME-$VERSION"
tar --exclude='.git' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='debian' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.egg-info' \
    -cf - . | tar -xf - -C "$TMPDIR/$NAME-$VERSION"

tar -czf "$TMPDIR/$NAME-$VERSION.tar.gz" -C "$TMPDIR" "$NAME-$VERSION"

echo "[*] Setting up rpmbuild tree..."
mkdir -p "$HOME/rpmbuild"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
cp "$TMPDIR/$NAME-$VERSION.tar.gz" "$HOME/rpmbuild/SOURCES/"
cp packaging/rpm/xxeripper.spec "$HOME/rpmbuild/SPECS/"

echo "[*] Running rpmbuild..."
rpmbuild -ba "$HOME/rpmbuild/SPECS/xxeripper.spec"

mkdir -p dist
find "$HOME/rpmbuild/RPMS" -name "*.rpm" -exec cp {} dist/ \;
find "$HOME/rpmbuild/SRPMS" -name "*.rpm" -exec cp {} dist/ \; 2>/dev/null || true

echo "[✓] Built:"
ls -la dist/*.rpm