#!/usr/bin/env bash
# Build an Arch Linux package for XXERipper using makepkg.
#
# Requirements:
#   - Run on Arch Linux (or an Arch container with base-devel)
#   - base-devel installed: sudo pacman -S base-devel
#   - makepkg cannot be run as root
#
# For a build inside a container:
#   docker run --rm -v "$PWD:/build" -w /build archlinux:latest \
#       bash -c "pacman -Sy --noconfirm base-devel python-build \
#                python-installer python-wheel python-hatchling && \
#                useradd -m builder && chown -R builder /build && \
#                su builder -c 'bash scripts/build-arch.sh'"
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ "$EUID" -eq 0 ]]; then
    echo "[!] makepkg cannot be run as root." >&2
    echo "    Run as an unprivileged user, or use the container command" >&2
    echo "    documented at the top of this script." >&2
    exit 1
fi

if ! command -v makepkg >/dev/null 2>&1; then
    echo "[!] makepkg not found. Install base-devel: sudo pacman -S base-devel" >&2
    exit 1
fi

echo "[*] Copying PKGBUILD into build directory..."
BUILD_DIR="$PROJECT_ROOT/build/arch"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cp packaging/arch/PKGBUILD "$BUILD_DIR/"
cp LICENSE "$BUILD_DIR/" 2>/dev/null || true

# makepkg downloads the tarball from GitHub, but during local development
# we can override it to use the current tree.
echo "[*] Preparing local source tarball..."
VERSION=$(grep -m1 '^version' pyproject.toml | sed 's/.*"\(.*\)".*/\1/')
SRC_NAME="xxeripper-$VERSION"
TMP_SRC=$(mktemp -d)
trap 'rm -rf "$TMP_SRC"' EXIT

mkdir -p "$TMP_SRC/XXERipper-$VERSION"
tar --exclude='.git' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='debian' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.egg-info' \
    -cf - . | tar -xf - -C "$TMP_SRC/XXERipper-$VERSION"

tar -czf "$BUILD_DIR/$SRC_NAME.tar.gz" -C "$TMP_SRC" "XXERipper-$VERSION"

echo "[*] Patching PKGBUILD source and checksum lines..."
sed -i "s|^source=.*|source=(\"$SRC_NAME.tar.gz\")|" "$BUILD_DIR/PKGBUILD"
sed -i "s|^sha256sums=.*|sha256sums=('SKIP')|" "$BUILD_DIR/PKGBUILD"

echo "[*] Running makepkg..."
cd "$BUILD_DIR"
makepkg -f --noconfirm

mkdir -p "$PROJECT_ROOT/dist"
cp "$BUILD_DIR"/*.pkg.tar.* "$PROJECT_ROOT/dist/" 2>/dev/null || true

echo "[✓] Built:"
ls -la "$PROJECT_ROOT/dist/"*.pkg.tar.*