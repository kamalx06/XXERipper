# =============================================================================
# XXERipper — Makefile
# =============================================================================

.PHONY: help version install lab build deb rpm arch all clean

PYTHON ?= python3
PIP    ?= $(PYTHON) -m pip

.DEFAULT_GOAL := help

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help:
	@echo "XXERipper — build targets:"
	@echo ""
	@echo "  Setup:"
	@echo "    install       Install XXERipper and runtime dependencies"
	@echo "    lab           Install XXERipper with lab/test dependencies"
	@echo ""
	@echo "  Building:"
	@echo "    build         Build Python wheel + sdist"
	@echo "    deb           Build .deb (Debian/Ubuntu)"
	@echo "    rpm           Build .rpm (Fedora/RHEL, via container)"
	@echo "    arch          Build Arch package (makepkg, via container)"
	@echo "    all           Build every package format"
	@echo ""
	@echo "  Misc:"
	@echo "    version       Print the current version"
	@echo "    clean         Remove all build artifacts"
	@echo ""
	@echo "Examples:"
	@echo "    make install"
	@echo "    make lab"
	@echo "    make build"
	@echo "    make build deb"
	@echo "    make all"

# -----------------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------------
version:
	@$(PYTHON) -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])"

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------
install:
	$(PIP) install .

lab:
	$(PIP) install ".[socks,http2]"
	@if [ -f requirements-lab.txt ]; then \
		$(PIP) install -r requirements-lab.txt; \
	fi

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
build:
	$(PYTHON) -m build

# -----------------------------------------------------------------------------
# Distribution packages
# -----------------------------------------------------------------------------
deb:
	bash scripts/build-deb.sh

rpm:
	bash scripts/build-rpm.sh

arch:
	bash scripts/build-arch.sh

# -----------------------------------------------------------------------------
# Build everything
# -----------------------------------------------------------------------------
all:
	@$(MAKE) --no-print-directory clean
	@$(MAKE) --no-print-directory build
	@$(MAKE) --no-print-directory deb
	@$(MAKE) --no-print-directory rpm
	@$(MAKE) --no-print-directory arch
	@echo ""
	@echo "[✓] All builds complete. Artifacts in dist/:"
	@ls -la dist/

# -----------------------------------------------------------------------------
# Clean
# -----------------------------------------------------------------------------
clean:
	@echo "[*] Cleaning build artifacts..."

	rm -rf build/ dist/ *.egg-info/ .eggs/
	rm -rf __pycache__/
	rm -rf debian/ .pybuild/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf .coverage htmlcov/ .tox/ .nox/
	rm -rf .venv/ venv/ env/ ENV/
	rm -rf packaging/arch/pkg/ packaging/arch/src/
	rm -f packaging/arch/*.pkg.tar.* packaging/arch/*.tar.gz

	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type f -name '*.pyo' -delete 2>/dev/null || true

	@echo "[✓] Clean complete."