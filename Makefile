# Makefile for open-friendly-net-detection-client

.PHONY: help clean clean-python clean-debian clean-all build deb test install

# Default target
help:
	@echo "Available targets:"
	@echo "  help        - Show this help message"
	@echo "  clean       - Clean all build artifacts (python + debian)"
	@echo "  clean-python - Clean Python build artifacts"
	@echo "  clean-debian - Clean Debian build artifacts"
	@echo "  clean-all   - Clean everything including caches"
	@echo "  build       - Build Python package"
	@echo "  deb         - Build Debian package"

# Clean targets based on .gitignore
clean: clean-python clean-debian

clean-python:
	@echo "Cleaning Python build artifacts..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/

clean-debian:
	@echo "Cleaning Debian build artifacts..."
	rm -f *.deb
	rm -f *.build
	rm -f *.changes
	rm -f *.dsc
	rm -f *.tar.*
	rm -f *.buildinfo
	rm -rf debian/.debhelper/
	rm -rf debian/open-friendly-net-detection-client/
	rm -f debian/files
	rm -f debian/debhelper-build-stamp
	rm -f debian/*.substvars
	rm -f debian/open-friendly-net-detection-client.debhelper.log
	rm -f debian/*.debhelper

clean-all: clean
	@echo "Cleaning additional caches and temporary files..."
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".coverage" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".DS_Store" -delete 2>/dev/null || true

# Build targets
build:
	@echo "Building Python package..."
	python3 -m pip install --upgrade build
	python3 -m build

deb:
	@echo "Building Debian package..."
	debuild -us -uc

