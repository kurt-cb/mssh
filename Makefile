# Top-level Makefile for the mssh project.
#
# Build, install, and dev-loop targets for the Python implementation.
# Future targets will cover the Go and C implementations once those
# trees materialize.
#
# Version is read from git via setuptools_scm. The latest annotated
# tag becomes the wheel version; dirty trees add a suffix.

# ---- knobs ------------------------------------------------------------
SHELL := /bin/bash
# Resolve PYTHON to an absolute path so `cd` in build recipes
# doesn't lose track of a relative path.
PYTHON ?= python3
PYTHON := $(shell command -v $(PYTHON) 2>/dev/null || echo $(PYTHON))
PIP ?= pip
PY_PKG_DIR := python/packages
PY_PACKAGES := mssh-common mssh msshd mssh-ca mssh-admin mssh-passkey
DIST_DIR := dist

# Where the venv lives — used so `make dev-install` doesn't accidentally
# touch the system Python. Override with VENV=/path/to/venv if needed.
VENV ?= .venv
VENV_PY := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

# Lab parameters — used by `make redeploy` to push freshly-built wheels
# into the currently-running adhoc lab. Override LAB_PREFIX to target
# a specific lab.
LAB_PREFIX ?= $(shell ls /tmp/lab_prefix 2>/dev/null | head -1 || echo claude)

# ---- meta -------------------------------------------------------------
.PHONY: help version
help:
	@echo "mssh — top-level build targets"
	@echo
	@echo "  make version          show the current version (from git tag)"
	@echo "  make pkg              build all 6 Python wheels into $(DIST_DIR)/"
	@echo "  make pkg-<name>       build just one wheel (e.g. make pkg-msshd)"
	@echo "  make dev-install      pip install -e the 6 packages into \$$VENV"
	@echo "  make clean-dist       remove just $(DIST_DIR)/*.whl (stale wheels)"
	@echo "  make clean            full clean: $(DIST_DIR)/, build/, *.egg-info, __pycache__"
	@echo "  make redeploy         push wheels into the running adhoc lab"
	@echo
	@echo "Current version: $$($(MAKE) -s version)"

version:
	@cd $(PY_PKG_DIR)/mssh-common && $(PYTHON) -m setuptools_scm 2>/dev/null \
	    || git describe --tags --dirty 2>/dev/null \
	    || echo "0.0.0+local"

# ---- build -----------------------------------------------------------
.PHONY: pkg clean-dist $(addprefix pkg-,$(PY_PACKAGES))

# Remove stale wheels before rebuilding — without this, dist/ accumulates
# every version ever built and pip sometimes picks the wrong one.
clean-dist:
	@rm -f $(DIST_DIR)/*.whl

pkg: clean-dist $(addprefix pkg-,$(PY_PACKAGES))
	@echo
	@echo "✓ built $(words $(PY_PACKAGES)) wheels into $(DIST_DIR)/"
	@ls -1 $(DIST_DIR)/*.whl 2>/dev/null | sed 's/^/  /'

# Pattern rule: build any package. `make pkg-msshd` invokes
# `python -m build` inside python/packages/msshd/ and copies the
# resulting wheel up to the top-level dist/.
$(addprefix pkg-,$(PY_PACKAGES)):
	@pkg=$(@:pkg-%=%); \
	echo "── building $$pkg ──"; \
	mkdir -p $(DIST_DIR); \
	cd $(PY_PKG_DIR)/$$pkg && $(PYTHON) -m build --wheel --outdir ../../../$(DIST_DIR)/

# ---- install (dev) ---------------------------------------------------
.PHONY: dev-install
dev-install:
	@if [ ! -x "$(VENV_PIP)" ]; then \
	    echo "error: no venv at $(VENV) — create one with: $(PYTHON) -m venv $(VENV)" >&2; \
	    exit 1; \
	fi
	@for pkg in $(PY_PACKAGES); do \
	    echo "── installing $$pkg (editable) ──"; \
	    $(VENV_PIP) install -e $(PY_PKG_DIR)/$$pkg --quiet; \
	done
	@echo "✓ installed $(words $(PY_PACKAGES)) packages editable in $(VENV)"

# ---- tarball (for install_mssh.sh) -----------------------------------
# `make tarball` produces dist/mssh-<version>.tar.gz containing the
# 6 wheels + config/ + systemd/. install_mssh.sh consumes this on a
# clean host (simulates what `apt install mssh-server` will install
# once we have real distro packaging — future-ideas §16).
.PHONY: tarball
TARBALL_VERSION ?= $(shell cd $(PY_PKG_DIR)/mssh-common && \
    $(PYTHON) -c "from setuptools_scm import get_version; \
                  print(get_version(root='../../..'))" 2>/dev/null \
    || git describe --tags --dirty 2>/dev/null || echo "0.0.0")
TARBALL_NAME := mssh-$(TARBALL_VERSION).tar.gz

tarball: clean pkg
	@echo "── packaging $(TARBALL_NAME) ──"
	@tmp=$$(mktemp -d) && \
	    mkdir -p "$$tmp/dist" "$$tmp/config" "$$tmp/systemd" && \
	    cp $(DIST_DIR)/*.whl "$$tmp/dist/" && \
	    cp config/sshd_config.template "$$tmp/config/" 2>/dev/null || true && \
	    cp systemd/*.service "$$tmp/systemd/" 2>/dev/null || true && \
	    tar -C "$$tmp" -czf $(DIST_DIR)/$(TARBALL_NAME) dist config systemd && \
	    rm -rf "$$tmp"
	@echo "✓ wrote $(DIST_DIR)/$(TARBALL_NAME)"
	@ls -lh $(DIST_DIR)/$(TARBALL_NAME)

# ---- redeploy to running lab -----------------------------------------
# Builds fresh wheels, pushes them to each container in the running
# adhoc lab, pip-installs them, and restarts the relevant services.
# Replaces the "lxc file push + restart" hot-patch workflow with the
# real upgrade path users will hit.
.PHONY: redeploy
redeploy: pkg
	@scripts/redeploy.sh "$(LAB_PREFIX)" "$(DIST_DIR)"

# ---- clean ----------------------------------------------------------
.PHONY: clean
clean:
	rm -rf $(DIST_DIR) build/
	find $(PY_PKG_DIR) -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	find $(PY_PKG_DIR) -name '*.egg-info' -type d -exec rm -rf {} + 2>/dev/null || true
	find $(PY_PKG_DIR) -name '_version.py' -path '*/mssh-common/*' -exec rm -f {} +
	@echo "✓ cleaned dist/, build/, pycache, egg-info, generated _version.py"
