#!/usr/bin/env bash
# ControlLoop shell installer: one command downloads, verifies, and
# installs the correct binary for the user's platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/controlloop-security/controlloop/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/controlloop-security/controlloop/main/install.sh | bash -s -- --version v0.2.0
#
# Releases are published by .github/workflows/release.yml on each
# `vX.Y.Z` tag; the first, v0.1.1 (2026-10-20), carries the binaries,
# checksums and attestations this script downloads and verifies. See
# docs/reference/release-pipeline.md.
#
# Checksum verification is mandatory and always aborts the
# install on a mismatch: `sha256sum`/`shasum` are effectively universal
# on Linux and macOS. Signature verification additionally requires the
# GitHub CLI (`gh`); when `gh` is present it also runs and also aborts
# on failure, but when it is absent this script does not silently treat
# the artifact as fully verified -- it prints a disclosed warning and
# proceeds on the checksum result alone. See
# docs/reference/release-verification.md and
# docs/reference/shell-installer.md for the full disclosure.
#
# Every network endpoint below is overridable via environment variable,
# defaulting to the real GitHub endpoints -- this is what makes testing
# in CI on every supported platform possible without a real
# published release: tests/test_install_script.py points these at a
# local fixture server serving synthetic release assets.
set -euo pipefail

REPO="controlloop-security/controlloop"
FINAL_BINARY_NAME="controlloop"

VERSION="${CONTROLLOOP_INSTALL_VERSION:-}"
INSTALL_DIR="${CONTROLLOOP_INSTALL_DIR:-${HOME}/.local/bin}"
BASE_URL="${CONTROLLOOP_INSTALL_BASE_URL:-https://github.com/${REPO}/releases/download}"
RELEASE_API_URL="${CONTROLLOOP_INSTALL_RELEASE_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
# Advanced/testing-only overrides -- a real end user never needs these;
# `uname` already reports the right values on every supported machine.
PLATFORM_OVERRIDE="${CONTROLLOOP_INSTALL_PLATFORM:-}"
ARCH_OVERRIDE="${CONTROLLOOP_INSTALL_ARCH:-}"

usage() {
  cat <<EOF
ControlLoop shell installer

Usage: install.sh [--version VERSION] [--install-dir DIR] [--help]

  --version VERSION   Install a specific release (for example v0.2.0).
                       Default: the latest published release.
  --install-dir DIR   Where to install the 'controlloop' binary.
                       Default: \$HOME/.local/bin (no elevated
                       privileges are ever required or used).
  --help               Show this message and exit.

Environment variable equivalents: CONTROLLOOP_INSTALL_VERSION,
CONTROLLOOP_INSTALL_DIR. See docs/reference/shell-installer.md for the
full set of environment variables, including advanced testing-only
overrides.
EOF
}

log_info() {
  printf 'controlloop-install: %s\n' "$1" >&2
}

log_error() {
  printf 'controlloop-install: error: %s\n' "$1" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="$2"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="$2"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      log_error "unrecognized argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

fetch_to_stdout() {
  # $1: URL
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O - "$1"
  else
    log_error "neither curl nor wget is available -- cannot download anything"
    exit 1
  fi
}

fetch_to_file() {
  # $1: URL, $2: destination path
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    log_error "neither curl nor wget is available -- cannot download anything"
    exit 1
  fi
}

compute_sha256() {
  # $1: file path. Prints the hex digest on stdout.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    log_error "neither sha256sum nor shasum is available -- cannot verify the downloaded artifact's checksum"
    exit 1
  fi
}

detect_platform() {
  # PLATFORM_OVERRIDE, when set, stands in for `uname -s`'s own raw
  # output (for example "Linux"/"Darwin"/"Windows") and is validated
  # exactly the same way -- an override naming an unsupported platform
  # fails loudly here, the same as a real unsupported machine would,
  # rather than silently bypassing this check.
  raw="${PLATFORM_OVERRIDE:-$(uname -s)}"
  case "$raw" in
    Linux) printf 'linux' ;;
    Darwin) printf 'macos' ;;
    *)
      log_error "unsupported platform: ${raw} (only Linux and macOS are supported; see docs/reference/supported-platforms.md)"
      exit 1
      ;;
  esac
}

detect_arch() {
  # ARCH_OVERRIDE, when set, stands in for `uname -m`'s own raw output
  # and is validated the same way -- see detect_platform's own comment.
  raw="${ARCH_OVERRIDE:-$(uname -m)}"
  case "$raw" in
    x86_64 | amd64) printf 'x86_64' ;;
    arm64 | aarch64) printf 'arm64' ;;
    *)
      log_error "unsupported architecture: ${raw}"
      exit 1
      ;;
  esac
}

resolve_version() {
  # Prints a real 'vX.Y.Z' tag on stdout: either the pinned version,
  # normalized to always carry its leading 'v', or the latest
  # published release resolved from the GitHub Releases API.
  if [ -n "$VERSION" ]; then
    case "$VERSION" in
      v*) printf '%s' "$VERSION" ;;
      *) printf 'v%s' "$VERSION" ;;
    esac
    return
  fi

  response="$(fetch_to_stdout "$RELEASE_API_URL")"
  tag="$(printf '%s' "$response" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed -E 's/.*"([^"]+)"$/\1/')"
  if [ -z "$tag" ]; then
    log_error "could not determine the latest release version from ${RELEASE_API_URL}"
    exit 1
  fi
  printf '%s' "$tag"
}

verify_checksum() {
  # $1: downloaded binary path, $2: downloaded SHA256SUMS path, $3: the
  # binary's own asset filename as it appears in SHA256SUMS.
  binary_path="$1"
  checksums_path="$2"
  asset_name="$3"

  expected="$(grep -E "  ${asset_name}\$" "$checksums_path" | awk '{print $1}' || true)"
  if [ -z "$expected" ]; then
    log_error "SHA256SUMS has no entry for ${asset_name} -- aborting, this artifact cannot be verified"
    exit 1
  fi

  actual="$(compute_sha256 "$binary_path")"
  if [ "$actual" != "$expected" ]; then
    log_error "checksum mismatch for ${asset_name}: expected ${expected}, got ${actual} -- aborting, this artifact may have been tampered with"
    exit 1
  fi
  log_info "checksum verified: ${asset_name}"
}

verify_signature() {
  # $1: downloaded binary path, $2: the binary's own asset filename, for
  # log messages only.
  binary_path="$1"
  asset_name="$2"

  if ! command -v gh >/dev/null 2>&1; then
    log_info "warning: gh (GitHub CLI) not found -- skipping signature verification. Checksum verification above still ran and passed. See docs/reference/release-verification.md to verify this artifact's signature manually once gh is installed."
    return
  fi

  if gh attestation verify "$binary_path" --repo "$REPO" >/dev/null 2>&1; then
    log_info "signature verified: ${asset_name} (gh attestation verify)"
  else
    log_error "signature verification failed for ${asset_name} -- aborting, this artifact's provenance could not be confirmed"
    exit 1
  fi
}

path_guidance() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      log_info "note: ${INSTALL_DIR} is not on your PATH. Add this to your shell profile:"
      log_info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac
}

main() {
  platform="$(detect_platform)"
  arch="$(detect_arch)"

  if [ "$platform" = "macos" ] && [ "$arch" = "x86_64" ]; then
    log_error "macOS x86_64 (Intel) has no published binary -- a disclosed gap, see docs/reference/standalone-binaries.md"
    exit 1
  fi

  tag="$(resolve_version)"
  asset_name="controlloop-${platform}-${arch}"
  log_info "installing ${asset_name} ${tag}"

  scratch_dir="$(mktemp -d)"
  trap 'rm -rf "${scratch_dir}"' EXIT

  binary_path="${scratch_dir}/${asset_name}"
  checksums_path="${scratch_dir}/SHA256SUMS"

  fetch_to_file "${BASE_URL}/${tag}/${asset_name}" "$binary_path"
  fetch_to_file "${BASE_URL}/${tag}/SHA256SUMS" "$checksums_path"

  verify_checksum "$binary_path" "$checksums_path" "$asset_name"
  verify_signature "$binary_path" "$asset_name"

  mkdir -p "$INSTALL_DIR"
  chmod +x "$binary_path"
  mv "$binary_path" "${INSTALL_DIR}/${FINAL_BINARY_NAME}"

  log_info "installed ${INSTALL_DIR}/${FINAL_BINARY_NAME}"
  path_guidance
  "${INSTALL_DIR}/${FINAL_BINARY_NAME}" --version >&2 || true
}

main
