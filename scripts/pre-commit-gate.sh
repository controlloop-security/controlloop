#!/usr/bin/env bash
# ControlLoop's own pre-commit hook entry point.
#
# pre-commit's own contract for a `language: script` hook (see
# .pre-commit-hooks.yaml) is: invoke this file directly, with the
# current working directory already set to the root of the repository
# being committed to (this is pre-commit's own documented behavior, not
# something this script arranges). Nothing here reads $PWD's git history
# except through `controlloop gate` itself, and nothing here contacts
# the network beyond the identical local-cache-first `uv sync` action.yml
# (this repository's own GitHub Action) already performs on every run.
#
# Baseline strategy (documented here and in
# docs/reference/pre-commit-hook.md): no --baseline override is passed,
# so `controlloop gate` resolves one automatically -- a baseline
# committed at .controlloup/baseline.json takes precedence, falling back
# to the merge-base of the default branch, falling back to no baseline
# at all when neither is available. This is the identical strategy the
# ControlLoop GitHub Action (action.yml) uses by default.
set -euo pipefail

# This hook's own checkout root -- the directory pre-commit cloned this
# repository into at the pinned revision, resolved from this script's
# own real path rather than assumed. It is also the root of the installable
# ControlLoop package.
HOOK_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_DIR="${HOOK_REPO_ROOT}"

# The repository being committed to -- pre-commit's own documented
# invocation contract sets this as the current working directory before
# running any hook.
TARGET_REPO="$(pwd)"

# Installs/verifies this hook's own pinned, locked ControlLoop checkout
# -- the identical mechanism action.yml's "Install ControlLoop from this
# action's own pinned checkout" step already uses. Fast and offline
# after the first run: uv resolves from its own local cache once the
# lockfile-pinned versions are already present.
uv sync --locked --all-groups --project "${CLI_DIR}" >/dev/null

# Evidence is written outside the target repository, to an isolated
# temporary path -- never inside $TARGET_REPO -- matching the disclosed
# interaction docs/reference/cli.md's `gate` section already documents:
# writing the evidence artifact inside the scanned tree changes the next
# run's own root_digest. A commit-time hook runs on every commit, so
# this matters far more here than it does for a single CI run.
EVIDENCE_DIR="$(mktemp -d)"
trap 'rm -rf "${EVIDENCE_DIR}"' EXIT

uv run --project "${CLI_DIR}" controlloop gate "${TARGET_REPO}" \
  --evidence-path "${EVIDENCE_DIR}/evidence.json" \
  "$@"
