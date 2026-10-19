---
type: reference
title: Release pipeline
tags:
  - reference
  - releases
  - ci
created: 2026-08-21
---

# Release pipeline

**No release has ever been published.** This page describes what
`.github/workflows/release.yml` does when a maintainer pushes a real tag
matching `v*.*.*` -- it has never actually run, and nothing on this page is
a claim that a version of ControlLoop is available to install.

The goal: one tagged release builds, verifies, and publishes every
artifact from a single reproducible pipeline.

## What triggers it

Only a `git push` of a tag shaped like `vX.Y.Z` (for example `v0.2.0`) to
this repository. The workflow never runs on a pull request or a branch
push, and nothing in this repository ever pushes a tag on its own --
publishing a release is always a deliberate, human act.

## What it does, in order

1. **Derive version** (`release-scripts/derive_release_metadata.py`).
   Strips the tag's leading `v` and compares it against
   `pyproject.toml`'s `[project].version` -- the one human-edited
   source of the package version. A mismatch fails the whole pipeline
   before anything else runs. It also statically records the current rule
   pack version and every ACBOM-family schema version
   (`CURRENT_*_SCHEMA_VERSION` constants across `src/controlloop`) into
   one `release-manifest.json`, so every later stage stamps artifacts from
   that one computed snapshot rather than re-deriving its own copy.
2. **Verify** -- calls the same reusable `verify.yml` workflow every pull
   request already runs: `uv sync --locked --all-groups`, `ruff format
   --check`, `ruff check`, `mypy`, `pytest`, `uv build`. A failure here
   stops every later stage.
3. **Changelog gate**
   (`release-scripts/changelog_release_notes.py`). Requires a real,
   non-empty `## [X.Y.Z]` section in `CHANGELOG.md` for the derived
   version. A release with no changelog entries fails here, before
   anything is published.
4. **Package** -- runs `uv build` again on a clean checkout and uploads the
   resulting wheel and sdist alongside the release manifest.
5. **Build standalone binaries** -- builds, smoke-tests,
   and reproducibility-checks one PyInstaller onefile executable per
   platform/architecture leg. See [Standalone
   binaries](standalone-binaries.md) for the full disclosure, including
   the macOS x86_64 gap and the unsigned/unnotarized macOS binary.
6. **Attest and checksum artifacts** (`release-scripts/checksums.py`) --
   runs independently of stage 5's own publish step (it needs only the built
   wheel, sdist, release manifest, and standalone binaries, not a created
   GitHub Release), writing one combined `SHA256SUMS` checksum file covering
   every published artifact and signing each one with GitHub's own built-in,
   Sigstore-backed build-provenance attestation
   (`actions/attest-build-provenance`) -- keyless (OIDC), no external
   secret. In the same job run, it verifies the checksums and attestations
   it just produced against the just-built artifacts, and proves a
   deliberately tampered copy of one fails both checks. See [Release
   verification](release-verification.md) for the full disclosure, including
   why this needs no separate signing-provider decision, and the exact
   commands a downloader runs.
7. **Publish** -- only if every prior stage, including artifact
   attestation, passed, creates a GitHub Release for the tag, attaching
   the wheel, the sdist, the release manifest, every built standalone
   binary with its checksum, and the combined `SHA256SUMS` file, with
   release notes taken verbatim from the changelog section the gate step
   already verified. This step uses only this repository's own
   `GITHUB_TOKEN`; no external secret is required or referenced. A
   floating `vMAJOR` tag (e.g. `v1`) is documented policy: the
   maintainers move it manually after each release, deliberately not
   automated here -- see [Action marketplace
   listing](marketplace-listing.md) for why.
8. **Publish schemas** (`release-scripts/assemble_schema_site.py`) -- runs
   independently of stages 4-7 (it only needs verification and the changelog
   gate, not a built wheel, built binaries, or a created GitHub Release),
   copying every packaged JSON Schema file -- every version of every family,
   including frozen historical ones -- to GitHub Pages using GitHub's own
   built-in `pages`/`id-token` permissions, no external secret. This makes
   the publish step real and automated; it does not by itself make
   `schemas.controlloop.ai` resolve -- GitHub Pages must still be enabled
   for this repository, and DNS must still be pointed at it, separately,
   once, by the maintainers.
9. **Publish to PyPI** -- only after stage 7 has created the GitHub
   Release, uploads the same wheel and sdist (not the release manifest) to
   the [`controlloop`](https://pypi.org/project/controlloop/) project with
   `pypa/gh-action-pypi-publish`. It uses PyPI trusted publishing: PyPI
   accepts a short-lived OIDC token GitHub issues to this run, so no PyPI
   API token is stored in the repository or its secrets. The action also
   uploads PEP 740 attestations, which PyPI shows on each file. It runs
   last because PyPI never accepts the same version twice: an upload
   cannot be replaced, only yanked. The job runs in the `pypi`
   environment.

## Setting up PyPI publishing

Done once, by a maintainer who owns the `controlloop` project on PyPI:

1. On PyPI, open the project's **Manage → Publishing** page and add a
   GitHub trusted publisher: owner `controlloop-security`, repository
   `controlloop`, workflow `release.yml`, environment `pypi`. All four
   must match exactly, or the upload is refused.
2. In this repository's **Settings → Environments**, create an
   environment named `pypi`. To hold every upload until a maintainer
   approves it, add required reviewers there. To stop uploads from
   anything but a release tag, add a deployment tag rule for `v*.*.*`.
3. Release by pushing a `vX.Y.Z` tag whose version matches
   `pyproject.toml` and has a `CHANGELOG.md` section. `0.1.0` was
   uploaded by hand when the name was reserved, so the first release from
   this pipeline must be a later version.

If the `publish-pypi` job fails after the GitHub Release is created, fix
the cause and re-run only that job; nothing earlier needs to run again.

## What this pipeline does not do

- **No GHCR or Homebrew publication.** Each is separate, later work, and
  each uses the same name, `controlloop`, as the PyPI project. The
  Homebrew tap repository now exists
  (`controlloop-security/homebrew-controlloop`, reserved, no formula yet),
  but the GHCR namespace has not been created. A later change adding
  either adds a new job that depends on this pipeline's existing `verify`
  and `changelog-gate` stages; it does not need to change them.
- **No macOS code signing or notarization, and no macOS x86_64 (Intel)
  binary.** Standalone binaries themselves are now built, smoke-tested,
  checksummed, and every published artifact now also
  carries a combined checksum and a GitHub-native build-provenance
  attestation (stage 6 above). Neither replaces OS-level code
  signing/notarization of the binary itself, which remains a separate,
  not-yet-implemented, paid decision. See [Standalone
  binaries](standalone-binaries.md) and [Release
  verification](release-verification.md) for the full disclosure.
- **No local or developer-machine publication of any kind.** Every step
  above runs only on GitHub-hosted Actions runners.

## Version consistency

The package version, the rule pack version, and the ACBOM-family schema
versions are **not** required to be numerically equal to each other -- rule
packs are versioned independently from the CLI (see [Rule pack
versioning](rule-pack-versioning.md)), and each schema (ACBOM, manifest,
baseline, evidence, report, diff, finding, capability, and others) already
carries its own independent semantic version in this repository. "Derived
from one source and consistent across every artifact" means every artifact
one release publishes is stamped from the exact one manifest computed once
during that release's own pipeline run, never independently re-derived or
hand-typed a second time.

## Next steps

- Review [Release notes](release-notes.md) for what is actually published
  today (nothing yet).
- Review [Release verification](release-verification.md) for how a
  downloader checks an artifact's checksum and signature.
- Review [Shell installer](shell-installer.md) for the one-command
  installer that performs that verification automatically.
- Review [Action marketplace listing](marketplace-listing.md) for what is
  prepared for a GitHub Marketplace listing and what still requires a
  maintainer's manual action.
- Review the [License and third-party dependency audit](licensing.md) for
  the license review a release depends on.
