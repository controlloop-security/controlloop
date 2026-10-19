---
type: reference
title: Release verification
tags:
  - reference
  - releases
  - ci
  - security
created: 2026-08-23
---

# Release verification

**No release has ever been published.** This page describes what
`.github/workflows/release.yml`'s `attest-artifacts` job does when a
maintainer pushes a real tag matching `v*.*.*`, and the commands a
downloader would run to verify a published artifact -- that job has
never actually run as part of a real release, because no release has
ever been published (see [Release pipeline](release-pipeline.md)).
Nothing on this page is a claim that a verifiable ControlLoop release is
available today.

The goal: every release publishes verifiable artifacts to GitHub
Releases with checksums and signatures.

## What gets checksummed and signed

Every artifact `publish-github-release` attaches to a GitHub Release:
the wheel, the sdist, `release-manifest.json`, and every standalone
binary ([Standalone binaries](standalone-binaries.md)). Two independent
proofs travel with each one:

1. **A checksum**, in one combined `SHA256SUMS` file (`sha256sum -c`
   compatible) covering every artifact by name. This is additive to the
   [standalone-binary](standalone-binaries.md) job's own per-binary
   `<binary>.sha256` files, which remain published unchanged.
2. **A signature** -- a GitHub-native, Sigstore-backed build-provenance
   attestation (`actions/attest-build-provenance`), created by the
   `attest-artifacts` job and independently verifiable through GitHub's
   own attestation API.

## Why GitHub's own attestation, not a GPG key or a third-party signer

Selecting a new signing provider would be a separate decision, and this
pipeline does not need one. Its signing mechanism is the same category
of choice already made for [schema
publication](release-pipeline.md#what-it-does-in-order):
GitHub's own built-in `pages`/`id-token` permissions, no external
credential. Artifact attestation is the direct analogue for signing --
GitHub's own native feature, keyless (OIDC-based, no long-lived private
key this repository would need to generate, store, or rotate), free for
public repositories, and requiring no decision about a signing key, a
certificate authority, a domain, or a paid tier. No GPG key, no
third-party signing service, and no paid code-signing certificate is
referenced anywhere in this pipeline.

## How to verify a downloaded artifact

Two independent checks, either sufficient on its own, both recommended:

**1. Checksum**, using the standard `sha256sum` (Linux) or `shasum`
(macOS) tool already present on every supported platform:

```
sha256sum -c SHA256SUMS --ignore-missing
```

(`shasum -a 256 -c SHA256SUMS --ignore-missing` on macOS.)
`--ignore-missing` is needed only if you downloaded fewer than every
artifact `SHA256SUMS` lists; a mismatch on any artifact you did download
still fails the command.

**2. Signature**, using the GitHub CLI's own built-in attestation
verification (`gh` version 2.49 or later, already present on every
GitHub-hosted runner):

```
gh attestation verify controlloop-0.2.0-py3-none-any.whl \
  --repo controlloop-security/controlloop
```

Run once per artifact you want to verify, substituting the actual
downloaded filename. A successful run reports the artifact's digest, the
signing workflow, and the exact commit and repository it was built from
-- proof the file was produced by this repository's own release
pipeline, not tampered with after the fact.

## Verified in CI

Because no release has ever been tagged, these commands cannot yet be
demonstrated against a real published release. Instead, the
`attest-artifacts` job runs the identical documented commands above
against the artifacts it just built and attested, in the same workflow
run, with real recorded output -- proving the procedure itself works,
not merely describing it. See the "Verify checksums against the
just-built artifacts" and "Verify attestations against the just-built
artifacts" steps in `.github/workflows/release.yml`.

## Tamper detection

The same job also proves the negative case: it copies one already-
checksummed, already-attested artifact, flips a single byte, and
confirms both `gh attestation verify` and the checksum verification
command reject the modified copy -- see the "Prove a tampered artifact
fails verification" step. `tests/test_checksums_script.py` covers
the identical tamper scenario for the checksum half locally and offline,
independent of any CI run.

## What this does not do

- **No artifact has ever been published anywhere.** No release tag has
  ever been pushed; see [Release
  pipeline](release-pipeline.md) for the same disclosure at the pipeline
  level.
- **No code signing or notarization of the standalone binaries
  themselves.** Build-provenance attestation proves *this repository's
  pipeline* produced the artifact; it is not an OS-level code signature.
  The macOS binary remains unsigned and unnotarized for the reasons
  [Standalone binaries](standalone-binaries.md#signing-and-notarization)
  already discloses -- a separate, not-yet-implemented, paid decision.
- **No installer or package-manager formula performs this verification
  automatically.** A downloader runs the commands above by hand; a
  guided installer script is separate, later scope.

## Next steps

- Review [Release pipeline](release-pipeline.md) for the surrounding
  tag-triggered workflow this job is one part of.
- Review [Standalone binaries](standalone-binaries.md) for the binaries
  this page's checksums and signatures cover.
