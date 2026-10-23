---
type: reference
title: Container image
tags:
  - reference
  - distribution
created: 2026-10-23
---

# Container image

The release pipeline publishes a container image of the CLI to the GitHub
Container Registry, `ghcr.io/controlloop-security/controlloop`, for every
tagged release from the first one cut after this page was added. It runs
`scan`, `gate`, `diff`, `bom`, `init` and `rules` with nothing installed on
the host but a container runtime. Until that first release is tagged, no
image exists under that name; this page describes the pipeline, not a
download that is already there.

## Pull and run

Mount the repository to scan at `/work`. Scanning needs no network, so
disable it:

```bash
docker run --rm --network none \
  -v "$PWD:/work:ro" \
  ghcr.io/controlloop-security/controlloop:<version> scan /work
```

`gate` writes an evidence artifact, so mount the repository writable, or
point `--evidence-path` at a separate writable mount:

```bash
docker run --rm --network none \
  -v "$PWD:/work" \
  ghcr.io/controlloop-security/controlloop:<version> \
  gate /work --default-branch main --evidence-path /work/evidence.json
```

Every option is the same as the installed command's; see the
[CLI reference](cli.md). The image's entrypoint is `controlloop`, so the
first argument is the subcommand.

## Tags, and why there is no `latest`

Each release is tagged by its exact version (`0.2.0`), and the release
notes record the image digest. Pull by version, or by digest for a build
that can never change underneath you:

```bash
docker pull ghcr.io/controlloop-security/controlloop@sha256:<digest from the release notes>
```

No moving tag (`latest`, `0`, `0.2`) is published or documented. A CI job
that pinned a moving tag would change behavior on a day nobody edited it,
which is the opposite of what a deterministic gate is for.

## What is in the image, and what is not

Built from the repository's `Dockerfile` in two stages:

- The builder stage installs the locked dependency set with `uv sync
  --locked`, the same lockfile every other install path uses.
- The published stage starts again from the bare Python base image and
  copies that environment in. It contains no `uv`, no `pip`, no compiler
  and no source tree; `git` is added, because `diff`, `scan` and `gate`
  resolve the merge-base baseline through local git.
- It runs as user `10001`, never root, with `/work` as the working
  directory.
- The Python base image is pinned by digest and `uv` by exact version, so
  two builds of the same commit start from the same bytes. The published
  stage applies Debian's security updates on top, so a fix shipped since
  the digest was pinned is in the image.

The image makes no network request when it runs. CI proves it on every
pull request by running a real scan with `--network none`
(`scripts/container-smoke.sh`), and the release pipeline runs the same
script before pushing.

## Architectures

`linux/amd64` and `linux/arm64`, as one multi-architecture image. On an
Apple Silicon Mac, Docker selects the arm64 image.

## How a release publishes it

The `publish-container` job in `.github/workflows/release.yml` runs after
the GitHub Release exists, and only if the tag's full verification suite
and changelog gate passed:

1. Build the `linux/amd64` image and run `scripts/container-smoke.sh`
   against it.
2. Scan it for known vulnerabilities with Trivy. A critical vulnerability
   with an available fix fails the job, and nothing is pushed; the remedy
   is to bump the base image digest in the `Dockerfile`. A critical
   vulnerability the distribution has no fix for (the base image carries
   a few such entries at any time, in packages the CLI never calls) is
   printed in the job log and does not block, because nothing the
   pipeline can do removes it.
3. Build the multi-architecture image and push it, tagged with the exact
   version, using the workflow's own `GITHUB_TOKEN` (`packages: write`).
   No registry password is stored anywhere.
4. Attest the pushed image's digest with GitHub's build-provenance
   attestation, the same keyless Sigstore attestation every other release
   artifact carries (see [Release verification](release-verification.md)).
5. Write the digest to the run summary.

To verify an image's provenance:

```bash
gh attestation verify oci://ghcr.io/controlloop-security/controlloop:<version> \
  --repo controlloop-security/controlloop
```

## The GitHub Action

The [GitHub Action](github-action.md) installs the CLI with `uv` from its
own pinned checkout and does not use this image. Moving it to the image is
a separate change.

## Next steps

- [Installation](../getting-started/installation.md) for every install
  path side by side.
- [Release pipeline](release-pipeline.md) for the whole release flow.
