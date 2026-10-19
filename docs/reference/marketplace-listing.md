---
type: reference
title: Action marketplace listing
tags:
  - reference
  - releases
  - ci
created: 2026-08-23
---

# Action marketplace listing

**The GitHub Action has never been published to the GitHub Marketplace.**
This page describes what is prepared for that listing and what still
requires a maintainer's manual action -- nothing here is a claim that
ControlLoop is discoverable from the Marketplace today.

The goal: the GitHub Action is discoverable and installable from the
Marketplace.

## What publishing to the Marketplace actually requires

GitHub Marketplace publication happens through GitHub's own web UI, on
the account that owns the repository, and is a public, effectively
irreversible action once a listing goes live. Nothing in this repository
performs that click -- the same category of action as registering the
PyPI and GHCR names, which is also still pending. What follows is
everything prepared for that action.

## What is already prepared

`action.yml` (repository root) already declares:

- A real, accurate `description` naming the exact behavior (`controlloop
  gate`), the `fetch-depth: 0` requirement, and the pinning
  recommendation.
- `branding: {icon: shield, color: blue}` -- the icon and color GitHub
  renders for the listing and in workflow logs.

**Category:** GitHub Marketplace's primary/secondary category selection
happens in the publish UI itself, not in a repository file, so there is
nothing to encode here. Recommended selection during the actual publish
step: **Security** (primary), **Code quality** (secondary) -- matching
ControlLoop's own positioning as a pre-deployment security product for
agentic software.

## Linked documentation

The listing's long-form body is GitHub Marketplace's own rendering of
this repository's root `README.md`, which now includes a real "GitHub
Action" section with a minimal usage snippet and a link to [The
ControlLoop GitHub Action](github-action.md) -- every input, output, and
the `fetch-depth: 0` requirement in full. Both pages exist and are
accurate as of this page's writing.

## Major-version tag maintenance

**Policy:** consumers should pin to either an exact `vX.Y.Z` tag or a
commit SHA for full reproducibility (this repository's own existing
recommendation, unchanged), or to a floating `vMAJOR` tag (for example
`v1`) to automatically receive every non-breaking update within that
major version -- the standard convention every published GitHub Action's
own consumers already expect (`actions/checkout@v4`,
`astral-sh/setup-uv@v10`).

**Deliberately a manual step performed by a maintainer, not automated
in `release.yml`.** This repository's release workflow carries a
standing, tested invariant: no workflow in this repository ever pushes a
tag itself
(`TestReleaseWorkflowScopeBoundary::test_never_pushes_a_tag_or_calls_uv_publish`
in `tests/test_release_workflow_structure.py`) -- a deliberate
safety boundary against any workflow ever creating or moving tags on its
own, considered and preserved rather than narrowed for this step. (For
the record: a `vMAJOR` tag like `v1` has no dot, so it could never match
this workflow's own `v*.*.*` trigger glob and re-trigger a release --
but the invariant is broader than only self-triggering risk, so it is
kept intact rather than reinterpreted.)

After tagging a real release, a maintainer moves the
corresponding `vMAJOR` tag themselves:

```
git tag -f v1 v1.2.3
git push origin v1 --force
```

No tag has ever been pushed to this repository, so no `vMAJOR` tag exists
yet, and this command has never been run for real.

## Accuracy

Root `README.md`'s "Repository status" section was once stale -- it claimed
repository scanning, adapters, diffs, policies, gates, and CI integration
were "not implemented," which was false (all implemented; only Team-tier
features and OASF wire-format version support remain unimplemented). It was
corrected because that exact file is what a Marketplace listing renders as
its body; a listing built from the prior text would have contradicted itself
(an Action published for CI gating, described by a README claiming CI
integration doesn't exist).

## What this does not do

- **Does not publish anything.** No listing exists; this page prepares
  for one.
- **No PyPI, GHCR, or Homebrew listing** -- separate, not-yet-implemented
  distribution channels, blocked on registering the `controlloop` name
  on each.

## Next steps

- Review [The ControlLoop GitHub Action](github-action.md) for the
  action's own full input/output reference.
- Review [Release pipeline](release-pipeline.md) for the major-version
  tag step in its surrounding workflow context.
