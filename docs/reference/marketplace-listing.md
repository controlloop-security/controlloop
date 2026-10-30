---
type: reference
title: Action marketplace listing
tags:
  - reference
  - releases
  - ci
created: 2026-08-23
updated: 2026-10-30
---

# Action marketplace listing

**The GitHub Action is not listed on GitHub Marketplace yet.** It works
today from any workflow (`uses: controlloop-security/controlloop@v0.6.0`);
a listing only makes it discoverable from Marketplace search. This page
records what is prepared and the steps a maintainer takes to publish it.

## What GitHub requires

From GitHub's [publishing guide](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace):

| Requirement | State in this repository |
| --- | --- |
| The repository is public | Yes |
| One action metadata file, at the root | `action.yml` |
| A unique `name` that matches no existing action, category, user, or organization | `ControlLoop gate` |
| The owning account accepts the GitHub Marketplace Developer Agreement | A maintainer does this once, in the publish form |
| Two-factor authentication on the publishing account | Required when the release is published |

`action.yml` also declares `branding: {icon: shield, color: blue}`, the
icon and color Marketplace shows on the listing and in workflow logs.
The listing's body is this repository's `README.md`: it opens with the
30-second demo and has a "Run it as a GitHub Action" section linking to
[The ControlLoop GitHub Action](github-action.md), which lists every
input, output, and the `fetch-depth: 0` requirement.

## Publish it

Publishing happens in GitHub's web UI on an account that can manage
releases for `controlloop-security/controlloop`. It is public, and the
listing stays up until a maintainer removes it.

1. Open the release to list, for example
   `https://github.com/controlloop-security/controlloop/releases/tag/v0.6.0`,
   and choose **Edit** (for a new release, start from **Draft a new
   release**).
2. Under **Release action**, check **Publish this Action to the GitHub
   Marketplace**. The first time, GitHub asks the account to accept the
   Marketplace Developer Agreement; accept it, then return to the form.
3. Wait for the metadata check to say **Everything looks good!**
4. Choose the categories: **Security** as the primary, **Code quality** as
   the secondary. These match ControlLoop's position as a pre-deployment
   security check for agentic software.
5. Keep the existing tag and title, choose **Update release** (or
   **Publish release**), and complete the two-factor prompt.
6. Check the listing at
   `https://github.com/marketplace/actions/controlloop-gate`.

Every later release that should appear on Marketplace needs the same
checkbox when it is published.

## Major-version tag maintenance

**Policy:** consumers should pin to either an exact `vX.Y.Z` tag or a
commit SHA for full reproducibility, or to a floating `vMAJOR` tag (for
example `v1`) to receive every non-breaking update within that major
version -- the convention Marketplace users expect
(`actions/checkout@v4`, `astral-sh/setup-uv@v10`).

**Deliberately a manual step performed by a maintainer, not automated
in `release.yml`.** This repository's release workflow carries a
standing, tested invariant: no workflow in this repository ever pushes a
tag itself
(`TestReleaseWorkflowScopeBoundary::test_never_pushes_a_tag_or_calls_uv_publish`
in `tests/test_release_workflow_structure.py`) -- a deliberate
safety boundary against any workflow creating or moving tags on its
own. (A `vMAJOR` tag like `v1` has no dot, so it could never match this
workflow's own `v*.*.*` trigger glob and re-trigger a release -- but the
invariant is broader than self-triggering risk, so it is kept intact.)

Release tags `v0.1.1` through `v0.6.0` exist. No floating tag exists yet,
and none is needed before 1.0: during `0.x` every minor release may
change behavior, so consumers should pin an exact tag. From `v1.0.0` on,
after tagging a release, a maintainer moves the major tag themselves:

```
git tag -f v1 v1.2.3
git push origin v1 --force
```

## Next steps

- Review [The ControlLoop GitHub Action](github-action.md) for the
  action's own full input/output reference.
- Review [Release pipeline](release-pipeline.md) for the major-version
  tag step in its surrounding workflow context.
