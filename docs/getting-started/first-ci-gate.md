---
type: guide
title: "Quickstart: your first CI gate"
tags:
  - getting-started
  - ci
created: 2026-10-23
---

# Quickstart: your first CI gate

`scan` is what you run at your desk. `gate` is the same analysis for CI:
one verdict, one exit code, and an evidence artifact every time. This
guide adds it to a repository and shows it blocking a real change.

## What the gate does on a pull request

1. Compares the pull request with its target branch, through local git,
   and works out which capabilities the change adds or removes.
2. Evaluates every rule in the rule pack, and any suppressions the
   repository's `controlloop.yaml` declares.
3. Returns one of four verdicts: pass, pass with warnings, review
   required, or deployment blocked, as exit code `0`, `0`, `1` or `1`
   (`2` for a usage error, `3` for an incomplete analysis with nothing
   blocking).
4. Writes `evidence.json`, a record of what it saw and decided that you
   can keep.

It never prompts, never reads standard input, and makes no network
request, so it needs no account and no secret.

## 1. On GitHub: add the Action

Create `.github/workflows/controlloop.yml`:

```yaml
name: ControlLoop

on:
  pull_request:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0

      - uses: controlloop-security/controlloop@v0.1.1
```

Two lines matter more than they look:

- `fetch-depth: 0`. The gate compares the pull request with its target
  branch through git history, and the default shallow checkout has none.
  Without it the check fails at exit `2` with a message naming the fix.
- `pull-requests: write` lets the Action post one comment on the pull
  request explaining the change in plain words. `security-events: write`
  lets it upload findings to the repository's Security tab. Drop either
  permission and that one feature is skipped with a notice; the check
  itself is unaffected.

Every input (path, severity threshold, evidence and SARIF paths) is in
[the GitHub Action reference](../reference/github-action.md).

## 2. Watch it block a change

Open a pull request that widens an agent's authority. If you want to see
it before touching your own repository, the public
[reference agent](https://github.com/controlloop-security/controlloop-reference-agent)
keeps such a change on the branch `scenario/capability-expansion`: it adds
a bulk-refund tool, a bulk-refund endpoint, and an IAM statement that
grants disbursement permissions. Running the gate against that branch
locally, recorded on 2026-10-23 with ControlLoop 0.1.1:

```bash
git clone https://github.com/controlloop-security/controlloop-reference-agent
git -C controlloop-reference-agent switch -c capability-expansion origin/scenario/capability-expansion
controlloop gate controlloop-reference-agent/scenarios/order-support-agent --default-branch main --evidence-path evidence.json
```

```text
! WORST REACHABLE  destructive-action: widgetworks-order-support-agent can
  invoke Bulk refund orders

✕ DEPLOYMENT BLOCKED

• material change: not evaluated

✕ HIGH     policy.destructive-or-financial-action: Agent gained new direct
  invokes access to 'Bulk refund orders', classified as destructive-action and
  financial-action.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Look up an order' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Reply to customer' is reachable but
  not declared in controlloop.yaml.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Issue a refund' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'Bulk refund orders' is reachable but
  not declared in controlloop.yaml.
    at agent-card.json

Suppressions: none declared

Completeness enforcement: warn (default)
Evidence: evidence.json
```

Exit code `1`. On GitHub the same run fails the `ControlLoop` check, posts
one comment that says the change gives the agent the power to issue bulk
refunds, and lists the `HIGH` finding under the Security tab. The same
command on `main` passes with exit `0`: the gate objects to what the
pull request adds, not to the agent having refunds at all.

## 3. Decide what to do with a block

- **Change the pull request** so the agent does not gain the authority,
  and the check passes on the next push.
- **Approve it on purpose.** Add a suppression to `controlloop.yaml` with
  the rule, the finding, a written reason and an expiry date
  ([expiring suppressions](../reference/suppressions.md)). The gate
  reports every suppression it applies, and blocks again when one
  expires.
- **Declare what the tool does.** Many first findings are
  `policy.undeclared-tools`: the repository never said what its tools can
  do. `controlloop init .` drafts the declarations from what is in the
  repository; review them and commit `controlloop.yaml`.

Whatever you choose, `evidence.json` records the verdict, the findings,
the suppressions applied and the versions of the rule pack and the CLI
that decided it ([format](../reference/evidence-artifact-format.md)).

## 4. On any other CI system

The gate is one command. Install the CLI in the job, check out with full
history, and run it with the target branch named:

```bash
uv tool install controlloop
controlloop gate . --default-branch main --evidence-path evidence.json
```

Keep `evidence.json` as a job artifact. Or use the container image
instead of an install (available from the first release after this page
was written; see [Container image](../reference/container-image.md)):

```bash
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  ghcr.io/controlloop-security/controlloop:<version> \
  gate /work --default-branch main --evidence-path /work/evidence.json
```

`--user` runs the container as the job's own user so it can write
`evidence.json` into the checkout.

A GitLab CI job, as one example:

```yaml
controlloop:
  image: python:3.12
  variables:
    GIT_DEPTH: 0
  script:
    - pip install uv && uv tool install controlloop
    - export PATH="$HOME/.local/bin:$PATH"
    - controlloop gate . --default-branch "$CI_DEFAULT_BRANCH" --evidence-path evidence.json
  artifacts:
    when: always
    paths: [evidence.json]
```

The exit code is the verdict, so the job fails exactly when the gate
blocks or asks for review.

## 5. Before every commit, locally

The [pre-commit hook](../reference/pre-commit-hook.md) runs the same gate
on your machine before a commit lands, so the first time you see a block
is not in CI.

## Next steps

- [The GitHub Action reference](../reference/github-action.md) for every
  input and output, the pull-request comment and the SARIF upload.
- [Severity, confidence and thresholds](../reference/policy-thresholds.md)
  to tune what blocks.
- [Your first Team gate](../guides/first-team-gate.md) to apply your
  organization's policy and approvals across repositories.
