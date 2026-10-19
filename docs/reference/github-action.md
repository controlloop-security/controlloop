---
type: reference
title: The ControlLoop GitHub Action
tags:
  - reference
  - ci
  - distribution
created: 2026-08-20
---

# The ControlLoop GitHub Action

A team adds ControlLoop to their pull-request checks by pasting a short
block of YAML. This page describes `action.yml` (repository root),
including its SARIF upload and check summary: its inputs, outputs, the
checkout requirement it depends on, and what "pinned" means for it
today.

## Minimal usage

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

      - uses: controlloop-security/controlloop@<tag-or-commit-sha>
```

`security-events: write` is required only if you keep the default
`upload-sarif: true` (below); set `upload-sarif: false` and drop this
permission if your workflow should never attempt a code-scanning
upload. `pull-requests: write` is required only for the
[pull-request comment](#pull-request-comment); without it the comment is
skipped with a notice and nothing else changes.

## The `fetch-depth: 0` requirement

`gate` computes an automatic baseline from the
merge-base between the current commit and the pull request's target
branch, purely through local git -- it needs real, shared commit history
to do that. GitHub Actions' `actions/checkout` defaults to
`fetch-depth: 1` (only the single commit being built), which strips
exactly the history a merge-base needs. Set `fetch-depth: 0` in your own
`actions/checkout` step, as shown above, before this action's own step.

If the checkout is too shallow anyway, `gate` fails clearly rather than
silently skipping the comparison (see [the `gate`
reference](cli.md#gate) for the disclosed distinction this makes from
`scan`): the check fails at exit `2` with a message naming the shallow
clone specifically and the exact remediation (`git fetch --unshallow`, or
`fetch-depth: 0`).

## Inputs

| Input | Default | Behavior |
| --- | --- | --- |
| `path` | `${{ github.workspace }}` | The repository directory to scan -- also where `controlloop.toml` and `controlloop.yaml`, if present, are resolved from (there is no separate configuration-file-path override; both are always resolved relative to this same directory, by existing, unchanged product design). |
| `default-branch` | `""` | Passed to `gate --default-branch` (see [the `gate` reference](cli.md#gate)). Left empty, this action derives it from `$GITHUB_BASE_REF` on a `pull_request` event (the PR's real target branch -- more reliable than `gate`'s own `origin/HEAD` auto-detection, which `actions/checkout` frequently leaves unset); left empty on any other event, `gate` auto-detects as usual. |
| `severity-threshold` | `""` | One of `info`, `low`, `medium`, `high`, `critical`. Left empty, uses the repository's own `controlloop.toml` / `CONTROLLOOP_SEVERITY_THRESHOLD` (product default: `high`). Passed through as `CONTROLLOOP_SEVERITY_THRESHOLD` for this run only -- no new configuration mechanism. |
| `fail-on-incomplete` | `"true"` | Whether an incomplete-analysis verdict (`gate`'s exit code `3`) fails this check. `false` still passes the check but emits a workflow warning annotation naming the condition. Every other verdict (pass, warn, fail) is unaffected. This is an action-level interpretation of `gate`'s own exit-code contract -- see "Interaction with `completeness_enforcement`," below, for how it composes with `gate`'s own separate, product-level completeness setting. |
| `evidence-path` | `evidence.json` | Path, relative to `path`, to write the retainable evidence artifact to. |
| `format` | `text` | `text`, `json`, or `sarif` -- see [the `gate` reference](cli.md#gate). |
| `sarif-path` | `sarif.json` | Path, relative to `path`, to write the SARIF 2.1.0 log document to. Always written, independent of `format` -- used by the upload and check-summary steps below. |
| `upload-sarif` | `"true"` | Whether to attempt uploading the SARIF document to GitHub code scanning. Requires `security-events: write` in the calling workflow. Upload failure degrades to a workflow warning and never affects this check's own pass/fail -- see "SARIF upload and the check summary," below. |
| `pr-comment` | `"true"` | Whether to keep one change-only comment on the pull request with the authority statement -- see [Pull-request comment](#pull-request-comment). Needs `pull-requests: write`. Set `"false"` to turn it off. |
| `github-token` | `${{ github.token }}` | The token the comment step uses, and nothing else. The CLI never sees it. |

## Outputs

| Output | Value |
| --- | --- |
| `verdict` | One of `passed`, `passed_with_warnings`, `review_required`, `deployment_blocked`. |
| `exit-code` | The real exit code `controlloop gate` returned. |
| `evidence-path` | Absolute path to the written evidence artifact. |
| `sarif-path` | Absolute path to the written SARIF log document. |

## Interaction with `completeness_enforcement`

`gate` itself has a separate, product-level `completeness_enforcement`
setting (`controlloop.toml` / `CONTROLLOOP_COMPLETENESS_ENFORCEMENT`):
`warn` (the default) maps incomplete analysis to
`passed_with_warnings`/exit `0`; `enforce` maps it to
`review_required`/exit `3`. This action's own `fail-on-incomplete`
input only ever matters when `gate` actually reaches exit `3` -- under
the product default (`warn`), it rarely fires. The two are independent
and compose correctly: `fail-on-incomplete: true` (this action's own
default) behaves identically to today's default `gate` behavior either
way; `fail-on-incomplete: false` is only meaningful for a repository
that has separately opted into `completeness_enforcement: enforce`
and wants this specific CI check to treat that condition as a warning
instead.

## SARIF upload and the check summary

Every run additionally writes a complete SARIF 2.1.0 document
(`sarif-path`, above) -- always, independent of `format` -- and:

1. **Uploads it to GitHub code scanning** (`github/codeql-action/
   upload-sarif`, a stable `category: controlloop` so repeated runs
   update rather than duplicate results). Upload runs with
   `continue-on-error` internally: if it fails (most commonly because
   code scanning is not enabled for the repository, or a private
   repository lacks GitHub Advanced Security), this action emits a
   workflow warning and the check's own pass/fail is entirely
   unaffected -- it is governed only by the real `gate` verdict.
2. **Writes a check summary** (`$GITHUB_STEP_SUMMARY`): the verdict,
   the [blast-radius statement](diff-output-format.md#blast-radius-statement)
   (read directly out of the SARIF document's own
   `runs[0].properties.controlloop.blastRadius`, embedded there by
   `render_sarif_log` -- see [SARIF export format](sarif-export-format.md)),
   the [authority statement](authority-statement.md) as an **Authority**
   list when the change hands an agent new power (from
   `runs[0].properties.controlloop.authorityDelta`),
   and the evidence path -- visible directly on the pull request's
   checks tab, not only in the raw log.

**Where the upload lands:** an uploaded log appears in the Security tab
only when code scanning is enabled for the repository, which is free for
public repositories and needs GitHub Advanced Security for private ones.
The graceful-degradation path is exercised in
`.github/workflows/action-e2e.yml`.

<a id="pull-request-comment"></a>
## Pull-request comment

**Available now** on `main`. When a pull request gives a coding agent
new power, the Action keeps one comment on the conversation tab with the
[authority statement](authority-statement.md):

```markdown
### ControlLoop: agent authority

**Verdict:** `deployment_blocked`

This pull request gives agents new power:

- This change gives **Claude Code** the power to run `node .github/setup.js`
  on every session start (`.claude/settings.json`, hook `SessionStart`).
  No approval is recorded.
```

How it behaves:

- **One comment per pull request.** It is found by the hidden marker
  `<!-- controlloop:authority-statement -->` in its body and edited in
  place on every later push; a second one is never posted, and nobody
  else's comment is touched.
- **Change-only.** A pull request that changes no agent authority gets no
  comment. If an earlier push did and a later one undoes it, the comment
  is edited to say the pull request no longer changes agent authority;
  it is never deleted silently or left stale.
- **Posted after `gate`, never by the CLI.** The step
  (`action-scripts/pr_comment.py`) reads only the SARIF document `gate`
  wrote and the verdict. Local scanning stays network-free.
- **Skipped, with a notice,** when the calling workflow does not grant
  `pull-requests: write`, on a `pull_request` from a fork (whose token
  cannot write), and on any event that is not a pull request. Any other
  failure to post is a workflow warning. Neither ever changes the
  check's verdict or exit code.
- **Bounded and redacted.** The body holds at most 50 statements (then a
  count) and is built only from the statements and the verdict; it
  passes through the redaction primitive before it is sent.
- **Off switch:** `pr-comment: "false"`.

It is not a Team annotation: annotations posted by the Team platform's
GitHub App, check runs with history, and stored capability diffs stay in
the Team tier. The `action-e2e` workflow proves create, edit in place,
and the empty-delta edit against an intercepting API server.

## The evidence artifact is always uploaded

`gate` writes its evidence artifact unconditionally, for every verdict it
reaches -- including a failing one. This
action uploads that exact file as a workflow artifact
(`actions/upload-artifact`, name `controlloop-evidence`) unconditionally
too, whether or not the check itself passes, so the evidence for *why* a
check failed is always retrievable from the run.

## What "pinned" means for this action today

Pin this action to a tagged release or commit SHA:
`uses: controlloop-security/controlloop@<tag-or-sha>`. GitHub resolves that
reference to this repository's own exact, immutable checkout at that
commit -- the identical pinning contract this repository's own CI already
relies on for `actions/checkout@v7.0.1` and `astral-sh/setup-uv@v10.0.1`.
The action installs the CLI from that same pinned checkout's own committed
`uv.lock` (`uv sync --locked`, run against
`${{ github.action_path }}`) -- never from PyPI, a container registry,
or any other unpinned or "latest" source.

**Disclosed boundary:** this is not zero-network-fetch. Installing `uv`
itself and resolving locked dependencies from PyPI both happen at run
time, deterministically pinned by version and lock hash. A published
PyPI package or container image does not exist yet; once one does,
later work can offer a genuinely network-free variant of this action
without changing its interface.

## Next steps

- Review [the `gate` reference](cli.md#gate) for the command this action
  wraps, including the `--default-branch` option and the shallow-clone
  behavior above.
- Review [Writing a capability ceiling](../guides/capability-ceiling-guide.md)
  for what a real blocking verdict looks like and why.
- Review [Evidence artifact format](evidence-artifact-format.md) for the
  uploaded artifact's own schema.
- Review [SARIF export format](sarif-export-format.md) for the uploaded
  document's own schema and the embedded blast-radius property.
