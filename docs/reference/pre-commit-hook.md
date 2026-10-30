---
type: reference
title: The pre-commit hook
tags:
  - reference
  - distribution
  - ci
created: 2026-08-20
---

# The pre-commit hook

A developer runs the same gate locally before a push, so a blocking
capability change is caught before CI rather than after. This page
describes `.pre-commit-hooks.yaml` and `scripts/pre-commit-gate.sh`
(repository root): the manifest, its prerequisites,
its documented baseline strategy, its documented time budget, and how it
stays in verdict-parity with CI.

**Status: implemented, real-tested.** `.pre-commit-hooks.yaml` validates
against [pre-commit](https://pre-commit.com)'s own official manifest
schema and was exercised end to end with `pre-commit try-repo` while this
page was written. Pin `rev:` to a release tag (`v0.1.1` through
`v0.6.3` exist) or a commit SHA.

## Minimal usage

```yaml
repos:
  - repo: https://github.com/controlloop-security/controlloop
    rev: v0.6.3  # a release tag or commit SHA, never an unpinned/"latest" ref
    hooks:
      - id: controlloop-gate
```

Then:

```bash
pre-commit install
```

## Prerequisite: `uv` on `PATH`

The hook's own entry script, `scripts/pre-commit-gate.sh`, installs and
runs ControlLoop from this hook repository's own pinned checkout using
[`uv`](https://docs.astral.sh/uv/) -- the identical mechanism the
[ControlLoop GitHub Action](github-action.md) (`action.yml`) already
uses (`uv sync --locked --all-groups` at the repository root, then
`uv run controlloop ...`). `uv` (along with Python 3.12 and Git) is
already this repository's only verified current CLI prerequisite (see
[CLI reference](cli.md)); the hook adds no new one. It uses
`language: script` in `.pre-commit-hooks.yaml` rather than
`language: python` so the hook runs the CLI from the locked
environment `uv` builds, with the same pinned dependencies as CI,
instead of whatever `pip install .` would resolve.

## Baseline strategy

The hook passes no `--baseline` or `--default-branch` override to
`controlloop gate` -- it resolves a baseline exactly the way a plain
local `gate` invocation, or the GitHub Action with no `default-branch`
input, already does: a baseline committed at
`.controlloop/baseline.json` takes precedence; otherwise the merge-base
of the default branch is resolved and scanned through local git alone;
otherwise the hook proceeds with no baseline comparison. See
[`gate`](cli.md#gate) for the complete resolution order. This is not a
new baseline mechanism -- it is the hook simply not overriding the one
`gate` already has.

## Evidence artifact handling

Every hook run writes ControlLoop's retainable evidence artifact to an
isolated `mktemp -d` path, outside the repository being committed to,
and removes it when the hook exits. [`gate`](cli.md#gate)'s own
documentation discloses that writing `--evidence-path` *inside* a
scanned tree changes the next scan's own `repository.root_digest` (and
therefore its ACBOM digest) -- a detail that matters far more for a hook
invoked on every commit than for a single CI job, so the hook
deliberately never writes there. If you want to retain a hook run's
evidence, capture it from the CI job's own upload instead (see [the
GitHub Action's evidence-artifact upload](github-action.md)).

## Documented time budget

Real, measured warm runs of `scripts/pre-commit-gate.sh` against this
codebase's own established representative small-repository fixture
(`golden_fixtures.py`'s `single-agent` shape) were
consistently under 1.5 seconds when the hook was written --
dominated by one dependency audit and one `controlloop gate`
invocation, both already using `uv`'s local cache. `tests/
test_pre_commit_hook.py`'s `TestDocumentedTimeBudget` asserts a real,
timed invocation stays under 15 seconds (roughly 10x headroom over the
observed reality, the same proportionate-headroom approach
`docs/reference/fixture-corpus.md` already established for this
repository's own CI job budget), and runs on every pull request as part
of the same `cli` job `.github/workflows/ci.yml` already runs.

## Verdict parity with CI

The hook's own exit code is exactly `controlloop gate`'s exit code --
nothing in `scripts/pre-commit-gate.sh` remaps, swallows, or
reinterprets it. `tests/test_pre_commit_hook.py`'s
`TestSameVerdictAsCi` proves this concretely: it hashes the real,
written evidence-artifact bytes from both a real invocation of the
hook's own script and a direct `gate` invocation (the "CI path") against
the identical tree and configuration, for both a clean pass and a
blocking verdict, and asserts they are byte-identical -- not merely
"the same verdict word," the same artifact.

## Known limitations

- `language: script` requires `uv` already on the developer's own
  `PATH`; nothing installs it for them.
- The hook always runs (`always_run: true`, `pass_filenames: false`) --
  it evaluates the whole repository's current capability graph on every
  commit, not only files pre-commit would otherwise select, matching
  `gate`'s own whole-repository scope. A large monorepo may want a
  narrower invocation strategy in the future; none is implemented today.

## Next step

See [CLI reference](cli.md) for `gate`'s complete flag and exit-code
contract, or [the ControlLoop GitHub Action](github-action.md) for the
CI-side counterpart this hook stays in verdict parity with.
