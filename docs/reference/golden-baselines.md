---
type: reference
title: Golden ACBOM, diff, and report baselines
tags:
  - reference
  - fixtures
  - testing
created: 2026-08-20
---

# Golden ACBOM, diff, and report baselines

**Status: Implemented test infrastructure.** Three
small synthetic scannable fixtures, and the real CLI's own output
against each of them, are committed under `tests/fixtures/golden/`
and compared on every test run -- any unintended change in
`controlloop bom`/`diff`/`scan`'s own output is caught the moment it
happens, not discovered later by a user. This is test infrastructure
only; it ships no new product behavior.

## What this is

Three fixtures, each a small synthetic repository built fresh into an
isolated directory (never committed as a literal directory tree --
see "Why fixtures are builder functions, not committed directories"
below):

- `empty` -- a bare directory with one inert file. Nothing discovered,
  nothing to evaluate.
- `single-agent` -- one agent invoking one tool, no manifest. A
  minimal non-empty ACBOM, a clean `scan` pass.
- `agent-with-ceiling-breach` -- the same agent/tool shape, plus a
  `controlloop.yaml` capability ceiling that prohibits reaching it: a
  real `policy.capability-ceiling` finding, `deployment_blocked`,
  exit `1`. This is the identical fixture shape [`controlloop scan`'s
  own tests](cli.md#scan) already established -- reused
  rather than reinvented.

For each fixture, `controlloop bom <fixture>` and `controlloop scan
<fixture> --format json`'s own real stdout are committed as
`tests/fixtures/golden/<fixture>/{acbom.json,report.json}`. One
additional diff golden, `diff-empty-to-single-agent/report.json`,
records `controlloop diff` comparing the `empty` and `single-agent`
ACBOM goldens against each other (a two-ACBOM-file comparison, needing
no baseline-resolution machinery of its own).

`tests/test_golden_baselines.py` rebuilds every fixture fresh on
every test run and asserts the result matches its committed golden
exactly, byte for byte. A mismatch's own assertion failure is a
readable unified diff naming the specific changed line -- see it fail
yourself with `uv run pytest tests/test_golden_baselines.py -k
readable_diff` for a self-contained demonstration that never touches
a real golden file.

## Regenerating goldens

One command, run by hand, from the repository root:

```bash
uv run python tests/golden_regenerate.py
```

This is never run implicitly by `pytest` -- the script's own filename
does not match pytest's `test_*.py` collection pattern, and its
regeneration logic additionally sits behind an `if __name__ ==
"__main__":` guard. After running it, **inspect every changed file
under `tests/fixtures/golden/` by hand before committing** -- the
script regenerates the comparison target; it does not itself confirm
the new output is correct. Regenerate only when a change to `bom`,
`diff`, or `scan`'s own output is intentional.

## Why fixtures are builder functions, not committed directories

A fixture "repository" committed as a literal directory tree *inside*
this git repository would have `controlloop.repository.
resolve_repository_root` resolve to controlloop's own enclosing
`.git` -- making the fixture's own `ACBOMDocument.repository.commit`
the actual current commit hash of controlloop itself, which changes on
every commit here. That would make the "golden" ACBOM non-reproducible
by construction. Instead, each fixture is a Python builder function
(`tests/golden_fixtures.py`) that writes its files fresh into an
isolated temporary directory at test/regeneration time, never inside a
git repository -- giving the same deterministic `repository.commit ==
"unknown"` [`controlloop bom`'s own tests](cli.md#bom) already rely on
for a non-git scan target.

The `diff` golden's own `baseline_description` field embeds its two
file-path arguments verbatim, so both the regeneration script and the
comparison test pass paths relative to the current working directory,
never absolute ones -- every verified command in this repository is
already run from the repository root, so a relative path stays stable across
checkouts as long as that convention holds.

## Determinism

Repeated-build stability is proven by direct reuse of the existing
determinism harness (`tests/determinism_support.
assert_stable_digest`) against the `single-agent`
fixture's own `ACBOMDocument` build, five runs in a row. Cross-process,
`PYTHONHASHSEED`, locale, and timezone stability are inherited from
that harness's own already-merged, already-tested guarantee (no
`locale`/`time`/`datetime` call exists anywhere in the canonicalization
path) rather than re-proven per fixture here. A dedicated multi-OS CI
matrix was out of scope when these fixtures were first written. It has
since shipped -- see [Supported platforms](supported-platforms.md) -- so
`uv run pytest`, including this page's own three fixtures, now runs on three real
separate machines (Linux x86_64, Linux arm64, macOS arm64), not only one
developer's own environment plus a single `ubuntu-latest` CI runner.

## Known limitations

- Three fixtures, not an exhaustive corpus. A fourth fixture is a natural,
  not-yet-scheduled extension.
- No CI job beyond the shared `uv run pytest` step in `.github/
  workflows/verify.yml` (called by both `ci.yml` and `release.yml`, and,
  now run across a real three-leg platform matrix -- see
  [Supported platforms](supported-platforms.md)) is added or needed for
  this page's own fixtures -- every CI-blocking check in this repository
  already rides that one job.

## Next steps

- Review [Synthetic fixture corpus](fixture-corpus.md) for the broader
  inventory of adapter- and rule-level test fixtures this page's own
  three end-to-end fixtures are distinct from.
- Review the [CLI reference](cli.md) for `bom`/`diff`/`scan`'s own
  documented behavior.
