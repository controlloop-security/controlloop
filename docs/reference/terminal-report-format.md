---
type: reference
title: Terminal report format
tags:
  - reference
  - reporting
created: 2026-08-20
---

# Terminal report format

**Status: Available now.** `controlloop.reporting.terminal`, described
below, is implemented and tested library code.
`controlloop.output.terminal_width` and `OutputStreams.color_enabled`
(the impure width/color detection this renderer relies on) are also
implemented and tested. `controlloop scan --format text` and
`controlloop gate --format text` both wire this in as their default
rendering, always passing
`color_enabled=False` -- see [CLI reference](cli.md#scan) and [CLI
reference](cli.md#gate).

## What this is

A reviewer reading a terminal needs to understand the verdict, the
worst consequence, and what to do next -- without color being required
to interpret any of it. `render_terminal_report`
composes four already-computed pieces into one report, in one fixed
order:

1. A [blast-radius statement](diff-output-format.md#blast-radius-statement)
   (`controlloop.capability.blast_radius`) -- the single worst
   reachable action in the analyzed graph, or an explicit "no material
   capability is reachable" line.
2. A `Verdict` -- one of the CLI's five canonical gate verdicts, named
   below.
3. An optional material change summary
   (`controlloop.diff.material_summary`) against a baseline.
4. Optional findings (`controlloop.findings`).

This module computes none of the four itself. Each is computed
elsewhere -- see "What this does not do" below.

## The five verdicts

`Verdict` (`controlloop.reporting.terminal`) names the five canonical
gate verdicts verbatim:

```python
class Verdict(StrEnum):  # controlloop.reporting.terminal
    PASSED = "passed"
    PASSED_WITH_WARNINGS = "passed_with_warnings"
    REVIEW_REQUIRED = "review_required"
    DEPLOYMENT_BLOCKED = "deployment_blocked"
    NOT_EVALUATED = "not_evaluated"
```

Each renders with a stable glyph and an upper-cased label, following
the CLI's stable-symbol convention (`✓ PASSED`, `! WARNING`,
`✕ BLOCKED`, `• INFO`):

| Verdict | Glyph | Rendered label |
| --- | --- | --- |
| `PASSED` | `✓` | `PASSED` |
| `PASSED_WITH_WARNINGS` | `!` | `PASSED WITH WARNINGS` |
| `REVIEW_REQUIRED` | `!` | `REVIEW REQUIRED` |
| `DEPLOYMENT_BLOCKED` | `✕` | `DEPLOYMENT BLOCKED` |
| `NOT_EVALUATED` | `•` | `NOT EVALUATED` |

Deciding *which* verdict applies to a real analysis is `gate`'s job --
`FindingSeverity` deliberately defines no ranking or threshold function
of its own for the same reason. `render_terminal_report` only knows how to
display whichever `Verdict` a caller supplies; `gate` computes it and
appends its own resolved-setting/evidence-path lines afterward, without
this renderer's own fixed section order changing -- see [CLI
reference](cli.md#gate).

## Ordering and honest omission

`render_terminal_report`'s four sections always appear in the fixed
order above, and every section is always present -- never silently
omitted. Where a section's underlying data was never computed at all,
that is rendered as an explicit line rather than an empty gap:

- `blast_radius=None` renders `describe_blast_radius`'s own "no
  material capability is reachable" line (`describe_blast_radius`
  already handles `None` this way; this module reuses it unmodified).
- `material_changes=None` renders `• material change: not evaluated`
  -- distinct from a real, successfully computed
  `MaterialChangeSummary` that happens to be empty, which renders
  `describe_material_change_summary`'s own `• no material capability
  change` line instead.
- `findings=None` renders `• findings: not evaluated` -- distinct from
  a real, empty `findings=()`, which renders `• no findings`.

This "not evaluated" versus "confirmed zero" distinction is the same
"Unknown, never omitted" invariant `controlloop.diff.report.DiffReport`'s
`comparison_scope` field already applies to node/edge comparison.

### The authority statement

The one section that is left out when it has nothing to say is the
[authority statement](authority-statement.md). It is change-only: a
change that hands no agent new power adds nothing, and a non-empty one
appears as an `Authority:` section between the verdict and the material
changes, ahead of the findings.

## No meaning by color alone

Every state's glyph and label text is identical whether or not color
is applied -- color is additive decoration only, never load-bearing.
The CLI's color convention reserves ANSI red for "a blocked or failed
outcome" only; `render_verdict` applies it to
exactly one case, `Verdict.DEPLOYMENT_BLOCKED`, and to no other verdict
or section. Wrapping to the requested width happens *before*
colorizing, so an escape sequence is never split across a wrapped line
boundary or counted toward the visible width.

## Width adaptation and redirection

`render_terminal_report(..., width=...)` word-wraps every rendered
line to `width` columns (`textwrap.wrap`, deterministic, no locale or
environment dependence), preserving each line's own leading indent on
the first wrapped segment. `width` and `color_enabled` are both plain
arguments -- this function performs no terminal detection of its own,
following the same pure-compute/impure-I/O boundary discipline every
other compute module in this codebase already follows:

- `controlloop.output.terminal_width(stream, default=80)` returns the
  real terminal column count for a `stream` attached to a terminal
  (via `shutil.get_terminal_size`, which itself already consults the
  `COLUMNS` environment variable before falling back to a live OS
  query), or `default` for a non-terminal stream -- the same
  "degrade when redirected" rule `OutputStreams.color_enabled` already
  applies to color.
- `OutputStreams.color_enabled()` (not extended by any code here)
  already disables color whenever `NO_COLOR` is present in the
  environment or stdout is not a terminal.

A future caller resolves both *before* calling `render_terminal_report`
-- for example `render_terminal_report(..., width=terminal_width(sys.stdout),
color_enabled=streams.color_enabled())`.

## Determinism

`render_terminal_report` and `render_verdict` are pure functions of
their arguments: identical `blast_radius`, `verdict`, `material_changes`,
`findings`, `color_enabled`, and `width` always produce byte-identical
output. `textwrap.wrap` introduces no hidden randomness, and no field
here is a timestamp, a random ID, or otherwise unstable across runs.

## What this does not do

- Compute a `Verdict` from findings, a material change summary, or a
  policy result -- that is `gate`'s job (implemented in
  `controlloop.cli`'s `_gate_classify`, not in this module).
- Compute the four pieces themselves from a real repository scan --
  `scan` and `gate` each assemble them from a live scan and then call
  `render_terminal_report` to render the result; this module only ever
  displays whatever it is handed.
- Produce JSON or SARIF. This is a terminal-only human renderer;
  `Finding.model_dump_json()` and `finding_to_sarif_result`
  already serve JSON and single-SARIF-result output independently.
- Apply any color beyond the one case the CLI's color convention
  sanctions (`DEPLOYMENT_BLOCKED`, ANSI red). The convention's separate
  suggestion of ANSI blue for "progress and selected paths" is not
  implemented here -- no testable requirement names it, so it is left
  as a disclosed, not-yet-implemented enhancement rather than an
  invented rule.

## Next steps

- Review [Diff output format](diff-output-format.md) for the
  blast-radius statement and material change summary this renderer
  composes.
- Review [Finding model](finding-model.md) for the findings this
  renderer composes.
- Review the [CLI reference](cli.md) for what is implemented today.
