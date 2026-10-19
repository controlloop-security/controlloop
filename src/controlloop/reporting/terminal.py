"""Terminal renderer.

This module composes already-computed pieces into one deterministic
terminal report; it computes none of them itself:

- The blast-radius statement (`controlloop.capability.blast_radius`)
  -- `describe_blast_radius` already renders a `None` statement as an
  explicit "no material capability is reachable" line rather than an
  omission, and this module reuses that behavior unmodified rather than
  special-casing it again here.
- The material change summary (`controlloop.diff.material_summary`) --
  optional here (`None` means no baseline comparison was even
  attempted, a materially different fact from a real,
  successfully-computed summary that happens to be empty; see
  `_render_material_changes`'s own docstring).
- Findings (`controlloop.findings`) -- also optional for the same "not
  evaluated" reason: `controlloop.policy.engine` currently
  ships with zero registered rules, so "no findings were produced" and
  "no policy was evaluated at all" are both real, distinct, common
  states today, and conflating them would violate this codebase's
  "Unknown, never omitted" invariant.
- The verdict (`Verdict` below) -- deciding *which* of the five gate
  verdicts applies to a real analysis is `gate`'s job; this module only
  knows how to display whichever `Verdict` a caller supplies.

`controlloop.cli`'s `scan` and `gate` commands both call this module --
`gate` reuses it unmodified for its own `--format text` rendering.
`render_terminal_report` is pure and deterministic given its arguments:
terminal-width and color
detection are both impure, and deliberately live in `controlloop.output`
(`terminal_width`, `OutputStreams.color_enabled`) for a caller to
resolve *before* calling this function, the same pure-compute/impure-
I/O boundary every other compute module in this codebase already
follows.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterable
from enum import StrEnum

from controlloop.capability.blast_radius import (
    BlastRadiusStatement,
    describe_blast_radius,
)
from controlloop.diff.material_summary import (
    MaterialChangeSummary,
    describe_material_change_summary,
)
from controlloop.diff.reduction import (
    compute_capability_reduction_report,
    describe_capability_reduction,
)
from controlloop.findings.models import Finding
from controlloop.findings.rendering import render_finding_text
from controlloop.policy.suppressions import SuppressionRecord, SuppressionStatus
from controlloop.reporting.authority import AuthorityDelta, describe_authority_delta

_DEFAULT_WIDTH = 80
_MIN_WIDTH = 20

#: The CLI style rule: "Use ANSI red only for blocked or failed
#: outcomes." No other color is applied anywhere in this module -- the
#: style rule names no other sanctioned use for this report's content,
#: and every state must already read correctly with no color at all, so
#: nothing here is invented beyond that one explicitly authorized case.
_RED = "\x1b[31m"
_RESET = "\x1b[0m"


class Verdict(StrEnum):
    """The five canonical gate verdicts, in a fixed order and wording.
    See this module's own docstring: computing *which* one applies is
    out of scope here."""

    PASSED = "passed"
    PASSED_WITH_WARNINGS = "passed_with_warnings"
    REVIEW_REQUIRED = "review_required"
    DEPLOYMENT_BLOCKED = "deployment_blocked"
    NOT_EVALUATED = "not_evaluated"


#: The CLI's four stable glyphs (`✓`, `!`, `✕`, `•`), assigned to the
#: five verdicts by severity: a clean pass keeps `✓`; the one truly
#: blocking outcome gets `✕`; the two warning-adjacent outcomes share
#: `!`; the neutral "not evaluated" state reuses `•`, the same glyph
#: `describe_material_change_summary` and `describe_blast_radius`
#: already use for their own neutral "nothing to report" lines.
_VERDICT_GLYPH: dict[Verdict, str] = {
    Verdict.PASSED: "✓",
    Verdict.PASSED_WITH_WARNINGS: "!",
    Verdict.REVIEW_REQUIRED: "!",
    Verdict.DEPLOYMENT_BLOCKED: "✕",
    Verdict.NOT_EVALUATED: "•",
}

#: The five verdict labels, upper-cased to match this codebase's
#: existing glyph-prefixed label convention (`✓ PASSED`, `! WARNING`,
#: `✕ BLOCKED`, `• INFO`).
_VERDICT_LABEL: dict[Verdict, str] = {
    Verdict.PASSED: "PASSED",
    Verdict.PASSED_WITH_WARNINGS: "PASSED WITH WARNINGS",
    Verdict.REVIEW_REQUIRED: "REVIEW REQUIRED",
    Verdict.DEPLOYMENT_BLOCKED: "DEPLOYMENT BLOCKED",
    Verdict.NOT_EVALUATED: "NOT EVALUATED",
}


def _wrap_line(line: str, *, width: int) -> str:
    """Word-wrap one already-composed line to `width` columns,
    preserving its own leading indentation on the first wrapped
    segment and indenting every continuation two columns deeper.
    Deterministic for identical input: `textwrap.wrap` has no
    hidden randomness, locale dependence, or environment lookup of its
    own. An empty or whitespace-only `line` is returned unchanged: its
    stripped content is also empty, so `textwrap.wrap` returns `[]`
    and the final line below falls back to `line` itself -- no special
    case is needed to preserve a deliberate blank separator line."""

    stripped = line.lstrip(" ")
    leading = line[: len(line) - len(stripped)]
    wrapped = textwrap.wrap(
        stripped,
        width=max(width, _MIN_WIDTH),
        initial_indent=leading,
        subsequent_indent=leading + "  ",
        break_long_words=False,
        break_on_hyphens=False,
    )
    return "\n".join(wrapped) if wrapped else line


def _wrap_block(text: str, *, width: int) -> str:
    """Apply `_wrap_line` to every physical line of a (possibly
    already multi-line) block, preserving its line structure."""

    return "\n".join(_wrap_line(line, width=width) for line in text.split("\n"))


def _wrap_lines(lines: Iterable[str], *, width: int) -> str:
    return "\n".join(_wrap_line(line, width=width) for line in lines)


def _colorize(text: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_RED}{text}{_RESET}"


def render_verdict(
    verdict: Verdict, *, color_enabled: bool = False, width: int = _DEFAULT_WIDTH
) -> str:
    """The report's second section: the verdict line. The glyph and
    label are always the same plain text regardless of
    `color_enabled`; only `DEPLOYMENT_BLOCKED` ever gains an ANSI wrapper, and
    wrapping to `width` happens *before* colorizing, so an inserted
    escape sequence is never split across a wrapped line boundary or
    counted toward the visible width."""

    glyph = _VERDICT_GLYPH[verdict]
    label = _VERDICT_LABEL[verdict]
    wrapped = _wrap_line(f"{glyph} {label}", width=width)
    if verdict is Verdict.DEPLOYMENT_BLOCKED:
        return _colorize(wrapped, enabled=color_enabled)
    return wrapped


def _render_material_changes(
    summary: MaterialChangeSummary | None, *, width: int
) -> str:
    """The report's third section. `None` means no baseline comparison was
    attempted at all -- a distinct, honest "not evaluated" state,
    never collapsed into `describe_material_change_summary`'s own
    "no material capability change" line, which means a comparison
    *was* made and found nothing."""

    if summary is None:
        return _wrap_line("• material change: not evaluated", width=width)

    # A change set that only *removes* authority is the one case the
    # generic summary describes poorly: every line reads as a change,
    # and nothing says the direction was safe.
    # `describe_capability_reduction` was built for exactly this.
    reduction = compute_capability_reduction_report(summary)
    if reduction.is_reduction_only:
        return _wrap_lines(describe_capability_reduction(reduction), width=width)

    return _wrap_lines(describe_material_change_summary(summary), width=width)


def _render_findings(findings: tuple[Finding, ...] | None, *, width: int) -> str:
    """The report's fourth section. `None` means no policy was evaluated at
    all (true of every repository today, since
    `controlloop.policy.engine` ships with zero registered rules); an
    empty tuple means policy *was* evaluated and produced nothing --
    the same "not evaluated" versus "confirmed zero" distinction
    `_render_material_changes` draws above."""

    if findings is None:
        return _wrap_line("• findings: not evaluated", width=width)
    if not findings:
        return _wrap_line("• no findings", width=width)
    return "\n\n".join(
        _wrap_block(render_finding_text(finding), width=width) for finding in findings
    )


#: A fixed, human-readable label per
#: `SuppressionStatus` member, since the raw enum value alone
#: (`"ceiling-protected"`) reads less clearly in a terminal report than
#: prose does.
_SUPPRESSION_STATUS_LABEL: dict[SuppressionStatus, str] = {
    SuppressionStatus.ACTIVE: "active",
    SuppressionStatus.EXPIRED: "expired",
    SuppressionStatus.STALE: "stale",
    SuppressionStatus.CEILING_PROTECTED: "ceiling-protected (cannot suppress a "
    "capability-ceiling breach)",
}


def render_suppressions(
    suppressions: tuple[SuppressionRecord, ...], *, width: int = _DEFAULT_WIDTH
) -> str:
    """Render every declared repo-local suppression's own disposition,
    one per line ("listed in every scan and gate result, never hidden")
    -- every declared suppression is shown here regardless of its
    `status`, not only `ACTIVE` ones, since an `EXPIRED`/`STALE`/
    `CEILING_PROTECTED` suppression is exactly the kind of thing a
    repository owner needs to see to avoid suppressions "accumulating
    invisibly".

    Deliberately **not** one of `render_terminal_report`'s own fixed
    four sections -- appended separately by `controlloop.cli`'s
    `scan`/`gate` commands after that function returns, the identical
    pattern `gate`'s own "Completeness enforcement"/"Evidence" trailer
    lines already established, so suppressions never touch that
    already-tested fixed ordering.
    """

    if not suppressions:
        return _wrap_line("Suppressions: none declared", width=width)

    lines = ["Suppressions:"]
    for suppression in suppressions:
        label = _SUPPRESSION_STATUS_LABEL[suppression.status]
        lines.append(
            f"  • {label}  rule={suppression.rule_id}  "
            f"target={suppression.target}  expires={suppression.expires_at}  "
            f'reason="{suppression.reason}"'
        )
    return _wrap_lines(lines, width=width)


def render_terminal_report(
    *,
    blast_radius: BlastRadiusStatement | None,
    verdict: Verdict,
    material_changes: MaterialChangeSummary | None = None,
    findings: tuple[Finding, ...] | None = None,
    authority_delta: AuthorityDelta | None = None,
    color_enabled: bool = False,
    width: int = _DEFAULT_WIDTH,
) -> str:
    """Assemble one deterministic terminal report in a fixed order --
    blast-radius statement, verdict, material changes,
    findings -- from already-computed pieces (see this module's own
    docstring for why each is accepted rather than recomputed). Every
    section is always present, in this exact order: "not evaluated" is
    rendered explicitly rather than a section ever being omitted, so a
    reader can never mistake "nothing to show here" for "this was
    never checked" ("Unknown, never omitted").

    The one exception is the authority statement:
    it is change-only, so a change that hands no agent new power adds
    nothing, and a non-empty one sits between the verdict and the
    material changes, ahead of the findings."""

    sections = [
        _wrap_lines(describe_blast_radius(blast_radius), width=width),
        render_verdict(verdict, color_enabled=color_enabled, width=width),
    ]
    if authority_delta is not None:
        sections.append(
            _wrap_lines(describe_authority_delta(authority_delta), width=width)
        )
    sections.extend(
        [
            _render_material_changes(material_changes, width=width),
            _render_findings(findings, width=width),
        ]
    )
    return "\n\n".join(sections)
