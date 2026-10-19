"""The CLI's exit-code contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class ExitCode(IntEnum):
    """Every terminal condition the CLI can signal to its caller."""

    PASS = 0
    POLICY_FAIL = 1
    INVALID_INPUT = 2
    INCOMPLETE_ANALYSIS = 3
    ENTITLEMENT = 4
    INTERNAL_ERROR = 5


@dataclass(frozen=True, slots=True)
class ExitCodeInfo:
    """One exit code's documented meaning, real trigger conditions, and
    remediation.

    This is the single source of truth `docs/reference/cli.md`'s
    generated exit-code table is rendered from
    (`tests/reference/cli_doc_fixtures.py`'s `render_exit_code_table`)
    -- the doc cannot silently drift from this module, because
    `tests/reference/test_cli_reference_doc.py` regenerates the table from
    here and fails the suite if the committed doc no longer matches.
    """

    meaning: str
    when_it_occurs: str
    remediation: str


#: Every `ExitCode` member's documented meaning, real trigger conditions,
#: and remediation. `tests/reference/test_cli_reference_doc.py` asserts
#: this dict has exactly one entry per `ExitCode` member ("every exit
#: code is documented with when it occurs and what to do about it") -- a
#: future exit code added here without a real
#: `docs/reference/cli.md` update fails that test immediately.
EXIT_CODE_INFO: dict[ExitCode, ExitCodeInfo] = {
    ExitCode.PASS: ExitCodeInfo(
        meaning="Scan completed and gate passed",
        when_it_occurs=(
            "`--help`, `--version`, `init` (generation and `--dry-run`), "
            "`bom` (generation and `--validate`), `diff` (any "
            "successfully computed comparison, empty or not), `scan` (a "
            "clean pass, or a pass with only warning-level findings), "
            "`gate` (verdict `passed` or `passed_with_warnings`)"
        ),
        remediation="Nothing to do -- this is success.",
    ),
    ExitCode.POLICY_FAIL: ExitCodeInfo(
        meaning="Gate failed because findings exceeded policy threshold",
        when_it_occurs=(
            "`scan`, when at least one finding meets or exceeds the "
            "configured severity threshold; `gate`, identically (verdict "
            "`deployment_blocked`)"
        ),
        remediation=(
            "Review the reported findings and either remediate the "
            "capability change, adjust the declared capability ceiling "
            "if the change is intentional and approved, or raise the "
            "configured `severity_threshold` if the finding is a known, "
            "accepted risk -- see [Concrete policy rules](policy-rules.md) "
            "and [Severity, confidence, and "
            "thresholds](policy-thresholds.md)."
        ),
    ),
    ExitCode.INVALID_INPUT: ExitCodeInfo(
        meaning="Configuration or input was invalid",
        when_it_occurs=(
            "A bare invocation, an unknown subcommand, a malformed flag, "
            "an unresolvable repository path, an invalid `bom "
            "--validate` target, an existing `controlloop.yaml` "
            "conflicting with `init`, `init` failing to write the "
            "manifest, any `diff` input/resolution/usage error, any "
            "`scan` input-resolution error, or the identical class of "
            "`gate` input-resolution error, plus an unwritable "
            "`--evidence-path`"
        ),
        remediation=(
            "Read the printed diagnostic message and location; it names "
            "the exact problem (an invalid flag combination, an "
            "unreadable path, a malformed configuration file) without "
            "echoing hostile input content back -- fix the named input "
            "and re-run."
        ),
    ),
    ExitCode.INCOMPLETE_ANALYSIS: ExitCodeInfo(
        meaning="Analysis was incomplete and policy requires completeness",
        when_it_occurs=(
            "`scan` always returns this when analysis is incomplete and "
            "nothing blocks (verdict `review_required`) -- unconditional, "
            "unchanged. `gate` returns this only when incomplete analysis "
            'is combined with `completeness_enforcement = "enforce"`; '
            'under the default `"warn"`, the identical '
            "incomplete analysis is exit `0` instead. A Team `gate` also "
            "returns this (verdict `review_required`) when the change adds "
            "an agent-authority grant the organization has not approved "
            "and its bundle leaves `policy.unsanctioned-agent-component` "
            "at the default require-review. `diff` never returns this."
        ),
        remediation=(
            "Review the `completeness`/diagnostics field naming what "
            "could not be fully analyzed (an adapter failure, a bound "
            "exceeded, an unresolved dynamic registration) and address "
            "it, or explicitly accept the incompleteness by leaving "
            '`completeness_enforcement` at its default `"warn"` -- see '
            "[Incomplete-analysis policy](policy-thresholds.md"
            "#completeness-enforcement). For an unsanctioned "
            "grant, have it approved in the organization's bundle, change "
            "it to match an approved entry, or record an organization "
            "exception -- see [Unsanctioned agent component]"
            "(policy-rules.md#unsanctioned-agent-component)."
        ),
    ),
    ExitCode.ENTITLEMENT: ExitCodeInfo(
        meaning="Team entitlement or authentication failed",
        when_it_occurs=(
            "`gate`, and only when `team_enabled = true`: the project is "
            "not entitled, the project "
            "token was rejected, or the platform could not be reached "
            "after the bounded retry window while `team_fail_mode` is "
            "`closed`. Unreachable on the Community path -- a repository "
            "with Team disabled makes no entitlement check at all, "
            "asserted by test rather than only observed, in "
            "`tests/test_free_public_repository_path.py`."
        ),
        remediation=(
            "Read the printed message: it names which of the three "
            "conditions occurred. For a not-entitled project, check the "
            "subscription and the project's plan in your ControlLoop "
            "organization. For a rejected token, check "
            "`CONTROLLOOP_TEAM_TOKEN` and that it belongs to this "
            "project. For an outage, either wait or set "
            '`team_fail_mode = "open"` to continue through one -- see '
            "[Your first Team gate](../guides/first-team-gate.md). "
            "Setting `team_enabled = false` runs the free Community gate, "
            "which never returns this code."
        ),
    ),
    ExitCode.INTERNAL_ERROR: ExitCodeInfo(
        meaning="Internal scanner error",
        when_it_occurs="Any unhandled exception in any command",
        remediation=(
            "The printed message is deliberately generic (only the "
            "exception's class name, never its own message, which could "
            "carry unsanitized interpolated content) -- re-run with "
            "`--log-level debug` for additional non-sensitive diagnostic "
            "context, and if the problem persists, report it including "
            "the command and repository shape that triggered it (never "
            "raw repository content) per `SECURITY.md`."
        ),
    ),
}
