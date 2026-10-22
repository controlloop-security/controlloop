"""General CLI error envelope and diagnostic model.

`CliDiagnostic` is distinct from `controlloop.acbom.models.Diagnostic`
(tied to graph `Evidence`, part of the versioned ACBOM schema) and from
`controlloop.acbom.completeness`'s incompleteness-specific registry: it
is the CLI's own general-purpose envelope for any failure or non-fatal
condition a command wants to report, independent of whether an ACBOM is
even involved. `controlloop.exit_codes.ExitCode` remains the sole
source of truth for process exit status -- constructing or rendering a
`CliDiagnostic` never touches it; every call site in `controlloop.cli`
chooses its own exit code.

Mirrors `controlloop.acbom.completeness`'s own shape: a closed,
documented code registry, a constructor function that enforces
membership before any model is built, and a deterministic rendering
function -- reusing `controlloop.acbom.models.DiagnosticSeverity` and
`SafeText` rather than inventing parallel types for concepts this
codebase already has one shared vocabulary for.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import DiagnosticCode, DiagnosticSeverity, SafeText

_INVALID_INPUT_CODE = "CLI-INVALID-INPUT"
_INVALID_CONFIG_CODE = "CLI-INVALID-CONFIG"
_INVALID_ACBOM_CODE = "CLI-INVALID-ACBOM"
_NOT_IMPLEMENTED_CODE = "CLI-NOT-IMPLEMENTED"
_INTERNAL_ERROR_CODE = "CLI-INTERNAL-ERROR"
_NONINTERACTIVE_ENVIRONMENT_CODE = "CLI-NONINTERACTIVE-ENVIRONMENT"
# The Team integration's own categories.
# Every one of them is reachable only when `team_enabled` is true.
_TEAM_STATUS_CODE = "CLI-TEAM-STATUS"
_TEAM_ENTITLEMENT_CODE = "CLI-TEAM-ENTITLEMENT"
_TEAM_POLICY_REJECTED_CODE = "CLI-TEAM-POLICY-REJECTED"
_TEAM_EXCEPTION_EXPIRED_CODE = "CLI-TEAM-EXCEPTION-EXPIRED"
_TEAM_EXCEPTION_APPLIED_CODE = "CLI-TEAM-EXCEPTION-APPLIED"
_TEAM_UPLOAD_CODE = "CLI-TEAM-UPLOAD"
_TEAM_UPLOAD_SKIPPED_CODE = "CLI-TEAM-UPLOAD-SKIPPED"

#: The closed set of general CLI diagnostic codes: every code a
#: command in `controlloop.cli` may report today, one per distinct
#: failure category currently reachable. Adding a code here without
#: updating `TestRegistry.test_registry_names_every_known_cli_diagnostic
#: _category` in the test suite fails that test: "adding a code without
#: a test fails the build."
CLI_DIAGNOSTIC_REGISTRY: Mapping[str, str] = {
    _INVALID_INPUT_CODE: (
        "A command-line argument, option, or input file was invalid."
    ),
    _INVALID_CONFIG_CODE: ("The repository configuration file could not be resolved."),
    _INVALID_ACBOM_CODE: (
        "A supplied ACBOM document failed schema-version or structural validation."
    ),
    _NOT_IMPLEMENTED_CODE: ("The requested command is not implemented yet."),
    _INTERNAL_ERROR_CODE: ("An unexpected internal error stopped the command."),
    _NONINTERACTIVE_ENVIRONMENT_CODE: (
        "An interactive confirmation was required but standard output "
        "is not a terminal."
    ),
    _TEAM_STATUS_CODE: (
        "A Team gate reported the state of its platform interaction: "
        "entitlement confirmed, or a policy bundle served from cache."
    ),
    _TEAM_ENTITLEMENT_CODE: (
        "A Team gate stopped because the project is not entitled, its "
        "token was rejected, or the platform was unreachable while "
        "team_fail_mode is closed."
    ),
    _TEAM_POLICY_REJECTED_CODE: (
        "Repository policy attempted to weaken a mandatory organization "
        "rule; the merge refused it and the stronger policy was enforced."
    ),
    _TEAM_EXCEPTION_EXPIRED_CODE: (
        "An organization exception expired, so the finding it covered is "
        "blocking again."
    ),
    _TEAM_EXCEPTION_APPLIED_CODE: (
        "An organization exception covered a finding, so it did not block. "
        "Named on every run so a passing gate says why."
    ),
    _TEAM_UPLOAD_CODE: (
        "A Team gate reported the outcome of submitting its scan "
        "envelope. Never affects the verdict."
    ),
    _TEAM_UPLOAD_SKIPPED_CODE: (
        "A Team gate could not render a scan envelope for this run, so "
        "nothing was submitted. Never affects the verdict."
    ),
}

#: Severity glyph, matching the brand style's recommended forms
#: (`✓ PASSED`, `! WARNING`, `✕ BLOCKED`, `• INFO`) -- output never
#: depends on colour alone.
_SEVERITY_GLYPH: Mapping[DiagnosticSeverity, str] = {
    DiagnosticSeverity.ERROR: "✕",
    DiagnosticSeverity.WARNING: "!",
    DiagnosticSeverity.INFO: "•",
}


class CliDiagnostic(BaseModel):
    """One structured CLI-level failure or non-fatal condition:
    a registered code, a severity, a message, and an optional sanitized
    location. `location` is deliberately `SafeText`, not the ACBOM
    layer's `RelativePath` -- a CLI diagnostic's location can be any
    path a user supplied on the command line, including an absolute one
    outside the repository, and validating it as repository-relative
    would make *reporting* an ordinary user error raise a second,
    unrelated validation error instead.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )

    code: DiagnosticCode
    severity: DiagnosticSeverity
    message: SafeText
    location: SafeText | None = None


def cli_diagnostic(
    *,
    code: str,
    severity: DiagnosticSeverity,
    message: str,
    location: str | None = None,
) -> CliDiagnostic:
    """Return a `CliDiagnostic`, after checking `code` is registered.

    `code` must be a member of `CLI_DIAGNOSTIC_REGISTRY`; membership is
    checked before any model is built, the same order
    `controlloop.acbom.completeness.incomplete_diagnostic` already uses,
    so a caller sees the same clear, unregistered-code error rather than
    a raw pydantic validation error.
    """

    if code not in CLI_DIAGNOSTIC_REGISTRY:
        raise ValueError(f"{code!r} is not a registered CLI diagnostic code")

    return CliDiagnostic(
        code=code, severity=severity, message=message, location=location
    )


def render_text(diagnostic: CliDiagnostic) -> str:
    """Return `diagnostic`'s brand-consistent, glyph-prefixed text line:
    the single rendering every retrofitted call site in `controlloop.cli`
    uses, so the same model always produces the same observable line
    regardless of which command constructed it.

    A future machine output format (JSON, SARIF) serializes the same
    `CliDiagnostic` through its own ordinary pydantic
    `model_dump_json()` -- this function is deliberately the only place
    that knows about the glyph convention, so a second format never has
    to reinvent or duplicate it ("serializes identically in every output
    format").
    """

    glyph = _SEVERITY_GLYPH[diagnostic.severity]
    label = diagnostic.code.removeprefix("CLI-").replace("-", " ")
    line = f"{glyph} {label}  {diagnostic.message}"
    if diagnostic.location is not None:
        line = f"{line} ({diagnostic.location})"
    return line


def sort_key(diagnostic: CliDiagnostic) -> tuple[str, str, str]:
    """Deterministic ordering for a collection of diagnostics:
    by code, then location (empty sorts first), then message -- the
    same `(code, path)`-first shape `controlloop.repository.
    summarize_skips` and `controlloop.acbom.completeness.
    completeness_summary` already use for their own diagnostic
    collections."""

    return (diagnostic.code, diagnostic.location or "", diagnostic.message)
