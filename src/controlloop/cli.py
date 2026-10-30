"""Command-line entry point for ControlLoop."""

import json
import os
import textwrap
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from controlloop import __version__, redaction
from controlloop.acbom import (
    ACBOMDocument,
    Generator,
    completeness_summary,
    load_acbom_document,
    serialize_document,
)
from controlloop.acbom.models import DiagnosticSeverity
from controlloop.acbom.serialization import canonical_json_bytes
from controlloop.adapters import (
    AGENT_HOST_DOCUMENTATION_SNAPSHOTS,
    SUPPORTED_OASF_VERSIONS,
)
from controlloop.baseline import (
    CONVENTIONAL_BASELINE_RELATIVE_PATH,
    ApprovalProvenance,
    BaselineIntegrityError,
    BaselineResolutionError,
    MergeBaseResolutionError,
    NoGitHistoryError,
    build_acbom_at_revision,
    build_merge_base_acbom,
    checked_out_branch,
    resolve_baseline,
    resolve_merge_base,
    resolve_revision_commit,
)
from controlloop.bom import build_acbom_document
from controlloop.capability import (
    BlastRadiusStatement,
    EffectiveAuthorityEntry,
    compute_blast_radius,
    compute_effective_authority,
    describe_blast_radius,
)
from controlloop.config import (
    CONFIG_FILENAME,
    ConfigError,
    ResolvedConfig,
    load_config,
)
from controlloop.diagnostics import cli_diagnostic, render_text
from controlloop.diff import (
    CURRENT_DIFF_REPORT_SCHEMA_VERSION,
    CURRENT_DIFF_SCHEMA_VERSION,
    BaselineOrigin,
    ChangeKind,
    ComparisonScope,
    DiffReport,
    DiffResult,
    MaterialChangeSummary,
    compute_diff,
    compute_material_change_summary,
    diff_effective_authority,
)
from controlloop.diff.authority import AuthorityDelta
from controlloop.exit_codes import ExitCode
from controlloop.findings import Finding
from controlloop.manifest import (
    ManifestDocument,
    ManifestValidationError,
    load_manifest,
    render_draft_manifest,
)
from controlloop.manifest.approvals import active_approvals
from controlloop.manifest.models import Approval
from controlloop.output import NonInteractiveEnvironmentError, OutputStreams
from controlloop.policy import (
    ActionSource,
    CompletenessEnforcement,
    EvaluationResult,
    GateVerdict,
    PolicyConfig,
    PolicyConfigError,
    RuleContext,
    SanctionContext,
    SuppressionOutcome,
    apply_suppressions,
    evaluate_gate,
    finding_action,
    resolve_policy_config,
    rule_pack_fingerprint,
    validate_disabled_rules,
)
from controlloop.policy import evaluate as engine_evaluate
from controlloop.policy.authority_scope import without_agent_authority
from controlloop.policy.rulepack import CURRENT_RULE_PACK
from controlloop.policy.rules import (
    AGENT_HOOK_COMMAND_CHANGE_RULE_ID,
    AGENT_SANDBOX_WEAKENED_RULE_ID,
    ALL_RULES,
    BROAD_PERMISSION_RULE_ID,
    CAPABILITY_CEILING_RULE_ID,
    COMPONENT_SELF_GRANT_RULE_ID,
    COMPONENT_SHELL_EXECUTION_RULE_ID,
    CREDENTIALED_REMOTE_MCP_SERVER_RULE_ID,
    DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE_ID,
    EXFILTRATION_TRIANGLE_RULE_ID,
    HARDCODED_SECRETS_RULE_ID,
    HOOK_SCRIPT_CHANGED_RULE_ID,
    MCP_SERVER_IDENTITY_CHANGE_RULE_ID,
    MISSING_ACTION_LOGGING_RULE_ID,
    OVERPRIVILEGED_AGENT_WORKFLOW_RULE_ID,
    PERMISSION_BYPASS_FROM_PROJECT_RULE_ID,
    SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE_ID,
    SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE_ID,
    UNAUTHORIZED_DELEGATION_RULE_ID,
    UNDECLARED_TOOLS_RULE_ID,
    UNPINNED_AGENT_COMPONENT_RULE_ID,
    UNRESOLVED_DYNAMIC_REGISTRATION_RULE_ID,
    UNSANCTIONED_AGENT_COMPONENT_RULE_ID,
    WIDENED_PERMISSION_RULE_RULE_ID,
    WORKSPACE_SCOPE_EXPANSION_RULE_ID,
    agent_hook_command_change_findings,
    agent_sandbox_weakened_findings,
    broad_permission_findings,
    capability_ceiling_findings,
    component_self_grant_findings,
    component_shell_execution_findings,
    credentialed_remote_mcp_server_findings,
    destructive_or_financial_action_findings,
    exfiltration_triangle_findings,
    hardcoded_secrets_findings,
    hook_script_changed_findings,
    mcp_server_identity_change_findings,
    missing_action_logging_findings,
    overprivileged_agent_workflow_findings,
    permission_bypass_from_project_findings,
    secret_exposed_to_untrusted_agent_run_findings,
    sensitive_write_without_approval_findings,
    unauthorized_delegation_findings,
    undeclared_tools_findings,
    unpinned_agent_component_findings,
    unresolved_dynamic_registration_findings,
    unsanctioned_agent_component_findings,
    widened_permission_rule_findings,
    workspace_scope_expansion_findings,
)
from controlloop.policy.rules._shared import documentation_url
from controlloop.reporting import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    CURRENT_REPORT_SCHEMA_VERSION,
    EvidenceArtifact,
    EvidenceVersions,
    ReportVersions,
    ScanReport,
    Verdict,
    compute_authority_delta,
    describe_authority_delta,
    render_cyclonedx,
    render_sarif_log,
    render_suppressions,
    render_terminal_report,
)
from controlloop.repository import (
    RepositoryRoot,
    RepositoryRootError,
    TraversalBounds,
    resolve_repository_root,
)
from controlloop.team import pipeline as team_pipeline
from controlloop.team.client import PlatformClient
from controlloop.team.components import judge_delta
from controlloop.team.config import TeamConfig, TeamConfigError, resolve_team_config
from controlloop.team.envelope import EnvelopeRenderError, render_envelope
from controlloop.team.evidence import FindingActionRecord
from controlloop.team.exceptions import ExceptionOutcome, ExceptionState
from controlloop.team.policy import apply_severity_floors
from controlloop.team.transport import UrllibTransport
from controlloop.verbosity import (
    LogFormat,
    LogLevel,
    OperatorLog,
    VerbosityError,
    resolve_log_format,
    resolve_log_level,
)

#: Maps each `ALL_RULES` member's own `id` to its module's `findings()`
#: function -- keyed by the real `RULE_ID` constant each rule module
#: exports, not by list position, so this pairing cannot silently drift
#: if `ALL_RULES`'s own order ever changes.
_RULE_FINDINGS_BY_ID: dict[str, Callable[[RuleContext], tuple[Finding, ...]]] = {
    UNDECLARED_TOOLS_RULE_ID: undeclared_tools_findings,
    DESTRUCTIVE_OR_FINANCIAL_ACTION_RULE_ID: destructive_or_financial_action_findings,
    BROAD_PERMISSION_RULE_ID: broad_permission_findings,
    SENSITIVE_WRITE_WITHOUT_APPROVAL_RULE_ID: sensitive_write_without_approval_findings,
    MISSING_ACTION_LOGGING_RULE_ID: missing_action_logging_findings,
    UNAUTHORIZED_DELEGATION_RULE_ID: unauthorized_delegation_findings,
    UNRESOLVED_DYNAMIC_REGISTRATION_RULE_ID: unresolved_dynamic_registration_findings,
    HARDCODED_SECRETS_RULE_ID: hardcoded_secrets_findings,
    CAPABILITY_CEILING_RULE_ID: capability_ceiling_findings,
    EXFILTRATION_TRIANGLE_RULE_ID: exfiltration_triangle_findings,
    UNPINNED_AGENT_COMPONENT_RULE_ID: unpinned_agent_component_findings,
    MCP_SERVER_IDENTITY_CHANGE_RULE_ID: mcp_server_identity_change_findings,
    OVERPRIVILEGED_AGENT_WORKFLOW_RULE_ID: overprivileged_agent_workflow_findings,
    COMPONENT_SELF_GRANT_RULE_ID: component_self_grant_findings,
    AGENT_HOOK_COMMAND_CHANGE_RULE_ID: agent_hook_command_change_findings,
    WIDENED_PERMISSION_RULE_RULE_ID: widened_permission_rule_findings,
    PERMISSION_BYPASS_FROM_PROJECT_RULE_ID: permission_bypass_from_project_findings,
    UNSANCTIONED_AGENT_COMPONENT_RULE_ID: unsanctioned_agent_component_findings,
    AGENT_SANDBOX_WEAKENED_RULE_ID: agent_sandbox_weakened_findings,
    SECRET_EXPOSED_TO_UNTRUSTED_AGENT_RUN_RULE_ID: (
        secret_exposed_to_untrusted_agent_run_findings
    ),
    CREDENTIALED_REMOTE_MCP_SERVER_RULE_ID: credentialed_remote_mcp_server_findings,
    WORKSPACE_SCOPE_EXPANSION_RULE_ID: workspace_scope_expansion_findings,
    COMPONENT_SHELL_EXECUTION_RULE_ID: component_shell_execution_findings,
    HOOK_SCRIPT_CHANGED_RULE_ID: hook_script_changed_findings,
}

app = typer.Typer(
    add_completion=False,
    help="Inspect and gate AI agent capabilities.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)


def _report(
    code: str,
    message: str,
    *,
    severity: DiagnosticSeverity = DiagnosticSeverity.ERROR,
    location: str | None = None,
) -> None:
    """Print one `CliDiagnostic` to stderr as its brand-consistent text
    line. Never touches the exit code -- every call site still raises
    its own `typer.Exit` separately, exactly as before this helper
    existed."""

    diagnostic = cli_diagnostic(
        code=code, severity=severity, message=message, location=location
    )
    typer.echo(render_text(diagnostic), err=True)


_MAX_FILE_SIZE_BYTES_OPTION = typer.Option(
    "--max-file-size-bytes",
    help="Override the per-file size bound (bytes) used by repository "
    "discovery. Takes precedence over the repository configuration file "
    "and the environment.",
)
_MAX_TOTAL_BYTES_OPTION = typer.Option(
    "--max-total-bytes",
    help="Override the total-bytes-read bound used by repository "
    "discovery. Takes precedence over the repository configuration file "
    "and the environment.",
)
_MAX_FILE_COUNT_OPTION = typer.Option(
    "--max-file-count",
    help="Override the total-file-count bound used by repository "
    "discovery. Takes precedence over the repository configuration file "
    "and the environment.",
)
_MAX_DEPTH_OPTION = typer.Option(
    "--max-depth",
    help="Override the traversal-depth bound used by repository "
    "discovery. Takes precedence over the repository configuration file "
    "and the environment.",
)
_LOG_LEVEL_OPTION = typer.Option(
    "--log-level",
    help="Set the operator diagnostic verbosity: quiet, default, verbose, "
    "or debug. Also selectable via CONTROLLOOP_LOG_LEVEL. Never changes "
    "findings, gate result, or exit code -- only how much optional "
    "diagnostic detail reaches standard error.",
)
_LOG_FORMAT_OPTION = typer.Option(
    "--log-format",
    help="Set the format of operator diagnostic lines on standard error: "
    "text (default) or json (one structured object per line). Also "
    "selectable via CONTROLLOOP_LOG_FORMAT.",
)


@app.callback(invoke_without_command=True)
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed ControlLoop version and exit.",
            is_eager=True,
        ),
    ] = False,
    show_config: Annotated[
        bool,
        typer.Option(
            "--show-config",
            help="Print the effective configuration and the source that "
            "supplied each value, then exit.",
            is_eager=True,
        ),
    ] = False,
    max_file_size_bytes: Annotated[int | None, _MAX_FILE_SIZE_BYTES_OPTION] = None,
    max_total_bytes: Annotated[int | None, _MAX_TOTAL_BYTES_OPTION] = None,
    max_file_count: Annotated[int | None, _MAX_FILE_COUNT_OPTION] = None,
    max_depth: Annotated[int | None, _MAX_DEPTH_OPTION] = None,
    log_level: Annotated[LogLevel | None, _LOG_LEVEL_OPTION] = None,
    log_format: Annotated[LogFormat | None, _LOG_FORMAT_OPTION] = None,
) -> None:
    """Inspect and gate AI agent capabilities."""
    # Resolved once per invocation -- this callback runs for every command
    # (`invoke_without_command=True`), not only the eager `--version`/
    # `--show-config` paths below -- so a malformed CONTROLLOOP_LOG_LEVEL/
    # CONTROLLOOP_LOG_FORMAT is reported the same way regardless of which
    # command was requested.
    try:
        resolved_log_level = resolve_log_level(flag=log_level)
        resolved_log_format = resolve_log_format(flag=log_format)
    except VerbosityError as error:
        _report("CLI-INVALID-INPUT", str(error))
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    if version:
        supported = (
            ", ".join(SUPPORTED_OASF_VERSIONS)
            if SUPPORTED_OASF_VERSIONS
            else "none yet"
        )
        host_snapshots = ", ".join(
            f"{host} {date}"
            for host, date in sorted(AGENT_HOST_DOCUMENTATION_SNAPSHOTS.items())
        )
        OutputStreams().write_data(
            f"ControlLoop {__version__}\n"
            f"Supported OASF versions: {supported}\n"
            f"Agent host key sets (documentation read on): {host_snapshots}\n"
            f"Rule pack: {CURRENT_RULE_PACK.name} {CURRENT_RULE_PACK.version} "
            f"({len(CURRENT_RULE_PACK.rules)} rules)"
        )
        raise typer.Exit
    if show_config:
        _show_config(
            flags={
                "max_file_size_bytes": max_file_size_bytes,
                "max_total_bytes": max_total_bytes,
                "max_file_count": max_file_count,
                "max_depth": max_depth,
            },
            log_level=resolved_log_level,
            log_format=resolved_log_format,
        )
        raise typer.Exit


def _show_config(
    *, flags: dict[str, int | None], log_level: LogLevel, log_format: LogFormat
) -> None:
    """Resolve and print the effective configuration.

    Resolution failure (an unknown repository-file key, a malformed
    repository file, or an unresolvable repository root) is reported as a
    stable, brand-consistent error line on stderr and exits 2 -- never an
    uncaught exception reaching `main`'s generic internal-error envelope,
    and never a raw parser exception or file content.

    ``log_level``/``log_format`` gate two purely additive stderr lines
    emitted through `OperatorLog`: they never affect the resolved
    configuration or this function's stdout lines below, so
    `--show-config`'s output stays byte-identical across every verbosity
    level.
    """
    log = OperatorLog(level=log_level, format=log_format)
    try:
        root = resolve_repository_root()
        log.verbose(f"resolved repository root: {root.path}")
        config_path = root.path / CONFIG_FILENAME
        log.debug(f"checking repository configuration file: {config_path}")
        resolved = load_config(root, environ=dict(os.environ), flags=flags)
    except (ConfigError, RepositoryRootError) as error:
        _report("CLI-INVALID-CONFIG", str(error))
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    for line in resolved.render_lines():
        typer.echo(line)


def _not_implemented(command: str) -> None:
    _report(
        "CLI-NOT-IMPLEMENTED",
        f"{command} is not implemented yet.",
        severity=DiagnosticSeverity.WARNING,
    )
    raise typer.Exit(code=ExitCode.INCOMPLETE_ANALYSIS)


_MANIFEST_FILENAME = "controlloop.yaml"


@app.command(help="Discover candidate agents and draft a reviewable security manifest.")
def init(
    ctx: typer.Context,
    repository: Annotated[
        Path | None,
        typer.Argument(
            help="Repository path to scan for candidate agents. Defaults "
            "to the current directory, or the nearest enclosing git "
            "repository."
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Print the draft controlloop.yaml that would be written, "
            "without creating it.",
        ),
    ] = False,
) -> None:
    _init_generate(ctx, repository, dry_run)


def _init_generate(ctx: typer.Context, repository: Path | None, dry_run: bool) -> None:
    """`controlloop init`: discovers candidate agents the same way `bom`
    does (`build_acbom_document`), then renders a schema-valid draft
    `controlloop.yaml` via `controlloop.manifest.render_draft_manifest`,
    with ownership, trust boundaries, and discovered tools pre-filled
    where discoverable and every other field marked TODO. `--dry-run`
    prints the draft instead of writing it. An existing manifest is
    never read, overwritten, or modified -- the conflict check below
    runs before any discovery or rendering happens, in both modes, and
    exits 2.

    Emits the same two `OperatorLog` lines `bom`/`--show-config` already
    establish: purely additive to stderr, never affecting stdout, the
    written file, or the exit code below, so repeated runs over
    unchanged input stay byte-identical across every verbosity level.
    """

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    raw_log_level = parent_params.get("log_level")
    raw_log_format = parent_params.get("log_format")
    try:
        log_level = resolve_log_level(
            flag=LogLevel(raw_log_level) if raw_log_level is not None else None
        )
        log_format = resolve_log_format(
            flag=LogFormat(raw_log_format) if raw_log_format is not None else None
        )
    except VerbosityError as error:
        typer.echo(f"✕ INVALID INPUT  {error}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None
    log = OperatorLog(level=log_level, format=log_format)

    try:
        root = resolve_repository_root(repository)
        log.verbose(f"resolved repository root: {root.path}")
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
        bounds = resolved_config.traversal_bounds()
        log.debug(
            "traversal bounds: "
            f"max_file_size_bytes={bounds.max_file_size_bytes}, "
            f"max_total_bytes={bounds.max_total_bytes}, "
            f"max_file_count={bounds.max_file_count}, "
            f"max_depth={bounds.max_depth}"
        )
    except (RepositoryRootError, ConfigError) as error:
        typer.echo(f"✕ INVALID INPUT  {error}", err=True)
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    manifest_path = root.path / _MANIFEST_FILENAME
    if manifest_path.exists():
        typer.echo(
            f"✕ INVALID INPUT  {_MANIFEST_FILENAME} already exists at "
            f"{manifest_path}; init never overwrites or modifies an "
            "existing manifest",
            err=True,
        )
        raise typer.Exit(code=ExitCode.INVALID_INPUT)

    document = build_acbom_document(root, bounds=bounds)
    draft = render_draft_manifest(document.nodes, document.edges)

    if dry_run:
        OutputStreams().write_data(draft)
    else:
        try:
            manifest_path.write_text(draft, encoding="utf-8")
        except OSError as error:
            reason = error.strerror or str(error)
            typer.echo(
                f"✕ INVALID INPUT  {manifest_path} could not be written: {reason}",
                err=True,
            )
            raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    incomplete = completeness_summary(document)
    if incomplete:
        codes = sorted({diagnostic.code for diagnostic in incomplete})
        OutputStreams().write_diagnostic(
            f"• COMPLETENESS  {len(incomplete)} diagnostic(s) indicate "
            f"incomplete analysis: {', '.join(codes)}"
        )


class BomFormat(StrEnum):
    """Output format for `controlloop bom` generation. `acbom` (default)
    writes the canonical ACBOM document unchanged; `cyclonedx` writes a
    CycloneDX 1.6 BOM, a reduced projection of the ACBOM (see
    `docs/reference/cyclonedx-export-format.md`). Not valid together
    with `--validate`, which only ever validates a native ACBOM file."""

    ACBOM = "acbom"
    CYCLONEDX = "cyclonedx"


_BOM_FORMAT_OPTION = typer.Option(
    "--format",
    help="Output format for generation: acbom (default, the native "
    "canonical document) or cyclonedx (a CycloneDX 1.6 BOM, a reduced "
    "projection -- see docs/reference/cyclonedx-export-format.md). Not "
    "valid together with --validate.",
)


@app.command(help="Generate or validate an Agent Capability Bill of Materials.")
def bom(
    ctx: typer.Context,
    repository: Annotated[
        Path | None,
        typer.Argument(
            help="Repository path to scan (default: the current directory, "
            "or the nearest enclosing git repository). With --validate, "
            "the path to the ACBOM file to validate instead."
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write the generated ACBOM to this file instead of standard "
            "output. Not valid together with --validate.",
        ),
    ] = None,
    validate: Annotated[
        bool,
        typer.Option(
            "--validate",
            help="Validate an existing ACBOM file against the published "
            "schema instead of generating one.",
        ),
    ] = False,
    output_format: Annotated[BomFormat, _BOM_FORMAT_OPTION] = BomFormat.ACBOM,
) -> None:
    if validate:
        if output is not None:
            _report("CLI-INVALID-INPUT", "--output cannot be combined with --validate")
            raise typer.Exit(code=ExitCode.INVALID_INPUT)
        if output_format is not BomFormat.ACBOM:
            _report(
                "CLI-INVALID-INPUT", "--format is not valid together with --validate"
            )
            raise typer.Exit(code=ExitCode.INVALID_INPUT)
        _bom_validate(repository)
    else:
        _bom_generate(ctx, repository, output, output_format)


def _bom_validate(path: Path | None) -> None:
    """`bom --validate`: exit 0 for a valid ACBOM, exit 2 otherwise.
    Never generates or prints the document itself."""

    if path is None:
        _report("CLI-INVALID-INPUT", "--validate requires a path to an ACBOM file")
        raise typer.Exit(code=ExitCode.INVALID_INPUT)

    try:
        raw = path.read_bytes()
    except OSError as error:
        reason = error.strerror or str(error)
        _report("CLI-INVALID-INPUT", f"could not be read: {reason}", location=str(path))
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    try:
        load_acbom_document(raw)
    except ValueError as error:
        _report(
            "CLI-INVALID-ACBOM", f"is not a valid ACBOM: {error}", location=str(path)
        )
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    typer.echo(f"✓ VALID  {path} is a valid ACBOM")
    raise typer.Exit(code=ExitCode.PASS)


def _bom_generate(
    ctx: typer.Context,
    repository: Path | None,
    output: Path | None,
    output_format: BomFormat,
) -> None:
    """`bom` generation: writes the canonical ACBOM to `output` or
    stdout, and a completeness summary to stderr. Requires no policy
    configuration and evaluates no rules.

    Also emits two purely additive `OperatorLog` lines: they never affect
    the generated document, `output`/stdout, or the exit code below, so
    repeated generation stays byte-identical across every verbosity level.
    """

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    # `ctx.parent.params` holds Click's own pre-Typer-conversion values.
    # For the four `int` bound flags below, Click's native `INT` type
    # already stores a real `int` there, so reading them back needs no
    # further conversion. `LogLevel`/`LogFormat` are different: Typer
    # implements an `Enum`-typed option as a Click `Choice` of the
    # enum's string *values*, and only its own generated wrapper
    # converts that string to the actual enum member -- exclusively when
    # invoking the annotated callback function itself, never inside
    # `ctx.params`. So `ctx.parent.params["log_level"]` is the raw
    # string (for example `"debug"`), not `LogLevel.DEBUG`, and must be
    # re-parsed here. `LogLevel(...)`/`LogFormat(...)` accept either an
    # already-converted member or its raw string value, so this is safe
    # regardless of which shape a future Typer version hands back.
    raw_log_level = parent_params.get("log_level")
    raw_log_format = parent_params.get("log_format")
    try:
        log_level = resolve_log_level(
            flag=LogLevel(raw_log_level) if raw_log_level is not None else None
        )
        log_format = resolve_log_format(
            flag=LogFormat(raw_log_format) if raw_log_format is not None else None
        )
    except VerbosityError as error:
        _report("CLI-INVALID-INPUT", str(error))
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None
    log = OperatorLog(level=log_level, format=log_format)

    try:
        root = resolve_repository_root(repository)
        log.verbose(f"resolved repository root: {root.path}")
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
        bounds = resolved_config.traversal_bounds()
        log.debug(
            "traversal bounds: "
            f"max_file_size_bytes={bounds.max_file_size_bytes}, "
            f"max_total_bytes={bounds.max_total_bytes}, "
            f"max_file_count={bounds.max_file_count}, "
            f"max_depth={bounds.max_depth}"
        )
    except (RepositoryRootError, ConfigError) as error:
        _report("CLI-INVALID-INPUT", str(error))
        raise typer.Exit(code=ExitCode.INVALID_INPUT) from None

    document = build_acbom_document(root, bounds=resolved_config.traversal_bounds())

    lossy_export: tuple[str, ...] = ()
    if output_format is BomFormat.CYCLONEDX:
        cyclonedx_bom, lossy_export = render_cyclonedx(document)
        data = canonical_json_bytes(cyclonedx_bom)
    else:
        data = serialize_document(document)

    if output is not None:
        try:
            output.write_bytes(data)
        except OSError as error:
            reason = error.strerror or str(error)
            _report(
                "CLI-INVALID-INPUT",
                f"could not be written: {reason}",
                location=str(output),
            )
            raise typer.Exit(code=ExitCode.INVALID_INPUT) from None
    else:
        OutputStreams().write_data(data.decode("utf-8"))

    incomplete = completeness_summary(document)
    if incomplete:
        codes = sorted({diagnostic.code for diagnostic in incomplete})
        OutputStreams().write_diagnostic(
            f"• COMPLETENESS  {len(incomplete)} diagnostic(s) indicate "
            f"incomplete analysis: {', '.join(codes)}"
        )
    if lossy_export:
        OutputStreams().write_diagnostic(
            f"• LOSSY EXPORT  {len(lossy_export)} node(s) or edge(s) have no "
            "CycloneDX representation and were omitted"
        )


class DiffFormat(StrEnum):
    """Output format for `controlloop diff`. `text` is the default: a
    human-oriented CLI-voice summary, matching `bom --validate`'s
    existing human-first stdout precedent for a report (as opposed to
    `bom` generation, whose purpose is producing the artifact itself).
    `json` serializes the complete `DiffReport` for machine consumption.
    No SARIF renderer exists anywhere in this codebase yet -- see
    docs/reference/diff-output-format.md."""

    TEXT = "text"
    JSON = "json"


_DIFF_BASELINE_OPTION = typer.Option(
    "--baseline",
    help="Repository-plus-baseline mode only: the baseline to compare "
    "against. Tried first as an existing file path (an explicit "
    "committed-baseline document); if it does not exist as a file, tried "
    "as a git revision. Omit to resolve automatically: a committed "
    "baseline at .controlloop/baseline.json takes precedence, falling "
    "back to the merge-base of the default branch.",
)
_DIFF_FORMAT_OPTION = typer.Option(
    "--format",
    help="Output format: text (default, human-oriented) or json (the "
    "complete comparison report for machine consumption).",
)

_CHANGE_KIND_LABEL: dict[ChangeKind, str] = {
    ChangeKind.ADDED: "ADDED",
    ChangeKind.REMOVED: "REMOVED",
    ChangeKind.CHANGED: "CHANGED",
    ChangeKind.UNKNOWN: "UNKNOWN",
}

_BASELINE_ORIGIN_LABEL: dict[BaselineOrigin, str] = {
    BaselineOrigin.TWO_ACBOMS: "two ACBOM files",
    BaselineOrigin.EXPLICIT_BASELINE_FILE: "explicit baseline file",
    BaselineOrigin.COMMITTED_BASELINE: "committed baseline",
    BaselineOrigin.MERGE_BASE: "merge-base of the default branch",
    BaselineOrigin.EXPLICIT_REVISION: "explicit git revision",
}


@app.command(help="Compare two ACBOMs, or the repository against a baseline.")
def diff(
    ctx: typer.Context,
    first: Annotated[
        Path | None,
        typer.Argument(
            help="With SECOND: the baseline ACBOM file. Alone (or omitted): "
            "the repository path to scan, default the current directory or "
            "the nearest enclosing git repository."
        ),
    ] = None,
    second: Annotated[
        Path | None,
        typer.Argument(
            help="The current ACBOM file to compare FIRST against. Supplying "
            "this switches to two-ACBOM-file mode; --baseline is not valid "
            "together with it."
        ),
    ] = None,
    baseline: Annotated[str | None, _DIFF_BASELINE_OPTION] = None,
    output_format: Annotated[DiffFormat, _DIFF_FORMAT_OPTION] = DiffFormat.TEXT,
) -> None:
    """`controlloop diff`: compares two ACBOM files, or a repository
    against a resolved baseline, evaluating no policy and returning exit
    `0` or `2` only. Never touches the network -- every baseline
    resolution path here (`resolve_baseline`, `resolve_merge_base`,
    `resolve_revision_commit`) is local-git-only, matching the modules it
    reuses.
    """
    if second is not None:
        if baseline is not None:
            _diff_error(
                "--baseline is not valid together with two ACBOM file "
                "arguments; supply a repository path instead"
            )
        assert first is not None  # Typer positional order guarantees this
        _diff_two_acboms(first, second, output_format)
    else:
        _diff_repository(ctx, first, baseline, output_format)


def _diff_error(
    message: str, *, code: str = "CLI-INVALID-INPUT", location: str | None = None
) -> NoReturn:
    """Reports one `CliDiagnostic` and exits `ExitCode.INVALID_INPUT` --
    every `diff` error path other than a malformed ACBOM document (which
    uses `CLI-INVALID-ACBOM`, matching `_bom_validate`'s own precedent)
    reuses the general-purpose `CLI-INVALID-INPUT` category rather than
    registering new codes."""

    _report(code, message, location=location)
    raise typer.Exit(code=ExitCode.INVALID_INPUT)


def _diff_emit_completeness(document: ACBOMDocument, *, label: str) -> None:
    """Mirrors `bom`/`init`'s own completeness-summary stderr line,
    applied to every ACBOM this command builds or loads -- a comparison
    target's own incomplete analysis is exactly the kind of thing the
    stream-separation contract requires reaching stderr, never silently
    folded into the diff itself."""

    incomplete = completeness_summary(document)
    if incomplete:
        codes = sorted({diagnostic.code for diagnostic in incomplete})
        OutputStreams().write_diagnostic(
            f"• COMPLETENESS  {label}: {len(incomplete)} diagnostic(s) "
            f"indicate incomplete analysis: {', '.join(codes)}"
        )


def _diff_active_approvals(root: RepositoryRoot) -> tuple[Approval, ...] | None:
    """The manifest approvals active now, for the authority statement.
    `diff` does not otherwise read the manifest and must not fail on one,
    so a manifest that cannot be read leaves approvals unevaluated
    (`None`) rather than ending the command."""

    manifest_path = root.path / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return ()
    try:
        manifest = load_manifest(
            manifest_path.read_text(encoding="utf-8"), path=str(manifest_path)
        )
    except (OSError, ManifestValidationError):
        return None
    return active_approvals(manifest, as_of=datetime.now(UTC))


def _scan_active_approvals(
    manifest: ManifestDocument | None, *, as_of: datetime
) -> tuple[Approval, ...]:
    return active_approvals(manifest, as_of=as_of) if manifest is not None else ()


def _with_active_approvals(context: RuleContext, *, as_of: datetime) -> RuleContext:
    """The context the agent-authority rules read: the manifest's
    approvals narrowed to the ones active at `as_of`, since a rule has no
    clock of its own. An approval naming a component lowers its finding
    so it does not block; an expired one does nothing. Other rules read
    the manifest as it is."""

    if context.manifest is None or not context.manifest.approvals:
        return context
    return replace(
        context,
        manifest=context.manifest.model_copy(
            update={"approvals": active_approvals(context.manifest, as_of=as_of)}
        ),
    )


def _rule_help() -> dict[str, str]:
    """SARIF `help.text` for the agent-authority rules: the rule pack's
    own summary, so a reviewer reading a result in a code scanning UI
    sees what the rule looks for."""

    authority_rule_ids = {rule.id for rule in ALL_RULES if rule.reads_agent_authority}
    return {
        item.id: item.summary
        for item in CURRENT_RULE_PACK.metadata
        if item.id in authority_rule_ids
    }


def _diff_render_and_exit(report: DiffReport, output_format: DiffFormat) -> NoReturn:
    if output_format is DiffFormat.JSON:
        OutputStreams().write_data(report.model_dump_json())
    else:
        OutputStreams().write_data(_render_diff_text(report))
    raise typer.Exit(code=ExitCode.PASS)


def _render_diff_text(report: DiffReport) -> str:
    lines = ["CONTROLLOOP / CAPABILITY DIFF", ""]
    origin_label = _BASELINE_ORIGIN_LABEL[report.baseline_origin]
    lines.append(f"• BASELINE   {origin_label}: {report.baseline_description}")
    if report.comparison_scope is ComparisonScope.EFFECTIVE_AUTHORITY_ONLY:
        lines.append(
            "• SCOPE      effective authority only -- node and edge changes "
            "were not evaluated; the resolved baseline carries no captured "
            "graph"
        )
    else:
        lines.append("• SCOPE      full -- nodes, edges, and effective authority")
    lines.append("")

    authority_lines = describe_authority_delta(report.authority_delta)
    if authority_lines:
        lines.extend(authority_lines)
        lines.append("")

    result = report.result
    if result.is_empty:
        lines.append("✓ COMPARED   no differences from baseline")
        return "\n".join(lines)

    for node_change in result.node_changes:
        endpoint = node_change.after or node_change.before
        name = endpoint.name if endpoint is not None else node_change.node_id
        kind_label = _CHANGE_KIND_LABEL[node_change.kind]
        lines.append(f"• {kind_label:<8} node        {node_change.node_id}  {name}")
    for edge_change in result.edge_changes:
        kind_label = _CHANGE_KIND_LABEL[edge_change.kind]
        lines.append(f"• {kind_label:<8} edge        {edge_change.edge_id}")
    for authority_change in result.effective_authority_changes:
        kind_label = _CHANGE_KIND_LABEL[authority_change.kind]
        lines.append(
            f"• {kind_label:<8} capability  {authority_change.agent_id}  "
            f"{authority_change.action.value}  {authority_change.resource_id}"
        )

    all_kinds: list[ChangeKind] = (
        [change.kind for change in result.node_changes]
        + [change.kind for change in result.edge_changes]
        + [change.kind for change in result.effective_authority_changes]
    )
    counts = Counter(all_kinds)
    total = sum(counts.values())
    summary = ", ".join(
        f"{counts[kind]} {label.lower()}"
        for kind, label in _CHANGE_KIND_LABEL.items()
        if counts[kind]
    )
    lines.append("")
    lines.append(f"{total} change{'s' if total != 1 else ''}: {summary}")
    return "\n".join(lines)


def _diff_load_acbom_file(path: Path, *, role: str) -> ACBOMDocument:
    try:
        raw = path.read_bytes()
    except OSError as error:
        reason = error.strerror or str(error)
        _diff_error(f"{role} ACBOM could not be read: {reason}", location=str(path))
    try:
        return load_acbom_document(raw)
    except ValueError as error:
        _diff_error(
            f"{role} ACBOM is not a valid ACBOM: {error}",
            code="CLI-INVALID-ACBOM",
            location=str(path),
        )


def _diff_two_acboms(first: Path, second: Path, output_format: DiffFormat) -> NoReturn:
    """Usage form 1: two ACBOM files, `first` the baseline side and
    `second` the current side, matching `compute_diff`'s own
    `baseline_*`/`current_*` argument order and `git diff A B`
    convention. Full node/edge/effective-authority diff (two ACBOM files
    carry no baseline-artifact limitation)."""

    baseline_document = _diff_load_acbom_file(first, role="baseline")
    current_document = _diff_load_acbom_file(second, role="current")

    result = compute_diff(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    report = DiffReport(
        schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
        baseline_origin=BaselineOrigin.TWO_ACBOMS,
        baseline_description=f"{first} (baseline) vs {second} (current)",
        comparison_scope=ComparisonScope.FULL,
        result=result,
        # Two files and no repository: there is no manifest to read.
        authority_delta=compute_authority_delta(current_document, result, None),
    )
    _diff_emit_completeness(baseline_document, label="baseline ACBOM")
    _diff_emit_completeness(current_document, label="current ACBOM")
    _diff_render_and_exit(report, output_format)


def _diff_repository(
    ctx: typer.Context,
    repository: Path | None,
    baseline: str | None,
    output_format: DiffFormat,
) -> NoReturn:
    """Usage forms 2 and 3: a repository path scanned live, compared
    against either an automatically resolved baseline (no `--baseline`)
    or an explicitly supplied one (`--baseline VALUE`, disambiguated as
    a file path or a git revision)."""

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    raw_log_level = parent_params.get("log_level")
    raw_log_format = parent_params.get("log_format")
    try:
        log_level = resolve_log_level(
            flag=LogLevel(raw_log_level) if raw_log_level is not None else None
        )
        log_format = resolve_log_format(
            flag=LogFormat(raw_log_format) if raw_log_format is not None else None
        )
    except VerbosityError as error:
        _diff_error(str(error))
    log = OperatorLog(level=log_level, format=log_format)

    try:
        root = resolve_repository_root(repository)
        log.verbose(f"resolved repository root: {root.path}")
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
        bounds = resolved_config.traversal_bounds()
        log.debug(
            "traversal bounds: "
            f"max_file_size_bytes={bounds.max_file_size_bytes}, "
            f"max_total_bytes={bounds.max_total_bytes}, "
            f"max_file_count={bounds.max_file_count}, "
            f"max_depth={bounds.max_depth}"
        )
    except (RepositoryRootError, ConfigError) as error:
        _diff_error(str(error))

    current_document = build_acbom_document(root, bounds=bounds)

    if baseline is not None:
        report = _diff_resolve_explicit_baseline(
            root, baseline, current_document, bounds
        )
    else:
        report = _diff_resolve_automatic_baseline(root, current_document, bounds)
    report = report.model_copy(
        update={
            "authority_delta": compute_authority_delta(
                current_document, report.result, _diff_active_approvals(root)
            )
        }
    )

    _diff_emit_completeness(current_document, label="current ACBOM")
    _diff_render_and_exit(report, output_format)


def _diff_effective_authority_only_report(
    *,
    origin: BaselineOrigin,
    description: str,
    baseline_effective_authority: tuple[EffectiveAuthorityEntry, ...],
    current_document: ACBOMDocument,
) -> DiffReport:
    """A resolved `BaselineDocument` (committed or explicit-file) carries
    no `nodes`/`edges` at all -- only `effective_authority`. `compute_diff`
    is deliberately not called here with a fabricated empty node/edge
    graph on the baseline side, which would incorrectly report every
    current node/edge as `ADDED`; `diff_effective_authority` is called
    directly instead, exactly as docs/reference/diff-output-format.md
    documents. `comparison_scope=EFFECTIVE_AUTHORITY_ONLY` on the
    returned report records the omission honestly in the same payload
    the changes themselves are in."""

    current_effective_authority = compute_effective_authority(
        current_document.nodes, current_document.edges
    )
    effective_authority_changes = diff_effective_authority(
        baseline_effective_authority, current_effective_authority
    )
    result = DiffResult(
        schema_version=CURRENT_DIFF_SCHEMA_VERSION,
        node_changes=(),
        edge_changes=(),
        effective_authority_changes=effective_authority_changes,
    )
    return DiffReport(
        schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
        baseline_origin=origin,
        baseline_description=description,
        comparison_scope=ComparisonScope.EFFECTIVE_AUTHORITY_ONLY,
        result=result,
    )


def _diff_resolve_automatic_baseline(
    root: RepositoryRoot,
    current_document: ACBOMDocument,
    bounds: TraversalBounds,
) -> DiffReport:
    """No `--baseline` given. `resolve_baseline` (a committed baseline)
    always takes precedence; only when it returns `None` (no committed
    baseline) is `resolve_merge_base` consulted. `NoGitHistoryError` (no
    committed baseline *and* no usable git history) is reported plainly
    as "no comparison is possible," never silently folded into an empty
    diff. `MergeBaseResolutionError` (a shallow clone, or another
    actionable git-history problem) is surfaced with its own already
    actionable message."""

    try:
        resolved = resolve_baseline(root)
    except (BaselineResolutionError, BaselineIntegrityError) as error:
        _diff_error(str(error))

    if resolved is not None:
        return _diff_effective_authority_only_report(
            origin=BaselineOrigin.COMMITTED_BASELINE,
            description=str(resolved.path),
            baseline_effective_authority=resolved.document.effective_authority,
            current_document=current_document,
        )

    try:
        merge_base_resolution = resolve_merge_base(root)
    except NoGitHistoryError as error:
        _diff_error(
            "no comparison is possible: no baseline is committed at "
            f"{CONVENTIONAL_BASELINE_RELATIVE_PATH}, and {error} This is "
            "distinct from an empty diff -- no comparison could be "
            "attempted at all."
        )
    except MergeBaseResolutionError as error:
        _diff_error(str(error))

    baseline_document = build_merge_base_acbom(
        root, merge_base_resolution, bounds=bounds
    )
    _diff_emit_completeness(baseline_document, label="merge-base baseline ACBOM")
    result = compute_diff(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    description = (
        f"merge-base {merge_base_resolution.merge_base_commit} against "
        f"{merge_base_resolution.default_branch_ref}"
    )
    return DiffReport(
        schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
        baseline_origin=BaselineOrigin.MERGE_BASE,
        baseline_description=description,
        comparison_scope=ComparisonScope.FULL,
        result=result,
    )


def _diff_resolve_explicit_baseline(
    root: RepositoryRoot,
    baseline: str,
    current_document: ACBOMDocument,
    bounds: TraversalBounds,
) -> DiffReport:
    """`--baseline VALUE` given: tried first as an existing file (an
    explicit committed-baseline-document override, reusing
    `resolve_baseline`'s own `explicit_path` semantics unmodified); if
    `VALUE` does not exist as a file, tried as a git revision, resolved
    and scanned the same way the merge-base fallback is. A value that
    resolves as neither is exit 2, naming both attempts."""

    candidate_path = Path(baseline)
    if candidate_path.is_file():
        try:
            resolved = resolve_baseline(root, explicit_path=candidate_path)
        except (BaselineResolutionError, BaselineIntegrityError) as error:
            _diff_error(str(error))
        # `resolve_baseline` only returns `None` when `explicit_path` is
        # not given; with an explicit path it always returns a document
        # or raises one of the two exceptions caught above.
        assert resolved is not None
        return _diff_effective_authority_only_report(
            origin=BaselineOrigin.EXPLICIT_BASELINE_FILE,
            description=str(resolved.path),
            baseline_effective_authority=resolved.document.effective_authority,
            current_document=current_document,
        )

    commit = resolve_revision_commit(root, baseline)
    if commit is None:
        _diff_error(
            f"--baseline {baseline!r} is neither an existing file path nor "
            "a git revision this repository can resolve locally"
        )

    try:
        baseline_document = build_acbom_at_revision(root, commit, bounds=bounds)
    except MergeBaseResolutionError as error:
        _diff_error(str(error))

    _diff_emit_completeness(baseline_document, label="baseline ACBOM at revision")
    result = compute_diff(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    return DiffReport(
        schema_version=CURRENT_DIFF_REPORT_SCHEMA_VERSION,
        baseline_origin=BaselineOrigin.EXPLICIT_REVISION,
        baseline_description=f"revision {baseline} ({commit})",
        comparison_scope=ComparisonScope.FULL,
        result=result,
    )


class ScanFormat(StrEnum):
    """Output format for `controlloop scan`. `text` (default) is a
    human-oriented CLI-voice summary via `render_terminal_report`;
    `json` serializes the complete `ScanReport`; `sarif` renders a
    complete SARIF 2.1.0 log document via `render_sarif_log`, for
    ingestion by code-scanning tooling."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


_SCAN_FORMAT_OPTION = typer.Option(
    "--format",
    help="Output format: text (default, human-oriented), json (the "
    "complete scan report for machine consumption), or sarif (a "
    "complete SARIF 2.1.0 log document).",
)


class RulesFormat(StrEnum):
    """Output format for `controlloop rules`. `text` is a human-oriented
    catalog; `json` is the same content for scripting, mirroring
    `scan`/`gate`'s own two-format convention."""

    TEXT = "text"
    JSON = "json"


_RULES_FORMAT_OPTION = typer.Option(
    "--format",
    help="Output format: text (default, human-oriented) or json (the "
    "complete rule catalog for machine consumption).",
)

#: Matches `controlloop.reporting.terminal`'s own default render width,
#: so `rules` wraps like every other human-facing command.
_RULES_WIDTH = 80

_RULES_ALL_OPTION = typer.Option(
    "--all",
    help="List every rule in the pack, ignoring this repository's own "
    "disabled_rules configuration. Omit to show which rules would "
    "actually run.",
)


@app.command(help="List the rule pack in use and what each rule looks for.")
def rules(
    ctx: typer.Context,
    repository: Annotated[
        Path | None,
        typer.Argument(
            help="Repository whose configuration decides which rules are "
            "active, default the current directory or the nearest "
            "enclosing git repository."
        ),
    ] = None,
    output_format: Annotated[RulesFormat, _RULES_FORMAT_OPTION] = RulesFormat.TEXT,
    show_all: Annotated[bool, _RULES_ALL_OPTION] = False,
) -> None:
    """`controlloop rules`: what is actually going to be evaluated, and
    what each rule looks for.

    Before this, `--version` reported a rule *count* and nothing listed
    the rules themselves; `Rule` carries only `id` and `evaluate`, so no
    description existed anywhere in the model layer. A repository that
    disabled a non-mandatory rule had no way to confirm what it turned
    off.

    Reads the catalog from `CURRENT_RULE_PACK.metadata` and the disabled
    set from the same `resolve_policy_config`/`validate_disabled_rules`
    pair `scan`/`gate` use, so "active" here means the same thing it
    means there rather than being computed a second, drifting way.

    Evaluates no policy and scans nothing: it reads configuration and
    prints. Always exits `0` on success.
    """

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    try:
        root = resolve_repository_root(repository)
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
    except (RepositoryRootError, ConfigError) as error:
        _scan_error(str(error))

    policy_config = resolve_policy_config(resolved_config)
    catalog = CURRENT_RULE_PACK.metadata
    try:
        validate_disabled_rules(policy_config, catalog)
    except PolicyConfigError as error:
        _scan_error(str(error))

    disabled = policy_config.disabled_rule_ids
    entries = [
        {
            "id": entry.id,
            "mandatory": entry.mandatory,
            "active": entry.id not in disabled,
            "summary": entry.summary,
            "documentation_url": documentation_url(entry.id),
        }
        for entry in catalog
        if show_all or entry.id not in disabled
    ]

    if output_format is RulesFormat.JSON:
        payload = {
            "rule_pack": {
                "name": CURRENT_RULE_PACK.name,
                "version": CURRENT_RULE_PACK.version,
                "fingerprint": rule_pack_fingerprint(CURRENT_RULE_PACK),
            },
            "rules": entries,
        }
        OutputStreams().write_data(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(int(ExitCode.PASS))

    lines = [
        f"• RULE PACK  {CURRENT_RULE_PACK.name} {CURRENT_RULE_PACK.version} "
        f"({len(catalog)} rules)",
        f"• FINGERPRINT  {rule_pack_fingerprint(CURRENT_RULE_PACK)}",
        "",
    ]
    for entry in entries:
        marker = "✓" if entry["active"] else "•"
        state = "active" if entry["active"] else "disabled"
        governance = "mandatory" if entry["mandatory"] else "optional"
        lines.append(f"{marker} {entry['id']}  [{state}, {governance}]")
        # Wrapped to the same 80 columns `render_terminal_report` uses,
        # so this command reads like the rest of the CLI rather than
        # emitting one very long line per rule.
        lines.extend(
            textwrap.wrap(
                str(entry["summary"]),
                width=_RULES_WIDTH,
                initial_indent="    ",
                subsequent_indent="    ",
            )
        )
        lines.append("")

    if not show_all and disabled:
        lines.append(
            f"{len(disabled)} rule(s) disabled by configuration; "
            "re-run with --all to list them."
        )
        lines.append("")
    lines.extend(
        textwrap.wrap(
            "A mandatory rule cannot be disabled. Full detail for every "
            "rule, including its detection shape and known limitations, "
            "is in docs/reference/policy-rules.md.",
            width=_RULES_WIDTH,
        )
    )
    OutputStreams().write_data("\n".join(lines))
    raise typer.Exit(int(ExitCode.PASS))


#: The walkthrough this command points at. The narrative lives in
#: `docs/` rather than in CLI output.
#:
#: It is the GitHub URL of the walkthrough in this repository rather than
#: the documentation host every `Finding.documentation_url` points at,
#: so the link works for anyone who can see the repository even before
#: the documentation site is published.
_EXAMPLE_DOC_PATH = "docs/guides/example-walkthrough.md"
_EXAMPLE_DOC_URL = (
    f"https://github.com/controlloop-security/controlloop/blob/main/{_EXAMPLE_DOC_PATH}"
)

#: Each step: the command, what is actually happening, and why it
#: matters. Written for someone who has never used ControlLoop -- an
#: earlier version assumed the reader already knew what a capability
#: graph, a node name, and a rule were.
_EXAMPLE_STEPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "controlloop bom ./demo-agent -o acbom.json",
        "Build the ACBOM -- the map of what your agent can do.",
        (
            "ACBOM stands for Agent Capability Bill of Materials. A "
            "software BOM lists the libraries you ship; an ACBOM lists "
            "the authority your agent holds.",
            "It is a graph. The nodes are agents, tools, resources, "
            "identities, and permissions. The edges are what connects "
            "them -- invokes, reads, writes, delegates-to.",
            "Why you need one: an agent's real authority is scattered "
            "across an agent card, an MCP config, an OpenAPI spec, an "
            "IAM policy -- and, for most agents, the framework code "
            "itself. No single file tells you that adding one skill "
            "just let it move money. The ACBOM is the one place that "
            "answers it.",
            "ControlLoop reads your framework too. A CrewAI crew, a "
            "LangGraph graph, and an OpenAI Agents SDK module are all "
            "discovered directly -- agents, delegation, and tool "
            "wiring, from the code you already wrote. If you build on "
            "one of those, you may not need an agent card at all. See "
            "the crewai-support, langgraph-support, and "
            "openai-agents-support reference pages.",
            "Everything here comes from reading files. ControlLoop never "
            "runs your code, never starts an MCP server, and never "
            "contacts a declared endpoint. Framework code is parsed, "
            "never imported or executed -- so a module that would crash "
            "on import is still analyzed correctly.",
        ),
    ),
    (
        "controlloop scan ./demo-agent",
        "Analyze the graph and apply policy. Read the result carefully.",
        (
            "A scan builds the ACBOM, compares it to your approved "
            "baseline if you have one, runs every policy rule, and "
            "prints a report.",
            'You will see "no material capability is reachable" and '
            '"PASSED". That looks like a clean bill of health. It is '
            "not.",
            "It means ControlLoop could not CLASSIFY anything -- not "
            "that there is nothing to worry about. Discovery can see a "
            "tool called email-customer. Nothing in your repository "
            "says that emailing a customer sends data outside your "
            "trust boundary, and ControlLoop will not guess from names.",
        ),
    ),
    (
        "# add tool_capabilities: to controlloop.yaml, then scan again",
        "Tell ControlLoop what your tools actually do.",
        (
            "controlloop.yaml is your manifest: what you have decided "
            "about this repository. tool_capabilities is where you say "
            "a tool is destructive, moves money, is read-only, or "
            "touches sensitive data.",
            "Now the first line of the report changes to WORST "
            "REACHABLE -- the blast-radius statement. That is the "
            "single worst thing this agent can do right now, printed "
            "before any list of findings. It is the line you forward to "
            "your manager.",
            "Name tools exactly as discovery found them. Run "
            "controlloop bom and read the node names: an A2A skill is "
            "named by its card `name`, not its `id`; a CrewAI tool by "
            "its class name; an OpenAI Agents function tool by its "
            "`name_override` when it has one.",
        ),
    ),
    (
        "controlloop gate ./demo-agent --evidence-path evidence.json",
        "Run the CI form after giving the agent a destructive tool.",
        (
            "gate is scan for machines. Same analysis, but it never "
            "prompts, always writes a retainable evidence artifact -- "
            "including on a failing run, which is when you need it -- "
            "and returns one verdict and one exit code your pipeline "
            "can act on.",
            "Add a tool that voids invoices and reverses charges. The "
            "blast radius correctly gets worse: external-communication "
            "becomes destructive-action.",
            "And it still passes, exit 0. That is not a bug. Rules "
            "catch risks somebody anticipated -- run `controlloop rules` "
            "to see every one in the pack -- and nobody wrote a rule "
            "about your invoice agent. You never said what this agent "
            "may not do.",
        ),
    ),
    (
        "# add a ceilings: block to controlloop.yaml, then gate again",
        "Declare the boundary. Now it blocks.",
        (
            "A capability ceiling is the maximum authority an agent may "
            "ever hold, declared by you. Not a pattern to match -- a "
            "boundary to stay inside.",
            "Same agent code as the last step. Now: DEPLOYMENT BLOCKED, "
            "exit 1. No rule matched anything. The ceiling caught it "
            "because you declared a limit and the agent crossed it.",
            "That is the product. Rules catch the anticipated; the "
            "ceiling catches the rest. A ceiling breach also cannot be "
            "suppressed -- that is enforced structurally, not by "
            "convention.",
        ),
    ),
    (
        "controlloop gate ./my-agent --default-branch main",
        "Give a coding agent new power, and read the authority statement.",
        (
            "Coding agents are configured by files in the repository too: "
            ".claude/settings.json, .mcp.json, skills, subagents, "
            ".codex/config.toml, and the workflows that run an agent in "
            "CI. Those files grant authority.",
            "Commit the examples/agent-config/baseline/ configuration on "
            "main, then on a branch replace it with head/: a "
            "SessionStart hook, Bash(*), two new MCP servers, a subagent "
            "in bypassPermissions, Codex set to never ask, and a "
            "workflow with a write token. The git history is the "
            "baseline.",
            "Right after the verdict, an Authority section gives one "
            'sentence per new power: "This change gives Claude Code the power to run '
            "`node .github/setup.js` on every session start "
            "(`.claude/settings.json`, hook `SessionStart`). No approval "
            'is recorded." DEPLOYMENT BLOCKED, exit 1.',
            'The two changes approved in controlloop.yaml end "Approval '
            'recorded." and do not block. A change that grants nothing '
            "prints no Authority section at all.",
        ),
    ),
)

#: What each exit code means, since a CI gate is judged by them.
_EXAMPLE_EXIT_CODES: tuple[tuple[str, str], ...] = (
    ("0", "passed -- nothing blocking"),
    ("1", "a blocking finding, or review required"),
    ("2", "invalid input -- bad manifest, bad path, unreadable ACBOM"),
    ("3", "analysis was incomplete and you set enforcement to fail"),
    ("5", "an internal error -- please report it"),
)


def _example_paragraph(text: str, *, indent: str = "   ") -> list[str]:
    # `break_on_hyphens=False` keeps hyphenated terms of art intact:
    # otherwise "blast-radius" wraps as "blast-" / "radius", which reads
    # as two words and is hard to search for in a scrollback.
    return textwrap.wrap(
        text,
        width=_RULES_WIDTH,
        initial_indent=indent,
        subsequent_indent=indent,
        break_on_hyphens=False,
    )


@app.command(help="Walk through an example and explain how ControlLoop works.")
def example() -> None:
    """`controlloop example`: the shortest path from "installed" to "I
    understand what this does".

    Explains what is happening at every step for someone who has never
    used ControlLoop -- what an ACBOM is, what a scan does, what a rule
    is, how `gate` differs from `scan`, what a capability ceiling is,
    and what the exit codes mean.

    The full narrative with real recorded output lives in `docs/` and is
    linked by URL, not by file path -- see `_EXAMPLE_DOC_URL` for why
    that is the GitHub blob URL rather than the canonical host.

    Reads nothing, writes nothing, contacts nothing, and always exits
    `0`. It is guidance, not a scan.
    """

    lines = [
        "• EXAMPLE  learning ControlLoop in six steps",
        "",
    ]
    lines.extend(
        _example_paragraph(
            "ControlLoop reads the files that define an AI agent, works "
            "out what that agent can actually do, and fails your build "
            "when its authority grows past a limit you declared. It runs "
            "locally and sends nothing anywhere.",
            indent="",
        )
    )
    lines.append("")
    lines.extend(
        _example_paragraph(
            "Make a directory with an agent-card.json in it, then follow "
            "these six steps in order. Each step below says what is "
            "happening and why.",
            indent="",
        )
    )
    lines.append("")
    lines.append("Full walkthrough, with the real output of every step:")
    lines.append(f"  {_EXAMPLE_DOC_URL}")
    lines.append("")

    for number, (command, headline, explanation) in enumerate(_EXAMPLE_STEPS, 1):
        lines.append(f"─ STEP {number} ─ {headline}")
        lines.append("")
        lines.append(f"   $ {command}")
        lines.append("")
        for paragraph in explanation:
            lines.extend(_example_paragraph(paragraph))
            lines.append("")

    lines.append("─ EXIT CODES ─ what your pipeline sees")
    lines.append("")
    for code, meaning in _EXAMPLE_EXIT_CODES:
        lines.append(f"   {code}  {meaning}")
    lines.append("")

    lines.append("─ REMEMBER ─")
    lines.append("")
    for reminder in (
        '"no material capability is reachable" means nothing was '
        "classified, not that nothing is wrong. Declare "
        "tool_capabilities.",
        "Rules catch anticipated risk. The ceiling catches everything "
        "else. Step 4 passed and step 5 blocked on identical agent code.",
    ):
        lines.extend(_example_paragraph(reminder))
        lines.append("")

    lines.append("Next:")
    lines.append("   controlloop rules    every rule in the pack, and what it detects")
    lines.append("   controlloop init     draft a manifest for a real repository")
    OutputStreams().write_data("\n".join(lines))
    raise typer.Exit(int(ExitCode.PASS))


@app.command(help="Discover, build the ACBOM, evaluate policy, and report results.")
def scan(
    ctx: typer.Context,
    repository: Annotated[
        Path | None,
        typer.Argument(
            help="Repository path to scan, default the current directory "
            "or the nearest enclosing git repository."
        ),
    ] = None,
    output_format: Annotated[ScanFormat, _SCAN_FORMAT_OPTION] = ScanFormat.TEXT,
) -> None:
    """`controlloop scan`: discovers the repository, builds its ACBOM,
    resolves a baseline when one is available, evaluates policy with
    every registered rule not disabled by configuration, and renders the
    result in the requested format, returning the exit code the result
    implies. Rules are read from `controlloop.policy.rules.ALL_RULES`
    for execution rather than `CURRENT_RULE_PACK.rules` (identical
    content, but execution deliberately stays decoupled from rule-pack
    identity; `CURRENT_RULE_PACK.metadata` is what this command's
    `validate_disabled_rules` call actually checks), and the five
    `Verdict` members and five `ExitCode` members are derived from a
    `GateVerdict` this command computes itself.
    """

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    raw_log_level = parent_params.get("log_level")
    raw_log_format = parent_params.get("log_format")
    try:
        log_level = resolve_log_level(
            flag=LogLevel(raw_log_level) if raw_log_level is not None else None
        )
        log_format = resolve_log_format(
            flag=LogFormat(raw_log_format) if raw_log_format is not None else None
        )
    except VerbosityError as error:
        _scan_error(str(error))
    log = OperatorLog(level=log_level, format=log_format)

    try:
        root = resolve_repository_root(repository)
        log.verbose(f"resolved repository root: {root.path}")
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
        bounds = resolved_config.traversal_bounds()
        log.debug(
            "traversal bounds: "
            f"max_file_size_bytes={bounds.max_file_size_bytes}, "
            f"max_total_bytes={bounds.max_total_bytes}, "
            f"max_file_count={bounds.max_file_count}, "
            f"max_depth={bounds.max_depth}"
        )
    except (RepositoryRootError, ConfigError) as error:
        _scan_error(str(error))

    current_document = build_acbom_document(root, bounds=bounds)
    manifest = _scan_load_manifest(root)
    diff_result, material_changes = _scan_resolve_baseline(
        root, current_document, bounds
    )

    context = RuleContext(
        acbom=current_document,
        policy_version=CURRENT_RULE_PACK.version,
        diff=diff_result,
        manifest=manifest,
    )

    policy_config = resolve_policy_config(resolved_config)
    catalog = CURRENT_RULE_PACK.metadata
    try:
        validate_disabled_rules(policy_config, catalog)
    except PolicyConfigError as error:
        _scan_error(str(error))

    # `policy.unsanctioned-agent-component` is a Team rule: `scan` has
    # no Team path, so it is never loaded here.
    active_rules = tuple(
        rule
        for rule in ALL_RULES
        if rule.id not in policy_config.disabled_rule_ids
        and rule.id != UNSANCTIONED_AGENT_COMPONENT_RULE_ID
    )
    evaluation_result: EvaluationResult = engine_evaluate(active_rules, context)

    collected_findings: list[Finding] = []
    scoped_context = without_agent_authority(context)
    authority_context = _with_active_approvals(context, as_of=datetime.now(UTC))
    for rule in active_rules:
        collected_findings.extend(
            _RULE_FINDINGS_BY_ID[rule.id](
                authority_context if rule.reads_agent_authority else scoped_context
            )
        )
    findings = tuple(sorted(collected_findings, key=lambda finding: finding.id))

    # Repo-local suppressions are applied before `evaluate_gate` ever
    # sees the findings tuple -- an ACTIVE suppression removes its exact
    # target finding from blocking/warning classification, but `findings`
    # itself (below, on `ScanReport`) stays the full, unfiltered set, so
    # a suppressed finding is never silently hidden from evidence, only
    # from the gate decision it would otherwise have driven.
    # `suppression_outcome.records` -- every declared suppression's own
    # disposition, always present -- is reported unconditionally:
    # suppressions are never hidden.
    suppression_outcome: SuppressionOutcome = apply_suppressions(
        findings,
        manifest.suppressions if manifest is not None else (),
        reference_date=date.today(),
    )

    gate_verdict = evaluate_gate(
        suppression_outcome.effective_findings,
        policy_config,
        scanner_version=__version__,
        rule_pack_name=CURRENT_RULE_PACK.name,
        rule_pack_version=CURRENT_RULE_PACK.version,
        rule_pack_fingerprint=rule_pack_fingerprint(CURRENT_RULE_PACK),
    )

    blast_radius = compute_blast_radius(current_document.nodes, current_document.edges)
    authority_delta = compute_authority_delta(
        current_document,
        diff_result,
        _scan_active_approvals(manifest, as_of=datetime.now(UTC)),
    )

    completeness = completeness_summary(current_document)
    analysis_incomplete = bool(completeness) or evaluation_result.is_incomplete
    diagnostics = tuple(
        sorted(
            (*completeness, *evaluation_result.diagnostics),
            key=lambda diagnostic: (diagnostic.code, diagnostic.message),
        )
    )

    if gate_verdict.blocking_findings:
        verdict = Verdict.DEPLOYMENT_BLOCKED
        exit_code = ExitCode.POLICY_FAIL
    elif analysis_incomplete:
        verdict = Verdict.REVIEW_REQUIRED
        exit_code = ExitCode.INCOMPLETE_ANALYSIS
    elif gate_verdict.warning_findings:
        verdict = Verdict.PASSED_WITH_WARNINGS
        exit_code = ExitCode.PASS
    else:
        verdict = Verdict.PASSED
        exit_code = ExitCode.PASS

    report = ScanReport(
        schema_version=CURRENT_REPORT_SCHEMA_VERSION,
        verdict=verdict,
        blast_radius=blast_radius,
        authority_delta=authority_delta,
        material_changes=material_changes,
        findings=findings,
        diagnostics=diagnostics,
        suppressions=suppression_outcome.records,
        versions=ReportVersions(
            scanner=Generator(name="controlloop", version=__version__),
            acbom_schema_version=current_document.schema_version,
            report_schema_version=CURRENT_REPORT_SCHEMA_VERSION,
            policy_version=CURRENT_RULE_PACK.version,
        ),
    )

    _scan_render_and_exit(report, output_format, exit_code=exit_code)


def _scan_error(
    message: str, *, code: str = "CLI-INVALID-INPUT", location: str | None = None
) -> NoReturn:
    """Mirrors `_diff_error` exactly -- every `scan` error path other
    than a malformed manifest or ACBOM reuses the general-purpose
    `CLI-INVALID-INPUT` category rather than registering new codes."""

    _report(code, message, location=location)
    raise typer.Exit(code=ExitCode.INVALID_INPUT)


def _scan_emit_completeness(document: ACBOMDocument, *, label: str) -> None:
    """Mirrors `_diff_emit_completeness`/`bom`'s own completeness-summary
    stderr line, applied to a baseline ACBOM `scan` builds along the way
    (the current document's own completeness is folded into
    `ScanReport.diagnostics` directly instead)."""

    incomplete = completeness_summary(document)
    if incomplete:
        codes = sorted({diagnostic.code for diagnostic in incomplete})
        OutputStreams().write_diagnostic(
            f"• COMPLETENESS  {label}: {len(incomplete)} diagnostic(s) "
            f"indicate incomplete analysis: {', '.join(codes)}"
        )


def _scan_load_manifest(root: RepositoryRoot) -> ManifestDocument | None:
    """`None` when no `controlloop.yaml` exists at the repository root
    -- never an error for mere absence. A manifest that exists but fails
    to parse or validate is a real repository problem, reported and
    exited the same way every other `scan` input-resolution failure
    is."""

    manifest_path = root.path / _MANIFEST_FILENAME
    if not manifest_path.exists():
        return None
    try:
        raw = manifest_path.read_text(encoding="utf-8")
    except OSError as error:
        reason = error.strerror or str(error)
        _scan_error(
            f"{manifest_path} could not be read: {reason}", location=str(manifest_path)
        )
    try:
        return load_manifest(raw, path=str(manifest_path))
    except ManifestValidationError as error:
        _scan_error(str(error), location=str(manifest_path))


def _scan_resolve_baseline(
    root: RepositoryRoot,
    current_document: ACBOMDocument,
    bounds: TraversalBounds,
) -> tuple[DiffResult | None, MaterialChangeSummary | None]:
    """Reuses `diff`'s own automatic-baseline combinator: a committed
    baseline takes precedence; only when none exists is the merge-base
    of the default branch consulted. Unlike `diff`, whose entire purpose
    is comparison and which therefore treats "no usable git history" as
    a hard error, `scan` treats it as the "no baseline" case --
    proceeding with `(None, None)`, never an error or an exit. A
    malformed *committed* baseline is still a hard error, since that is
    a real repository problem, not merely an absent one.

    A committed baseline document carries no `nodes`/`edges` -- only
    `effective_authority` -- so material change classification cannot
    run without both sides' full graphs; only the merge-base fallback
    path, which builds a real baseline ACBOM, returns a non-`None`
    `MaterialChangeSummary`.
    """

    try:
        resolved = resolve_baseline(root)
    except (BaselineResolutionError, BaselineIntegrityError) as error:
        _scan_error(str(error))

    if resolved is not None:
        current_authority = compute_effective_authority(
            current_document.nodes, current_document.edges
        )
        effective_authority_changes = diff_effective_authority(
            resolved.document.effective_authority, current_authority
        )
        diff_result = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(),
            edge_changes=(),
            effective_authority_changes=effective_authority_changes,
        )
        return diff_result, None

    try:
        merge_base_resolution = resolve_merge_base(root)
    except (NoGitHistoryError, MergeBaseResolutionError):
        return None, None

    baseline_document = build_merge_base_acbom(
        root, merge_base_resolution, bounds=bounds
    )
    _scan_emit_completeness(baseline_document, label="merge-base baseline ACBOM")
    diff_result = compute_diff(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    material_changes = compute_material_change_summary(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    return diff_result, material_changes


def _scan_render_and_exit(
    report: ScanReport, output_format: ScanFormat, *, exit_code: ExitCode
) -> NoReturn:
    if output_format is ScanFormat.JSON:
        OutputStreams().write_data(report.model_dump_json())
    elif output_format is ScanFormat.SARIF:
        tool = Generator(name="controlloop", version=__version__)
        sarif_log = render_sarif_log(
            report.findings or (),
            tool=tool,
            blast_radius_lines=describe_blast_radius(report.blast_radius),
            authority_delta=report.authority_delta,
            rule_help=_rule_help(),
        )
        OutputStreams().write_data(json.dumps(sarif_log))
    else:
        text = render_terminal_report(
            blast_radius=report.blast_radius,
            verdict=report.verdict,
            material_changes=report.material_changes,
            findings=report.findings,
            authority_delta=report.authority_delta,
            suppressions=report.suppressions,
            color_enabled=False,
        )
        # Appended after render_terminal_report's own fixed section
        # order, never inside it -- see render_suppressions's own
        # docstring for why.
        suppressions_text = render_suppressions(report.suppressions)
        OutputStreams().write_data(f"{text}\n\n{suppressions_text}")
    raise typer.Exit(code=exit_code)


class GateFormat(StrEnum):
    """Output format for `controlloop gate`. `text` (default) is a
    human-oriented CLI-voice summary via `render_terminal_report`,
    exactly as `scan` renders, with two appended lines: the resolved
    completeness-enforcement setting, then the resolved evidence path --
    matching the CLI's own worked example
    (`Evidence: build/controlloop/evidence.json`). `json` is the literal
    `EvidenceArtifact` (`model_dump_json()`) -- the same bytes written to
    `--evidence-path`, also on stdout, so nothing here invents a second
    "gate report" schema alongside the already-approved evidence
    artifact. `sarif` renders the same findings `scan` does, through the
    same `render_sarif_log`."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


_GATE_FORMAT_OPTION = typer.Option(
    "--format",
    help="Output format: text (default, human-oriented, ending with the "
    "resolved completeness-enforcement setting and evidence path), json "
    "(the literal evidence artifact, byte-identical to the file written "
    "to --evidence-path), or sarif (a complete SARIF 2.1.0 log "
    "document).",
)
_GATE_EVIDENCE_PATH_OPTION = typer.Option(
    "--evidence-path",
    help="Write the retainable evidence artifact to this path. "
    "Written for every run that reaches a verdict, "
    "including a failing one. Defaults to evidence.json in the current "
    "directory. The parent directory must already exist; it is never "
    "created automatically.",
)
_GATE_DEFAULT_BRANCH_OPTION = typer.Option(
    "--default-branch",
    help="Override the branch merge-base baseline resolution treats as "
    "the default/target branch, for example a CI "
    "checkout where origin/HEAD is unset. Omit to resolve automatically "
    "(origin/HEAD, falling back to common candidate names). A bare name "
    "that does not resolve locally is also tried as origin/<name>, the "
    "only form a pull-request checkout has. Does not "
    "provide diff's own explicit-file/-revision baseline override -- "
    "use diff for that.",
)
_GATE_SARIF_PATH_OPTION = typer.Option(
    "--sarif-path",
    help="Additionally write a complete SARIF 2.1.0 log document to this "
    "path, independent of --format -- mirroring "
    "--evidence-path's own unconditional-write guarantee. Includes the "
    "blast-radius statement as runs[0].properties.controlloop.blastRadius. "
    "Omit to skip writing one; --format sarif still renders one to "
    "stdout either way.",
)

_DEFAULT_EVIDENCE_PATH = Path("evidence.json")


@dataclass(frozen=True, slots=True)
class _GateBaseline:
    """Everything `gate` needs from baseline resolution: the same
    `DiffResult`/`MaterialChangeSummary` pair `_scan_resolve_baseline`
    already returns, plus the baseline's own digest, provenance, and
    schema version -- fields `EvidenceArtifact` additionally requires
    that `_scan_resolve_baseline`'s narrower return shape does not
    carry. `_scan_resolve_baseline` itself is deliberately not reused or
    modified here."""

    diff_result: DiffResult | None
    material_changes: MaterialChangeSummary | None
    baseline_digest: str | None
    baseline_provenance: ApprovalProvenance | None
    baseline_schema_version: str | None


def _gate_error(
    message: str, *, code: str = "CLI-INVALID-INPUT", location: str | None = None
) -> NoReturn:
    """Mirrors `_scan_error`/`_diff_error` exactly -- every `gate` error
    path other than a malformed manifest, ACBOM, or evidence-artifact
    write reuses the general-purpose `CLI-INVALID-INPUT` category rather
    than registering new codes."""

    _report(code, message, location=location)
    raise typer.Exit(code=ExitCode.INVALID_INPUT)


def _gate_emit_completeness(document: ACBOMDocument, *, label: str) -> None:
    """Mirrors `_scan_emit_completeness` exactly, applied to a baseline
    ACBOM `gate` builds along the way."""

    incomplete = completeness_summary(document)
    if incomplete:
        codes = sorted({diagnostic.code for diagnostic in incomplete})
        OutputStreams().write_diagnostic(
            f"• COMPLETENESS  {label}: {len(incomplete)} diagnostic(s) "
            f"indicate incomplete analysis: {', '.join(codes)}"
        )


def _gate_resolve_baseline(
    root: RepositoryRoot,
    current_document: ACBOMDocument,
    bounds: TraversalBounds,
    *,
    default_branch: str | None = None,
) -> _GateBaseline:
    """Mirrors `_scan_resolve_baseline`'s own resolution order (a
    committed baseline takes precedence; only when none exists is the
    merge-base of the default branch consulted) -- see that function's
    own docstring for the full reasoning. Additionally returns the
    baseline digest/provenance/schema-version `EvidenceArtifact` needs:
    for a resolved committed or explicit-file baseline,
    `BaselineDocument.digest`/`.provenance`/`.schema_version` directly.
    For the merge-base fallback, there is no `BaselineDocument` at all --
    `baseline_digest` is the merge-base `ACBOMDocument`'s own digest
    instead, the only real digest available identifying "the thing
    compared against"; this is forced by `EvidenceArtifact`'s own
    existing validator requiring `baseline_digest` and
    `effective_authority_diff` to both be `None` or both present, not a
    stylistic choice. `baseline_provenance` and `baseline_schema_version`
    both stay `None` in that case: no human approved a merge-base
    reference, and there is no baseline-*format* schema version to
    report.

    `default_branch` forwards to `resolve_merge_base` unchanged (the
    `--default-branch` option) -- `None` preserves
    `resolve_merge_base`'s own existing automatic detection exactly.

    **Refined from `gate`'s original behavior:** `NoGitHistoryError`
    ("no git history at all") is still the "no baseline" case --
    returned silently, never an error, unchanged.
    `MergeBaseResolutionError` ("git history exists, but the merge-base
    specifically could not be resolved" -- the shallow-CI-checkout case)
    is no longer swallowed into the same silent no-baseline result: it
    now reaches `_gate_error` (exit `2`) with its own already-actionable
    message. Scoped to `gate` only; `scan`'s `_scan_resolve_baseline`
    keeps its own, independently documented and justified behavior
    unchanged."""

    try:
        resolved = resolve_baseline(root)
    except (BaselineResolutionError, BaselineIntegrityError) as error:
        _gate_error(str(error))

    if resolved is not None:
        current_authority = compute_effective_authority(
            current_document.nodes, current_document.edges
        )
        effective_authority_changes = diff_effective_authority(
            resolved.document.effective_authority, current_authority
        )
        diff_result = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(),
            edge_changes=(),
            effective_authority_changes=effective_authority_changes,
        )
        return _GateBaseline(
            diff_result=diff_result,
            material_changes=None,
            baseline_digest=resolved.document.digest,
            baseline_provenance=resolved.document.provenance,
            baseline_schema_version=resolved.document.schema_version,
        )

    try:
        merge_base_resolution = resolve_merge_base(root, default_branch=default_branch)
    except NoGitHistoryError:
        return _GateBaseline(
            diff_result=None,
            material_changes=None,
            baseline_digest=None,
            baseline_provenance=None,
            baseline_schema_version=None,
        )
    except MergeBaseResolutionError as error:
        _gate_error(str(error))

    baseline_document = build_merge_base_acbom(
        root, merge_base_resolution, bounds=bounds
    )
    _gate_emit_completeness(baseline_document, label="merge-base baseline ACBOM")
    diff_result = compute_diff(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    material_changes = compute_material_change_summary(
        baseline_nodes=baseline_document.nodes,
        baseline_edges=baseline_document.edges,
        current_nodes=current_document.nodes,
        current_edges=current_document.edges,
    )
    return _GateBaseline(
        diff_result=diff_result,
        material_changes=material_changes,
        baseline_digest=baseline_document.digest,
        baseline_provenance=None,
        baseline_schema_version=None,
    )


@dataclass(frozen=True, slots=True)
class _GateTeam:
    """One gate run's Team context.

    Holds the resolved configuration and the client alongside the
    preparation, because the upload at the end of `gate` needs all three
    and threading them separately through the command body would make the
    Team path harder to see, not easier.
    """

    preparation: team_pipeline.TeamPreparation
    client: PlatformClient
    config: TeamConfig


def _gate_team_prepare(
    resolved_config: ResolvedConfig,
    root: RepositoryRoot,
    *,
    disabled_rule_ids: frozenset[str],
    now: datetime,
    log: OperatorLog,
) -> _GateTeam | None:
    """Resolve Team configuration and run the pre-evaluation Team steps.

    Returns `None` -- meaning "this is a Community run, do nothing Team
    related" -- whenever `team_enabled` is false. That path constructs no
    transport, opens no connection, and reads no token: it is the single
    place the Community path's "no network attempt, byte-identical
    output" guarantee is enforced, and `tests/test_offline_canary.py`
    asserts a Team-off `gate` completes with all network access denied.

    Exits with the documented exit-2 contract for a misconfiguration and
    with exit 4 for a not-entitled project or a fail-closed outage.
    """

    try:
        config = resolve_team_config(
            resolved_config,
            environ=dict(os.environ),
            git_branch=lambda: checked_out_branch(root),
        )
    except TeamConfigError as error:
        _gate_error(str(error))

    if config is None:
        log.debug("team integration is disabled; no platform request will be made")
        return None

    log.verbose(f"team integration enabled for endpoint {config.endpoint}")
    client = PlatformClient(
        config=config,
        transport=UrllibTransport(),
        sleep=team_pipeline.make_sleeper(),
    )
    preparation = team_pipeline.prepare(
        config=config,
        client=client,
        repository_root=root.path,
        repository_disabled_rules=disabled_rule_ids,
        now=now,
    )

    for note in preparation.notes:
        _report("CLI-TEAM-STATUS", note, severity=DiagnosticSeverity.INFO)

    if not preparation.decision.proceed:
        _report("CLI-TEAM-ENTITLEMENT", preparation.decision.message)
        assert preparation.decision.exit_code is not None
        raise typer.Exit(code=preparation.decision.exit_code)

    if preparation.merge is not None:
        for rejection in preparation.merge.rejections:
            # The rejection names the rule and the organization policy
            # version. Reported as a warning rather than an error because
            # the merge already refused the weakening -- the gate is
            # enforcing the *stronger* policy, so the run is correct; what
            # is wrong is the repository's configuration, and its author
            # needs to hear that.
            _report(
                "CLI-TEAM-POLICY-REJECTED",
                rejection.reason,
                severity=DiagnosticSeverity.WARNING,
            )

    return _GateTeam(preparation=preparation, client=client, config=config)


def _gate_upload(
    team: _GateTeam,
    *,
    document: ACBOMDocument,
    findings: tuple[Finding, ...],
    verdict: Verdict,
    authority_delta: AuthorityDelta | None,
) -> None:
    """Render and submit the Team scan envelope, as 1.1.0 when the scan
    holds agent authority.

    Never changes the exit code. A scan the contract cannot describe -- a
    repository with no resolvable commit, or a verdict that evaluated no
    policy -- is reported as an upload that did not happen, because the
    alternative is failing a build over a reporting problem.
    """

    try:
        envelope = render_envelope(
            document=document,
            findings=findings,
            verdict=verdict,
            scanner_version=__version__,
            policy_version=CURRENT_RULE_PACK.version,
            branch=team.config.branch,
            pull_request_number=team.config.pull_request,
            repository_policy=team_pipeline.delta_for_envelope(
                team.preparation.repository_delta
            ),
            authority_delta=authority_delta,
        )
    except EnvelopeRenderError as error:
        _report(
            "CLI-TEAM-UPLOAD-SKIPPED",
            f"Team upload skipped: {error}",
            severity=DiagnosticSeverity.WARNING,
        )
        return

    _report(
        "CLI-TEAM-UPLOAD",
        team_pipeline.upload(client=team.client, envelope=envelope),
        severity=DiagnosticSeverity.INFO,
    )


def _gate_finding_actions(
    findings: tuple[Finding, ...],
    policy_config: PolicyConfig,
    rule_actions: dict[str, str],
) -> tuple[FindingActionRecord, ...]:
    """The action the gate took on each finding, for the evidence."""

    records = []
    for finding in findings:
        action, source = finding_action(finding, policy_config, rule_actions)
        records.append(
            FindingActionRecord(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                action=action.value,
                source=source.value,
            )
        )
    return tuple(records)


def _gate_classify(
    gate_verdict: GateVerdict,
    *,
    analysis_incomplete: bool,
    completeness_enforcement: CompletenessEnforcement,
    review_required: bool = False,
) -> tuple[Verdict, ExitCode]:
    """The verdict/exit-code reconciliation: gate's own
    pass/warn/require-review/fail vocabulary, computed independently of
    `scan`'s identical inline classification -- `scan`'s own function
    body is never touched. `pass` and `warn` deliberately share exit
    `0`, matching `scan`'s own already-shipped precedent and the
    documented exit-code table; `ExitCode` gains no new member. A
    blocking finding always wins regardless of completeness or its
    enforcement setting, matching `scan`'s own ordering.

    Incomplete analysis alone blocks (`Verdict.REVIEW_REQUIRED`, exit
    `ExitCode.INCOMPLETE_ANALYSIS`) only when `completeness_enforcement`
    is `CompletenessEnforcement.ENFORCE` -- a repository has explicitly
    opted in. Under the default `CompletenessEnforcement.WARN`, the
    identical incomplete analysis produces `Verdict.PASSED_WITH_WARNINGS`
    at exit `0` instead -- the same "surfaced, never hidden, never
    blocking" outcome a low-confidence finding already gets under
    `low_confidence_action = warn` ("a warning and exit 0 by default," so
    a first run is never a wall). Before the completeness-enforcement
    setting existed, incomplete analysis unconditionally returned
    `review_required`/exit `3`; `scan`'s own separate inline
    classification keeps that unconditional behavior unchanged."""

    if gate_verdict.blocking_findings:
        return Verdict.DEPLOYMENT_BLOCKED, ExitCode.POLICY_FAIL
    if review_required:
        # An unsanctioned agent-authority grant the organization has not
        # raised to fail: by default an unsanctioned grant requires review,
        # at the exit code that verdict already carries.
        return Verdict.REVIEW_REQUIRED, ExitCode.INCOMPLETE_ANALYSIS
    if analysis_incomplete:
        if completeness_enforcement is CompletenessEnforcement.ENFORCE:
            return Verdict.REVIEW_REQUIRED, ExitCode.INCOMPLETE_ANALYSIS
        return Verdict.PASSED_WITH_WARNINGS, ExitCode.PASS
    if gate_verdict.warning_findings:
        return Verdict.PASSED_WITH_WARNINGS, ExitCode.PASS
    return Verdict.PASSED, ExitCode.PASS


def _gate_write_evidence(artifact: EvidenceArtifact, path: Path) -> None:
    """The write guarantee itself: called unconditionally, for every
    verdict `gate` reaches, immediately after the artifact is built and
    before any stdout rendering or exit is raised -- there is no early
    return between artifact construction and this call, so the write is
    unconditional-on-verdict by the function's own straight-line
    structure rather than by a `try`/`finally` wrapper. The guarantee
    has a disclosed boundary (it covers every reached verdict; it does
    not cover a pre-verdict `INVALID_INPUT` failure or an uncaught
    internal error, neither of which has a verdict or digest to report).

    A failure to write `path` itself (an unwritable directory,
    permissions, disk full) is an input problem, not a policy outcome,
    and is reported and exited the same way `bom --output`'s own
    `OSError` handling already is.
    """

    try:
        path.write_bytes(artifact.model_dump_json().encode("utf-8"))
    except OSError as error:
        reason = error.strerror or str(error)
        _gate_error(
            f"evidence artifact could not be written: {reason}", location=str(path)
        )


def _gate_render_and_exit(
    artifact: EvidenceArtifact,
    *,
    blast_radius: BlastRadiusStatement | None,
    material_changes: MaterialChangeSummary | None,
    output_format: GateFormat,
    evidence_path: Path,
    sarif_path: Path | None,
    exit_code: ExitCode,
) -> NoReturn:
    tool = Generator(name="controlloop", version=__version__)
    blast_radius_lines = describe_blast_radius(blast_radius)
    sarif_log: dict[str, object] | None = None
    if output_format is GateFormat.SARIF or sarif_path is not None:
        sarif_log = render_sarif_log(
            artifact.findings or (),
            tool=tool,
            blast_radius_lines=blast_radius_lines,
            authority_delta=artifact.authority_delta,
            rule_help=_rule_help(),
        )

    # Written unconditionally, regardless of `output_format`, exactly
    # mirroring `--evidence-path`'s own unconditional-write guarantee --
    # a GitHub Actions step needs a real SARIF file to upload and to
    # read the embedded blast-radius property from, whichever `--format`
    # the caller chose for the primary rendering below.
    if sarif_path is not None:
        assert sarif_log is not None
        try:
            sarif_path.write_bytes(json.dumps(sarif_log).encode("utf-8"))
        except OSError as error:
            reason = error.strerror or str(error)
            _gate_error(
                f"SARIF artifact could not be written: {reason}",
                location=str(sarif_path),
            )

    if output_format is GateFormat.JSON:
        OutputStreams().write_data(artifact.model_dump_json())
    elif output_format is GateFormat.SARIF:
        assert sarif_log is not None
        OutputStreams().write_data(json.dumps(sarif_log))
    else:
        team = artifact.team
        text = render_terminal_report(
            blast_radius=blast_radius,
            verdict=artifact.verdict,
            material_changes=material_changes,
            findings=artifact.findings,
            authority_delta=artifact.authority_delta,
            suppressions=artifact.suppressions,
            excepted_until={
                record.finding_fingerprint: record.expires_at.date().isoformat()
                for record in (team.applied_exceptions if team is not None else ())
                if record.state is ExceptionState.APPLIED
            },
            organization_actions={
                record.finding_id: record.action
                for record in (team.finding_actions if team is not None else ())
                if record.source == ActionSource.ORGANIZATION
            },
            color_enabled=False,
        )
        # The active setting is stated in the gate result. Appended by this
        # wrapper, exactly as `Evidence: <path>` already is, without
        # touching `render_terminal_report`'s own fixed section order.
        setting_line = (
            f"Completeness enforcement: {artifact.completeness_enforcement.value} "
            f"({artifact.completeness_enforcement_source.value})"
        )
        # Same appended-after-render_terminal_report placement `scan`
        # uses -- see render_suppressions's own docstring.
        suppressions_text = render_suppressions(artifact.suppressions)
        OutputStreams().write_data(
            f"{text}\n\n{suppressions_text}\n\n{setting_line}\n"
            f"Evidence: {evidence_path}"
        )
    raise typer.Exit(code=exit_code)


@app.command(
    help="Evaluate policy noninteractively and return a deterministic verdict for CI."
)
def gate(
    ctx: typer.Context,
    repository: Annotated[
        Path | None,
        typer.Argument(
            help="Repository path to scan, default the current directory "
            "or the nearest enclosing git repository."
        ),
    ] = None,
    evidence_path: Annotated[Path, _GATE_EVIDENCE_PATH_OPTION] = _DEFAULT_EVIDENCE_PATH,
    output_format: Annotated[GateFormat, _GATE_FORMAT_OPTION] = GateFormat.TEXT,
    default_branch: Annotated[str | None, _GATE_DEFAULT_BRANCH_OPTION] = None,
    sarif_path: Annotated[Path | None, _GATE_SARIF_PATH_OPTION] = None,
) -> None:
    """`controlloop gate`: the noninteractive CI-facing command. Composes
    the identical discovery, baseline-resolution, and policy-evaluation
    pipeline `scan` already established, reusing every underlying
    function unmodified, and adds what `scan` does not: a four-state
    pass/warn/require-review/fail verdict vocabulary mapped onto `scan`'s
    own already-documented five exit codes (never a new `ExitCode`
    member), and an `EvidenceArtifact` written unconditionally to
    `--evidence-path` for every verdict this command reaches, including a
    failing one. Never prompts and never blocks on an interactive read:
    this function and every private helper it calls never invoke this
    codebase's one prompt-shaped primitive -- asserted structurally by
    test coverage in `tests/test_cli.py`.
    """

    parent_params = ctx.parent.params if ctx.parent is not None else {}
    raw_log_level = parent_params.get("log_level")
    raw_log_format = parent_params.get("log_format")
    try:
        log_level = resolve_log_level(
            flag=LogLevel(raw_log_level) if raw_log_level is not None else None
        )
        log_format = resolve_log_format(
            flag=LogFormat(raw_log_format) if raw_log_format is not None else None
        )
    except VerbosityError as error:
        _gate_error(str(error))
    log = OperatorLog(level=log_level, format=log_format)

    try:
        root = resolve_repository_root(repository)
        log.verbose(f"resolved repository root: {root.path}")
        resolved_config = load_config(
            root,
            environ=dict(os.environ),
            flags={
                "max_file_size_bytes": parent_params.get("max_file_size_bytes"),
                "max_total_bytes": parent_params.get("max_total_bytes"),
                "max_file_count": parent_params.get("max_file_count"),
                "max_depth": parent_params.get("max_depth"),
            },
        )
        bounds = resolved_config.traversal_bounds()
        log.debug(
            "traversal bounds: "
            f"max_file_size_bytes={bounds.max_file_size_bytes}, "
            f"max_total_bytes={bounds.max_total_bytes}, "
            f"max_file_count={bounds.max_file_count}, "
            f"max_depth={bounds.max_depth}"
        )
    except (RepositoryRootError, ConfigError) as error:
        _gate_error(str(error))

    current_document = build_acbom_document(root, bounds=bounds)
    manifest = _scan_load_manifest(root)
    gate_baseline = _gate_resolve_baseline(
        root, current_document, bounds, default_branch=default_branch
    )

    context = RuleContext(
        acbom=current_document,
        policy_version=CURRENT_RULE_PACK.version,
        diff=gate_baseline.diff_result,
        manifest=manifest,
    )

    policy_config = resolve_policy_config(resolved_config)
    catalog = CURRENT_RULE_PACK.metadata
    try:
        validate_disabled_rules(policy_config, catalog)
    except PolicyConfigError as error:
        _gate_error(str(error))

    # `team` is `None` for every repository that has not enabled the paid
    # tier, and every Team step below is written so that `None` means the
    # step does not happen -- not that it happens and is discarded. See
    # `controlloop.team.pipeline`.
    evaluated_at = datetime.now(UTC)
    team = _gate_team_prepare(
        resolved_config,
        root,
        disabled_rule_ids=policy_config.disabled_rule_ids,
        now=evaluated_at,
        log=log,
    )

    disabled_rule_ids = policy_config.disabled_rule_ids
    if team is not None:
        merged = team.preparation.disabled_rule_ids()
        if merged is not None:
            # The merged set replaces, rather than unions with, the
            # repository's own: the merge already incorporates the
            # repository delta and has *refused* any part of it that would
            # have weakened a mandatory organization rule. Unioning would
            # reinstate exactly the weakening the merge just rejected.
            disabled_rule_ids = merged

    authority_delta = compute_authority_delta(
        current_document,
        gate_baseline.diff_result,
        _scan_active_approvals(manifest, as_of=evaluated_at),
    )
    team_merge = team.preparation.merge if team is not None else None
    # The sanctioned-list rule runs only on a Team gate that has an
    # effective policy; a Community gate never loads it and makes no
    # network call on its account.
    active_rules = tuple(
        rule
        for rule in ALL_RULES
        if rule.id not in disabled_rule_ids
        and (team_merge is not None or rule.id != UNSANCTIONED_AGENT_COMPONENT_RULE_ID)
    )
    evaluation_result: EvaluationResult = engine_evaluate(active_rules, context)

    collected_findings: list[Finding] = []
    scoped_context = without_agent_authority(context)
    authority_context = _with_active_approvals(context, as_of=evaluated_at)
    if team is not None and team_merge is not None:
        bundle_version = team.preparation.organization_bundle_version
        authority_context = replace(
            authority_context,
            sanction=SanctionContext(
                # An empty bundle version is the platform's "no published
                # bundle": nothing is judged, never an implied approval.
                approved=team_merge.approved_components if bundle_version else None,
                organization_bundle_version=bundle_version,
                delta=authority_delta,
            ),
        )
    for rule in active_rules:
        collected_findings.extend(
            _RULE_FINDINGS_BY_ID[rule.id](
                authority_context if rule.reads_agent_authority else scoped_context
            )
        )
    findings = tuple(sorted(collected_findings, key=lambda finding: finding.id))

    if team is not None:
        # Raising a finding to its rule's organization floor happens before
        # suppressions and before the verdict, so the floor governs what
        # blocks -- which is the only reading under which a floor tightens
        # anything.
        findings = apply_severity_floors(findings, team.preparation.severity_floors())

    # Identical suppression handling to `scan` -- see that command's own
    # comment for the full rationale. `findings` on the evidence
    # artifact stays the full, unfiltered set; only the tuple passed to
    # `evaluate_gate` is narrowed.
    suppression_outcome: SuppressionOutcome = apply_suppressions(
        findings,
        manifest.suppressions if manifest is not None else (),
        reference_date=date.today(),
    )

    # Organization exceptions narrow the evaluated set the same way
    # repo-local suppressions just did, and for the same reason -- a risk
    # someone recorded as accepted should not also block. Applied after
    # suppressions so the two compose rather than compete, and recorded
    # either way: an expired exception re-blocks, visibly.
    exception_outcome: ExceptionOutcome | None = None
    effective_findings = suppression_outcome.effective_findings
    if team is not None:
        covered = {finding.id: finding for finding in effective_findings}
        exception_outcome = team_pipeline.apply_team_exceptions(
            effective_findings, team.preparation, now=evaluated_at
        )
        effective_findings = exception_outcome.effective_findings
        for applied in exception_outcome.applied():
            # Named, because a gate that passes only thanks to an approval
            # should not read the same as one with nothing to approve. The
            # evidence records it too; this is the line a reviewer reads.
            finding = covered.get(applied.finding_fingerprint)
            subject = (
                f"{finding.rule_id} ({applied.finding_fingerprint})"
                if finding
                else applied.finding_fingerprint
            )
            _report(
                "CLI-TEAM-EXCEPTION-APPLIED",
                f"organization exception applied to {subject} until "
                f"{applied.expires_at.date().isoformat()}; that finding does not block",
                severity=DiagnosticSeverity.INFO,
            )
        for expired in exception_outcome.expired():
            # Reported unconditionally, not at a verbosity level: a build
            # that broke because an approval lapsed must say so on the
            # run that broke it, or the next hour is spent looking for a
            # change that never happened.
            _report(
                "CLI-TEAM-EXCEPTION-EXPIRED",
                f"organization exception for {expired.finding_fingerprint} "
                f"expired on {expired.expires_at.date().isoformat()}; the "
                "finding it covered is blocking again",
                severity=DiagnosticSeverity.WARNING,
            )

    # Each organization rule's `action` decides what its findings do to
    # the verdict; a rule without one, and every Community gate, keeps the
    # severity threshold.
    rule_actions = team.preparation.rule_actions() if team is not None else {}
    gate_verdict = evaluate_gate(
        effective_findings,
        policy_config,
        scanner_version=__version__,
        rule_pack_name=CURRENT_RULE_PACK.name,
        rule_pack_version=CURRENT_RULE_PACK.version,
        rule_pack_fingerprint=rule_pack_fingerprint(CURRENT_RULE_PACK),
        rule_actions=rule_actions,
    )

    blast_radius = compute_blast_radius(current_document.nodes, current_document.edges)

    completeness = completeness_summary(current_document)
    analysis_incomplete = bool(completeness) or evaluation_result.is_incomplete

    verdict, exit_code = _gate_classify(
        gate_verdict,
        analysis_incomplete=analysis_incomplete,
        completeness_enforcement=policy_config.completeness_enforcement,
        # An unsanctioned grant requires review by default; an
        # organization makes it fail with a severity floor that blocks,
        # or decides it outright with the rule's action.
        review_required=bool(gate_verdict.review_findings)
        or any(
            finding.rule_id == UNSANCTIONED_AGENT_COMPONENT_RULE_ID
            and finding.rule_id not in rule_actions
            for finding in effective_findings
        ),
    )

    artifact = EvidenceArtifact(
        schema_version=CURRENT_EVIDENCE_SCHEMA_VERSION,
        acbom_digest=current_document.digest,
        baseline_digest=gate_baseline.baseline_digest,
        baseline_provenance=gate_baseline.baseline_provenance,
        effective_authority_diff=(
            gate_baseline.diff_result.effective_authority_changes
            if gate_baseline.diff_result is not None
            else None
        ),
        authority_delta=authority_delta,
        findings=findings,
        completeness=completeness,
        completeness_enforcement=policy_config.completeness_enforcement,
        completeness_enforcement_source=policy_config.completeness_enforcement_source,
        suppressions=suppression_outcome.records,
        # The platform's half of what decided this verdict. `None` on a
        # Community run, which is itself the fact that no organization
        # policy participated.
        team=(
            team_pipeline.build_evidence(
                team.preparation,
                exception_outcome,
                judge_delta(
                    current_document,
                    authority_delta,
                    team_merge.approved_components
                    if team_merge is not None
                    and team.preparation.organization_bundle_version
                    else None,
                ),
                _gate_finding_actions(findings, policy_config, rule_actions),
            )
            if team is not None and exception_outcome is not None
            else None
        ),
        verdict=verdict,
        versions=EvidenceVersions(
            scanner=Generator(name="controlloop", version=__version__),
            acbom_schema_version=current_document.schema_version,
            baseline_schema_version=gate_baseline.baseline_schema_version,
            evidence_schema_version=CURRENT_EVIDENCE_SCHEMA_VERSION,
            policy_version=CURRENT_RULE_PACK.version,
        ),
    )

    # The write guarantee: unconditional for every verdict reached
    # above, before any stdout rendering or exit below -- see
    # `_gate_write_evidence`'s own docstring.
    _gate_write_evidence(artifact, evidence_path)

    # The upload happens after the verdict exists and after evidence is
    # on disk, and it reports success or failure distinctly without
    # touching `exit_code`. A gate's answer is decided by local policy
    # evaluation; whether a report of that answer reached a server is a
    # separate fact.
    if team is not None:
        _gate_upload(
            team,
            document=current_document,
            findings=findings,
            verdict=verdict,
            authority_delta=authority_delta,
        )

    _gate_render_and_exit(
        artifact,
        blast_radius=blast_radius,
        material_changes=gate_baseline.material_changes,
        output_format=output_format,
        evidence_path=evidence_path,
        sarif_path=sarif_path,
        exit_code=exit_code,
    )


def main() -> None:
    """Run the ControlLoop CLI.

    Every command dispatched from here runs with stdout and stderr wrapped
    by the redaction boundary (`controlloop.redaction`), so no output path
    reachable from this entry point can bypass it.

    A command that needs an interactive confirmation but finds stdout is not
    a terminal fails closed with `NonInteractiveEnvironmentError` (see
    `controlloop.output`) instead of blocking on stdin. That is caught here,
    ahead of the generic handler below, and turned into a diagnostic on
    stderr plus the documented `ExitCode.INVALID_INPUT`, rather than being
    swallowed into a generic internal-error envelope. Its message is a fixed,
    non-interpolated string (never repository, prompt, or credential
    content), so writing it directly does not bypass the redaction boundary's
    intent.

    Any other exception that escapes a command is never let through as a raw
    traceback: it is caught here and reported as a stable, generic envelope,
    since the exception's own message could carry redaction-boundary-
    bypassing content (a path, a value) that was never meant to reach output.
    `typer.Exit`/usage errors are unaffected -- they surface as `SystemExit`,
    not `Exception`, before control reaches this handler.
    """
    with redaction.redirected_streams():
        try:
            app()
        except NonInteractiveEnvironmentError as error:
            _report("CLI-NONINTERACTIVE-ENVIRONMENT", str(error))
            raise SystemExit(int(ExitCode.INVALID_INPUT)) from None
        except Exception as error:
            _report(
                "CLI-INTERNAL-ERROR",
                "controlloop encountered an unexpected internal error and "
                f"stopped ({type(error).__name__}).",
            )
            raise SystemExit(int(ExitCode.INTERNAL_ERROR)) from None
