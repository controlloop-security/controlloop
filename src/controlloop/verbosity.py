"""Logging verbosity primitive.

Operators can raise verbosity for troubleshooting without ever changing
what the gate decides or leaking protected content. This module is
deliberately small and additive: it resolves a `LogLevel` and `LogFormat`
from a flag and the environment, and exposes `OperatorLog`, whose two
emission methods (`verbose`, `debug`) only ever *add* optional stderr
lines gated by the resolved level. Nothing in this module can remove,
replace, or alter any existing diagnostic, any command's stdout, or any
exit code -- so "verbosity never alters findings, gate result, or exit
code" holds by construction rather than by a rule callers have to
remember to follow.

Both emission methods route through
`controlloop.output.OutputStreams .write_diagnostic`, which always
targets stderr and never stdout. `OutputStreams` defaults to reading
`sys.stdout`/`sys.stderr` at construction time, so an `OperatorLog()`
built inside a command handler -- which always runs inside
`controlloop.cli.main`'s `with redaction.redirected_streams():` block
-- automatically writes through the single redaction boundary with no
special wiring, exactly like every existing `OutputStreams()` call
site in `controlloop.cli` already does. This module never imports
`controlloop.redaction` directly; it relies entirely on that ambient
wrapping, the same way `controlloop.cli`'s existing `_show_config` and
`_bom_generate` diagnostics already do.

This module is not a general-purpose logging framework. It has no logger
hierarchy, no handlers, and no configuration beyond the one level and
one format resolved here. A future need for more can build on top of
these primitives.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from controlloop.exit_codes import ExitCode
from controlloop.output import OutputStreams

#: Environment variable selecting the log level.
LOG_LEVEL_ENV_VAR = "CONTROLLOOP_LOG_LEVEL"

#: Environment variable selecting the log line format.
LOG_FORMAT_ENV_VAR = "CONTROLLOOP_LOG_FORMAT"


class LogLevel(StrEnum):
    """The four verbosity levels: quiet, default, verbose, and debug. Values
    are the level's own lowercase name, so they render directly as both the
    flag's choice values and the environment variable's accepted values with
    no separate mapping to keep in sync."""

    QUIET = "quiet"
    DEFAULT = "default"
    VERBOSE = "verbose"
    DEBUG = "debug"


#: Ordinal rank for each level, lowest (quietest) to highest (most
#: verbose). Used only to compare a resolved level against a message's
#: own threshold; never serialized or exposed outside this module.
_LOG_LEVEL_ORDER: Mapping[LogLevel, int] = {
    LogLevel.QUIET: 0,
    LogLevel.DEFAULT: 1,
    LogLevel.VERBOSE: 2,
    LogLevel.DEBUG: 3,
}


class LogFormat(StrEnum):
    """The log line format: plain text, or structured JSON Lines when a
    machine format is selected."""

    TEXT = "text"
    JSON = "json"


class VerbosityError(ValueError):
    """A `--log-level`/`--log-format` value or its environment-variable
    equivalent could not be resolved.

    Carries `exit_code = ExitCode.INVALID_INPUT`, mirroring
    `controlloop.config.ConfigError`'s existing shape so a caller can
    translate it directly into the documented exit-2 contract. The
    message never contains the raw offending value -- only the
    environment variable name and the valid choices -- matching
    `controlloop.config`'s established "never echo hostile values in
    errors" discipline.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.exit_code = ExitCode.INVALID_INPUT


def resolve_log_level(
    *, flag: LogLevel | None, environ: Mapping[str, str] | None = None
) -> LogLevel:
    """Resolve the effective log level: flag beats environment beats the
    `default` level.

    ``flag`` is ``None`` when `--log-level` was not supplied, distinct
    from an explicit `--log-level default`; either way a supplied flag
    always wins over the environment. ``environ`` defaults to the real
    process environment when not supplied, matching
    `controlloop.output.no_color_requested`'s existing "accept an
    optional override, default to `os.environ`" shape -- every other
    caller, including this module's own tests, injects its own mapping.

    Raises `VerbosityError` for an unrecognized `CONTROLLOOP_LOG_LEVEL`
    value; a bad flag value is rejected earlier, by Typer/Click's own
    enum-choice validation, and never reaches this function.
    """

    if flag is not None:
        return flag

    environment = os.environ if environ is None else environ
    if LOG_LEVEL_ENV_VAR in environment:
        raw = environment[LOG_LEVEL_ENV_VAR].strip().lower()
        try:
            return LogLevel(raw)
        except ValueError:
            choices = ", ".join(member.value for member in LogLevel)
            raise VerbosityError(
                f"environment variable {LOG_LEVEL_ENV_VAR} must be one of: {choices}"
            ) from None

    return LogLevel.DEFAULT


def resolve_log_format(
    *, flag: LogFormat | None, environ: Mapping[str, str] | None = None
) -> LogFormat:
    """Resolve the effective log format: flag beats environment beats
    `text`. See `resolve_log_level` for the precedence and
    environment-injection rationale, which this mirrors exactly."""

    if flag is not None:
        return flag

    environment = os.environ if environ is None else environ
    if LOG_FORMAT_ENV_VAR in environment:
        raw = environment[LOG_FORMAT_ENV_VAR].strip().lower()
        try:
            return LogFormat(raw)
        except ValueError:
            choices = ", ".join(member.value for member in LogFormat)
            raise VerbosityError(
                f"environment variable {LOG_FORMAT_ENV_VAR} must be one of: {choices}"
            ) from None

    return LogFormat.TEXT


@dataclass(frozen=True, slots=True)
class OperatorLog:
    """Emits optional, level-gated operator diagnostics to stderr.

    Every message this emits is additional: below a method's own
    threshold, the call is a silent no-op, never a partial or altered
    version of anything else the command already writes. This is what
    keeps "verbosity never alters findings, gate result, or exit code"
    true by construction -- there is no code path here that can reach
    stdout, change an exit code, or rewrite an existing diagnostic.
    """

    streams: OutputStreams = field(default_factory=OutputStreams)
    level: LogLevel = LogLevel.DEFAULT
    format: LogFormat = LogFormat.TEXT

    def verbose(self, message: str) -> None:
        """Emit ``message`` only at `LogLevel.VERBOSE` or `LogLevel.DEBUG`."""

        self._emit(LogLevel.VERBOSE, message)

    def debug(self, message: str) -> None:
        """Emit ``message`` only at `LogLevel.DEBUG`."""

        self._emit(LogLevel.DEBUG, message)

    def _emit(self, threshold: LogLevel, message: str) -> None:
        if _LOG_LEVEL_ORDER[self.level] < _LOG_LEVEL_ORDER[threshold]:
            return
        # Equality, not identity: `LogLevel`/`LogFormat` are `StrEnum`, so
        # a plain string equal to a member's value (for example a caller
        # that forgot to convert one, as `controlloop.cli._bom_generate`
        # once did before deriving its `LogFormat` from
        # `ctx.parent.params`) still compares equal and hashes the same,
        # even though it would fail an `is` identity check.
        if self.format == LogFormat.JSON:
            payload = json.dumps(
                {"level": threshold.value, "message": message}, sort_keys=True
            )
            self.streams.write_diagnostic(payload)
        else:
            self.streams.write_diagnostic(f"• {threshold.value.upper()}  {message}")
