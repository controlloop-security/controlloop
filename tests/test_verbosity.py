"""Tests for the logging verbosity primitive.

Covers level selection (quiet/default/verbose/debug selectable by flag and
environment), redaction (log output passes the redaction boundary, including
at debug level), and format (structured JSON Lines output when the `json`
log format is selected). The guarantee that verbosity never alters findings,
gate result, or exit code is asserted end to end through the real CLI entry
point in `test_cli.py`'s `TestVerbosity`, since it is a property of a whole
command invocation, not of this module in isolation.

Offline: `controlloop.verbosity` performs no filesystem or network I/O of
its own -- only `os.environ` reads and stream writes through
`controlloop.output.OutputStreams` -- so it is covered by the autouse
`_deny_network_access` fixture in `conftest.py` merely by living under
`tests/`. A dedicated grep-style check is unnecessary; a quick read of
`src/controlloop/verbosity.py` shows no `socket`, `requests`, `httpx`, or
`open(` usage.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from controlloop import redaction
from controlloop.exit_codes import ExitCode
from controlloop.output import OutputStreams
from controlloop.verbosity import (
    LOG_FORMAT_ENV_VAR,
    LOG_LEVEL_ENV_VAR,
    LogFormat,
    LogLevel,
    OperatorLog,
    VerbosityError,
    resolve_log_format,
    resolve_log_level,
)

_SECRET_SHAPED_CANARY = "ghp_" + "a" * 36


class TestResolveLogLevel:
    """Quiet, default, verbose, and debug are selectable by flag
    and by the CONTROLLOOP_LOG_LEVEL environment variable."""

    def test_defaults_to_default_level_with_no_flag_or_environment(self) -> None:
        assert resolve_log_level(flag=None, environ={}) == LogLevel.DEFAULT

    @pytest.mark.parametrize("level", list(LogLevel))
    def test_flag_selects_every_level(self, level: LogLevel) -> None:
        assert resolve_log_level(flag=level, environ={}) == level

    @pytest.mark.parametrize("level", list(LogLevel))
    def test_environment_selects_every_level(self, level: LogLevel) -> None:
        resolved = resolve_log_level(
            flag=None, environ={LOG_LEVEL_ENV_VAR: level.value}
        )
        assert resolved == level

    def test_environment_value_is_case_and_whitespace_insensitive(self) -> None:
        resolved = resolve_log_level(
            flag=None, environ={LOG_LEVEL_ENV_VAR: "  VERBOSE  "}
        )
        assert resolved == LogLevel.VERBOSE

    def test_flag_wins_over_environment(self) -> None:
        resolved = resolve_log_level(
            flag=LogLevel.DEBUG, environ={LOG_LEVEL_ENV_VAR: "quiet"}
        )
        assert resolved == LogLevel.DEBUG

    def test_malformed_environment_value_is_a_verbosity_error(self) -> None:
        with pytest.raises(VerbosityError) as excinfo:
            resolve_log_level(flag=None, environ={LOG_LEVEL_ENV_VAR: "loud"})

        assert excinfo.value.exit_code == ExitCode.INVALID_INPUT
        assert LOG_LEVEL_ENV_VAR in str(excinfo.value)
        assert "quiet" in str(excinfo.value)
        assert "debug" in str(excinfo.value)

    def test_malformed_environment_value_never_echoes_the_raw_value(self) -> None:
        with pytest.raises(VerbosityError) as excinfo:
            resolve_log_level(
                flag=None, environ={LOG_LEVEL_ENV_VAR: _SECRET_SHAPED_CANARY}
            )

        assert _SECRET_SHAPED_CANARY not in str(excinfo.value)

    def test_reads_the_real_process_environment_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(LOG_LEVEL_ENV_VAR, "debug")

        assert resolve_log_level(flag=None) == LogLevel.DEBUG


class TestResolveLogFormat:
    """The log format (text/json) is likewise selectable by flag
    and by the CONTROLLOOP_LOG_FORMAT environment variable."""

    def test_defaults_to_text_with_no_flag_or_environment(self) -> None:
        assert resolve_log_format(flag=None, environ={}) == LogFormat.TEXT

    @pytest.mark.parametrize("fmt", list(LogFormat))
    def test_flag_selects_every_format(self, fmt: LogFormat) -> None:
        assert resolve_log_format(flag=fmt, environ={}) == fmt

    def test_environment_selects_json(self) -> None:
        resolved = resolve_log_format(flag=None, environ={LOG_FORMAT_ENV_VAR: "json"})
        assert resolved == LogFormat.JSON

    def test_flag_wins_over_environment(self) -> None:
        resolved = resolve_log_format(
            flag=LogFormat.TEXT, environ={LOG_FORMAT_ENV_VAR: "json"}
        )
        assert resolved == LogFormat.TEXT

    def test_malformed_environment_value_is_a_verbosity_error(self) -> None:
        with pytest.raises(VerbosityError) as excinfo:
            resolve_log_format(flag=None, environ={LOG_FORMAT_ENV_VAR: "xml"})

        assert excinfo.value.exit_code == ExitCode.INVALID_INPUT
        assert LOG_FORMAT_ENV_VAR in str(excinfo.value)


class TestOperatorLogGating:
    """Positive and negative gating for `.verbose`/`.debug` at each of the
    four levels -- the levels must actually change what is emitted."""

    @pytest.mark.parametrize("level", [LogLevel.QUIET, LogLevel.DEFAULT])
    def test_verbose_message_is_suppressed_below_verbose_level(
        self, level: LogLevel
    ) -> None:
        stderr = io.StringIO()
        log = OperatorLog(streams=OutputStreams(stderr=stderr), level=level)

        log.verbose("progress detail")

        assert stderr.getvalue() == ""

    @pytest.mark.parametrize("level", [LogLevel.VERBOSE, LogLevel.DEBUG])
    def test_verbose_message_is_emitted_at_or_above_verbose_level(
        self, level: LogLevel
    ) -> None:
        stderr = io.StringIO()
        log = OperatorLog(streams=OutputStreams(stderr=stderr), level=level)

        log.verbose("progress detail")

        assert "VERBOSE" in stderr.getvalue()
        assert "progress detail" in stderr.getvalue()

    @pytest.mark.parametrize(
        "level", [LogLevel.QUIET, LogLevel.DEFAULT, LogLevel.VERBOSE]
    )
    def test_debug_message_is_suppressed_below_debug_level(
        self, level: LogLevel
    ) -> None:
        stderr = io.StringIO()
        log = OperatorLog(streams=OutputStreams(stderr=stderr), level=level)

        log.debug("internal detail")

        assert stderr.getvalue() == ""

    def test_debug_message_is_emitted_at_debug_level(self) -> None:
        stderr = io.StringIO()
        log = OperatorLog(streams=OutputStreams(stderr=stderr), level=LogLevel.DEBUG)

        log.debug("internal detail")

        assert "DEBUG" in stderr.getvalue()
        assert "internal detail" in stderr.getvalue()

    def test_operator_log_never_writes_to_stdout(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        log = OperatorLog(
            streams=OutputStreams(stdout=stdout, stderr=stderr),
            level=LogLevel.DEBUG,
        )

        log.verbose("v")
        log.debug("d")

        assert stdout.getvalue() == ""
        assert stderr.getvalue() != ""


class TestOperatorLogFormat:
    """Text is human-oriented, json is one structured object per
    line -- "structured when a machine format is selected"."""

    def test_text_format_uses_the_brand_info_glyph(self) -> None:
        stderr = io.StringIO()
        log = OperatorLog(
            streams=OutputStreams(stderr=stderr),
            level=LogLevel.DEBUG,
            format=LogFormat.TEXT,
        )

        log.debug("hello")

        assert stderr.getvalue() == "• DEBUG  hello\n"

    def test_json_format_is_one_parseable_object_per_line(self) -> None:
        stderr = io.StringIO()
        log = OperatorLog(
            streams=OutputStreams(stderr=stderr),
            level=LogLevel.DEBUG,
            format=LogFormat.JSON,
        )

        log.verbose("first")
        log.debug("second")

        lines = [line for line in stderr.getvalue().splitlines() if line]
        assert len(lines) == 2
        first, second = (json.loads(line) for line in lines)
        assert first == {"level": "verbose", "message": "first"}
        assert second == {"level": "debug", "message": "second"}


class TestOperatorLogRedaction:
    """All log output passes the redaction boundary, including at
    debug level. `OperatorLog` writes through `OutputStreams`, which reads
    `sys.stderr` at construction time -- inside
    `redaction.redirected_streams()`, that is the redacting wrapper, the
    same mechanism every real command already relies on."""

    def test_debug_message_containing_a_secret_is_redacted(self) -> None:
        stderr_buffer = io.StringIO()

        with redaction.redirected_streams(
            target_stdout=io.StringIO(), target_stderr=stderr_buffer
        ):
            log = OperatorLog(level=LogLevel.DEBUG)
            log.debug(f"resolved token: {_SECRET_SHAPED_CANARY}")

        value = stderr_buffer.getvalue()
        assert _SECRET_SHAPED_CANARY not in value
        assert "controlloop:redacted:sha256:" in value

    def test_verbose_message_containing_a_secret_is_redacted(self) -> None:
        stderr_buffer = io.StringIO()

        with redaction.redirected_streams(
            target_stdout=io.StringIO(), target_stderr=stderr_buffer
        ):
            log = OperatorLog(level=LogLevel.VERBOSE)
            log.verbose(f"resolved token: {_SECRET_SHAPED_CANARY}")

        value = stderr_buffer.getvalue()
        assert _SECRET_SHAPED_CANARY not in value
        assert "controlloop:redacted:sha256:" in value

    def test_json_format_debug_message_containing_a_secret_is_redacted(self) -> None:
        stderr_buffer = io.StringIO()

        with redaction.redirected_streams(
            target_stdout=io.StringIO(), target_stderr=stderr_buffer
        ):
            log = OperatorLog(level=LogLevel.DEBUG, format=LogFormat.JSON)
            log.debug(f"resolved token: {_SECRET_SHAPED_CANARY}")

        value = stderr_buffer.getvalue()
        assert _SECRET_SHAPED_CANARY not in value
        assert "controlloop:redacted:sha256:" in value

    def test_previous_stderr_is_restored_after_the_block(self) -> None:
        previous_stderr = sys.stderr

        with redaction.redirected_streams(target_stdout=io.StringIO()):
            assert sys.stderr is not previous_stderr

        assert sys.stderr is previous_stderr
