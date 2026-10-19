"""Unit tests for the output stream separation primitive.

Privacy (redaction canary): not applicable. This module accepts no
repository content, prompt text, credential material, or environment
values as data to output -- it only routes caller-supplied strings to
stdout or stderr and inspects the *presence* of the NO_COLOR variable, never
any secret-shaped value. There is nothing here for the redaction canary to
cover, so this comment records that explicitly instead of silently omitting
the check category.

Offline: not applicable. `controlloop.output` makes no network or
filesystem calls (it only writes to injected/stdlib text streams), which a
quick grep confirms: no `socket`, `requests`, `httpx`, or `open(` usage
appears in `src/controlloop/output.py`.

Exit-code reconciliation: this module used to define its own module-local
`EXIT_INVALID_INPUT` constant. Now that the shared
`controlloop.exit_codes.ExitCode` registry exists, that constant is gone and
`NonInteractiveEnvironmentError` -> `ExitCode.INVALID_INPUT` mapping is
tested where it is actually performed: `tests/test_cli.py`'s
`test_main_fails_closed_on_noninteractive_environment_error`.
"""

from __future__ import annotations

import io
import json
import os
import shutil

import pytest

from controlloop.output import (
    NO_COLOR_ENV_VAR,
    NonInteractiveEnvironmentError,
    OutputStreams,
    is_tty,
    no_color_requested,
    terminal_width,
)


class _TTYStringIO(io.StringIO):
    """An in-memory text stream that reports a configurable TTY status."""

    def __init__(self, *args: object, tty: bool, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class _NoIsATTy:
    """A minimal duck-typed stream with no ``isatty`` attribute at all."""

    def write(self, _: str) -> int:
        return 0

    def flush(self) -> None:
        return None


# --- stdout carries only data, stderr carries diagnostics ---


def test_write_data_targets_only_stdout() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    streams = OutputStreams(stdout=stdout, stderr=stderr)

    streams.write_data('{"ok": true}')

    assert stdout.getvalue() == '{"ok": true}\n'
    assert stderr.getvalue() == ""


def test_write_diagnostic_targets_only_stderr() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()
    streams = OutputStreams(stdout=stdout, stderr=stderr)

    streams.write_diagnostic("scanning repository...")

    assert stderr.getvalue() == "scanning repository...\n"
    assert stdout.getvalue() == ""


# --- Boundary / malformed input handling ---


def test_write_data_does_not_double_trailing_newline() -> None:
    stdout = io.StringIO()
    streams = OutputStreams(stdout=stdout, stderr=io.StringIO())

    streams.write_data("already-terminated\n")

    assert stdout.getvalue() == "already-terminated\n"


def test_write_data_empty_payload_produces_only_newline() -> None:
    stdout = io.StringIO()
    streams = OutputStreams(stdout=stdout, stderr=io.StringIO())

    streams.write_data("")

    assert stdout.getvalue() == "\n"


def test_is_tty_false_for_stream_without_isatty_attribute() -> None:
    assert is_tty(_NoIsATTy()) is False  # type: ignore[arg-type]


# --- piping stdout to a parser succeeds while stderr is a terminal ---


def test_stdout_parses_cleanly_while_stderr_is_attached_to_a_terminal() -> None:
    stdout = io.StringIO()
    stderr = _TTYStringIO(tty=True)
    streams = OutputStreams(stdout=stdout, stderr=stderr)

    streams.write_diagnostic("progress: 1/3 adapters complete")
    streams.write_diagnostic("warning: unresolved identity for tool x")
    streams.write_data(json.dumps({"schema_version": "1.0.0", "nodes": []}))

    # A parser consuming only stdout must succeed and see none of the
    # diagnostic text that was attached to the (simulated) terminal stderr.
    parsed = json.loads(stdout.getvalue())
    assert parsed == {"schema_version": "1.0.0", "nodes": []}
    assert "progress" not in stdout.getvalue()
    assert "warning" not in stdout.getvalue()
    assert stderr.isatty() is True


# --- fail-closed interactive confirmation ---


class _RaisingStdin:
    """A stdin fake that fails the test if it is ever read from."""

    def readline(self, *_: object) -> str:  # pragma: no cover - guard path
        raise AssertionError("must not read stdin when failing closed")


def test_confirm_or_exit_fails_closed_when_stdout_is_not_a_terminal() -> None:
    stdout = _TTYStringIO(tty=False)
    stderr = io.StringIO()
    streams = OutputStreams(stdout=stdout, stderr=stderr, stdin=_RaisingStdin())  # type: ignore[arg-type]

    with pytest.raises(NonInteractiveEnvironmentError):
        streams.confirm_or_exit("Proceed?")

    # Failing closed must not write the prompt anywhere either.
    assert stderr.getvalue() == ""


def test_confirm_or_exit_prompts_on_stderr_and_reads_stdin_when_interactive() -> None:
    stdout = _TTYStringIO(tty=True)
    stderr = io.StringIO()
    stdin = io.StringIO("y\n")
    streams = OutputStreams(stdout=stdout, stderr=stderr, stdin=stdin)

    result = streams.confirm_or_exit("Proceed?")

    assert result is True
    assert "Proceed?" in stderr.getvalue()
    assert stdout.getvalue() == ""


def test_confirm_or_exit_returns_default_for_empty_response() -> None:
    stdout = _TTYStringIO(tty=True)
    streams = OutputStreams(
        stdout=stdout, stderr=io.StringIO(), stdin=io.StringIO("\n")
    )

    assert streams.confirm_or_exit("Proceed?", default=True) is True


def test_confirm_or_exit_recognizes_no_response() -> None:
    stdout = _TTYStringIO(tty=True)
    streams = OutputStreams(
        stdout=stdout, stderr=io.StringIO(), stdin=io.StringIO("n\n")
    )

    assert streams.confirm_or_exit("Proceed?", default=True) is False


# --- color/progress rendering gated by TTY and NO_COLOR ---


@pytest.mark.parametrize(
    ("env", "stdout_is_tty", "expected"),
    [
        ({}, True, True),
        ({}, False, False),
        ({NO_COLOR_ENV_VAR: ""}, True, False),
        ({NO_COLOR_ENV_VAR: "1"}, True, False),
        ({NO_COLOR_ENV_VAR: "0"}, True, False),
    ],
)
def test_color_enabled_matrix(
    env: dict[str, str],
    stdout_is_tty: bool,
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(NO_COLOR_ENV_VAR, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    stdout = _TTYStringIO(tty=stdout_is_tty)
    streams = OutputStreams(stdout=stdout, stderr=io.StringIO())

    assert streams.color_enabled() is expected


def test_no_color_requested_true_only_for_presence_not_value() -> None:
    assert no_color_requested({}) is False
    assert no_color_requested({NO_COLOR_ENV_VAR: ""}) is True
    assert no_color_requested({NO_COLOR_ENV_VAR: "anything"}) is True


# --- Determinism ---


def test_write_data_is_deterministic_across_calls() -> None:
    first = io.StringIO()
    second = io.StringIO()

    OutputStreams(stdout=first, stderr=io.StringIO()).write_data("stable-payload")
    OutputStreams(stdout=second, stderr=io.StringIO()).write_data("stable-payload")

    assert first.getvalue() == second.getvalue() == "stable-payload\n"


# --- terminal_width ---


def test_terminal_width_returns_default_for_non_terminal_stream() -> None:
    stream = _TTYStringIO(tty=False)

    assert terminal_width(stream, default=42) == 42


def test_terminal_width_returns_default_for_stream_with_no_isatty() -> None:
    assert terminal_width(_NoIsATTy(), default=42) == 42  # type: ignore[arg-type]


def test_terminal_width_reads_real_size_for_a_terminal_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil, "get_terminal_size", lambda fallback: os.terminal_size((132, 43))
    )
    stream = _TTYStringIO(tty=True)

    assert terminal_width(stream, default=80) == 132


def test_terminal_width_is_deterministic_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil, "get_terminal_size", lambda fallback: os.terminal_size((100, 30))
    )
    stream = _TTYStringIO(tty=True)

    assert terminal_width(stream) == terminal_width(stream) == 100
