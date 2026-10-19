"""Output stream separation primitives.

Machine-readable output (JSON, SARIF, or any future machine format) belongs
on stdout and nowhere else. Progress, warnings, diagnostics, and interactive
prompts belong on stderr and must never contaminate stdout. This module is
the single enforced boundary for that separation across the CLI.

It deliberately owns no exit-code concept of its own: the shared
exit-code registry is ``controlloop.exit_codes.ExitCode``, and callers
(see ``controlloop.cli``) are expected to map
:class:`NonInteractiveEnvironmentError` to ``ExitCode.INVALID_INPUT``
themselves rather than this module duplicating that mapping.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TextIO

#: Environment variable name recognized by the https://no-color.org
#: convention. Its presence disables color regardless of its value.
NO_COLOR_ENV_VAR = "NO_COLOR"


class NonInteractiveEnvironmentError(RuntimeError):
    """Raised when an interactive prompt is required but stdout is not a TTY.

    Callers must not catch this to retry a blocking read from stdin; it
    signals that the command should fail closed instead.
    """


def is_tty(stream: TextIO) -> bool:
    """Return whether ``stream`` is attached to an interactive terminal.

    Safe against streams that do not implement ``isatty`` at all (for
    example plain duck-typed fakes or some redirected-file wrappers): such
    streams are treated as non-interactive rather than raising.
    """
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    return bool(isatty())


def no_color_requested(env: Mapping[str, str] | None = None) -> bool:
    """Return whether ``NO_COLOR`` was requested.

    Per the NO_COLOR convention (https://no-color.org), color output should
    be disabled whenever the variable is *present* in the environment,
    regardless of its value -- including an empty string. The value itself
    is never interpreted.
    """
    environ = os.environ if env is None else env
    return NO_COLOR_ENV_VAR in environ


def terminal_width(stream: TextIO, *, default: int = 80) -> int:
    """Return the column width to render `stream` at: rendering adapts to
    terminal width and degrades to plain text when redirected.

    A non-terminal `stream` (redirected to a file or pipe, or any
    duck-typed fake without a real `isatty`) always gets `default`
    rather than whatever unrelated terminal the parent process happens
    to be attached to -- the same "degrade when redirected" rule
    :meth:`OutputStreams.color_enabled` already applies to color.
    A real terminal's width comes from
    :func:`shutil.get_terminal_size`, which already consults the
    `COLUMNS` environment variable before falling back to the OS
    query and finally to its own `fallback` value.
    """
    if not is_tty(stream):
        return default
    return shutil.get_terminal_size(fallback=(default, 24)).columns


@dataclass(frozen=True)
class OutputStreams:
    """Explicit stdout/stderr boundary for CLI output.

    Machine-readable payloads must only ever be written through
    :meth:`write_data`, which always targets stdout. Everything else --
    progress, warnings, diagnostics -- must go through :meth:`write_diagnostic`,
    which always targets stderr. Keeping both behind one small interface makes
    the separation trivially testable and hard to bypass by accident.

    ``stdout``, ``stderr``, and ``stdin`` default to the real process streams
    but accept injected fakes for deterministic, offline testing.
    """

    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)
    stdin: TextIO = field(default_factory=lambda: sys.stdin)

    def write_data(self, payload: str) -> None:
        """Write one machine-readable payload to stdout.

        ``payload`` must already be the complete, final serialized document.
        Callers must not interleave any other stdout writes around this
        call, or stdout stops parsing as a single valid document with no
        leading or trailing noise.
        """
        self.stdout.write(payload)
        if not payload.endswith("\n"):
            self.stdout.write("\n")
        self.stdout.flush()

    def write_diagnostic(self, message: str) -> None:
        """Write one progress, warning, or diagnostic line to stderr.

        This is the only method allowed to emit progress, warning, or
        diagnostic text, and it must never target stdout.
        """
        self.stderr.write(message)
        if not message.endswith("\n"):
            self.stderr.write("\n")
        self.stderr.flush()

    def color_enabled(self) -> bool:
        """Return whether color/progress rendering may be used on stdout.

        Disabled automatically when stdout is not a terminal, and whenever
        ``NO_COLOR`` is present in the environment.
        """
        if no_color_requested():
            return False
        return is_tty(self.stdout)

    def confirm_or_exit(self, prompt: str, *, default: bool = False) -> bool:
        """Ask for interactive confirmation, failing closed when not possible.

        The prompt text is written to stderr, never stdout, so an
        interactive confirmation never contaminates machine-readable output.

        When stdout is not attached to a terminal, this fails closed by
        raising :class:`NonInteractiveEnvironmentError` immediately, without
        reading stdin or writing the prompt, instead of blocking on a read
        that can never be satisfied.
        """
        if not is_tty(self.stdout):
            raise NonInteractiveEnvironmentError(
                "stdout is not a terminal; refusing to block on an interactive prompt"
            )
        suffix = "[Y/n]" if default else "[y/N]"
        self.stderr.write(f"{prompt} {suffix} ")
        self.stderr.flush()
        response = self.stdin.readline().strip().lower()
        if not response:
            return default
        return response in {"y", "yes"}
