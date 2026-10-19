"""Denies an adapter the ability to write files, execute subprocesses, or
open sockets while its code runs.

Adapters are first-party-authored but parse untrusted, hostile repository
content; this is a defense-in-depth boundary, not a claim of exhaustive
process isolation -- it covers exactly those three things, not every
conceivable I/O primitive.
"""

from __future__ import annotations

import builtins
import socket
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_WRITE_MODE_CHARACTERS = frozenset("wxa+")


class AdapterSandboxViolationError(RuntimeError):
    """An adapter attempted a file write, a subprocess, or a socket while
    the adapter sandbox was active."""


@contextmanager
def adapter_sandbox() -> Iterator[None]:
    """Deny file writes, subprocess execution, and socket creation for the
    duration of the block, restoring whatever was active immediately
    before the block even if it raises.

    Captures the previous `open`/`Popen.__init__`/`socket.socket`
    dynamically at entry, not once at import time -- so nesting inside
    another guard (for example the offline-enforcement test harness,
    which already replaces `socket.socket` for the whole suite) restores
    that guard's state on exit, rather than clobbering it with the
    true, unguarded original.
    """

    previous_open = builtins.open
    previous_popen_init = subprocess.Popen.__init__
    previous_socket = socket.socket

    def _denied_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _WRITE_MODE_CHARACTERS.intersection(mode):
            raise AdapterSandboxViolationError(
                "adapters may not open a file in a write-capable mode"
            )
        return previous_open(file, mode, *args, **kwargs)

    def _denied_popen_init(*_args: Any, **_kwargs: Any) -> None:
        raise AdapterSandboxViolationError("adapters may not execute a subprocess")

    def _denied_socket(*_args: Any, **_kwargs: Any) -> Any:
        raise AdapterSandboxViolationError("adapters may not open a socket")

    builtins.open = _denied_open
    subprocess.Popen.__init__ = _denied_popen_init  # type: ignore[method-assign]
    socket.socket = _denied_socket  # type: ignore[assignment, misc]
    try:
        yield
    finally:
        builtins.open = previous_open
        subprocess.Popen.__init__ = previous_popen_init  # type: ignore[method-assign]
        socket.socket = previous_socket  # type: ignore[misc]
