"""Shared test configuration: the offline enforcement harness.

Every test under `tests/` runs with all socket access denied by
default. Everything this CLI implements today -- ACBOM construction and
serialization, the redaction boundary, repository root resolution and
walking, `--help`/`--version` -- is core, local-first Community CLI
behavior, so the whole suite is "core scanning" as it exists now. A future
Team-tier test suite that genuinely needs network access is not exempted
here; that opt-in mechanism belongs to whichever story introduces it,
gated by an explicit flag and off by default, never a default-on escape
hatch from this fixture.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from controlloop.team.config import BRANCH_ENVIRONMENT_VARIABLES


class NetworkAccessDeniedError(RuntimeError):
    """A test attempted network access while the offline harness was active.

    Deliberately not an `OSError` subclass: sockets naturally raise
    `OSError`/`ConnectionError`, so a distinct exception type guarantees
    this can never be silently swallowed by ordinary network- or
    file-error handling. It is meant to fail a test loudly, not to be
    caught.
    """


def _deny(*_args: object, **_kwargs: object) -> None:
    raise NetworkAccessDeniedError(
        "network access is denied in tests/ by the offline harness"
    )


@pytest.fixture(autouse=True)
def _deny_network_access(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(socket, "socket", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    yield


@pytest.fixture(autouse=True)
def _clear_ci_branch_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Team upload reads the branch from CI variables. Clearing them
    keeps every test's envelope the same on a laptop and on a CI runner,
    which sets them for its own build."""

    for name in BRANCH_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)
