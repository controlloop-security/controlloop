"""Tests for adapter_sandbox."""

from __future__ import annotations

import socket
import subprocess

import pytest

from controlloop.adapters import AdapterSandboxViolationError, adapter_sandbox


def test_reading_a_file_is_allowed(tmp_path: object) -> None:
    path = f"{tmp_path}/readable.txt"
    with open(path, "w") as handle:  # setup, outside the sandbox
        handle.write("content")

    with adapter_sandbox(), open(path) as handle:
        assert handle.read() == "content"


@pytest.mark.parametrize("mode", ["w", "a", "x", "r+", "w+", "wb"])
def test_writing_a_file_is_denied(tmp_path: object, mode: str) -> None:
    path = f"{tmp_path}/should-not-be-created-{mode.replace('+', 'plus')}.txt"

    with adapter_sandbox(), pytest.raises(AdapterSandboxViolationError):
        open(path, mode)  # noqa: SIM115 -- asserting the call raises, never a handle


def test_subprocess_run_is_denied() -> None:
    with adapter_sandbox(), pytest.raises(AdapterSandboxViolationError):
        subprocess.run(["echo", "hi"], check=False)


def test_subprocess_popen_is_denied() -> None:
    with adapter_sandbox(), pytest.raises(AdapterSandboxViolationError):
        subprocess.Popen(["echo", "hi"])


def test_socket_creation_is_denied() -> None:
    with adapter_sandbox(), pytest.raises(AdapterSandboxViolationError):
        socket.socket()


def test_everything_is_restored_after_the_block_exits() -> None:
    real_open, real_popen_init, real_socket = (
        open,
        subprocess.Popen.__init__,
        socket.socket,
    )

    with adapter_sandbox():
        pass

    assert open is real_open
    assert subprocess.Popen.__init__ is real_popen_init
    assert socket.socket is real_socket


def test_everything_is_restored_even_if_the_block_raises() -> None:
    real_open = open

    with pytest.raises(RuntimeError, match="boom"), adapter_sandbox():
        raise RuntimeError("boom")

    assert open is real_open
