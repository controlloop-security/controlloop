"""Offline evidence for controlloop.findings.

`controlloop.findings.models`, `controlloop.findings.identity`, and
`controlloop.findings.rendering` perform no file, subprocess, or
network access of their own -- they only transform already-sanitized
objects a caller passes in. `tests/test_redaction.py`'s
`TestCanary` class carries the structural AST-import proof of that
(mirroring `test_diff_module_never_reads_raw_content`). No dedicated
network-denial test is needed beyond that structural check, since
`tests/conftest.py`'s autouse `_deny_network_access` fixture already
covers every test under `tests/`, including this module -- recorded
explicitly here rather than silently omitted, mirroring
`tests/policy/test_policy_engine.py`'s own
`TestOffline.test_offline_harness_is_active_for_this_module`.
"""

from __future__ import annotations

import socket

import pytest


class TestOffline:
    def test_offline_harness_is_active_for_this_module(self) -> None:
        with pytest.raises(RuntimeError, match="offline harness"):
            socket.socket()
