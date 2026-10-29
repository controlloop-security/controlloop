"""Tests for `policy.agent-sandbox-weakened`."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from functools import partial
from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.adapters import agent_hosts
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.manifest.models import Approval, ManifestDocument
from controlloop.policy.rules.agent_sandbox_weakened import (
    CURSOR_EGRESS_SCALE,
    RULE,
)
from controlloop.policy.rules.agent_sandbox_weakened import (
    findings as agent_sandbox_weakened_findings,
)


def test_the_rule_reads_agent_authority() -> None:
    assert RULE.reads_agent_authority is True


def test_the_cursor_egress_scale_matches_the_adapter() -> None:
    """The rule keeps its own copy so policy does not import discovery
    code; this holds the copies equal."""

    assert CURSOR_EGRESS_SCALE == agent_hosts.CURSOR_EGRESS_SCALE


def _claude(root: Path, sandbox: dict[str, object] | None) -> None:
    write(
        root, ".claude/settings.json", {} if sandbox is None else {"sandbox": sandbox}
    )


def _codex(root: Path, network_access: bool) -> None:
    flag = "true" if network_access else "false"
    write(
        root,
        ".codex/config.toml",
        f"[sandbox_workspace_write]\nnetwork_access = {flag}\n",
    )


def _gemini(root: Path, tools: dict[str, object]) -> None:
    write(root, ".gemini/settings.json", {"tools": tools})


def _cursor(root: Path, egress: str) -> None:
    write(root, ".cursor/environment.json", {"egressMode": egress})


# (write the tight state, write the loose state, the setting the message names)
_HOSTS: dict[str, tuple[Callable[[Path], None], Callable[[Path], None], str]] = {
    "claude-sandbox-off": (
        partial(_claude, sandbox={"enabled": True}),
        partial(_claude, sandbox={"enabled": False}),
        "sandbox.enabled",
    ),
    "claude-unsandboxed-commands": (
        partial(_claude, sandbox={"allowUnsandboxedCommands": False}),
        partial(_claude, sandbox={"allowUnsandboxedCommands": True}),
        "sandbox.allowUnsandboxedCommands",
    ),
    "claude-auto-allow-bash": (
        partial(_claude, sandbox={"autoAllowBashIfSandboxed": False}),
        partial(_claude, sandbox={"autoAllowBashIfSandboxed": True}),
        "sandbox.autoAllowBashIfSandboxed",
    ),
    "codex-network": (
        partial(_codex, network_access=False),
        partial(_codex, network_access=True),
        "sandbox_workspace_write.network_access",
    ),
    "gemini-sandbox-off": (
        partial(_gemini, tools={"sandbox": "docker"}),
        partial(_gemini, tools={"sandbox": False}),
        "tools.sandbox",
    ),
    "gemini-network": (
        partial(_gemini, tools={"sandboxNetworkAccess": False}),
        partial(_gemini, tools={"sandboxNetworkAccess": True}),
        "tools.sandboxNetworkAccess",
    ),
    "cursor-egress": (
        partial(_cursor, egress="network_settings_only"),
        partial(_cursor, egress="allow_all"),
        "egressMode",
    ),
}


@pytest.mark.parametrize("case", sorted(_HOSTS))
def test_loosening_is_high_and_names_the_setting(tmp_path: Path, case: str) -> None:
    tight, loose, setting = _HOSTS[case]
    base, head = repos(tmp_path)
    tight(base)
    loose(head)

    (finding,) = agent_sandbox_weakened_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert finding.change_state is FindingChangeState.CHANGED
    assert f"'{setting}' moved from" in finding.message
    assert finding.remediation is not None
    assert setting in finding.remediation


@pytest.mark.parametrize("case", sorted(_HOSTS))
def test_tightening_is_silent(tmp_path: Path, case: str) -> None:
    tight, loose, _ = _HOSTS[case]
    base, head = repos(tmp_path)
    loose(base)
    tight(head)

    assert agent_sandbox_weakened_findings(context(head, base)) == ()


@pytest.mark.parametrize("case", sorted(_HOSTS))
def test_unchanged_is_silent(tmp_path: Path, case: str) -> None:
    _, loose, _ = _HOSTS[case]
    base, head = repos(tmp_path)
    loose(base)
    loose(head)

    assert agent_sandbox_weakened_findings(context(head, base)) == ()


@pytest.mark.parametrize("case", sorted(_HOSTS))
def test_a_first_scan_at_the_loose_end_is_low(tmp_path: Path, case: str) -> None:
    _, loose, setting = _HOSTS[case]
    loose(tmp_path)

    (finding,) = agent_sandbox_weakened_findings(context(tmp_path))

    assert summary((finding,)) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)
    ]
    assert f"'{setting}'" in finding.message


@pytest.mark.parametrize("case", sorted(_HOSTS))
def test_a_first_scan_at_the_tight_end_is_silent(tmp_path: Path, case: str) -> None:
    tight, _, _ = _HOSTS[case]
    tight(tmp_path)

    assert agent_sandbox_weakened_findings(context(tmp_path)) == ()


def test_removing_a_tight_setting_loosens(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _claude(base, {"enabled": True})
    _claude(head, None)

    (finding,) = agent_sandbox_weakened_findings(context(head, base))

    assert "'sandbox.enabled' moved from 'true' to 'unset'" in finding.message


def test_a_step_along_the_cursor_scale_loosens(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _cursor(base, "network_settings_only")
    _cursor(head, "default_with_network_settings")

    (finding,) = agent_sandbox_weakened_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH


def test_a_value_the_rule_does_not_know_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _cursor(base, "network_settings_only")
    _cursor(head, "some_future_mode")

    assert agent_sandbox_weakened_findings(context(head, base)) == ()


def test_several_loosened_settings_are_one_finding(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _claude(base, {"enabled": True, "allowUnsandboxedCommands": False})
    _claude(head, {"enabled": False, "allowUnsandboxedCommands": True})

    (finding,) = agent_sandbox_weakened_findings(context(head, base))

    assert "'sandbox.enabled'" in finding.message
    assert "'sandbox.allowUnsandboxedCommands'" in finding.message


def test_an_approval_keeps_the_finding_at_info(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _claude(base, {"enabled": True})
    _claude(head, {"enabled": False})
    manifest = ManifestDocument(
        schema_version="1.0.0",
        owner="security-team",
        approvals=(Approval(capability="Claude Code", approver="alice"),),
    )

    (approved,) = agent_sandbox_weakened_findings(
        replace(context(head, base), manifest=manifest)
    )

    assert approved.severity is FindingSeverity.INFO
