"""Tests for `policy.permission-bypass-from-project`."""

from __future__ import annotations

from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.adapters import agent_hosts
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules import ALL_RULES, permission_bypass_from_project_findings
from controlloop.policy.rules.permission_bypass_from_project import SCALES


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [
        rule for rule in ALL_RULES if rule.id == "policy.permission-bypass-from-project"
    ]

    assert rule.reads_agent_authority is True


def test_the_rules_scales_match_the_adapters() -> None:
    """The rule keeps its own copy so policy does not import discovery
    code; this holds the copies equal."""

    assert SCALES[("codex", "approval_policy")][0] == agent_hosts.CODEX_APPROVAL_SCALE
    assert SCALES[("codex", "sandbox_mode")][0] == agent_hosts.CODEX_SANDBOX_SCALE
    assert (
        SCALES[("codex", "default_permissions")][0]
        == agent_hosts.CODEX_PERMISSIONS_SCALE
    )
    assert (
        SCALES[("gemini-cli", "default_approval_mode")][0]
        == agent_hosts.GEMINI_MODE_SCALE
    )


def _claude(root: Path, settings: dict[str, object]) -> None:
    write(root, ".claude/settings.json", settings)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            {"permissions": {"defaultMode": "plan"}},
            {"permissions": {"defaultMode": "acceptEdits"}},
        ),
        ({}, {"permissions": {"defaultMode": "bypassPermissions"}}),
        ({"disableAllHooks": True}, {"disableAllHooks": False}),
        ({"permissions": {"disableBypassPermissionsMode": "disable"}}, {}),
        ({"disableSkillShellExecution": True}, {}),
        ({"sandbox": {"enabled": True}}, {"sandbox": {"enabled": False}}),
    ],
    ids=[
        "mode-right",
        "mode-to-bypass",
        "hooks-enabled",
        "bypass-guard-removed",
        "skill-shell",
        "sandbox-off",
    ],
)
def test_claude_code_loosening_is_high(
    tmp_path: Path, before: dict[str, object], after: dict[str, object]
) -> None:
    base, head = repos(tmp_path)
    _claude(base, before)
    _claude(head, after)

    findings = permission_bypass_from_project_findings(context(head, base))

    assert summary(findings) == [(FindingSeverity.HIGH, FindingChangeState.CHANGED)]


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            {"permissions": {"defaultMode": "acceptEdits"}},
            {"permissions": {"defaultMode": "plan"}},
        ),
        ({"disableAllHooks": False}, {"disableAllHooks": True}),
        (
            {"permissions": {"defaultMode": "default"}},
            {"permissions": {"defaultMode": "manual"}},
        ),
    ],
    ids=["mode-left", "hooks-disabled", "alias"],
)
def test_tightening_or_an_alias_is_silent(
    tmp_path: Path, before: dict[str, object], after: dict[str, object]
) -> None:
    base, head = repos(tmp_path)
    _claude(base, before)
    _claude(head, after)

    assert permission_bypass_from_project_findings(context(head, base)) == ()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ('approval_policy = "on-request"\n', 'approval_policy = "never"\n'),
        ('sandbox_mode = "read-only"\n', 'sandbox_mode = "danger-full-access"\n'),
    ],
)
def test_codex_loosening_is_high(tmp_path: Path, before: str, after: str) -> None:
    base, head = repos(tmp_path)
    write(base, ".codex/config.toml", before)
    write(head, ".codex/config.toml", after)

    (finding,) = permission_bypass_from_project_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "moved from" in finding.message


def test_codex_tightening_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".codex/config.toml", 'approval_policy = "never"\n')
    write(head, ".codex/config.toml", 'approval_policy = "on-request"\n')

    assert permission_bypass_from_project_findings(context(head, base)) == ()


def test_gemini_mode_and_server_trust(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(
        base,
        ".gemini/settings.json",
        {
            "general": {"defaultApprovalMode": "default"},
            "mcpServers": {"fs": {"command": "npx"}},
        },
    )
    write(
        head,
        ".gemini/settings.json",
        {
            "general": {"defaultApprovalMode": "auto_edit"},
            "mcpServers": {"fs": {"command": "npx", "trust": True}},
        },
    )

    findings = permission_bypass_from_project_findings(context(head, base))
    messages = sorted(finding.message for finding in findings)

    assert len(findings) == 2
    assert any("auto_edit" in message for message in messages)
    assert any("Every tool of MCP server 'fs'" in message for message in messages)


@pytest.mark.parametrize(
    ("path", "field"),
    [
        (".kiro/settings/mcp.json", "autoApprove"),
        (".roo/mcp.json", "alwaysAllow"),
        ("cline_mcp_settings.json", "autoApprove"),
    ],
)
def test_auto_approve_additions_are_high(tmp_path: Path, path: str, field: str) -> None:
    base, head = repos(tmp_path)
    write(base, path, {"mcpServers": {"git": {"command": "npx"}}})
    write(head, path, {"mcpServers": {"git": {"command": "npx", field: ["push"]}}})

    (finding,) = permission_bypass_from_project_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "tool 'push'" in finding.message.lower()


def test_a_subagent_mode_loosening_short_of_bypass(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".claude/agents/a.md", "---\nname: a\npermissionMode: plan\n---\n")
    write(
        head, ".claude/agents/a.md", "---\nname: a\npermissionMode: acceptEdits\n---\n"
    )

    (finding,) = permission_bypass_from_project_findings(context(head, base))

    assert "permissionMode moved from 'plan' to 'acceptEdits'" in finding.message


def test_a_first_scan_reports_bypass_hosts_and_approvals_at_low(tmp_path: Path) -> None:
    _claude(tmp_path, {"permissions": {"defaultMode": "bypassPermissions"}})
    write(
        tmp_path,
        ".roo/mcp.json",
        {"mcpServers": {"git": {"command": "npx", "alwaysAllow": ["status"]}}},
    )

    findings = permission_bypass_from_project_findings(context(tmp_path))

    assert summary(findings) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED),
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED),
    ]


def test_a_first_scan_with_a_default_mode_is_silent(tmp_path: Path) -> None:
    _claude(tmp_path, {"permissions": {"defaultMode": "default"}})

    assert permission_bypass_from_project_findings(context(tmp_path)) == ()
