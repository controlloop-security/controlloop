"""Tests for `policy.component-self-grant`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from _authority_rule_support import SECRET, context, repos, summary, write

from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import RuleContext
from controlloop.policy.rules import (
    ALL_RULES,
    component_self_grant_findings,
    mcp_server_identity_change_findings,
    overprivileged_agent_workflow_findings,
    unpinned_agent_component_findings,
)


def _marketplace(root: Path, source: dict[str, object]) -> None:
    write(
        root,
        ".claude/settings.json",
        {"extraKnownMarketplaces": {"team": {"source": source}}},
    )


def _server(root: Path, args: list[str], command: str = "npx") -> None:
    write(
        root,
        ".mcp.json",
        {"mcpServers": {"postmark": {"command": command, "args": args}}},
    )


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [rule for rule in ALL_RULES if rule.id == "policy.component-self-grant"]

    assert rule.reads_agent_authority is True


def _skill(root: Path, allowed: str) -> None:
    write(
        root,
        ".claude/skills/deploy/SKILL.md",
        f"---\nallowed-tools: {allowed}\n---\nbody\n",
    )


def test_a_skill_grant_beyond_the_host_allow_set_is_medium(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    for root in (base, head):
        write(
            root, ".claude/settings.json", {"permissions": {"allow": ["Bash(npm *)"]}}
        )
    _skill(base, "Bash(npm test)")
    _skill(head, "Bash(npm test) Bash(kubectl *)")

    (finding,) = component_self_grant_findings(context(head, base))

    assert finding.severity is FindingSeverity.MEDIUM
    assert "Bash(kubectl *)" in finding.message


@pytest.mark.parametrize(
    "allowed", ["Read Grep", "Bash(npm test)", "Bash(npm run build)"]
)
def test_a_grant_the_host_covers_is_silent(tmp_path: Path, allowed: str) -> None:
    write(
        tmp_path, ".claude/settings.json", {"permissions": {"allow": ["Bash(npm *)"]}}
    )
    _skill(tmp_path, allowed)

    assert component_self_grant_findings(context(tmp_path)) == ()


def test_editing_tools_are_covered_by_accept_edits(tmp_path: Path) -> None:
    write(
        tmp_path,
        ".claude/settings.json",
        {"permissions": {"defaultMode": "acceptEdits"}},
    )
    _skill(tmp_path, "Edit Write")

    assert component_self_grant_findings(context(tmp_path)) == ()


def test_a_bypass_subagent_is_high_when_added(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    for root in (base, head):
        write(root, ".claude/settings.json", {})
    write(
        head,
        ".claude/agents/ops.md",
        "---\nname: ops\ntools: Read\npermissionMode: bypassPermissions\n---\n",
    )

    findings = component_self_grant_findings(context(head, base))

    assert summary(findings) == [(FindingSeverity.HIGH, FindingChangeState.ADDED)]


def test_a_first_scan_self_grant_is_low(tmp_path: Path) -> None:
    _skill(tmp_path, "Bash(kubectl *)")

    assert summary(component_self_grant_findings(context(tmp_path))) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)
    ]


def _all_e18_8(context: RuleContext) -> list[Finding]:
    return [
        *unpinned_agent_component_findings(context),
        *mcp_server_identity_change_findings(context),
        *overprivileged_agent_workflow_findings(context),
        *component_self_grant_findings(context),
    ]


def test_a_pinned_plugin_addition_is_at_most_low(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".claude/settings.json", {})
    _marketplace(head, {"source": "github", "repo": "acme/p", "sha": "b" * 40})

    findings = _all_e18_8(context(head, base))

    assert all(
        f.severity in (FindingSeverity.LOW, FindingSeverity.INFO) for f in findings
    )


def test_a_narrow_skill_grant_is_clean(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    for root in (base, head):
        write(
            root,
            ".claude/settings.json",
            {"permissions": {"allow": ["Bash(npm test)"]}},
        )
    _skill(head, "Bash(npm test) Read")

    assert _all_e18_8(context(head, base)) == []


def test_findings_never_carry_a_secret_and_are_deterministic(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _server(base, ["-y", "pkg@1.0.0", f"--token={SECRET}"])
    _server(head, ["-y", "pkg@1.0.1", f"--token={SECRET}"])

    first = _all_e18_8(context(head, base))
    second = _all_e18_8(context(head, base))

    assert first == second
    assert SECRET not in json.dumps([f.model_dump(mode="json") for f in first])
