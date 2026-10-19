"""An approval lowers an agent-authority finding.

A manifest approval naming a component keeps its finding for the record
but lowers it to `info`, which never blocks. The CLI passes only the
approvals active at evaluation time; rules have no clock.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from _authority_rule_support import context, repos, write

from controlloop.findings.models import FindingSeverity
from controlloop.manifest.models import Approval, ManifestDocument
from controlloop.policy.rules import (
    agent_hook_command_change_findings,
    mcp_server_identity_change_findings,
    widened_permission_rule_findings,
)


def _manifest(*capabilities: str) -> ManifestDocument:
    return ManifestDocument(
        schema_version="1.0.0",
        owner="security-team",
        approvals=tuple(
            Approval(capability=capability, approver="alice")
            for capability in capabilities
        ),
    )


def _hook(root: Path) -> None:
    write(
        root,
        ".claude/settings.json",
        {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "x"}]}]}},
    )


def test_an_approval_by_file_and_key_path_lowers_the_finding(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _hook(head)
    approved = replace(
        context(head, base),
        manifest=_manifest(".claude/settings.json#hooks.SessionStart[0].hooks[0]"),
    )

    (finding,) = agent_hook_command_change_findings(approved)

    assert finding.severity is FindingSeverity.INFO
    assert finding.message.endswith("Approval recorded by alice.")


def test_an_approval_for_something_else_changes_nothing(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _hook(head)
    other = replace(context(head, base), manifest=_manifest("some-other-server"))

    (finding,) = agent_hook_command_change_findings(other)

    assert finding.severity is FindingSeverity.HIGH
    assert "Approval recorded" not in finding.message


def test_an_approval_by_server_name_lowers_an_identity_change(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(
        base, ".mcp.json", {"mcpServers": {"docs": {"command": "npx", "args": ["a@1"]}}}
    )
    write(
        head, ".mcp.json", {"mcpServers": {"docs": {"command": "npx", "args": ["a@2"]}}}
    )

    (unapproved,) = mcp_server_identity_change_findings(context(head, base))
    (approved,) = mcp_server_identity_change_findings(
        replace(context(head, base), manifest=_manifest("docs"))
    )

    assert unapproved.severity is FindingSeverity.HIGH
    assert approved.severity is FindingSeverity.INFO


def test_an_approval_keeps_the_finding_identity(tmp_path: Path) -> None:
    """The finding ID does not change with the approval, so a suppression
    and an approval for the same change never disagree about which finding
    they mean."""

    base, head = repos(tmp_path)
    write(head, ".claude/settings.json", {"permissions": {"allow": ["Bash(*)"]}})

    (plain,) = widened_permission_rule_findings(context(head, base))
    (approved,) = widened_permission_rule_findings(
        replace(context(head, base), manifest=_manifest("allow Bash(*)"))
    )

    assert approved.severity is FindingSeverity.INFO
    assert approved.id == plain.id
