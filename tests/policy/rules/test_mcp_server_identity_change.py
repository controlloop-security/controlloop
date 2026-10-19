"""Tests for `policy.mcp-server-identity-change`."""

from __future__ import annotations

from pathlib import Path

from _authority_rule_support import context, repos, summary, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules import (
    ALL_RULES,
    mcp_server_identity_change_findings,
)


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [
        rule for rule in ALL_RULES if rule.id == "policy.mcp-server-identity-change"
    ]

    assert rule.reads_agent_authority is True


def _server(root: Path, args: list[str], command: str = "npx") -> None:
    write(
        root,
        ".mcp.json",
        {"mcpServers": {"postmark": {"command": command, "args": args}}},
    )


def test_a_same_name_package_version_change_is_high(tmp_path: Path) -> None:
    """The postmark-mcp pattern: fifteen clean releases, then 1.0.16."""

    base, head = repos(tmp_path)
    _server(base, ["-y", "postmark-mcp@1.0.15"])
    _server(head, ["-y", "postmark-mcp@1.0.16"])

    (finding,) = mcp_server_identity_change_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert finding.change_state is FindingChangeState.CHANGED
    assert "package version from '1.0.15' to '1.0.16'" in finding.message
    assert finding.affected_agent is not None


def test_a_changed_command_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _server(base, ["server.js"], command="node")
    _server(head, ["server.js"], command="bun")

    (finding,) = mcp_server_identity_change_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "command from 'node' to 'bun'" in finding.message


def test_changed_arguments_with_the_same_package_are_medium(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _server(base, ["-y", "postmark-mcp@1.0.15"])
    _server(head, ["-y", "postmark-mcp@1.0.15", "--verbose"])

    (finding,) = mcp_server_identity_change_findings(context(head, base))

    assert finding.severity is FindingSeverity.MEDIUM
    assert "args" in finding.message


def test_a_new_server_is_medium_and_a_first_scan_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".mcp.json", {"mcpServers": {}})
    _server(head, ["-y", "postmark-mcp@1.0.15"])

    assert summary(mcp_server_identity_change_findings(context(head, base))) == [
        (FindingSeverity.MEDIUM, FindingChangeState.ADDED)
    ]
    assert mcp_server_identity_change_findings(context(head)) == ()
