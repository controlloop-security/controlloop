"""Tests for `policy.widened-permission-rule`."""

from __future__ import annotations

from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules import ALL_RULES, widened_permission_rule_findings


def _allow(
    root: Path,
    rules: list[str],
    *,
    deny: list[str] | None = None,
    path: str = ".claude/settings.json",
) -> None:
    write(root, path, {"permissions": {"allow": rules, "deny": deny or []}})


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [
        rule for rule in ALL_RULES if rule.id == "policy.widened-permission-rule"
    ]

    assert rule.reads_agent_authority is True


def test_replacing_a_narrow_rule_with_bash_star_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _allow(base, ["Bash(npm test)"])
    _allow(head, ["Bash(*)"])

    (finding,) = widened_permission_rule_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "widened from 'Bash(npm test)' to 'Bash(*)'" in finding.message


@pytest.mark.parametrize("added", ["Bash(npm *)", "Bash", "mcp__github"])
def test_adding_a_superset_or_wildcard_rule_is_high(tmp_path: Path, added: str) -> None:
    base, head = repos(tmp_path)
    _allow(base, ["Bash(npm test)"])
    _allow(head, ["Bash(npm test)", added])

    (finding,) = widened_permission_rule_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert finding.change_state is FindingChangeState.ADDED


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (["Bash(npm *)"], ["Bash(npm test)"]),
        (["Bash(npm test)", "Read"], ["Bash(npm test)"]),
        (["Bash(npm test)"], ["Bash(npm test)", "Bash(npm run lint)"]),
    ],
    ids=["narrowed", "removed", "narrow-addition"],
)
def test_narrowing_removing_or_adding_a_narrow_rule_is_silent(
    tmp_path: Path, before: list[str], after: list[str]
) -> None:
    base, head = repos(tmp_path)
    _allow(base, before)
    _allow(head, after)

    assert widened_permission_rule_findings(context(head, base)) == ()


def test_a_new_deny_rule_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _allow(base, ["Bash(npm test)"])
    _allow(head, ["Bash(npm test)"], deny=["Bash(*)"])

    assert widened_permission_rule_findings(context(head, base)) == ()


def test_moving_an_identical_rule_between_files_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _allow(base, ["Bash(*)"])
    write(base, ".claude/settings.local.json", {})
    write(head, ".claude/settings.json", {})
    _allow(head, ["Bash(*)"], path=".claude/settings.local.json")

    assert widened_permission_rule_findings(context(head, base)) == ()


def test_a_first_scan_reports_only_wildcards_at_low(tmp_path: Path) -> None:
    _allow(tmp_path, ["Bash(*)", "Bash(npm test)"])

    assert summary(widened_permission_rule_findings(context(tmp_path))) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)
    ]


def test_a_skill_grant_is_left_to_the_self_grant_rule(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".claude/settings.json", {})
    write(head, ".claude/settings.json", {})
    write(head, ".claude/skills/s/SKILL.md", "---\nallowed-tools: Bash(*)\n---\n")

    assert widened_permission_rule_findings(context(head, base)) == ()


@pytest.mark.parametrize("added", ["Read", "Grep", "Glob", "Read(**)"])
def test_a_read_only_tool_rule_added_is_medium(tmp_path: Path, added: str) -> None:
    """A read-only tool rule added is medium, as amended after a corpus
    of benign repositories: a read-only tool cannot run, change, or send
    anything."""

    base, head = repos(tmp_path)
    _allow(base, ["Bash(npm test)"])
    _allow(head, ["Bash(npm test)", added])

    (finding,) = widened_permission_rule_findings(context(head, base))

    assert finding.severity is FindingSeverity.MEDIUM


def test_gemini_read_tools_added_are_medium(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".gemini/settings.json", {"tools": {"allowed": []}})
    write(
        head,
        ".gemini/settings.json",
        {"tools": {"allowed": ["read_file", "glob", "search_file_content"]}},
    )

    found = widened_permission_rule_findings(context(head, base))

    assert [finding.severity for finding in found] == [FindingSeverity.MEDIUM] * 3


@pytest.mark.parametrize(
    "added", ["Bash(git diff:*)", "Bash(npm run:*)", "Edit", "WebFetch"]
)
def test_a_shell_prefix_or_a_write_or_network_tool_stays_high(
    tmp_path: Path, added: str
) -> None:
    """However narrow a shell prefix looks, it is code execution:
    `Bash(npm run:*)` runs any script in a file the pull request can edit."""

    base, head = repos(tmp_path)
    _allow(base, ["Bash(npm test)"])
    _allow(head, ["Bash(npm test)", added])

    (finding,) = widened_permission_rule_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
