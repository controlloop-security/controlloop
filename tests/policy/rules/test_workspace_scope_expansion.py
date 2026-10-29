"""Tests for `policy.workspace-scope-expansion`."""

from __future__ import annotations

from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.adapters import agent_authority
from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules.workspace_scope_expansion import (
    OUTSIDE_REPOSITORY_PATH,
    RULE,
)
from controlloop.policy.rules.workspace_scope_expansion import (
    findings as workspace_findings,
)

_HOME = "/Users/someone/private-notes"


def test_the_rule_reads_agent_authority() -> None:
    assert RULE.reads_agent_authority is True


def test_the_outside_marker_matches_the_adapter() -> None:
    assert OUTSIDE_REPOSITORY_PATH == agent_authority.OUTSIDE_REPOSITORY_PATH


def _directories(root: Path, *paths: str) -> None:
    write(
        root,
        ".claude/settings.json",
        {"permissions": {"additionalDirectories": list(paths)}},
    )


@pytest.mark.parametrize("path", [_HOME, "~", "/", "../sibling-project"])
def test_an_outside_directory_added_is_high(tmp_path: Path, path: str) -> None:
    base, head = repos(tmp_path)
    _directories(base)
    _directories(head, path)

    (finding,) = workspace_findings(context(head, base))

    assert summary((finding,)) == [(FindingSeverity.HIGH, FindingChangeState.ADDED)]
    assert finding.message == (
        "Claude Code can now read and write a directory outside the repository."
    )
    assert "someone" not in finding.model_dump_json()


def test_an_inside_directory_added_is_low(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _directories(base)
    _directories(head, "docs")

    assert summary(workspace_findings(context(head, base))) == [
        (FindingSeverity.LOW, FindingChangeState.ADDED)
    ]


def test_an_entry_changed_to_an_outside_directory_is_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _directories(base, "docs")
    _directories(head, _HOME)

    assert summary(workspace_findings(context(head, base))) == [
        (FindingSeverity.HIGH, FindingChangeState.CHANGED)
    ]


def test_an_outside_directory_on_a_first_scan_is_low(tmp_path: Path) -> None:
    _directories(tmp_path, _HOME)

    assert summary(workspace_findings(context(tmp_path))) == [
        (FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)
    ]


def test_an_inside_directory_on_a_first_scan_is_silent(tmp_path: Path) -> None:
    _directories(tmp_path, "docs")

    assert workspace_findings(context(tmp_path)) == ()


def test_an_outside_directory_removed_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _directories(base, _HOME)
    _directories(head)

    assert workspace_findings(context(head, base)) == ()


def test_an_unchanged_outside_directory_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _directories(base, _HOME)
    _directories(head, _HOME)

    assert workspace_findings(context(head, base)) == ()


def test_narrowing_to_an_inside_directory_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _directories(base, _HOME)
    _directories(head, "docs")

    assert workspace_findings(context(head, base)) == ()
