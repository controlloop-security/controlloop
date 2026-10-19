"""Tests for `policy.unpinned-agent-component`."""

from __future__ import annotations

from pathlib import Path

import pytest
from _authority_rule_support import context, repos, summary, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules import (
    ALL_RULES,
    unpinned_agent_component_findings,
)


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [
        rule for rule in ALL_RULES if rule.id == "policy.unpinned-agent-component"
    ]

    assert rule.reads_agent_authority is True


def _marketplace(root: Path, source: dict[str, object]) -> None:
    write(
        root,
        ".claude/settings.json",
        {"extraKnownMarketplaces": {"team": {"source": source}}},
    )


@pytest.mark.parametrize(
    ("source", "severity"),
    [
        ({"source": "github", "repo": "acme/p"}, FindingSeverity.MEDIUM),
        ({"source": "github", "repo": "acme/p", "sha": "a" * 40}, FindingSeverity.LOW),
    ],
)
def test_an_added_marketplace_is_medium_unpinned_and_low_pinned(
    tmp_path: Path, source: dict[str, object], severity: FindingSeverity
) -> None:
    base, head = repos(tmp_path)
    write(base, ".claude/settings.json", {})
    _marketplace(head, source)

    findings = unpinned_agent_component_findings(context(head, base))

    assert summary(findings) == [(severity, FindingChangeState.ADDED)]


def test_a_changed_pin_is_medium_and_names_what_changed(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _marketplace(base, {"source": "github", "repo": "acme/p", "sha": "a" * 40})
    _marketplace(head, {"source": "github", "repo": "acme/p", "ref": "main"})

    (finding,) = unpinned_agent_component_findings(context(head, base))

    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.change_state is FindingChangeState.CHANGED
    assert "pinned" in finding.message


def test_an_unchanged_or_removed_component_is_silent(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _marketplace(base, {"source": "github", "repo": "acme/p"})
    _marketplace(head, {"source": "github", "repo": "acme/p"})
    removed = tmp_path / "removed"
    removed.mkdir()
    write(removed, ".claude/settings.json", {})

    assert unpinned_agent_component_findings(context(head, base)) == ()
    assert unpinned_agent_component_findings(context(removed, base)) == ()


def test_a_first_scan_reports_low_and_not_compared(tmp_path: Path) -> None:
    _marketplace(tmp_path, {"source": "github", "repo": "acme/p"})

    findings = unpinned_agent_component_findings(context(tmp_path))

    assert summary(findings) == [(FindingSeverity.LOW, FindingChangeState.NOT_COMPARED)]
