"""Tests for `policy.unsanctioned-agent-component`.

The command-level behavior (verdict, exit code, exceptions, evidence) is
in `tests/team/test_sanctioned_list_gate.py`; these are the rule on
its own, on real adapters' nodes and a real diff.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from _authority_rule_support import context, repos, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.manifest.models import Approval, ManifestDocument
from controlloop.policy.models import RuleContext, SanctionContext
from controlloop.policy.rules import (
    ALL_RULES,
    unsanctioned_agent_component_findings,
)
from controlloop.reporting.authority import compute_authority_delta
from controlloop.team.sanction import ApprovedEntry

_HOOK = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": "node .github/setup.js"}]}
        ]
    }
}


def _hook_change(tmp_path: Path) -> RuleContext:
    base, head = repos(tmp_path)
    write(head, ".claude/settings.json", _HOOK)
    return context(head, base)


def _sanctioned(
    rule_context: RuleContext, approved: list[ApprovedEntry] | None
) -> RuleContext:
    return replace(
        rule_context,
        sanction=SanctionContext(
            approved=None if approved is None else tuple(approved),
            organization_bundle_version="7" if approved is not None else "",
            delta=compute_authority_delta(rule_context.acbom, rule_context.diff),
        ),
    )


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [r for r in ALL_RULES if r.id == "policy.unsanctioned-agent-component"]

    assert rule.reads_agent_authority is True


def test_a_community_run_judges_nothing(tmp_path: Path) -> None:
    assert unsanctioned_agent_component_findings(_hook_change(tmp_path)) == ()


def test_no_published_bundle_judges_nothing(tmp_path: Path) -> None:
    rule_context = _sanctioned(_hook_change(tmp_path), None)

    assert unsanctioned_agent_component_findings(rule_context) == ()


def test_an_unlisted_hook_is_one_medium_finding(tmp_path: Path) -> None:
    rule_context = _sanctioned(_hook_change(tmp_path), [])

    (finding,) = unsanctioned_agent_component_findings(rule_context)

    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.change_state is FindingChangeState.ADDED
    assert finding.message == (
        "The hook `SessionStart` is not approved by organization policy version "
        "7: no approved entry has its type and name (constraint `name`)."
    )


def test_a_matching_command_pattern_sanctions_it(tmp_path: Path) -> None:
    entry = ApprovedEntry("hook", "sessionstart", command_pattern="node .github/*")

    assert (
        unsanctioned_agent_component_findings(
            _sanctioned(_hook_change(tmp_path), [entry])
        )
        == ()
    )


def test_a_command_outside_the_pattern_names_the_constraint(tmp_path: Path) -> None:
    entry = ApprovedEntry("hook", "SessionStart", command_pattern="npm run *")

    (finding,) = unsanctioned_agent_component_findings(
        _sanctioned(_hook_change(tmp_path), [entry])
    )

    assert "(constraint `command_pattern`)" in finding.message


def test_a_removed_grant_is_not_judged(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    write(base, ".claude/settings.json", _HOOK)

    assert (
        unsanctioned_agent_component_findings(_sanctioned(context(head, base), []))
        == ()
    )


def test_a_repository_approval_does_not_clear_it(tmp_path: Path) -> None:
    rule_context = replace(
        _sanctioned(_hook_change(tmp_path), []),
        manifest=ManifestDocument(
            schema_version="1.0.0",
            owner="team",
            approvals=(Approval(capability="SessionStart", approver="someone"),),
        ),
    )

    (finding,) = unsanctioned_agent_component_findings(rule_context)

    assert finding.severity is FindingSeverity.MEDIUM


def test_identical_input_gives_identical_findings(tmp_path: Path) -> None:
    rule_context = _sanctioned(_hook_change(tmp_path), [])

    assert unsanctioned_agent_component_findings(
        rule_context
    ) == unsanctioned_agent_component_findings(rule_context)
