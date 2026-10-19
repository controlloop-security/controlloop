"""Tests for `policy.overprivileged-agent-workflow`."""

from __future__ import annotations

from pathlib import Path

from _authority_rule_support import context, repos, write

from controlloop.findings.models import FindingChangeState, FindingSeverity
from controlloop.policy.rules import (
    ALL_RULES,
    overprivileged_agent_workflow_findings,
)


def test_the_rule_reads_agent_authority() -> None:
    (rule,) = [
        rule for rule in ALL_RULES if rule.id == "policy.overprivileged-agent-workflow"
    ]

    assert rule.reads_agent_authority is True


def _workflow(
    root: Path, *, permissions: str, args: str, trigger: str = "pull_request"
) -> None:
    lines = [f"on: {trigger}", *permissions.splitlines()]
    lines += [
        "jobs:",
        "  review:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: anthropics/claude-code-action@v1",
        "        with:",
        f'          claude_args: "{args}"',
    ]
    write(root, ".github/workflows/agent.yml", "\n".join(lines) + "\n")


def test_write_tokens_with_skipped_permissions_are_high(tmp_path: Path) -> None:
    base, head = repos(tmp_path)
    _workflow(base, permissions="permissions:\n  contents: read", args="--max-turns 5")
    _workflow(
        head,
        permissions="permissions:\n  contents: write\n  id-token: write",
        args="--dangerously-skip-permissions",
    )

    (finding,) = overprivileged_agent_workflow_findings(context(head, base))

    assert finding.severity is FindingSeverity.HIGH
    assert "id-token: write" in finding.message
    assert "skips permission prompts" in finding.message


def test_untrusted_input_without_a_permissions_block_is_flagged(tmp_path: Path) -> None:
    _workflow(tmp_path, permissions="", args="--max-turns 5", trigger="issue_comment")

    (finding,) = overprivileged_agent_workflow_findings(context(tmp_path))

    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.change_state is FindingChangeState.NOT_COMPARED


def test_a_read_only_workflow_is_silent(tmp_path: Path) -> None:
    _workflow(
        tmp_path,
        permissions="permissions:\n  contents: read",
        args="--dangerously-skip-permissions",
    )

    assert overprivileged_agent_workflow_findings(context(tmp_path)) == ()


def test_an_already_overprivileged_workflow_that_changes_is_not_new(
    tmp_path: Path,
) -> None:
    base, head = repos(tmp_path)
    for root, turns in ((base, "1"), (head, "2")):
        _workflow(
            root,
            permissions="permissions:\n  contents: write",
            args=f"--dangerously-skip-permissions --max-turns {turns}",
        )

    assert overprivileged_agent_workflow_findings(context(head, base)) == ()
