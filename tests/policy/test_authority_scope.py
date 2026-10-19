"""Coding-agent host authority is hidden from rules that predate it --
`controlloop.policy.authority_scope`."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from controlloop.acbom import AuthoritySubtype
from controlloop.adapters import ALL_ADAPTERS, ScanContext, run_adapters
from controlloop.bom import build_acbom_document
from controlloop.cli import app
from controlloop.policy.authority_scope import without_agent_authority
from controlloop.policy.engine import evaluate
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import ALL_RULES
from controlloop.repository import resolve_repository_root

runner = CliRunner()


def _write(root: Path, relative_path: str, payload: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


def _context(root: Path) -> RuleContext:
    document = build_acbom_document(resolve_repository_root(root))
    return RuleContext(acbom=document, policy_version="test")


def _with_host(root: Path) -> None:
    _write(
        root,
        ".claude/settings.json",
        {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit",
                        "hooks": [{"type": "command", "command": "prettier --write"}],
                    }
                ]
            },
            "permissions": {"allow": ["Bash(npm test)"]},
        },
    )
    _write(root, ".mcp.json", {"mcpServers": {"files": {"command": "npx"}}})


def test_a_document_without_authority_components_is_passed_through(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "agent-card.json", {"name": "a"})
    context = _context(tmp_path)

    assert without_agent_authority(context) is context


def test_authority_components_and_their_edges_are_removed(tmp_path: Path) -> None:
    _with_host(tmp_path)
    context = _context(tmp_path)
    authority_values = {subtype.value for subtype in AuthoritySubtype}

    scoped = without_agent_authority(context)
    remaining_ids = {node.id for node in scoped.acbom.nodes}

    assert any(node.subtype in authority_values for node in context.acbom.nodes)
    assert not any(node.subtype in authority_values for node in scoped.acbom.nodes)
    assert [node.name for node in scoped.acbom.nodes] == ["files"]
    assert all(
        edge.source in remaining_ids and edge.target in remaining_ids
        for edge in scoped.acbom.edges
    )


def test_only_a_rule_that_reads_agent_authority_sees_the_host(tmp_path: Path) -> None:
    _with_host(tmp_path)
    context = _context(tmp_path)
    seen: dict[str, int] = {}

    def counting(rule_id: str) -> Rule:
        def evaluate_rule(rule_context: RuleContext) -> tuple[RuleObservation, ...]:
            seen[rule_id] = sum(
                1 for node in rule_context.acbom.nodes if node.subtype == "host"
            )
            return ()

        return Rule(
            id=rule_id,
            evaluate=evaluate_rule,
            reads_agent_authority=rule_id.endswith("aware"),
        )

    evaluate((counting("test.legacy"), counting("test.aware")), context)

    assert seen == {"test.legacy": 0, "test.aware": 1}


#: The rules that read agent authority, each opting in deliberately.
_E18_RULE_IDS = frozenset(
    {
        "policy.unpinned-agent-component",
        "policy.mcp-server-identity-change",
        "policy.overprivileged-agent-workflow",
        "policy.component-self-grant",
        "policy.agent-hook-command-change",
        "policy.widened-permission-rule",
        "policy.permission-bypass-from-project",
        # Judges the authority delta on a Team gate.
        "policy.unsanctioned-agent-component",
    }
)


def test_no_pre_e18_rule_reads_agent_authority() -> None:
    """Every rule shipped before coding-agent hosts were recorded keeps
    its original view. A rule that opts in does so deliberately."""

    reading = {rule.id for rule in ALL_RULES if rule.reads_agent_authority}

    assert reading == _E18_RULE_IDS


def test_a_formatter_hook_and_a_project_server_do_not_block_the_gate(
    tmp_path: Path,
) -> None:
    """A repository's first scan is never blocked on agent authority
    alone. Before scoping, `policy.missing-action-logging`
    blocked this repository at high severity."""

    _with_host(tmp_path)

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    report = json.loads(result.stdout)

    assert report["verdict"] != "deployment_blocked"
    # The agent-authority rules report a first scan at `low`, never at a
    # blocking severity.
    assert {finding["severity"] for finding in report["findings"]} <= {"low", "info"}


def test_the_scoped_view_is_deterministic(tmp_path: Path) -> None:
    _with_host(tmp_path)
    root = resolve_repository_root(tmp_path)
    discovery = run_adapters([cls() for cls in ALL_ADAPTERS], ScanContext(root=root))
    assert discovery.nodes

    first = without_agent_authority(_context(tmp_path))
    second = without_agent_authority(_context(tmp_path))

    assert first.acbom.nodes == second.acbom.nodes
    assert first.acbom.edges == second.acbom.edges
