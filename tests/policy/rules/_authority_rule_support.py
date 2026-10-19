"""Shared support for the agent-authority rule tests.

Builds real ACBOMs with the real adapters and a real diff, so each rule
is exercised on the nodes the adapters actually emit.

Each test writes a repository, builds its ACBOM with the real adapters,
and evaluates the rule against a real diff, so a rule is exercised on
the nodes the adapters actually emit rather than on hand-built ones.
"""

from __future__ import annotations

import json
from pathlib import Path

from controlloop.bom import build_acbom_document
from controlloop.diff.compute import compute_diff
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import RuleContext
from controlloop.repository import resolve_repository_root

SECRET = "planted-rule-secret-6e6e"


def write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def context(head: Path, base: Path | None = None) -> RuleContext:
    current = build_acbom_document(resolve_repository_root(head))
    diff = None
    if base is not None:
        baseline = build_acbom_document(resolve_repository_root(base))
        diff = compute_diff(
            baseline_nodes=baseline.nodes,
            baseline_edges=baseline.edges,
            current_nodes=current.nodes,
            current_edges=current.edges,
        )
    return RuleContext(acbom=current, policy_version="test", diff=diff)


def repos(tmp_path: Path) -> tuple[Path, Path]:
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir()
    head.mkdir()
    return base, head


def summary(
    findings: tuple[Finding, ...],
) -> list[tuple[FindingSeverity, FindingChangeState]]:
    return [(finding.severity, finding.change_state) for finding in findings]
