"""Shared helpers for the agent-authority rules.

These rules are change-only. With a baseline, a component the diff does
not mention is unchanged and produces nothing: the point of the
authority diff is what a pull request changes. With no baseline (a first
scan), every component is reported once at a reduced first-scan
severity, with `change_state: not-compared` -- the state that already
means "no baseline was compared".

Every function here is pure and reads only the `RuleContext`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from controlloop.acbom.models import Confidence, Edge, EdgeType, Node, NodeType
from controlloop.capability.agent_authority import approval_for
from controlloop.capability.models import (
    CURRENT_CAPABILITY_SCHEMA_VERSION,
    CapabilityPath,
    PathHop,
)
from controlloop.diff.models import ChangeKind, NodeChange
from controlloop.findings.models import (
    Finding,
    FindingChangeState,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url

#: How a component stands against the baseline, or `None` when it is
#: unchanged and the rule should say nothing.
ComponentState = FindingChangeState | None


def node_changes(context: RuleContext) -> dict[str, NodeChange]:
    if context.diff is None:
        return {}
    return {change.node_id: change for change in context.diff.node_changes}


def component_state(context: RuleContext, node: Node) -> ComponentState:
    if context.diff is None:
        return FindingChangeState.NOT_COMPARED
    change = node_changes(context).get(node.id)
    if change is None:
        return None
    return FindingChangeState(change.kind.value)


def baseline_node(context: RuleContext, node_id: str) -> Node | None:
    change = node_changes(context).get(node_id)
    return change.before if change is not None else None


def changed_attributes(before: Node | None, after: Node) -> list[str]:
    """Attribute and security-flag names whose value differs."""

    if before is None:
        return []
    names = sorted(
        key
        for key in set(before.attributes) | set(after.attributes)
        if before.attributes.get(key) != after.attributes.get(key)
    )
    before_flags = before.security_attributes.model_dump()
    after_flags = after.security_attributes.model_dump()
    names.extend(
        sorted(
            key for key in after_flags if before_flags.get(key) != after_flags.get(key)
        )
    )
    return names


def nodes_with_subtype(context: RuleContext, *subtypes: str) -> list[Node]:
    return sorted(
        (node for node in context.acbom.nodes if node.subtype in subtypes),
        key=lambda node: node.id,
    )


def removed_nodes(context: RuleContext, *subtypes: str) -> list[Node]:
    if context.diff is None:
        return []
    return [
        change.before
        for change in context.diff.node_changes
        if change.kind is ChangeKind.REMOVED
        and change.before is not None
        and change.before.subtype in subtypes
    ]


def edges_into(context: RuleContext, node_id: str) -> list[Edge]:
    return [edge for edge in context.acbom.edges if edge.target == node_id]


def edges_out_of(context: RuleContext, node_id: str, edge_type: EdgeType) -> list[Edge]:
    return [
        edge
        for edge in context.acbom.edges
        if edge.source == node_id and edge.type is edge_type
    ]


def owning_host(context: RuleContext, node_id: str) -> Node | None:
    """The agent host that reaches `node_id`, walking edges backwards a
    bounded number of steps (a hook in a skill in a plugin is three)."""

    by_id = {node.id: node for node in context.acbom.nodes}
    frontier = [node_id]
    seen = {node_id}
    for _ in range(6):
        next_frontier: list[str] = []
        for current in frontier:
            node = by_id.get(current)
            if node is not None and node.subtype == "host":
                return node
            for edge in edges_into(context, current):
                if edge.source not in seen:
                    seen.add(edge.source)
                    next_frontier.append(edge.source)
        frontier = sorted(next_frontier)
        if not frontier:
            break
    for current in sorted(seen):
        node = by_id.get(current)
        if node is not None and node.subtype == "host":
            return node
    return None


def first_line(values: Iterable[str]) -> str:
    return ", ".join(values)


_PATH_TARGET_TYPES = frozenset(
    {
        NodeType.TOOL,
        NodeType.RESOURCE,
        NodeType.IDENTITY,
        NodeType.PERMISSION,
        NodeType.DATA_CLASS,
    }
)


def host_path(context: RuleContext, node: Node) -> CapabilityPath | None:
    """The shortest edge chain from an agent host to `node`, or `None`
    when there is none or `node` is not a capability-path target (a
    workflow runtime or a subagent: those findings are repository-scoped
    rather than attributed to an agent they are not reachable from)."""

    if node.type not in _PATH_TARGET_TYPES:
        return None
    by_id = {item.id: item for item in context.acbom.nodes}
    parent: dict[str, Edge] = {}
    frontier = [node.id]
    seen = {node.id}
    for _ in range(8):
        next_frontier: list[str] = []
        for current in frontier:
            for edge in sorted(edges_into(context, current), key=lambda e: e.id):
                if edge.source in seen:
                    continue
                seen.add(edge.source)
                parent[edge.source] = edge
                source = by_id.get(edge.source)
                if source is not None and source.subtype == "host":
                    hops: list[PathHop] = []
                    cursor = edge.source
                    while cursor != node.id:
                        step = parent[cursor]
                        hops.append(
                            PathHop(
                                edge_id=step.id,
                                edge_type=step.type,
                                source_id=step.source,
                                target_id=step.target,
                                evidence=step.evidence,
                            )
                        )
                        cursor = step.target
                    return CapabilityPath(
                        schema_version=CURRENT_CAPABILITY_SCHEMA_VERSION,
                        agent_id=source.id,
                        target_id=node.id,
                        target_type=node.type,
                        hops=tuple(hops),
                        confidence=Confidence.HIGH,
                    )
                next_frontier.append(edge.source)
        frontier = sorted(next_frontier)
        if not frontier:
            break
    return None


def build_finding(
    *,
    rule_id: str,
    rule_version: str,
    message: str,
    node: Node,
    context: RuleContext,
    severity: FindingSeverity,
    confidence: Confidence,
    change_state: FindingChangeState,
    remediation: str,
    honor_approval: bool = True,
) -> Finding:
    """A finding about `node`. An approval in the manifest that names the
    component (owner decision, 2026-10-17) keeps the finding for the record
    but lowers it to `info`, which never blocks; the caller supplies only
    approvals active at evaluation time. `honor_approval=False` is for a
    finding a repository's own manifest must not clear, such as one an
    organization's approved list decides."""

    path = host_path(context, node)
    approval = (
        approval_for(node, context.manifest.approvals)
        if context.manifest is not None and honor_approval
        else None
    )
    if approval is not None and severity is not FindingSeverity.INFO:
        severity = FindingSeverity.INFO
        message = f"{message} Approval recorded by {approval.approver}."
    return finding_from_observation(
        RuleObservation(
            rule_id=rule_id, message=message[:1024], evidence=node.evidence
        ),
        rule_version=rule_version,
        severity=severity,
        confidence=confidence,
        affected_agent=path.agent_id if path is not None else None,
        capability_path=path,
        change_state=change_state,
        remediation=remediation,
        documentation_url=documentation_url(rule_id),
    )


def observations(findings: Iterable[Finding]) -> tuple[RuleObservation, ...]:
    return tuple(
        RuleObservation(rule_id=f.rule_id, message=f.message, evidence=f.evidence)
        for f in sorted(findings, key=lambda finding: finding.id)
    )


_RULE_SHAPE = re.compile(r"^(?P<tool>[^()]+?)(?:\((?P<spec>.*)\))?$", re.DOTALL)


def parse_rule(rule: str) -> tuple[str, str | None]:
    match = _RULE_SHAPE.fullmatch(rule.strip())
    if match is None:
        return rule.strip(), None
    spec = match.group("spec")
    return match.group("tool").strip(), spec.strip() if spec is not None else None


def rule_covers(host_rule: str, grant: str) -> bool:
    """Whether `host_rule` allows everything `grant` allows."""

    host_tool, host_spec = parse_rule(host_rule)
    grant_tool, grant_spec = parse_rule(grant)
    if host_tool != grant_tool:
        return False
    if host_spec is None or host_spec in {"*", "**"}:
        return True
    if grant_spec is None:
        return False
    if host_spec == grant_spec:
        return True
    if host_spec.endswith("*"):
        prefix = host_spec[:-1]
        if prefix.endswith(":"):
            prefix = prefix[:-1]
        return grant_spec.startswith(prefix.rstrip())
    return False
