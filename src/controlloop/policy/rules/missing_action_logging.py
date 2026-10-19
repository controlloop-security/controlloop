"""Rule: missing action logging on a privileged tool.

Depends on the material capability taxonomy, the `controlloop.yaml`
manifest, and the finding model. `controlloop.manifest.models.
ManifestDocument.logged_tools` is a dedicated, additive manifest field
for this rule rather than a reuse of an existing field.

**Two-layer output (the `unauthorized_delegation` and
`unresolved_dynamic_registration` rules share the same shape):**
`evaluate()` is the pure function registered as this rule's
`controlloop.policy.models.Rule.evaluate` -- its return type,
`tuple[RuleObservation, ...]`, is a fixed contract from the engine.
`RuleObservation` has no concept of severity, confidence, affected
agent, or capability path (see `docs/reference/rule-engine.md`), so
`findings()` performs the identical detection and additionally attaches
that context, producing real `controlloop.findings.models.Finding`
instances via `finding_from_observation`. Both functions are exposed;
only `evaluate` is wrapped in a `Rule` for engine registration, since
only it type-checks against `Rule.evaluate`'s signature.
"""

from __future__ import annotations

from controlloop.acbom.models import EdgeType, Node, NodeType
from controlloop.capability.compute import compute_direct_capability_paths
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.findings.models import (
    Finding,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url, node_change_state

RULE_ID = "policy.missing-action-logging"
_RULE_VERSION = "1.0.0"
_DOCUMENTATION_URL = documentation_url(RULE_ID)


def _declared_tool_names(context: RuleContext) -> frozenset[str]:
    if context.manifest is None:
        return frozenset()
    return frozenset(declaration.tool for declaration in context.manifest.logged_tools)


def _privileged_undeclared_tools(
    context: RuleContext,
) -> tuple[tuple[Node, frozenset[MaterialCapabilityClass]], ...]:
    """Every `TOOL` node invoked by at least one `AGENT` ("privilege
    is determined by the capability taxonomy": a tool is
    privileged exactly when `classify_material_capability` on its own
    `security_attributes`, with `edge_type=EdgeType.INVOKES`, returns a
    non-empty set -- including the taxonomy's own `UNCLASSIFIED`
    member, since an unclassifiable tool must never be treated as
    safer than a classified one) that has no matching entry in
    `context.manifest.logged_tools`. A tool is only considered
    at all if some `invokes` edge actually reaches it -- a tool node
    with no inbound `invokes` edge is not held by any agent and is not
    "privileged" in any observable sense this rule can report.
    Deterministically ordered by node ID, independent of `context.
    acbom.nodes`'s own input order."""

    invoked_tool_ids = {
        edge.target for edge in context.acbom.edges if edge.type is EdgeType.INVOKES
    }
    declared = _declared_tool_names(context)

    results: list[tuple[Node, frozenset[MaterialCapabilityClass]]] = []
    for node in context.acbom.nodes:
        if node.type is not NodeType.TOOL or node.id not in invoked_tool_ids:
            continue
        classes = classify_material_capability(
            node.security_attributes, edge_type=EdgeType.INVOKES
        )
        if not classes:
            continue
        if node.name in declared:
            continue
        results.append((node, classes))

    return tuple(sorted(results, key=lambda item: item[0].id))


def _observation_message(
    tool: Node, classes: frozenset[MaterialCapabilityClass]
) -> str:
    class_text = ", ".join(sorted(member.value for member in classes))
    return (
        f"tool {tool.name!r} is privileged ({class_text}) and has no declared "
        "logging or audit path; add a `logged_tools` entry (tool + audit_path) "
        "for it in controlloop.yaml to satisfy this rule"
    )


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """One `RuleObservation` per privileged tool with no declared
    logging or audit path, evidenced by the tool node's own evidence.
    Remediation guidance is included directly in the message text."""

    return tuple(
        RuleObservation(
            rule_id=RULE_ID,
            message=_observation_message(tool, classes),
            evidence=tool.evidence,
        )
        for tool, classes in _privileged_undeclared_tools(context)
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
    documentation_url_value: str = _DOCUMENTATION_URL,
) -> tuple[Finding, ...]:
    """The `Finding`-producing counterpart to `evaluate()` (see this
    module's own docstring). One `Finding` per (agent, tool) pair --
    `compute_direct_capability_paths` supplies the required one-hop
    `CapabilityPath`; a tool invoked by two agents produces two
    independently agent-scoped findings, since `Finding.affected_agent`
    is required and non-optional. Confidence is the invoking edge's own
    confidence."""

    privileged = {
        tool.id: (tool, classes)
        for tool, classes in _privileged_undeclared_tools(context)
    }
    if not privileged:
        return ()

    paths = compute_direct_capability_paths(context.acbom.nodes, context.acbom.edges)

    results: list[Finding] = []
    for path in paths:
        if path.target_type is not NodeType.TOOL or path.target_id not in privileged:
            continue
        tool, classes = privileged[path.target_id]
        observation = RuleObservation(
            rule_id=RULE_ID,
            message=_observation_message(tool, classes),
            evidence=tool.evidence,
        )
        results.append(
            finding_from_observation(
                observation,
                rule_version=rule_version,
                severity=FindingSeverity.HIGH,
                confidence=path.confidence,
                affected_agent=path.agent_id,
                capability_path=path,
                change_state=node_change_state(context.diff, tool.id),
                remediation=(
                    f"declare a `logged_tools` entry for {tool.name!r} in "
                    "controlloop.yaml naming where its invocations are logged "
                    "or audited (a repository-relative path, or a system "
                    "identifier such as `datadog:agent-audit-log`), or add "
                    "real logging to the tool itself"
                ),
                documentation_url=documentation_url_value,
            )
        )

    return tuple(sorted(results, key=lambda finding: finding.id))


__all__ = [
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
]
