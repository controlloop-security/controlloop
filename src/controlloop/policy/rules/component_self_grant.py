"""Rule: a skill or subagent that grants itself more than its host allows.

A skill's `allowed-tools` is never gated by workspace trust, and a
subagent can name its own tools and permission mode. Either can hand the
agent a tool the repository's own `permissions.allow` never granted.
This rule compares each such grant with the host's allow set: its own
allow rules, plus the read-only tools every permission mode already runs
without asking, plus the editing tools when the host's mode is
`acceptEdits` or looser. A grant the set covers is silent. Severities:
added or changed `medium`, `high` for a subagent in `bypassPermissions`,
first scan `low`.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, EdgeType, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.component-self-grant"
_RULE_VERSION = "1.0.0"

#: Tools every permission mode runs without asking.
_READ_ONLY_TOOLS = frozenset(
    {"Read", "Grep", "Glob", "LS", "NotebookRead", "TodoWrite"}
)
#: Tools `acceptEdits` and looser modes run without asking.
_EDIT_TOOLS = frozenset({"Edit", "MultiEdit", "Write", "NotebookEdit"})
_EDITING_MODES = frozenset({"acceptEdits", "auto", "dontAsk", "bypassPermissions"})

_REMEDIATION = (
    "Narrow the component's grant to what the host already allows, or add "
    "the rule to the host's `permissions.allow` if the whole agent should "
    "have it."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _host_allow_set(context: RuleContext, host: Node | None) -> tuple[list[str], bool]:
    """`(rules, everything)`: the host's allow rules and whether its
    mode already allows every tool."""

    if host is None:
        return sorted(_READ_ONLY_TOOLS), False
    mode = host.attributes.get("default_mode", "default")
    if mode == "bypassPermissions":
        return [], True
    by_id = {node.id: node for node in context.acbom.nodes}
    rules = [
        by_id[edge.target].attributes.get("pattern", "")
        for edge in authority.edges_out_of(context, host.id, EdgeType.PERMITTED_BY)
        if edge.target in by_id
        and by_id[edge.target].attributes.get("effect") == "allow"
    ]
    rules.extend(sorted(_READ_ONLY_TOOLS))
    if mode in _EDITING_MODES:
        rules.extend(sorted(_EDIT_TOOLS))
    return rules, False


def _grant_state(context: RuleContext, node: Node) -> FindingChangeState | None:
    return authority.component_state(context, node)


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    by_id = {node.id: node for node in context.acbom.nodes}
    results: list[Finding] = []
    for component in authority.nodes_with_subtype(context, "skill", "subagent"):
        host = authority.owning_host(context, component.id)
        allowed, everything = _host_allow_set(context, host)
        kind = component.subtype
        label = component.name

        if kind == "subagent" and component.security_attributes.bypass_mode is True:
            state = _grant_state(context, component)
            before = authority.baseline_node(context, component.id)
            already = (
                before is not None and before.security_attributes.bypass_mode is True
            )
            if (
                state is not None
                and state is not FindingChangeState.REMOVED
                and not already
                and not everything
            ):
                results.append(
                    authority.build_finding(
                        rule_id=RULE_ID,
                        rule_version=rule_version,
                        message=(
                            f"{label.capitalize()} runs in bypassPermissions mode, "
                            "which the host does not."
                        ),
                        node=component,
                        context=context,
                        severity=(
                            FindingSeverity.LOW
                            if state is FindingChangeState.NOT_COMPARED
                            else FindingSeverity.HIGH
                        ),
                        confidence=Confidence.HIGH,
                        change_state=state,
                        remediation=_REMEDIATION,
                    )
                )

        if everything:
            continue
        for edge in authority.edges_out_of(
            context, component.id, EdgeType.PERMITTED_BY
        ):
            grant = by_id.get(edge.target)
            if grant is None or grant.attributes.get("effect") != "allow":
                continue
            pattern = grant.attributes.get("pattern", "")
            if any(authority.rule_covers(rule, pattern) for rule in allowed):
                continue
            state = _grant_state(context, grant)
            if state is None or state is FindingChangeState.REMOVED:
                continue
            results.append(
                authority.build_finding(
                    rule_id=RULE_ID,
                    rule_version=rule_version,
                    message=(
                        f"{label.capitalize()} allows '{pattern}', which the "
                        "host's allow set does not grant."
                    ),
                    node=grant,
                    context=context,
                    severity=(
                        FindingSeverity.LOW
                        if state is FindingChangeState.NOT_COMPARED
                        else FindingSeverity.MEDIUM
                    ),
                    confidence=Confidence.HIGH,
                    change_state=state,
                    remediation=_REMEDIATION,
                )
            )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
