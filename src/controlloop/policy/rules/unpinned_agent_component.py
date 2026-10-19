"""Rule: an agent plugin or marketplace without a pin.

A plugin runs with the user's privileges, and a marketplace decides which
plugins exist. Without a commit or digest pin, what a plugin does can
change upstream with no change in this repository at all. Severities:
an unpinned addition `medium`, a pinned addition `low`, a changed pin or
source `medium`, a first scan `low`, a removal nothing.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.unpinned-agent-component"
_RULE_VERSION = "1.0.0"
_SUBTYPES = ("plugin", "marketplace")
_PIN_FIELDS = frozenset({"pinned", "ref", "location", "source_type", "command"})

_REMEDIATION = (
    "Pin the component to a full commit SHA (`sha`, or a 40-character `ref`) "
    "or a SHA-256 digest (`sha256`) so its contents cannot change without a "
    "change to this repository."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _describe(node_name: str, pinned: object, source_type: str) -> str:
    if pinned is True:
        return f"{node_name.capitalize()} ({source_type}) is pinned."
    if pinned is False:
        return f"{node_name.capitalize()} ({source_type}) has no commit or digest pin."
    return (
        f"{node_name.capitalize()} ({source_type}) has no pin this repository can "
        "verify; its source is resolved elsewhere."
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, *_SUBTYPES):
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        pinned = node.security_attributes.pinned
        source_type = node.attributes.get("source_type", "unknown")
        description = _describe(node.name, pinned, source_type)
        if state is FindingChangeState.NOT_COMPARED:
            severity = FindingSeverity.LOW
            message = f"{description} Recorded on a scan with no baseline."
        elif state is FindingChangeState.ADDED:
            severity = FindingSeverity.LOW if pinned is True else FindingSeverity.MEDIUM
            message = f"Added: {description}"
        else:
            before = authority.baseline_node(context, node.id)
            changed = [
                name
                for name in authority.changed_attributes(before, node)
                if name in _PIN_FIELDS
            ]
            if not changed:
                continue
            severity = FindingSeverity.MEDIUM
            message = (
                f"{node.name.capitalize()} changed its "
                f"{authority.first_line(changed)}. {description}"
            )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=message,
                node=node,
                context=context,
                severity=severity,
                confidence=Confidence.HIGH
                if pinned in (True, False)
                else Confidence.MEDIUM,
                change_state=state,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
