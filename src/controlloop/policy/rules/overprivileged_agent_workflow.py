"""Rule: an agent workflow with write tokens and no brakes.

A workflow runtime is over-privileged when the agent it runs holds a
write token (`contents`, `pull-requests`, or `id-token`) and either skips
its permission prompts, or is triggered by untrusted input with no
explicit `permissions` block (so the token is whatever the repository
default grants). Severities: added or changed `high`, first scan
`medium`.
"""

from __future__ import annotations

from controlloop.capability.agent_authority import overprivileged_workflow_reason
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.overprivileged-agent-workflow"
_RULE_VERSION = "1.0.0"
_REMEDIATION = (
    "Give the job an explicit `permissions` block with the narrowest scopes "
    "it needs, remove the skip-permissions flag, and avoid running an agent "
    "on untrusted triggers with write access."
)


_reason = overprivileged_workflow_reason


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "workflow-runtime"):
        reason = _reason(node.attributes)
        if reason is None:
            continue
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        if state is FindingChangeState.CHANGED:
            before = authority.baseline_node(context, node.id)
            if before is not None and _reason(before.attributes) is not None:
                # It was already over-privileged; nothing new to report.
                continue
        text, confidence = reason
        severity = (
            FindingSeverity.MEDIUM
            if state is FindingChangeState.NOT_COMPARED
            else FindingSeverity.HIGH
        )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=f"Job '{node.name}' {text}.",
                node=node,
                context=context,
                severity=severity,
                confidence=confidence,
                change_state=state,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
