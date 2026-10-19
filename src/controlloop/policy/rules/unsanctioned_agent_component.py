"""Rule: an agent-authority grant the organization has not approved.

On a Team gate, every grant a change adds or changes (the authority
delta) is judged against the organization's effective
approved-components list, after the strengthen-only merge with the
repository's own list. The judgment is the platform's, ported to
`controlloop.team.sanction` and held to the platform's vector files, so a
grant the platform flags as unsanctioned is the grant this rule reports.

One finding per unsanctioned grant, naming the grant, the constraint
that failed (`name`, `package`, `version_range`, `digest`,
`command_pattern`, or `pin_required`), and the organization policy
version that judged it. The finding is `medium`, and by default it
**requires review**, which the gate turns into a
`review_required` verdict. An organization makes it fail instead with a
`severity_floor` of `high` or `critical` in its bundle.

Nothing is judged without a Team run (`RuleContext.sanction` is `None`),
or without a published bundle: an organization that has never published
one gets an explicit `unevaluated` note in evidence and no finding, never
a pass that implies approval. A repository's own `controlloop.yaml`
approval does not clear these findings; an organization exception does.
"""

from __future__ import annotations

from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority
from controlloop.team.components import judge_delta
from controlloop.team.sanction import SanctionState

RULE_ID = "policy.unsanctioned-agent-component"
_RULE_VERSION = "1.0.0"

_REASONS = {
    "name": "no approved entry has its type and name",
    "package": "its package is not the approved package",
    "version_range": "its version is not inside the approved range",
    "digest": "its digest does not start with the approved digest",
    "command_pattern": "its command does not match the approved command pattern",
    "pin_required": "the approved entry requires a pin, and it is not pinned",
}

_REMEDIATION = (
    "Ask an organization admin to approve it on Policies -> Review queue "
    "(pinned, or by pattern) and publish the bundle, change it to match an "
    "approved entry, or remove it. An organization exception lets a "
    "reviewed grant through until it expires."
)


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    sanction = context.sanction
    if sanction is None or sanction.approved is None:
        return ()
    results: list[Finding] = []
    for item in judge_delta(context.acbom, sanction.delta, sanction.approved):
        if item.judgment.state is not SanctionState.UNSANCTIONED:
            continue
        failed = item.judgment.failed or "name"
        component = item.component
        message = (
            f"The {component.type} `{component.name}` is not approved by "
            f"organization policy version {sanction.organization_bundle_version}: "
            f"{_REASONS.get(failed, failed)} (constraint `{failed}`)."
        )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=message,
                node=item.node,
                context=context,
                severity=FindingSeverity.MEDIUM,
                confidence=item.node.confidence,
                change_state=FindingChangeState(item.entry.change),
                remediation=_REMEDIATION,
                honor_approval=False,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
