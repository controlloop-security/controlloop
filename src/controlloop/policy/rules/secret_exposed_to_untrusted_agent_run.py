"""Rule: a workflow secret handed to an agent job that untrusted input can
trigger.

A job that runs a coding agent on `pull_request_target`,
`issue_comment`, `workflow_run`, or a checkout of the pull request head
lets whoever opens the pull request or writes the comment steer the
agent. If the job also references a repository secret, an injected
instruction can read it and send it anywhere the agent can reach. This
is the exfiltration triangle for CI agents: untrusted input, sensitive
data, and an agent that can talk to the network.

It is its own rule rather than part of `policy.exfiltration-triangle`
because the triangle reads agent, resource, and tool nodes, and this
reads one workflow runtime node's attributes. `GITHUB_TOKEN` is not
counted here; the token's permissions are
`policy.overprivileged-agent-workflow`'s. The agent's own API key counts:
it is still exfiltrable.

Severities: added, changed into this state, or given another secret,
`high`, naming only the newly exposed secrets; first scan `medium`. A
runtime whose exposed secrets are unchanged since the baseline, or one
that drops the untrusted trigger or the secrets, is silent. Secret names are
reported, never values; the adapter never reads values.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.secret-exposed-to-untrusted-agent-run"
_RULE_VERSION = "1.0.0"

#: The job's own token; its scopes are policy.overprivileged-agent-workflow's.
_NOT_A_SECRET = frozenset({"GITHUB_TOKEN"})

_REMEDIATION = (
    "Run the agent on `pull_request` from the base branch, move the secret "
    "to a job the agent does not run in, or gate the job on an environment "
    "that needs approval. If the secret is the agent's own API key, scope "
    "it to this job and set a spend limit."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def exposed_secrets(node: Node) -> list[str]:
    """The secret names an untrusted-input runtime is given, or `[]`."""

    if node.security_attributes.untrusted_input is not True:
        return []
    names = node.attributes.get("secret_names", "")
    return sorted(
        name
        for name in (part.strip() for part in names.split(","))
        if name and name not in _NOT_A_SECRET
    )


def _trigger(node: Node) -> str:
    events = [
        event
        for event in node.attributes.get("untrusted_events", "").split(",")
        if event
    ]
    return ", ".join(events) if events else "a checkout of the pull request head"


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "workflow-runtime"):
        secrets = exposed_secrets(node)
        if not secrets:
            continue
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        if state is FindingChangeState.CHANGED:
            before = authority.baseline_node(context, node.id)
            if before is not None:
                # Only what the change newly exposes.
                already = set(exposed_secrets(before))
                secrets = [name for name in secrets if name not in already]
                if not secrets:
                    continue
        severity = (
            FindingSeverity.MEDIUM
            if state is FindingChangeState.NOT_COMPARED
            else FindingSeverity.HIGH
        )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=(
                    f"Job '{node.name}' runs an agent on untrusted input "
                    f"({_trigger(node)}) and is given "
                    f"{'secret' if len(secrets) == 1 else 'secrets'} "
                    f"{', '.join(secrets)}."
                ),
                node=node,
                context=context,
                severity=severity,
                confidence=Confidence.HIGH,
                change_state=state,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "exposed_secrets", "findings"]
