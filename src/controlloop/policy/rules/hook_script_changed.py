"""Rule: the script a hook runs changed while the hook did not.

`policy.agent-hook-command-change` reports a hook whose command changes,
but a pull request can leave `.claude/settings.json` alone and edit
`.claude/hooks/setup.sh`, the file the hook runs. The adapters record a
`script_digest` for every hook, helper command, skill shell line, and
plugin `bin/` directory whose command names a file committed in the
repository; this rule compares it with the baseline. Severities: the
digest changed with the command unchanged `high`; a digest that could be
read becoming `unknown` (the file moved outside the repository, grew past
the size bound, or went missing) `medium`. A node whose command also
changed is left to `policy.agent-hook-command-change` and
`policy.component-shell-execution`, so one change produces one finding. A
first scan, an added or removed node, `unknown` on both sides, and a
baseline recorded before digests existed are silent.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.hook-script-changed"
_RULE_VERSION = "1.0.0"
_SUBTYPES = ("hook", "helper-command")
_UNKNOWN = "unknown"

_REMEDIATION = (
    "Review the script change as agent code: it runs with the hook's "
    "authority on every machine that opens the repository. Or pin the "
    "script behind a permission rule."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _subject(context: RuleContext, node: Node) -> str:
    host = authority.owning_host(context, node.id)
    host_name = host.name if host is not None else "an agent host"
    if node.subtype == "hook":
        event = node.attributes.get("event", "unknown")
        return f"The hook on event '{event}' for host '{host_name}'"
    setting = node.attributes.get("setting", "unknown")
    return f"Setting '{setting}' for host '{host_name}'"


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, *_SUBTYPES):
        if authority.component_state(context, node) is not FindingChangeState.CHANGED:
            continue
        before = authority.baseline_node(context, node.id)
        if before is None:
            continue
        old = before.attributes.get("script_digest")
        new = node.attributes.get("script_digest")
        if old is None or new is None or old == new:
            continue
        if before.attributes.get("command") != node.attributes.get("command"):
            continue
        path = node.attributes.get("script_path", "unknown")
        subject = _subject(context, node)
        if new == _UNKNOWN:
            severity = FindingSeverity.MEDIUM
            message = (
                f"{subject} runs `{path}`, which can no longer be read, so its "
                "contents are not tracked: it moved outside the repository, "
                "grew past the size bound, or is missing."
            )
        else:
            severity = FindingSeverity.HIGH
            message = (
                f"{subject} runs `{path}`, whose contents changed while the "
                "command did not."
            )
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=message,
                node=node,
                context=context,
                severity=severity,
                confidence=Confidence.HIGH,
                change_state=FindingChangeState.CHANGED,
                remediation=_REMEDIATION,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
