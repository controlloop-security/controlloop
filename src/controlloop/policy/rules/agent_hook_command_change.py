"""Rule: a hook or helper command added or changed.

A committed `SessionStart` hook ran the Miasma worm, Mini Shai-Hulud,
and CVE-2026-25725 on every machine that opened the repository. A
formatter hook and a credential harvester are both hook changes, so this
rule reports the change and the command it runs; the shell
classification carries a confidence label, not a verdict. Severities: a
command added or changed `high`, a non-command hook `medium`, a removal
`info`, a first scan `low`.

A skill's shell lines and a plugin's `bin/` directory are recorded as
helper commands too, but they belong to `policy.component-shell-execution`
(read here before 1.1.0), so this rule skips the `skill-shell` and
`plugin-bin` settings.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.agent-hook-command-change"
_RULE_VERSION = "1.1.0"
_SUBTYPES = ("hook", "helper-command")
#: Helper-command settings policy.component-shell-execution reports.
_COMPONENT_SETTINGS = frozenset({"skill-shell", "plugin-bin"})
_TRUNCATION_MARKER = "...[truncated]"
_IDENTITY_FIELDS = ("command", "hook_type", "url_host", "mcp_server", "mcp_tool")

_REMEDIATION = (
    "Read the command and confirm it is what every developer and CI run "
    "should execute, or remove it."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _command(node: Node) -> str:
    return (
        node.attributes.get("command")
        or node.attributes.get("url_host")
        or (
            node.attributes.get("mcp_server", "?")
            + "/"
            + node.attributes.get("mcp_tool", "?")
            if "mcp_server" in node.attributes
            else node.attributes.get("hook_type", "unknown")
        )
    )


def _describe(node: Node, host_name: str) -> str:
    command = _command(node)
    if node.subtype == "helper-command":
        return (
            f"Setting '{node.attributes.get('setting', 'unknown')}' for host "
            f"'{host_name}' runs `{command}`"
        )
    event = node.attributes.get("event", "unknown")
    hook_type = node.attributes.get("hook_type", "unknown")
    if hook_type == "command":
        return f"Hook on event '{event}' for host '{host_name}' runs `{command}`"
    return f"A {hook_type} hook on event '{event}' for host '{host_name}' ({command})"


def _is_command(node: Node) -> bool:
    return (
        node.subtype == "helper-command"
        or node.attributes.get("hook_type") == "command"
    )


def _confidence(node: Node) -> Confidence:
    command = node.attributes.get("command", "")
    return (
        Confidence.MEDIUM if command.endswith(_TRUNCATION_MARKER) else Confidence.HIGH
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    removed = [
        node
        for node in authority.removed_nodes(context, *_SUBTYPES)
        if node.attributes.get("setting") not in _COMPONENT_SETTINGS
    ]
    current = [
        node
        for node in authority.nodes_with_subtype(context, *_SUBTYPES)
        if node.attributes.get("setting") not in _COMPONENT_SETTINGS
    ]
    added = [
        node
        for node in current
        if authority.component_state(context, node) is FindingChangeState.ADDED
    ]

    def host_of(node: Node) -> str:
        host = authority.owning_host(context, node.id)
        return host.name if host is not None else "an agent host"

    # A hook removed and re-added with the same command and host is a
    # rename or a move, not a new command.
    removed_keys = {
        (node.attributes.get("command"), node.evidence[0].path) for node in removed
    }
    moved = {
        node.id
        for node in added
        if node.attributes.get("command")
        and (node.attributes.get("command"), node.evidence[0].path) in removed_keys
    }
    moved_keys = {
        (node.attributes.get("command"), node.evidence[0].path)
        for node in added
        if node.id in moved
    }

    for node in current:
        state = authority.component_state(context, node)
        if state is None or node.id in moved:
            continue
        host_name = host_of(node)
        description = _describe(node, host_name)
        if state is FindingChangeState.NOT_COMPARED:
            severity = FindingSeverity.LOW
            message = f"{description}. Recorded on a scan with no baseline."
        elif state is FindingChangeState.ADDED:
            severity = (
                FindingSeverity.HIGH if _is_command(node) else FindingSeverity.MEDIUM
            )
            message = f"Added: {description}."
        else:
            before = authority.baseline_node(context, node.id)
            if before is None:
                continue
            changed = [
                field
                for field in _IDENTITY_FIELDS
                if before.attributes.get(field) != node.attributes.get(field)
            ]
            if not changed:
                continue
            severity = (
                FindingSeverity.HIGH if _is_command(node) else FindingSeverity.MEDIUM
            )
            message = f"Changed: {description}; it previously ran `{_command(before)}`."
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=message,
                node=node,
                context=context,
                severity=severity,
                confidence=_confidence(node),
                change_state=state,
                remediation=_REMEDIATION,
            )
        )

    for node in removed:
        if (node.attributes.get("command"), node.evidence[0].path) in moved_keys:
            continue
        results.append(
            authority.build_finding(
                rule_id=RULE_ID,
                rule_version=rule_version,
                message=f"Removed: {_describe(node, 'its host')}.",
                node=node,
                context=context,
                severity=FindingSeverity.INFO,
                confidence=Confidence.HIGH,
                change_state=FindingChangeState.REMOVED,
                remediation="No action is needed; the command no longer runs.",
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "evaluate", "findings"]
