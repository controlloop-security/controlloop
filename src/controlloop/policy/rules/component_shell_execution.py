"""Rule: a skill shell line or a plugin `bin/` directory added or changed.

A skill's `` !`cmd` `` line or ` ```! ` block runs when the skill loads,
before any prompt reaches the model and with no permission prompt. A
plugin's `bin/` directory joins the agent's `PATH`, so whatever it holds
runs as a bare command name. Both are code execution a repository ships
to everyone who opens it, the way a hook is.

**Why a separate rule, not more of `policy.agent-hook-command-change`:**
the adapter records both as helper commands, and before this rule the
hook rule reported them as "Setting 'skill-shell' for host ..." findings.
A separate rule names the skill or plugin, compares a skill's commands
as a set (so a line inserted above another does not report the
unchanged one as changed), and lets an organization give skills and
plugins their own action, for example blocking hook changes while
warning on skill lines. The detection shares no logic with the hook
rule beyond `_authority`, so nothing is factored out.

Severities: a command added `high`; a plugin `bin/` directory added
`high`; a command removed `info`; first scan `low`, once per skill or
plugin. The command is the adapter's recorded text, already redacted
the way hook commands are.
"""

from __future__ import annotations

from collections import defaultdict

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.component-shell-execution"
_RULE_VERSION = "1.0.0"

#: The helper-command settings this rule owns.
SETTINGS = frozenset({"skill-shell", "plugin-bin"})
_TRUNCATION_MARKER = "...[truncated]"

_REMEDIATION = (
    "Read the command and confirm every developer should run it when the "
    "skill loads or the plugin is enabled. Prefer moving it behind a "
    "permission rule, or drop the shell line and let the model call the "
    "tool when asked."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _owned(node: Node) -> bool:
    return (
        node.subtype == "helper-command" and node.attributes.get("setting") in SETTINGS
    )


def _path(node: Node) -> str:
    return (node.evidence[0].path or "unknown") if node.evidence else "unknown"


def _component(context: RuleContext, node: Node) -> str:
    """`Skill deploy` or `Plugin tools`, or the declaring file."""

    by_id = {candidate.id: candidate for candidate in context.acbom.nodes}
    for edge in authority.edges_into(context, node.id):
        parent = by_id.get(edge.source)
        if parent is not None and parent.subtype in ("skill", "plugin"):
            return parent.name[:1].upper() + parent.name[1:]
    kind = "Plugin" if node.attributes.get("setting") == "plugin-bin" else "Skill"
    return f"{kind} at {_path(node)}"


def _describe(context: RuleContext, node: Node) -> str:
    command = node.attributes.get("command", "unknown")
    if node.attributes.get("setting") == "plugin-bin":
        return f"{_component(context, node)} adds `{command}` to the agent's PATH"
    return (
        f"{_component(context, node)} runs `{command}` when it loads, before "
        "any prompt reaches the model"
    )


def _finding(
    context: RuleContext,
    node: Node,
    message: str,
    severity: FindingSeverity,
    state: FindingChangeState,
    rule_version: str,
    remediation: str = _REMEDIATION,
) -> Finding:
    command = node.attributes.get("command", "")
    return authority.build_finding(
        rule_id=RULE_ID,
        rule_version=rule_version,
        message=message,
        node=node,
        context=context,
        severity=severity,
        confidence=(
            Confidence.MEDIUM
            if command.endswith(_TRUNCATION_MARKER)
            else Confidence.HIGH
        ),
        change_state=state,
        remediation=remediation,
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    current = [
        node
        for node in authority.nodes_with_subtype(context, "helper-command")
        if _owned(node)
    ]
    results: list[Finding] = []

    if context.diff is None:
        # First scan: once per skill or plugin.
        by_component: dict[str, list[Node]] = defaultdict(list)
        for node in current:
            by_component[_path(node)].append(node)
        for nodes in by_component.values():
            first = min(nodes, key=lambda node: node.id)
            count = len(nodes)
            what = (
                _describe(context, first)
                if count == 1
                else f"{_component(context, first)} runs {count} shell commands "
                "when it loads"
            )
            results.append(
                _finding(
                    context,
                    first,
                    f"{what}. Recorded on a scan with no baseline.",
                    FindingSeverity.LOW,
                    FindingChangeState.NOT_COMPARED,
                    rule_version,
                )
            )
        return tuple(sorted(results, key=lambda finding: finding.id))

    # Compare each file's commands as a set, so a line inserted above
    # another does not report the unchanged command as changed.
    head: dict[str, dict[str, Node]] = defaultdict(dict)
    base: dict[str, dict[str, Node]] = defaultdict(dict)
    head_state: dict[str, FindingChangeState] = {}
    for node in current:
        command = node.attributes.get("command", "unknown")
        head[_path(node)].setdefault(command, node)
        state = authority.component_state(context, node)
        if state is None:
            base[_path(node)].setdefault(command, node)
        else:
            head_state[node.id] = state
            if state is FindingChangeState.CHANGED:
                before = authority.baseline_node(context, node.id)
                if before is not None:
                    base[_path(before)].setdefault(
                        before.attributes.get("command", "unknown"), before
                    )
    for node in authority.removed_nodes(context, "helper-command"):
        if _owned(node):
            base[_path(node)].setdefault(
                node.attributes.get("command", "unknown"), node
            )

    for path in sorted(set(head) | set(base)):
        for command, node in sorted(head[path].items()):
            if command in base[path]:
                continue
            state = head_state.get(node.id, FindingChangeState.ADDED)
            results.append(
                _finding(
                    context,
                    node,
                    f"Added: {_describe(context, node)}.",
                    FindingSeverity.HIGH,
                    state,
                    rule_version,
                )
            )
        for command, node in sorted(base[path].items()):
            if command in head[path]:
                continue
            results.append(
                _finding(
                    context,
                    node,
                    f"Removed: {_describe(context, node)}.",
                    FindingSeverity.INFO,
                    FindingChangeState.REMOVED,
                    rule_version,
                    remediation="No action is needed; the command no longer runs.",
                )
            )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = ["RULE", "RULE_ID", "SETTINGS", "evaluate", "findings"]
