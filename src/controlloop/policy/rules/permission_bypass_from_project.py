"""Rule: a permission or approval mode loosened from a project file.

Each host documents an ordered scale of permission or approval modes; a
move to the right needs fewer confirmations. A pull request that sets
`defaultMode: bypassPermissions`, `approval_policy = "never"`, or a
Gemini server's `trust: true` changes how much the agent may do without
asking for everyone who opens the repository, whether or not a given
host version honors it from a project file. Leftward moves are silent.
Severities: a loosening `high`; on a first scan, a host already at the
loose end, and each auto-approval, `low`.

The scales are copied from the adapters that record them rather than
imported, so policy does not depend on discovery code;
`tests/policy/rules/test_permission_bypass_from_project.py` holds the
two copies equal.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.permission-bypass-from-project"
_RULE_VERSION = "1.0.0"

CLAUDE_CODE_MODE_SCALE = (
    "plan",
    "default",
    "acceptEdits",
    "dontAsk",
    "auto",
    "bypassPermissions",
)
_ALIASES = {"manual": "default"}

#: `(host, attribute) -> (scale, value when absent)`.
SCALES: dict[tuple[str, str], tuple[tuple[str, ...], str | None]] = {
    ("claude-code", "default_mode"): (CLAUDE_CODE_MODE_SCALE, "default"),
    ("codex", "approval_policy"): (
        ("untrusted", "on-request", "on-failure", "never"),
        None,
    ),
    ("codex", "sandbox_mode"): (
        ("read-only", "workspace-write", "danger-full-access"),
        None,
    ),
    ("codex", "default_permissions"): (
        (":read-only", ":workspace", ":danger-full-access"),
        None,
    ),
    ("gemini-cli", "default_approval_mode"): (
        ("plan", "default", "auto_edit", "yolo"),
        "default",
    ),
}

#: Claude Code switches that turn a protection off: `(attribute, safe value)`.
#: Loosening is the safe value going to anything else, or going away.
_SWITCHES = (
    ("disable_all_hooks", "true"),
    ("disable_skill_shell_execution", "true"),
    ("sandbox_enabled", "true"),
)
_PRESENCE_SWITCHES = ("disable_bypass_permissions_mode",)
_AUTO_APPROVAL_SOURCES = frozenset({"autoApprove", "trust"})

_REMEDIATION = (
    "Keep the stricter mode in the project file and set looser modes in "
    "personal settings outside the repository."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _position(value: str | None, scale: tuple[str, ...]) -> int | None:
    if value is None:
        return None
    value = _ALIASES.get(value, value)
    return scale.index(value) if value in scale else None


def loosened_reasons(before: Node, after: Node) -> list[str]:
    host = after.attributes.get("host", "")
    reasons: list[str] = []
    for (scale_host, attribute), (scale, absent) in SCALES.items():
        if scale_host != host:
            continue
        old = before.attributes.get(attribute, absent)
        new = after.attributes.get(attribute, absent)
        old_position = _position(old, scale)
        new_position = _position(new, scale)
        if new_position is None or new == old:
            continue
        if old_position is None:
            if new_position == len(scale) - 1:
                reasons.append(f"'{attribute}' set to '{new}'")
            continue
        if new_position > old_position:
            reasons.append(f"'{attribute}' moved from '{old}' to '{new}'")
    if host == "claude-code":
        for attribute, safe in _SWITCHES:
            if (
                before.attributes.get(attribute) == safe
                and after.attributes.get(attribute) != safe
            ):
                new = after.attributes.get(attribute, "removed")
                reasons.append(f"'{attribute}' changed from '{safe}' to '{new}'")
        for attribute in _PRESENCE_SWITCHES:
            if attribute in before.attributes and attribute not in after.attributes:
                reasons.append(f"'{attribute}' was removed")
    return reasons


def subagent_loosened_reasons(before: Node, after: Node) -> list[str]:
    old = before.attributes.get("permission_mode")
    new = after.attributes.get("permission_mode")
    if new is None or new == old or new == "bypassPermissions":
        # A move into bypassPermissions is policy.component-self-grant's.
        return []
    old_position = _position(old or "default", CLAUDE_CODE_MODE_SCALE)
    new_position = _position(new, CLAUDE_CODE_MODE_SCALE)
    if old_position is None or new_position is None or new_position <= old_position:
        return []
    return [f"permissionMode moved from '{old or 'default'}' to '{new}'"]


def _finding(
    context: RuleContext,
    node: Node,
    message: str,
    severity: FindingSeverity,
    state: FindingChangeState,
    rule_version: str,
) -> Finding:
    return authority.build_finding(
        rule_id=RULE_ID,
        rule_version=rule_version,
        message=message,
        node=node,
        context=context,
        severity=severity,
        confidence=Confidence.HIGH,
        change_state=state,
        remediation=_REMEDIATION,
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "host", "subagent"):
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        if state is FindingChangeState.NOT_COMPARED:
            if node.subtype == "host" and node.security_attributes.bypass_mode is True:
                results.append(
                    _finding(
                        context,
                        node,
                        f"{node.name} is configured in a bypass mode by a project "
                        "file. Recorded on a scan with no baseline.",
                        FindingSeverity.LOW,
                        state,
                        rule_version,
                    )
                )
            continue
        before = authority.baseline_node(context, node.id)
        if before is None:
            if state is FindingChangeState.ADDED and node.subtype == "host":
                before = node.model_copy(
                    update={"attributes": {"host": node.attributes.get("host", "")}}
                )
            else:
                continue
        reasons = (
            loosened_reasons(before, node)
            if node.subtype == "host"
            else subagent_loosened_reasons(before, node)
        )
        if not reasons:
            continue
        results.append(
            _finding(
                context,
                node,
                f"{node.name.capitalize()}: {authority.first_line(reasons)}.",
                FindingSeverity.HIGH,
                state,
                rule_version,
            )
        )

    for node in authority.nodes_with_subtype(context, "permission-rule"):
        if node.attributes.get("source") not in _AUTO_APPROVAL_SOURCES:
            continue
        state = authority.component_state(context, node)
        if state not in (FindingChangeState.ADDED, FindingChangeState.NOT_COMPARED):
            continue
        server = node.attributes.get("server", "a server")
        tool = node.attributes.get("tool", "?")
        what = "every tool" if tool == "*" else f"tool '{tool}'"
        message = (
            f"{what.capitalize()} of MCP server '{server}' now runs without approval."
        )
        severity = FindingSeverity.HIGH
        if state is FindingChangeState.NOT_COMPARED:
            message = (
                f"{what.capitalize()} of MCP server '{server}' runs without approval. "
                "Recorded on a scan with no baseline."
            )
            severity = FindingSeverity.LOW
        results.append(_finding(context, node, message, severity, state, rule_version))
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = [
    "RULE",
    "RULE_ID",
    "SCALES",
    "evaluate",
    "findings",
    "loosened_reasons",
    "subagent_loosened_reasons",
]
