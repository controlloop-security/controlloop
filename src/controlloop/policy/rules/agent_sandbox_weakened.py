"""Rule: a change that turns off a coding agent's sandbox or opens its
network egress.

A sandbox is what keeps an agent's shell commands away from the rest of
the machine and the network; the limits page tells users to pair a
passing gate with sandboxed or network-restricted runs. A project file
that switches it off, lets commands escape it, approves every command
because a sandbox exists, or opens the network changes that for everyone
who opens the repository. Each setting has an order from tight to loose;
a move toward loose against the baseline is `high`, and a move toward
tight is silent. Removing a tight setting counts as loosening: the
protection is gone. On a first scan, a host with a setting already at
the loose end is reported once, at `low`.

Approval modes and Codex `sandbox_mode` stay with
`policy.permission-bypass-from-project`; this rule takes the remaining
sandbox and egress settings. The Cursor egress scale is copied from the
adapter rather than imported, so policy does not depend on discovery
code; `tests/policy/rules/test_agent_sandbox_weakened.py` holds the two
equal.
"""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Node
from controlloop.findings.models import Finding, FindingChangeState, FindingSeverity
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules import _authority as authority

RULE_ID = "policy.agent-sandbox-weakened"
_RULE_VERSION = "1.0.0"

_ON_OFF = ("true", "false")
_OFF_ON = ("false", "true")

#: Cursor cloud-agent `egressMode`, tightest first.
CURSOR_EGRESS_SCALE = (
    "network_settings_only",
    "default_with_network_settings",
    "parent_plus_network_settings",
    "allow_all",
)

#: `(host, attribute) -> (setting name for messages, scale tightest first)`.
SCALES: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("claude-code", "sandbox_enabled"): ("sandbox.enabled", _ON_OFF),
    ("claude-code", "sandbox_allow_unsandboxed_commands"): (
        "sandbox.allowUnsandboxedCommands",
        _OFF_ON,
    ),
    ("claude-code", "sandbox_auto_allow_bash"): (
        "sandbox.autoAllowBashIfSandboxed",
        _OFF_ON,
    ),
    ("codex", "sandbox_network_access"): (
        "sandbox_workspace_write.network_access",
        _OFF_ON,
    ),
    ("gemini-cli", "sandbox"): ("tools.sandbox", _ON_OFF),
    ("gemini-cli", "sandbox_network_access"): ("tools.sandboxNetworkAccess", _OFF_ON),
    ("cursor", "egress_mode"): ("egressMode", CURSOR_EGRESS_SCALE),
}

_REMEDIATION = (
    "Keep the tight value in the project file: {tight}. Set looser values "
    "in personal settings outside the repository if one person needs them."
    " Once reviewed, an approval in controlloop.yaml naming the component "
    "keeps the finding at info, so it no longer blocks."
)


def _value(host: str, attribute: str, node: Node) -> str | None:
    value = node.attributes.get(attribute)
    if value is not None and (host, attribute) == ("gemini-cli", "sandbox"):
        # Gemini CLI takes `true` or the name of a sandbox command
        # (`docker`, `podman`, `sandbox-exec`); every value but `false`
        # turns it on.
        return "false" if value == "false" else "true"
    return value


def _position(value: str | None, scale: tuple[str, ...]) -> int | None:
    return scale.index(value) if value in scale else None


def loosened_settings(before: Node | None, after: Node) -> list[tuple[str, str, str]]:
    """`(setting, old, new)` for each setting that moved toward loose.

    `old` and `new` are `unset` when the project file does not set it.
    With no `before`, a setting counts only when it is at the loose end.
    """

    host = after.attributes.get("host", "")
    moves: list[tuple[str, str, str]] = []
    for (scale_host, attribute), (setting, scale) in SCALES.items():
        if scale_host != host:
            continue
        old = _value(host, attribute, before) if before is not None else None
        new = _value(host, attribute, after)
        if old == new:
            continue
        old_position = _position(old, scale)
        new_position = _position(new, scale)
        if new is None:
            loosened = old_position is not None and old_position < len(scale) - 1
        elif new_position is None:
            # A value this rule does not know cannot be shown to loosen.
            loosened = False
        elif old is None or old_position is None:
            loosened = new_position == len(scale) - 1
        else:
            loosened = new_position > old_position
        if loosened:
            moves.append((setting, old or "unset", new or "unset"))
    return moves


def _tight_values(host: str) -> str:
    return ", ".join(
        f"{setting} = {scale[0]}"
        for (scale_host, _), (setting, scale) in SCALES.items()
        if scale_host == host
    )


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
        remediation=_REMEDIATION.format(
            tight=_tight_values(node.attributes.get("host", ""))
        ),
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
) -> tuple[Finding, ...]:
    results: list[Finding] = []
    for node in authority.nodes_with_subtype(context, "host"):
        state = authority.component_state(context, node)
        if state is None or state is FindingChangeState.REMOVED:
            continue
        if state is FindingChangeState.NOT_COMPARED:
            at_loose_end = loosened_settings(None, node)
            if at_loose_end:
                settings = ", ".join(
                    f"'{setting}' is '{new}'" for setting, _, new in at_loose_end
                )
                results.append(
                    _finding(
                        context,
                        node,
                        f"{node.name}: {settings}. Recorded on a scan with no "
                        "baseline.",
                        FindingSeverity.LOW,
                        state,
                        rule_version,
                    )
                )
            continue
        moves = loosened_settings(authority.baseline_node(context, node.id), node)
        if not moves:
            continue
        changes = "; ".join(
            f"'{setting}' moved from '{old}' to '{new}'" for setting, old, new in moves
        )
        results.append(
            _finding(
                context,
                node,
                f"{node.name}: {changes}.",
                FindingSeverity.HIGH,
                state,
                rule_version,
            )
        )
    return tuple(sorted(results, key=lambda finding: finding.id))


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    return authority.observations(findings(context))


RULE = Rule(id=RULE_ID, evaluate=evaluate, reads_agent_authority=True)

__all__ = [
    "CURSOR_EGRESS_SCALE",
    "RULE",
    "RULE_ID",
    "SCALES",
    "evaluate",
    "findings",
    "loosened_settings",
]
