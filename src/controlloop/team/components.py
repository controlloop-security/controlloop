"""An ACBOM node as the component the platform judges, and the identity
envelope 1.1.0 sends.

The platform flags a component by its type, its name, its value-free
attributes, and its flags. The gate must
judge a grant by exactly those same values, or a component the platform
records as sanctioned would block locally, or the reverse. This module is
the one place that mapping is written.

| ACBOM subtype | Component type | Name |
| --- | --- | --- |
| `host` | `host` | the host's display name, e.g. `Claude Code` |
| `hook` | `hook` | the event, e.g. `SessionStart` |
| `helper-command` | `helper_command` | the setting, e.g. `apiKeyHelper` |
| `permission-rule` | `permission_rule` | the rule pattern, e.g. `Bash(*)` |
| `mcp-server-stdio`, `mcp-server-http` | `mcp_server` | the server name |
| `plugin`, `marketplace`, `skill`, `subagent` | the same | its own name |
| `workflow-runtime` | `workflow_runtime` | `<workflow> / <job>` |

Attributes the approved-component constraints read: `package` and `version` (an MCP
server's package and version), `digest` (an MCP server's declaration
digest), and `command` (a hook's or helper's command). Flags: `pinned`,
`code_execution`, `bypass_mode`, `wildcard`, and `untrusted_input`, each
`True`, `False`, or `None` when the scanner could not tell.

An attribute value longer than the envelope accepts (512 characters) is
dropped rather than cut: a cut command would match a pattern the full
command does not. Dropped, it meets no constraint, here and on the
platform alike.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from controlloop.acbom.models import ACBOMDocument, Node
from controlloop.capability.agent_authority import component_label
from controlloop.diff.authority import AuthorityDelta, AuthorityEntry
from controlloop.team.sanction import ApprovedEntry, Component, Judgment, judge

COMPONENT_TYPE_BY_SUBTYPE = {
    "host": "host",
    "subagent": "subagent",
    "hook": "hook",
    "helper-command": "helper_command",
    "plugin": "plugin",
    "marketplace": "marketplace",
    "skill": "skill",
    "workflow-runtime": "workflow_runtime",
    "permission-rule": "permission_rule",
    "mcp-server-stdio": "mcp_server",
    "mcp-server-http": "mcp_server",
}

#: `NormalizedComponentRequest.attributes`: values of 1 to 512 characters.
MAX_ATTRIBUTE_LENGTH = 512

_FLAG_NAMES = ("pinned", "code_execution", "bypass_mode", "wildcard", "untrusted_input")


def _name(node: Node, component_type: str) -> str:
    attributes = node.attributes
    if component_type == "hook":
        return attributes.get("event") or node.name
    if component_type == "helper_command":
        return attributes.get("setting") or node.name
    if component_type == "permission_rule":
        return attributes.get("pattern") or node.name
    return component_label(node)


def _attributes(node: Node, component_type: str) -> dict[str, str]:
    attributes = node.attributes
    out: dict[str, str] = {}
    if component_type == "mcp_server":
        for source, target in (
            ("package", "package"),
            ("package_version", "version"),
            ("declaration_digest", "digest"),
        ):
            value = attributes.get(source)
            if value and value != "unknown":
                out[target] = value
    if component_type in ("hook", "helper_command"):
        command = attributes.get("command")
        if command:
            out["command"] = command
    return {
        key: value for key, value in out.items() if len(value) <= MAX_ATTRIBUTE_LENGTH
    }


def _flags(node: Node) -> dict[str, object]:
    flags = node.security_attributes.model_dump()
    return {
        name: (flags.get(name) if isinstance(flags.get(name), bool) else None)
        for name in _FLAG_NAMES
    }


def component_for(node: Node) -> Component | None:
    """The component identity of `node`, or `None` for a node that is not
    an agent-authority component or an MCP server."""

    component_type = COMPONENT_TYPE_BY_SUBTYPE.get(node.subtype or "")
    if component_type is None:
        return None
    return Component(
        type=component_type,
        name=_name(node, component_type),
        attributes=_attributes(node, component_type),
        flags=_flags(node),
    )


@dataclass(frozen=True, slots=True)
class DeltaJudgment:
    """One authority-delta entry and how the approved list judged it."""

    entry: AuthorityEntry
    node: Node
    component: Component
    judgment: Judgment


def judge_delta(
    document: ACBOMDocument,
    delta: AuthorityDelta | None,
    approved: Iterable[ApprovedEntry] | None,
) -> tuple[DeltaJudgment, ...]:
    """Every added or changed grant in `delta`, judged against `approved`
    (`None`: no published bundle, so each is `unevaluated`). Ordered as
    the delta is, which is deterministic."""

    if delta is None:
        return ()
    by_id = {node.id: node for node in document.nodes}
    approved_list = None if approved is None else tuple(approved)
    judged: list[DeltaJudgment] = []
    for entry in delta.entries:
        if entry.change not in ("added", "changed"):
            continue
        node = by_id.get(entry.node_id)
        if node is None:
            continue
        component = component_for(node)
        if component is None:
            continue
        judged.append(
            DeltaJudgment(
                entry=entry,
                node=node,
                component=component,
                judgment=judge(component, approved_list),
            )
        )
    return tuple(judged)


__all__ = [
    "COMPONENT_TYPE_BY_SUBTYPE",
    "MAX_ATTRIBUTE_LENGTH",
    "DeltaJudgment",
    "component_for",
    "judge_delta",
]
