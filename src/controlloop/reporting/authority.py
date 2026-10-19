"""The authority statement.

When a change hands an agent new power, every output leads with one
plain-language sentence per grant: what the power is, which agent gets
it, and where it was granted. For example:

    This change gives Claude Code the power to run `node .github/setup.js`
    on every session start (`.claude/settings.json`, hook `SessionStart`).
    No approval is recorded.

The delta is change-only. It is computed from the baseline diff, and a
scan with no baseline has no delta: a first scan's components are the
rules' business, not a change anyone made. An empty delta is `None`,
and every renderer then adds nothing.

Every command, pattern, and name here was bounded and redacted by the
adapter that recorded it; each sentence passes through
`controlloop.redaction.redact_text` again before it leaves this module,
so a value an adapter missed cannot reach any output format.

This module is pure: it reads the current ACBOM document, the diff, and
the approvals already filtered to the ones active at evaluation time.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from controlloop.acbom.identity import host_node_id
from controlloop.acbom.models import (
    ACBOMDocument,
    Node,
)
from controlloop.capability.agent_authority import (
    approval_keys,
    component_label,
    granting_path,
)
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
    worst_class,
)
from controlloop.diff.authority import (
    CURRENT_AUTHORITY_DELTA_SCHEMA_VERSION,
    AuthorityDelta,
    AuthorityEntry,
)
from controlloop.diff.models import ChangeKind, DiffResult
from controlloop.manifest.models import Approval
from controlloop.policy.rules.permission_bypass_from_project import (
    loosened_reasons,
    subagent_loosened_reasons,
)
from controlloop.redaction import redact_text

APPROVAL_RECORDED = "Approval recorded."
NO_APPROVAL_RECORDED = "No approval is recorded."
#: Two ACBOM files compared with no repository have no manifest to read.
APPROVALS_NOT_EVALUATED = "Approvals were not evaluated."

#: Hook events the statement names in words; any other event is quoted.
_EVENT_PHRASES = {
    "SessionStart": "on every session start",
    "SessionEnd": "on every session end",
    "UserPromptSubmit": "on every prompt",
    "PreToolUse": "before every matching tool call",
    "PostToolUse": "after every matching tool call",
    "Stop": "every time the agent stops",
    "SubagentStop": "every time a subagent stops",
    "Notification": "on every notification",
    "PreCompact": "before every context compaction",
}

_MCP_SUBTYPES = frozenset({"mcp-server-stdio", "mcp-server-http"})
_MCP_IDENTITY = ("declaration_digest", "tools_digest", "command", "args", "url_host")
_HOOK_IDENTITY = ("command", "hook_type", "url_host", "mcp_server", "mcp_tool")
_WRITE_SCOPE_SUFFIX = "_write"
#: The settings key each recorded host attribute comes from, so the
#: statement names what a reviewer sees in the file.
_HOST_KEYS = {
    "default_mode": "permissions.defaultMode",
    "disable_bypass_permissions_mode": "permissions.disableBypassPermissionsMode",
    "disable_all_hooks": "disableAllHooks",
    "disable_skill_shell_execution": "disableSkillShellExecution",
    "sandbox_enabled": "sandbox.enabled",
    "approval_policy": "approval_policy",
    "sandbox_mode": "sandbox_mode",
    "default_permissions": "default_permissions",
    "default_approval_mode": "general.defaultApprovalMode",
}
_GRANT_HOLDERS = frozenset({"host", "workflow-runtime", "skill", "subagent"})


_SHELL_TOOLS = frozenset({"Bash", "PowerShell", "Shell", "run_shell_command", "shell"})
_WRITE_TOOLS = frozenset(
    {"Edit", "MultiEdit", "Write", "NotebookEdit", "write_file", "replace"}
)
_NETWORK_TOOLS = frozenset({"WebFetch", "WebSearch", "web_fetch", "google_web_search"})


def _tool_class(tools: Iterable[str]) -> MaterialCapabilityClass:
    """The class of a set of tool names or rule patterns (`Bash(npm *)`)."""

    names = {tool.split("(", 1)[0].strip() for tool in tools}
    if names & _SHELL_TOOLS:
        return MaterialCapabilityClass.CODE_EXECUTION
    if names & _WRITE_TOOLS:
        return MaterialCapabilityClass.WRITE_ACCESS
    if names & _NETWORK_TOOLS:
        return MaterialCapabilityClass.EXTERNAL_COMMUNICATION
    return MaterialCapabilityClass.UNCLASSIFIED


def _node_class(node: Node) -> MaterialCapabilityClass:
    """The taxonomy's reading of the node's own security attributes: the
    worst named class it holds, or `unclassified` when it holds none."""

    classes = classify_material_capability(node.security_attributes)
    named = [
        item for item in classes if item is not MaterialCapabilityClass.UNCLASSIFIED
    ]
    return worst_class(named) if named else MaterialCapabilityClass.UNCLASSIFIED


def _material_class(kind: str, node: Node) -> MaterialCapabilityClass:
    """What kind of power the grant hands over. The taxonomy decides for
    nodes that carry the facts (hooks, servers, plugins); the grant's
    kind decides where the power is in the rule or mode itself."""

    if kind == "subagent":
        return MaterialCapabilityClass.DELEGATION
    if kind == "permission-rule":
        if node.attributes.get("source") in ("autoApprove", "trust"):
            return MaterialCapabilityClass.UNCLASSIFIED
        return _tool_class([node.attributes.get("pattern", "")])
    if kind == "skill":
        return _tool_class(node.attributes.get("allowed_tools", "").split(","))
    if kind == "workflow-runtime":
        writes = any(
            key.endswith(_WRITE_SCOPE_SUFFIX) and value == "true"
            for key, value in node.attributes.items()
        )
        return (
            MaterialCapabilityClass.WRITE_ACCESS
            if writes
            else MaterialCapabilityClass.CODE_EXECUTION
        )
    if kind == "mode":
        # A looser mode lets the agent run its tools, the shell among
        # them, with fewer confirmations.
        return MaterialCapabilityClass.CODE_EXECUTION
    if kind in ("hook", "helper-command") and node.attributes.get("hook_type") in (
        None,
        "command",
    ):
        return MaterialCapabilityClass.CODE_EXECUTION
    if node.attributes.get("hook_type") == "http":
        return MaterialCapabilityClass.EXTERNAL_COMMUNICATION
    return _node_class(node)


_label = component_label


def _code(text: str) -> str:
    return f"`{text.replace('`', "'")}`"


def _owning_host(
    node: Node,
    by_id: Mapping[str, Node],
    sources_of: Mapping[str, list[str]],
) -> Node | None:
    """The agent host that holds `node`: the first host found walking
    edges backwards, where a workflow runtime resolves to the host it
    runs (it `invokes` the host rather than being reached from it)."""

    frontier = [node.id]
    seen = {node.id}
    for _ in range(6):
        next_frontier: list[str] = []
        for current_id in frontier:
            current = by_id.get(current_id)
            if current is None:
                continue
            if current.subtype == "host":
                return current
            if current.subtype == "workflow-runtime":
                host = by_id.get(host_node_id(current.attributes.get("host", "")))
                if host is not None:
                    return host
            for source in sources_of.get(current_id, ()):
                if source not in seen:
                    seen.add(source)
                    next_frontier.append(source)
        frontier = sorted(next_frontier)
        if not frontier:
            break
    return None


def owning_host_ids(document: ACBOMDocument) -> dict[str, str | None]:
    """Every node's owning host, by node ID, found the way the
    authority statement finds it (`None` when no host holds the node).
    The Team envelope sends it as a component's `host_id`."""

    by_id = {node.id: node for node in document.nodes}
    sources_of: dict[str, list[str]] = {}
    for edge in sorted(document.edges, key=lambda item: item.id):
        sources_of.setdefault(edge.target, []).append(edge.source)
    hosts: dict[str, str | None] = {}
    for node in document.nodes:
        host = _owning_host(node, by_id, sources_of)
        hosts[node.id] = host.id if host is not None else None
    return hosts


def _holder(
    node: Node, by_id: Mapping[str, Node], sources_of: Mapping[str, list[str]]
) -> Node | None:
    for source in sources_of.get(node.id, ()):
        holder = by_id.get(source)
        if holder is not None and holder.subtype in _GRANT_HOLDERS:
            return holder
    return None


def _identity_changed(before: Node | None, after: Node, fields: Iterable[str]) -> bool:
    if before is None:
        return True
    return any(
        before.attributes.get(key) != after.attributes.get(key) for key in fields
    )


def _hook_grant(node: Node, before: Node | None, changed: bool) -> tuple[str, str]:
    event = node.attributes.get("event", "unknown")
    when = _EVENT_PHRASES.get(event, f"on every {_code(event)} event")
    matcher = node.attributes.get("matcher")
    if matcher and event in ("PreToolUse", "PostToolUse"):
        when = when.replace("matching tool call", f"{_code(matcher)} tool call")
    hook_type = node.attributes.get("hook_type", "unknown")
    if node.subtype == "helper-command":
        setting = node.attributes.get("setting", "unknown")
        action = f"run {_code(node.attributes.get('command', 'unknown'))}"
        grant = f"{action} through the {_code(setting)} setting"
        detail = f"setting {_code(setting)}"
    elif hook_type == "command":
        grant = f"run {_code(node.attributes.get('command', 'unknown'))} {when}"
        detail = f"hook {_code(event)}"
    elif hook_type == "http":
        grant = (
            f"send hook data to {_code(node.attributes.get('url_host', 'unknown'))} "
            f"{when}"
        )
        detail = f"hook {_code(event)}"
    elif hook_type == "mcp_tool":
        tool = (
            f"{node.attributes.get('mcp_server', '?')}/"
            f"{node.attributes.get('mcp_tool', '?')}"
        )
        grant = f"call MCP tool {_code(tool)} {when}"
        detail = f"hook {_code(event)}"
    else:
        grant = f"run a {hook_type} hook {when}"
        detail = f"hook {_code(event)}"
    if changed and before is not None:
        previous = before.attributes.get("command") or before.attributes.get("url_host")
        if previous:
            grant += f", replacing {_code(previous)}"
    return grant, detail


def _rule_grant(
    node: Node, by_id: Mapping[str, Node], sources_of: Mapping[str, list[str]]
) -> tuple[str, str] | None:
    source = node.attributes.get("source")
    pattern = node.attributes.get("pattern", "unknown")
    if source in ("autoApprove", "trust"):
        server = node.attributes.get("server", "unknown")
        tool = node.attributes.get("tool", "*")
        what = "every tool" if tool == "*" else f"tool {_code(tool)}"
        return (
            f"run {what} of MCP server {_code(server)} without approval",
            f"server {_code(server)}",
        )
    if node.attributes.get("effect") != "allow":
        return None
    holder = _holder(node, by_id, sources_of)
    if holder is None:
        return None
    grant = f"use {_code(pattern)} without asking"
    if node.security_attributes.wildcard is True:
        grant += " (a wildcard)"
    if holder.subtype in ("skill", "subagent"):
        grant += f" through {holder.subtype} {_code(_label(holder))}"
    elif holder.subtype == "workflow-runtime":
        grant += f" in workflow {_code(holder.attributes.get('workflow', 'unknown'))}"
    return grant, f"rule {_code(pattern)}"


def _workflow_grant(node: Node) -> tuple[str, str]:
    workflow = node.attributes.get("workflow", "unknown")
    job = node.attributes.get("job", "unknown")
    writes = sorted(
        key[: -len(_WRITE_SCOPE_SUFFIX)].replace("_", "-")
        for key, value in node.attributes.items()
        if key.endswith(_WRITE_SCOPE_SUFFIX) and value == "true"
    )
    grant = f"run in GitHub Actions workflow {_code(workflow)}"
    if writes:
        grant += " with write access to " + ", ".join(writes)
    elif node.attributes.get("job_permissions") == "unknown":
        grant += " with the repository's default token permissions"
    if node.attributes.get("skip_permissions") == "true":
        grant += ", skipping every permission prompt"
    untrusted = node.attributes.get("untrusted_events")
    if untrusted:
        grant += f", triggered by {untrusted.replace(',', ', ')}"
    return grant, f"job {_code(job)}"


def _mcp_grant(node: Node, changed: bool) -> tuple[str, str]:
    name = node.name
    if node.subtype == "mcp-server-stdio":
        command = node.attributes.get("command", "unknown")
        args = node.attributes.get("args")
        run = f"{command} {args}" if args else command
        grant = f"start MCP server {_code(name)} by running {_code(run)}"
    else:
        grant = (
            f"connect to MCP server {_code(name)} at "
            f"{_code(node.attributes.get('url_host', 'unknown'))}"
        )
    if changed:
        grant += ", whose declaration or tool list changed"
    return grant, f"server {_code(name)}"


def _component_grant(node: Node, changed: bool) -> tuple[str, str] | None:
    name = _code(_label(node))
    if node.subtype in ("plugin", "marketplace"):
        location = node.attributes.get("location")
        grant = f"install {node.subtype} {name}"
        if location:
            grant += f" from {_code(location)}"
        if node.security_attributes.pinned is False:
            grant += ", unpinned"
        if changed:
            grant += ", whose source changed"
        return grant, f"{node.subtype} {name}"
    if node.subtype == "skill":
        tools = node.attributes.get("allowed_tools")
        if tools is None:
            return None
        return (
            f"load skill {name}, which may use {_code(tools)} without asking",
            f"skill {name}",
        )
    if node.subtype == "subagent":
        mode = node.attributes.get("permission_mode")
        if mode == "bypassPermissions":
            return (
                f"delegate to subagent {name} in {_code(mode)} mode",
                f"subagent {name}",
            )
        tools = node.attributes.get("tools", "inherit")
        if tools == "inherit" and mode is None:
            return None
        grant = f"delegate to subagent {name} with tools {_code(tools)}"
        if mode is not None:
            grant += f" in {_code(mode)} mode"
        return grant, f"subagent {name}"
    return None


def _entry_for(
    kind: ChangeKind,
    before: Node | None,
    node: Node,
    by_id: Mapping[str, Node],
    sources_of: Mapping[str, list[str]],
) -> tuple[str, str, str] | None:
    """`(kind, grant, detail)` for one changed node, or `None` when the
    change hands no agent new power."""

    changed = kind is ChangeKind.CHANGED
    subtype = node.subtype
    if subtype in ("hook", "helper-command"):
        if changed and not _identity_changed(before, node, _HOOK_IDENTITY):
            return None
        return (subtype, *_hook_grant(node, before, changed))
    if subtype == "permission-rule":
        if changed and not _identity_changed(before, node, ("pattern", "effect")):
            return None
        rule = _rule_grant(node, by_id, sources_of)
        return None if rule is None else ("permission-rule", *rule)
    if subtype == "workflow-runtime":
        if changed and not _identity_changed(
            before,
            node,
            [key for key in node.attributes if key.endswith(_WRITE_SCOPE_SUFFIX)]
            + ["skip_permissions", "untrusted_events", "action"],
        ):
            return None
        return ("workflow-runtime", *_workflow_grant(node))
    if subtype in _MCP_SUBTYPES:
        if changed and not _identity_changed(before, node, _MCP_IDENTITY):
            return None
        return ("mcp-server", *_mcp_grant(node, changed))
    if subtype == "host":
        baseline = (
            before
            if before is not None
            else node.model_copy(
                update={"attributes": {"host": node.attributes.get("host", "")}}
            )
        )
        reasons = loosened_reasons(baseline, node)
        if not reasons:
            return None
        keys = [
            _HOST_KEYS.get(reason.split("'")[1], reason.split("'")[1])
            for reason in reasons
            if reason.count("'") >= 2
        ]
        for attribute, key in _HOST_KEYS.items():
            reasons = [
                reason.replace(f"'{attribute}'", f"'{key}'") for reason in reasons
            ]
        return (
            "mode",
            "act with fewer confirmations: " + "; ".join(reasons),
            "setting " + ", ".join(_code(key) for key in keys),
        )
    if subtype == "subagent" and changed and before is not None:
        reasons = subagent_loosened_reasons(before, node)
        if (
            node.attributes.get("permission_mode") == "bypassPermissions"
            and before.attributes.get("permission_mode") != "bypassPermissions"
        ):
            reasons = ["permissionMode moved to 'bypassPermissions'"]
        if reasons:
            return (
                "mode",
                f"run subagent {_code(_label(node))} with fewer confirmations: "
                + "; ".join(reasons),
                f"subagent {_code(_label(node))}",
            )
        if not _identity_changed(before, node, ("tools",)):
            return None
    component_identity = {
        "plugin": ("location", "ref", "source_type"),
        "marketplace": ("location", "ref", "source_type"),
        "skill": ("allowed_tools",),
    }
    if (
        changed
        and subtype in component_identity
        and not _identity_changed(before, node, component_identity[subtype])
    ):
        return None
    component = _component_grant(node, changed)
    return None if component is None else (subtype or "component", *component)


def compute_authority_delta(
    document: ACBOMDocument,
    diff: DiffResult | None,
    approvals: Iterable[Approval] | None = (),
) -> AuthorityDelta | None:
    """Every new or changed grant in `diff`, or `None` when there is none
    (including when there is no baseline at all). `approvals` are the
    manifest approvals active at evaluation time; one whose `capability`
    is `"<path>#<key_path>"`, the component's name, or its node ID marks
    the grant "Approval recorded.". `None` means no manifest could be
    read at all, and every statement says approvals were not evaluated."""

    if diff is None:
        return None
    by_id = {node.id: node for node in document.nodes}
    sources_of: dict[str, list[str]] = {}
    for edge in sorted(document.edges, key=lambda item: item.id):
        sources_of.setdefault(edge.target, []).append(edge.source)
    approved = (
        None
        if approvals is None
        else frozenset(str(approval.capability) for approval in approvals)
    )

    entries: list[AuthorityEntry] = []
    for change in diff.node_changes:
        if change.kind not in (ChangeKind.ADDED, ChangeKind.CHANGED):
            continue
        node = by_id.get(change.node_id) or change.after
        if node is None:
            continue
        found = _entry_for(change.kind, change.before, node, by_id, sources_of)
        if found is None:
            continue
        kind, grant, detail = found
        host = _owning_host(node, by_id, sources_of)
        host_name = host.name if host is not None else "an agent"
        path = granting_path(node)
        key_path = node.attributes.get("key_path", node.name)
        recorded = None if approved is None else bool(approval_keys(node) & approved)
        approval = (
            APPROVALS_NOT_EVALUATED
            if recorded is None
            else (APPROVAL_RECORDED if recorded else NO_APPROVAL_RECORDED)
        )
        statement = redact_text(
            f"This change gives {host_name} the power to {grant} "
            f"({_code(path)}, {detail}). {approval}"
        )
        entries.append(
            AuthorityEntry(
                node_id=node.id,
                host_id=host.id if host is not None else None,
                host_name=host_name,
                kind=kind,
                change=change.kind.value,
                grant=redact_text(grant),
                material_class=_material_class(kind, node),
                statement=statement,
                path=path,
                key_path=redact_text(key_path),
                detail=redact_text(detail),
                approval_recorded=recorded,
                confidence=node.confidence,
            )
        )
    if not entries:
        return None
    entries.sort(
        key=lambda entry: (entry.host_name, entry.path, entry.key_path, entry.statement)
    )
    return AuthorityDelta(
        schema_version=CURRENT_AUTHORITY_DELTA_SCHEMA_VERSION,
        entries=tuple(entries),
    )


def describe_authority_delta(delta: AuthorityDelta | None) -> tuple[str, ...]:
    """The terminal and check-summary lines: nothing for an empty delta."""

    if delta is None:
        return ()
    return ("Authority:", *(f"  • {entry.statement}" for entry in delta.entries))


__all__ = [
    "APPROVALS_NOT_EVALUATED",
    "APPROVAL_RECORDED",
    "CURRENT_AUTHORITY_DELTA_SCHEMA_VERSION",
    "NO_APPROVAL_RECORDED",
    "AuthorityDelta",
    "AuthorityEntry",
    "compute_authority_delta",
    "describe_authority_delta",
    "owning_host_ids",
]
