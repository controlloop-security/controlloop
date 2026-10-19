"""Claude Code skills, subagents, and plugins.

A skill can grant itself tools without asking (`allowed-tools`), run a
shell command before its text reaches the model (`` !`cmd` ``), and
register hooks for the rest of the session. A subagent can run in a
bypass permission mode with its own servers and hooks. A plugin carries
all of these and can put executables on the agent's `PATH`. This adapter
records each of them from the committed files, attached to the Claude
Code host, without running anything.

Prompt bodies are protected content. From a skill or subagent file this
adapter reads the YAML frontmatter and the shell-injection lines, and
nothing else: no description, no instruction text, no example.

The host itself belongs to `controlloop.adapters.claude_code`; this
adapter connects to it through a host reference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from controlloop.acbom import (
    Diagnostic,
    Edge,
    EdgeType,
    KnownBoolean,
    Node,
    NodeType,
    SecurityAttributes,
    host_node_id,
)
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.claude_code import (
    HOST,
    ComponentDiscovery,
    discover_hooks,
    helper_command_node,
    permission_rule_node,
    source_pin,
)
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.adapters.mcp import discover_mcp_config, inline_server_node
from controlloop.bounded_recursion import bounded_recursion

_NAME = "claude-code-components"
_DISPLAY_NAME = "Claude Code"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("docs-2026-10-17",)

_SKILL_ROOTS = (".claude/skills/", ".agents/skills/", ".github/skills/")
_COMMAND_ROOT = ".claude/commands/"
_AGENT_ROOT = ".claude/agents/"
_PLUGIN_MANIFEST = ".claude-plugin/plugin.json"
_MARKETPLACE_MANIFEST = ".claude-plugin/marketplace.json"
_PROJECT_MCP_CONFIG = ".mcp.json"

_SKILL_NAMESPACE = "claude-code.skill"
_SUBAGENT_NAMESPACE = "claude-code.subagent"
_PLUGIN_NAMESPACE = "claude-code.repository-plugin"
_MARKETPLACE_NAMESPACE = "claude-code.repository-marketplace"
_SKILL_RULE_NAMESPACE = "claude-code.skill-rule"

_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)
_INLINE_SHELL = re.compile(r"(?:^|(?<=\s))!`([^`\n]+)`", re.MULTILINE)
_FENCED_SHELL = re.compile(r"^```![ \t]*\r?\n(.*?)^```", re.DOTALL | re.MULTILINE)
_TOOL_SPLIT = re.compile(r"[,\s]+(?![^()]*\))")
_MAX_SHELL_LINES = 64


def _split_tools(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()][
            : aa.MAX_ENTRIES
        ]
    if isinstance(value, str):
        return [part for part in _TOOL_SPLIT.split(value.strip()) if part][
            : aa.MAX_ENTRIES
        ]
    return []


def _read_text(path: Path) -> str:
    if path.stat().st_size > aa.MAX_CONFIG_BYTES:
        raise ValueError("the file is larger than the configuration bound")
    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> tuple[dict[str, Any] | None, str, bool]:
    """Return `(fields, body, parsed)`. `fields` is `None` when there is
    no frontmatter; `parsed` is `False` when it exists but does not
    parse, which Claude Code treats as a skill with no fields."""

    match = _FRONTMATTER.match(text)
    if match is None:
        return None, text, True
    body = text[match.end() :]
    try:
        with bounded_recursion(margin=500):
            fields = yaml.safe_load(match.group(1))
    except (yaml.YAMLError, RecursionError):
        return {}, body, False
    if fields is None:
        return {}, body, True
    if not isinstance(fields, dict):
        return {}, body, False
    return fields, body, True


def _shell_commands(body: str) -> list[str]:
    commands = [match.group(1) for match in _INLINE_SHELL.finditer(body)]
    for block in _FENCED_SHELL.finditer(body):
        commands.extend(line for line in block.group(1).splitlines() if line.strip())
    return commands[:_MAX_SHELL_LINES]


@dataclass(slots=True)
class _Discovery:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    skills_by_name: dict[str, str] = field(default_factory=dict)

    def take(self, found: ComponentDiscovery) -> None:
        self.nodes.extend(found.nodes)
        self.edges.extend(found.edges)
        self.diagnostics.extend(found.diagnostics)
        if found.unknown_keys:
            self.diagnostics.append(
                aa.unrecognized_key_diagnostic(
                    host_label=_DISPLAY_NAME,
                    path=found.path,
                    adapter=_NAME,
                    key_paths=found.unknown_keys,
                )
            )


def _grants(
    found: ComponentDiscovery, fields: dict[str, Any], allow_key: str, deny_key: str
) -> None:
    for key, effect, relationship in (
        (allow_key, "allow", EdgeType.PERMITTED_BY),
        (deny_key, "deny", EdgeType.CONSTRAINED_BY),
    ):
        for index, rule in enumerate(_split_tools(fields.get(key))):
            component_key = aa.key_path("frontmatter", key, index)
            try:
                node = permission_rule_node(
                    found,
                    effect=effect,
                    rule=rule,
                    component_key=component_key,
                    namespace=_SKILL_RULE_NAMESPACE,
                )
            except ValueError:
                found.unparsed("a tool grant could not be represented")
                continue
            found.nodes.append(node)
            found.link(node.id, relationship, component_key)


def _skill(
    context: ScanContext,
    relative_path: str,
    *,
    parent_id: str,
    default_name: str,
    out: _Discovery,
) -> str | None:
    """Record one skill or command file; returns its node ID."""

    evidence = aa.evidence_for(_NAME, relative_path)
    try:
        text = _read_text(context.root.path / relative_path)
    except (OSError, UnicodeDecodeError, ValueError):
        out.diagnostics.append(
            aa.unparsed_diagnostic(
                adapter=_NAME, path=relative_path, reason="the file could not be read"
            )
        )
        return None
    fields, body, parsed = _frontmatter(text)
    fields = fields or {}
    if not parsed:
        out.diagnostics.append(
            aa.unparsed_diagnostic(
                adapter=_NAME,
                path=relative_path,
                reason=(
                    "the skill frontmatter is not valid YAML, so the skill loads "
                    "with no fields"
                ),
            )
        )
    name_field = fields.get("name")
    name = (
        name_field
        if isinstance(name_field, str) and name_field.strip()
        else default_name
    )
    attributes: dict[str, str] = {}
    if fields.get("allowed-tools") is not None:
        attributes["allowed_tools"] = aa.authority_text(
            ",".join(_split_tools(fields.get("allowed-tools"))) or "none"
        )
    for key in ("context", "agent", "model", "shell"):
        value = fields.get(key)
        if isinstance(value, str) and value:
            attributes[key] = aa.authority_text(value)
    skill = aa.component_node(
        node_type=NodeType.TOOL,
        subtype="skill",
        namespace=_SKILL_NAMESPACE,
        declaring_path=relative_path,
        component_key="skill",
        name=f"skill {name}",
        attributes=attributes,
        security_attributes=SecurityAttributes(),
        evidence=evidence,
    )
    out.nodes.append(skill)
    out.edges.append(
        aa.edge(
            source=parent_id,
            target=skill.id,
            relationship=EdgeType.INVOKES,
            discriminator=f"{relative_path}#skill",
            evidence=evidence,
        )
    )
    out.skills_by_name.setdefault(name, skill.id)

    found = ComponentDiscovery(relative_path, skill.id, adapter=_NAME)
    _grants(found, fields, "allowed-tools", "disallowed-tools")
    discover_hooks(found, fields.get("hooks"), root_key=("frontmatter", "hooks"))
    for index, command in enumerate(_shell_commands(body)):
        helper_command_node(
            found,
            setting="skill-shell",
            command=aa.command_text(command),
            component_key=aa.key_path("body", "shell", index),
        )
    out.take(found)
    return skill.id


def _subagent(
    context: ScanContext,
    relative_path: str,
    *,
    parent_id: str,
    servers: dict[str, Node],
    in_plugin: bool,
    out: _Discovery,
    pending_skill_links: list[tuple[str, str, str]],
) -> None:
    evidence = aa.evidence_for(_NAME, relative_path)
    try:
        text = _read_text(context.root.path / relative_path)
    except (OSError, UnicodeDecodeError, ValueError):
        out.diagnostics.append(
            aa.unparsed_diagnostic(
                adapter=_NAME, path=relative_path, reason="the file could not be read"
            )
        )
        return
    fields, _body, parsed = _frontmatter(text)
    if fields is None or not parsed:
        out.diagnostics.append(
            aa.unparsed_diagnostic(
                adapter=_NAME,
                path=relative_path,
                reason="the subagent has no readable frontmatter",
            )
        )
        return
    name_field = fields.get("name")
    name = (
        name_field
        if isinstance(name_field, str) and name_field
        else PurePosixPath(relative_path).stem
    )
    attributes: dict[str, str] = {
        "tools": aa.authority_text(
            ",".join(_split_tools(fields.get("tools"))) or "none"
        )
        if fields.get("tools") is not None
        else "inherit"
    }
    ignored = [
        key for key in ("hooks", "mcpServers", "permissionMode") if key in fields
    ]
    mode = fields.get("permissionMode")
    bypass: KnownBoolean | None = None
    if in_plugin:
        if ignored:
            attributes["ignored_in_plugin"] = ",".join(ignored)
    elif isinstance(mode, str):
        attributes["permission_mode"] = aa.authority_text(mode)
        bypass = mode == "bypassPermissions"
    for key in ("model", "isolation", "memory"):
        value = fields.get(key)
        if isinstance(value, str) and value:
            attributes[key] = aa.authority_text(value)
    subagent = aa.component_node(
        node_type=NodeType.AGENT,
        subtype="subagent",
        namespace=_SUBAGENT_NAMESPACE,
        declaring_path=relative_path,
        component_key="subagent",
        name=f"subagent {name}",
        attributes=attributes,
        security_attributes=SecurityAttributes(bypass_mode=bypass),
        evidence=evidence,
    )
    out.nodes.append(subagent)
    out.edges.append(
        aa.edge(
            source=parent_id,
            target=subagent.id,
            relationship=EdgeType.DELEGATES_TO,
            discriminator=f"{relative_path}#subagent",
            evidence=evidence,
        )
    )
    found = ComponentDiscovery(relative_path, subagent.id, adapter=_NAME)
    _grants(found, fields, "tools", "disallowedTools")
    if not in_plugin:
        discover_hooks(found, fields.get("hooks"), root_key=("frontmatter", "hooks"))
        mcp_servers = fields.get("mcpServers")
        entries: list[tuple[str, object]] = []
        if isinstance(mcp_servers, dict):
            entries = [(str(k), v) for k, v in mcp_servers.items()]
        elif isinstance(mcp_servers, list):
            for item in mcp_servers:
                if isinstance(item, str):
                    entries.append((item, None))
                elif isinstance(item, dict):
                    entries.extend((str(k), v) for k, v in item.items())
        for server_name, entry in entries[: aa.MAX_ENTRIES]:
            if isinstance(entry, dict):
                try:
                    server = inline_server_node(
                        context,
                        declaring_path=relative_path,
                        name=server_name,
                        entry=entry,
                        evidence=evidence,
                    )
                except ValueError:
                    found.unparsed("an inline MCP server could not be represented")
                    continue
                found.nodes.append(server)
                found.link(server.id, EdgeType.INVOKES, f"mcpServers.{server_name}")
            elif server_name in servers:
                found.nodes.append(servers[server_name])
                found.link(
                    servers[server_name].id,
                    EdgeType.INVOKES,
                    f"mcpServers.{server_name}",
                )
            else:
                found.diagnostics.append(
                    aa.unresolved_reference_diagnostic(
                        adapter=_NAME,
                        path=relative_path,
                        what=(
                            "An MCP server a subagent names is not declared in "
                            ".mcp.json, so it"
                        ),
                    )
                )
    for skill_name in _split_tools(fields.get("skills")):
        pending_skill_links.append((subagent.id, skill_name, relative_path))
    out.take(found)


def _plugin_root_of(relative: str) -> str | None:
    if relative == _PLUGIN_MANIFEST:
        return ""
    if relative.endswith("/" + _PLUGIN_MANIFEST):
        return relative[: -len(_PLUGIN_MANIFEST)]
    return None


def _under(path: str, root: str) -> bool:
    return path.startswith(root) if root else True


class ClaudeCodeComponentsAdapter:
    """Discovers Claude Code skills, subagents, plugins, and marketplaces
    committed to a repository."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def _paths(self, context: ScanContext) -> list[str]:
        return sorted(file.relative for file in context.repository_files())

    def detect(self, context: ScanContext) -> DetectionResult:
        claimed = [
            path
            for path in self._paths(context)
            if (
                path.endswith("/SKILL.md")
                and any(path.startswith(root) for root in _SKILL_ROOTS)
            )
            or (path.startswith(_COMMAND_ROOT) and path.endswith(".md"))
            or (path.startswith(_AGENT_ROOT) and path.endswith(".md"))
            or _plugin_root_of(path) is not None
            or path.endswith(_MARKETPLACE_MANIFEST)
        ]
        return DetectionResult(adapter=self.name, claimed_paths=tuple(claimed))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        paths = self._paths(context)
        out = _Discovery()
        host_id = host_node_id(HOST)
        servers: dict[str, Node] = {}
        if _PROJECT_MCP_CONFIG in paths:
            servers = {
                node.name: node
                for node in discover_mcp_config(context, _PROJECT_MCP_CONFIG)[0]
            }
        pending_skill_links: list[tuple[str, str, str]] = []
        plugin_roots = sorted(
            (
                root
                for root in (_plugin_root_of(path) for path in paths)
                if root is not None
            ),
            key=len,
            reverse=True,
        )

        def owning_plugin(path: str) -> str | None:
            for root in plugin_roots:
                if root and path.startswith(root):
                    return root
            return None

        plugin_ids: dict[str, str] = {}
        for root in sorted(plugin_roots):
            plugin_id = self._plugin(
                context, root, paths, host_id, servers, out, pending_skill_links
            )
            if plugin_id is not None:
                plugin_ids[root] = plugin_id

        for path in paths:
            if owning_plugin(path) is not None:
                continue
            if path.endswith("/SKILL.md") and any(
                path.startswith(root) for root in _SKILL_ROOTS
            ):
                _skill(
                    context,
                    path,
                    parent_id=host_id,
                    default_name=PurePosixPath(path).parent.name,
                    out=out,
                )
            elif path.startswith(_COMMAND_ROOT) and path.endswith(".md"):
                _skill(
                    context,
                    path,
                    parent_id=host_id,
                    default_name=PurePosixPath(path).stem,
                    out=out,
                )
        for path in paths:
            if (
                owning_plugin(path) is None
                and path.startswith(_AGENT_ROOT)
                and path.endswith(".md")
            ):
                _subagent(
                    context,
                    path,
                    parent_id=host_id,
                    servers=servers,
                    in_plugin=False,
                    out=out,
                    pending_skill_links=pending_skill_links,
                )
        for path in paths:
            if path.endswith(_MARKETPLACE_MANIFEST):
                self._marketplace(context, path, out)

        for subagent_id, skill_name, declaring_path in pending_skill_links:
            target = out.skills_by_name.get(skill_name)
            if target is None:
                continue
            out.edges.append(
                aa.edge(
                    source=subagent_id,
                    target=target,
                    relationship=EdgeType.INVOKES,
                    discriminator=f"{declaring_path}#skills:{skill_name}",
                    evidence=aa.evidence_for(_NAME, declaring_path),
                )
            )

        if any(edge.source == host_id for edge in out.edges):
            evidence = sorted(
                {
                    item
                    for edge in out.edges
                    if edge.source == host_id
                    for item in edge.evidence
                },
                key=lambda item: item.path or "",
            )
            out.nodes.append(
                aa.host_reference_node(
                    host=HOST, display_name=_DISPLAY_NAME, evidence=evidence
                )
            )
        unique: dict[str, Node] = {}
        for node in out.nodes:
            unique.setdefault(node.id, node)
        return DiscoveryResult(
            nodes=tuple(unique.values()),
            edges=tuple(out.edges),
            diagnostics=tuple(out.diagnostics),
        )

    def _plugin(
        self,
        context: ScanContext,
        root: str,
        paths: list[str],
        host_id: str,
        servers: dict[str, Node],
        out: _Discovery,
        pending_skill_links: list[tuple[str, str, str]],
    ) -> str | None:
        manifest_path = root + _PLUGIN_MANIFEST
        try:
            manifest = aa.load_json_object(context.root.path / manifest_path)
        except aa.ConfigLoadError as error:
            out.diagnostics.append(
                aa.unparsed_diagnostic(
                    adapter=_NAME, path=manifest_path, reason=str(error)
                )
            )
            return None
        evidence = aa.evidence_for(_NAME, manifest_path)
        name_field = manifest.get("name")
        name = (
            name_field
            if isinstance(name_field, str) and name_field
            else (PurePosixPath(root).name or "repository")
        )
        plugin = aa.component_node(
            node_type=NodeType.TOOL,
            subtype="plugin",
            namespace=_PLUGIN_NAMESPACE,
            declaring_path=manifest_path,
            component_key="plugin",
            name=f"plugin {name}",
            attributes={
                "source_type": "local",
                "location": aa.authority_text(root.rstrip("/") or "."),
            },
            security_attributes=SecurityAttributes(
                pinned=True, code_execution="unknown"
            ),
            evidence=evidence,
        )
        out.nodes.append(plugin)
        out.edges.append(
            aa.edge(
                source=host_id,
                target=plugin.id,
                relationship=EdgeType.INVOKES,
                discriminator=f"{manifest_path}#plugin",
                evidence=evidence,
            )
        )
        found = ComponentDiscovery(manifest_path, plugin.id, adapter=_NAME)
        if isinstance(manifest.get("hooks"), dict):
            discover_hooks(found, manifest.get("hooks"), root_key=("hooks",))
        for key in ("lspServers", "monitors"):
            value = manifest.get(key)
            entries = (
                value.items()
                if isinstance(value, dict)
                else enumerate(value)
                if isinstance(value, list)
                else []
            )
            for entry_key, entry in entries:
                command = entry.get("command") if isinstance(entry, dict) else None
                if isinstance(command, str) and command.strip():
                    helper_command_node(
                        found,
                        setting=key,
                        command=aa.command_text(command, entry.get("args")),
                        component_key=aa.key_path(key, entry_key),
                    )
        inline_servers = manifest.get("mcpServers")
        if isinstance(inline_servers, dict):
            for server_name, entry in list(inline_servers.items())[: aa.MAX_ENTRIES]:
                if not isinstance(entry, dict):
                    continue
                try:
                    server = inline_server_node(
                        context,
                        declaring_path=manifest_path,
                        name=str(server_name),
                        entry=entry,
                        evidence=evidence,
                    )
                except ValueError:
                    found.unparsed("a plugin MCP server could not be represented")
                    continue
                found.nodes.append(server)
                found.link(server.id, EdgeType.INVOKES, f"mcpServers.{server_name}")
        out.take(found)

        hooks_file = root + "hooks/hooks.json"
        if hooks_file in paths:
            hooks_found = ComponentDiscovery(hooks_file, plugin.id, adapter=_NAME)
            try:
                payload = aa.load_json_object(context.root.path / hooks_file)
                discover_hooks(
                    hooks_found, payload.get("hooks", payload), root_key=("hooks",)
                )
            except aa.ConfigLoadError as error:
                hooks_found.unparsed(str(error))
            out.take(hooks_found)
        mcp_file = root + ".mcp.json"
        if mcp_file in paths and root:
            plugin_servers, plugin_diagnostics = _plugin_mcp(context, mcp_file)
            out.diagnostics.extend(plugin_diagnostics)
            for server in plugin_servers:
                out.nodes.append(server)
                out.edges.append(
                    aa.edge(
                        source=plugin.id,
                        target=server.id,
                        relationship=EdgeType.INVOKES,
                        discriminator=f"{mcp_file}#{server.name}",
                        evidence=aa.evidence_for(_NAME, mcp_file),
                    )
                )
        if any(path.startswith(root + "bin/") for path in paths):
            bin_found = ComponentDiscovery(manifest_path, plugin.id, adapter=_NAME)
            helper_command_node(
                bin_found,
                setting="plugin-bin",
                command=aa.authority_text((root + "bin/").lstrip("/")),
                component_key="bin",
            )
            out.take(bin_found)
        for path in paths:
            if not path.startswith(root) or path == manifest_path:
                continue
            relative = path[len(root) :]
            if relative.startswith("skills/") and relative.endswith("/SKILL.md"):
                _skill(
                    context,
                    path,
                    parent_id=plugin.id,
                    default_name=PurePosixPath(path).parent.name,
                    out=out,
                )
            elif relative.startswith("commands/") and relative.endswith(".md"):
                _skill(
                    context,
                    path,
                    parent_id=plugin.id,
                    default_name=PurePosixPath(path).stem,
                    out=out,
                )
            elif relative.startswith("agents/") and relative.endswith(".md"):
                _subagent(
                    context,
                    path,
                    parent_id=plugin.id,
                    servers=servers,
                    in_plugin=True,
                    out=out,
                    pending_skill_links=pending_skill_links,
                )
        return plugin.id

    def _marketplace(
        self, context: ScanContext, manifest_path: str, out: _Discovery
    ) -> None:
        try:
            manifest = aa.load_json_object(context.root.path / manifest_path)
        except aa.ConfigLoadError as error:
            out.diagnostics.append(
                aa.unparsed_diagnostic(
                    adapter=_NAME, path=manifest_path, reason=str(error)
                )
            )
            return
        evidence = aa.evidence_for(_NAME, manifest_path)
        name_field = manifest.get("name")
        name = (
            name_field if isinstance(name_field, str) and name_field else "repository"
        )
        marketplace = aa.component_node(
            node_type=NodeType.TOOL,
            subtype="marketplace",
            namespace=_MARKETPLACE_NAMESPACE,
            declaring_path=manifest_path,
            component_key="marketplace",
            name=f"marketplace {name}",
            attributes={"source_type": "local"},
            security_attributes=SecurityAttributes(pinned=True),
            evidence=evidence,
        )
        out.nodes.append(marketplace)
        plugins = manifest.get("plugins")
        if not isinstance(plugins, list):
            if plugins is not None:
                out.diagnostics.append(
                    aa.unparsed_diagnostic(
                        adapter=_NAME,
                        path=manifest_path,
                        reason="plugins is not a list",
                    )
                )
            return
        found = ComponentDiscovery(manifest_path, marketplace.id, adapter=_NAME)
        for index, entry in enumerate(found.bounded(plugins, "marketplace plugins")):
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                found.unparsed("a marketplace plugin entry has no name")
                continue
            source = entry.get("source")
            if isinstance(source, str):
                source = {"source": "directory", "path": source}
            if not isinstance(source, dict):
                found.unparsed("a marketplace plugin entry has no source")
                continue
            source_type, pinned = source_pin(source)
            attributes = {"source_type": aa.authority_text(source_type)}
            for key in ("repo", "url", "path", "package"):
                value = source.get(key)
                if isinstance(value, str) and value:
                    attributes["location"] = (
                        aa.repository_path_text(value)
                        if key == "path"
                        else aa.authority_text(value)
                    )
                    break
            code_execution: KnownBoolean = (
                True if source_type == "command" else "unknown"
            )
            if source_type == "command":
                attributes["command"] = aa.command_text(
                    source.get("command"), source.get("args")
                )
            plugin = aa.component_node(
                node_type=NodeType.TOOL,
                subtype="plugin",
                namespace=_PLUGIN_NAMESPACE,
                declaring_path=manifest_path,
                component_key=aa.key_path("plugins", index),
                name=f"plugin {entry['name']}@{name}",
                attributes=attributes,
                security_attributes=SecurityAttributes(
                    pinned=pinned, code_execution=code_execution
                ),
                evidence=evidence,
            )
            found.nodes.append(plugin)
            found.link(
                marketplace.id,
                EdgeType.RECEIVES_FROM,
                aa.key_path("plugins", index),
                source=plugin.id,
            )
        out.take(found)


def _plugin_mcp(
    context: ScanContext, relative_path: str
) -> tuple[list[Node], list[Diagnostic]]:
    """A plugin's own `.mcp.json`, read with the MCP adapter's Claude
    Code dialect but declared by this file."""

    try:
        payload = aa.load_json_object(context.root.path / relative_path)
    except aa.ConfigLoadError as error:
        return [], [
            aa.unparsed_diagnostic(adapter=_NAME, path=relative_path, reason=str(error))
        ]
    servers = payload.get("mcpServers", payload)
    nodes: list[Node] = []
    diagnostics: list[Diagnostic] = []
    evidence = aa.evidence_for(_NAME, relative_path)
    if not isinstance(servers, dict):
        return [], [
            aa.unparsed_diagnostic(
                adapter=_NAME, path=relative_path, reason="no mcpServers object"
            )
        ]
    for server_name, entry in list(servers.items())[: aa.MAX_ENTRIES]:
        if not isinstance(entry, dict):
            continue
        try:
            nodes.append(
                inline_server_node(
                    context,
                    declaring_path=relative_path,
                    name=str(server_name),
                    entry=entry,
                    evidence=evidence,
                )
            )
        except ValueError:
            diagnostics.append(
                aa.unparsed_diagnostic(
                    adapter=_NAME,
                    path=relative_path,
                    reason="a server could not be represented",
                )
            )
    return nodes, diagnostics
