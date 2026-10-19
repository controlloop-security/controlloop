"""MCP server discovery.

Discovers MCP server declarations committed to a repository in the
configuration files of the agent hosts that read them, without launching
or connecting to any of them (this module never imports `subprocess` or
`socket`, and runs inside `adapter_sandbox`, which denies both). Only the
declared environment-variable and header *names* a server references are
ever captured -- the parsing code below never binds a variable to a value.

Each server also records what makes its identity visible across a change:
its command, redacted arguments, the package and version its launcher
names, the remote host, and a digest of the whole redacted declaration.
A server that keeps its name while any of those change keeps its node ID
and shows in a diff as changed. Per-tool auto-approval (Kiro
`autoApprove`, Roo and Cline `alwaysAllow`, Gemini CLI `trust`) becomes
granted permission.

Each declaring host other than Claude Code becomes an agent host node
here. Claude Code's project file, `.mcp.json`, is the one exception: the
Claude Code settings adapter owns that host, because its approval keys
decide which `.mcp.json` servers it connects to, and one owner per host
is what keeps two adapters from emitting two different copies of it.

MCP tool/resource normalization (calling a live server) is out of scope
-- that is `controlloop.adapters.mcp_live`.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
    host_node_id,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import NodeIdentityMaterial, SemanticIdentity, node_id
from controlloop.adapters import agent_authority as aa
from controlloop.adapters.framework import DetectionResult, DiscoveryResult, ScanContext
from controlloop.bounded_recursion import bounded_recursion

_NAME = "mcp"
_SUPPORTED_VERSIONS: tuple[str, ...] = ("2025-06-18",)
_NAMESPACE = "mcp.server"
_TOOL_APPROVAL_NAMESPACE = "mcp.tool-approval"

#: The date the per-host declaration formats below were read from each
#: vendor's documentation.
DOCUMENTATION_SNAPSHOT = "2026-10-17"

#: The host that owns `.mcp.json`; its host node comes from
#: `controlloop.adapters.claude_code`.
CLAUDE_CODE_HOST = "claude-code"

#: Hosts whose host node another adapter owns: this adapter
#: connects their servers through a host reference instead.
_HOSTS_OWNED_ELSEWHERE = frozenset({"codex", "gemini-cli", "cursor", "kiro"})


@dataclass(frozen=True, slots=True)
class _Location:
    host: str
    display_name: str
    dialect: str


#: Fixed locations, repository-relative.
_LOCATIONS: dict[str, _Location] = {
    ".mcp.json": _Location(CLAUDE_CODE_HOST, "Claude Code", "mcpServers"),
    ".vscode/mcp.json": _Location("vscode", "VS Code", "vscode"),
    ".cursor/mcp.json": _Location("cursor", "Cursor", "mcpServers"),
    ".gemini/settings.json": _Location("gemini-cli", "Gemini CLI", "gemini"),
    ".kiro/settings/mcp.json": _Location("kiro", "Kiro", "mcpServers"),
    ".roo/mcp.json": _Location("roo", "Roo Code", "mcpServers"),
    ".continue/config.json": _Location("continue", "Continue", "continue-json"),
    ".continue/config.yaml": _Location("continue", "Continue", "continue-yaml"),
    ".windsurf/mcp.json": _Location("windsurf", "Windsurf", "mcpServers"),
    "opencode.json": _Location("opencode", "opencode", "opencode"),
    ".codex/config.toml": _Location("codex", "Codex", "codex"),
}
#: Matched by file name anywhere in the repository: Cline keeps this file
#: in editor storage, and a repository that commits it may put it anywhere.
_CLINE_FILENAME = "cline_mcp_settings.json"
#: Dialects whose file is a host's general settings, where the server
#: section is optional. A dedicated MCP file with no server section is
#: still reported as unparsed.
_GENERAL_SETTINGS_DIALECTS = frozenset({"gemini", "codex", "opencode"})
_CLINE_LOCATION = _Location("cline", "Cline", "mcpServers")

#: Launchers whose first package argument names an npm or PyPI package.
_NPM_LAUNCHERS = frozenset({"npx", "bunx"})
_NPM_SUBCOMMAND_LAUNCHERS = frozenset({"pnpm", "yarn"})
_PYPI_LAUNCHERS = frozenset({"uvx"})
_CONTAINER_LAUNCHERS = frozenset({"docker", "podman"})
#: Launcher flags that take a value, so the value is not the package.
_FLAGS_WITH_VALUES = frozenset(
    {
        "-p", "--package", "--from", "--with", "--python", "--index-url",
        "-e", "--env", "--env-file", "-v", "--volume", "--name", "--network",
        "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform",
        "--mount", "-l", "--label", "--cidfile", "--registry",
    }
)  # fmt: skip
_KEY_VALUE_ARG = re.compile(r"^(-{0,2}[A-Za-z_][A-Za-z0-9_.-]*=)(?!\$\{)(.+)$")

#: Tool manifests read, when committed beside a local server.
_TOOL_MANIFESTS = ("manifest.json", "server.json", "tools.json")


@dataclass(slots=True)
class _Server:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    env_names: list[str] = field(default_factory=list)
    header_names: list[str] = field(default_factory=list)
    auto_approve: list[str] = field(default_factory=list)
    trust: bool | None = None
    disabled: bool = False


def _location_for(relative: str) -> _Location | None:
    if relative in _LOCATIONS:
        return _LOCATIONS[relative]
    if relative.rsplit("/", 1)[-1] == _CLINE_FILENAME:
        return _CLINE_LOCATION
    return None


def _claimed_paths(context: ScanContext) -> tuple[str, ...]:
    found = set()
    for file in context.repository_files():
        if _location_for(file.relative) is not None:
            found.add(file.relative)
    return tuple(sorted(found))


def _malformed_diagnostic(evidence: tuple[Evidence, ...], reason: str) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=f"MCP server configuration could not be parsed: {reason}.",
        evidence=evidence,
    )


def _names(value: object) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value)
    return []


def _strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [
            str(item)
            for item in value[: aa.MAX_ENTRIES]
            if isinstance(item, (str, int, float))
        ]
    return []


def _server_from_entry(name: str, entry: dict[str, Any], dialect: str) -> _Server:
    """Normalize one server entry from any supported host's dialect."""

    server = _Server(name=name)
    command = entry.get("command")
    if dialect == "opencode":
        # opencode: {"type": "local", "command": ["npx", "pkg"]} or
        # {"type": "remote", "url": ...}; env under "environment".
        if isinstance(command, list) and command:
            server.command = str(command[0])
            server.args = _strings(command[1:])
        server.env_names = _names(entry.get("environment"))
        server.disabled = entry.get("enabled") is False
    else:
        if isinstance(command, str) and command:
            server.command = command
        server.args = _strings(entry.get("args"))
        server.env_names = _names(entry.get("env"))
        server.disabled = entry.get("disabled") is True or entry.get("enabled") is False
    for key in ("url", "httpUrl", "serverUrl"):
        url = entry.get(key)
        if isinstance(url, str) and url:
            server.url = url
            break
    headers = entry.get("headers") if "headers" in entry else entry.get("http_headers")
    server.header_names = _names(headers)
    if dialect == "codex":
        bearer = entry.get("bearer_token_env_var")
        if isinstance(bearer, str) and bearer:
            server.env_names = sorted({*server.env_names, bearer})
    server.auto_approve = _strings(entry.get("autoApprove") or entry.get("alwaysAllow"))
    trust = entry.get("trust")
    if isinstance(trust, bool):
        server.trust = trust
    return server


def _servers_in(
    payload: Any, dialect: str
) -> tuple[list[tuple[str, dict[str, Any]]] | None, str | None]:
    """Return `(entries, None)` or `(None, reason)` for a loaded file."""

    if dialect == "continue-yaml" or (
        dialect == "continue-json" and isinstance(payload, dict)
    ):
        container = payload.get("mcpServers") if isinstance(payload, dict) else None
        entries: list[tuple[str, dict[str, Any]]] = []
        if isinstance(container, dict):
            entries = [(str(k), v) for k, v in container.items()]
        elif isinstance(container, list):
            for item in container:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    entries.append((item["name"], item))
                else:
                    entries.append(("", item))
        experimental = (
            payload.get("experimental") if isinstance(payload, dict) else None
        )
        legacy = (
            experimental.get("modelContextProtocolServers")
            if isinstance(experimental, dict)
            else None
        )
        if isinstance(legacy, list):
            for index, item in enumerate(legacy):
                transport = item.get("transport") if isinstance(item, dict) else None
                entries.append(
                    (
                        f"server-{index}",
                        transport if isinstance(transport, dict) else item,
                    )
                )
        if container is None and legacy is None:
            # Continue's config.json holds every setting; no server
            # section means no servers, not an unparsed file.
            return [], None
        return entries, None
    if not isinstance(payload, dict):
        return None, "the file's top level is not a JSON object"
    key = {"vscode": "servers", "opencode": "mcp", "codex": "mcp_servers"}.get(
        dialect, "mcpServers"
    )
    servers = payload.get(key)
    if servers is None and dialect == "vscode":
        servers = payload.get("mcpServers")
    if servers is None and dialect in _GENERAL_SETTINGS_DIALECTS:
        # A host's general settings file with no server section declares
        # no servers. Found by the benign agent-authority corpus: a
        # plain `.codex/config.toml` or `.gemini/settings.json` was
        # reported as incomplete.
        return [], None
    if not isinstance(servers, dict):
        return None, "no mcpServers object was found"
    return [(str(name), entry) for name, entry in servers.items()], None


def _load(path: Path, dialect: str) -> Any:
    if path.stat().st_size > aa.MAX_CONFIG_BYTES:
        raise ValueError("the file is larger than the configuration bound")
    text = path.read_text(encoding="utf-8")
    with bounded_recursion(margin=500):
        if dialect == "codex":
            return tomllib.loads(text)
        if dialect == "continue-yaml":
            return yaml.safe_load(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if dialect in {"vscode", "gemini", "opencode"}:
                # These hosts accept JSON with comments.
                return json.loads(aa._strip_jsonc(text))
            raise


def _redacted_args(args: list[str]) -> list[str]:
    redacted: list[str] = []
    for arg in args:
        match = _KEY_VALUE_ARG.match(arg)
        redacted.append(
            f"{match.group(1)}{aa.REDACTED_VALUE}" if match else aa.authority_text(arg)
        )
    return redacted


def _first_positional(args: list[str]) -> str | None:
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in _FLAGS_WITH_VALUES:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _package_identity(
    command: str | None, args: list[str]
) -> tuple[str, str, str] | None:
    """Return `(registry, package, version)` when the launcher names one."""

    if command is None:
        return None
    launcher = command.rsplit("/", 1)[-1]
    rest = args
    if launcher in _NPM_SUBCOMMAND_LAUNCHERS and args[:1] == ["dlx"]:
        launcher, rest = "npx", args[1:]
    elif launcher == "pipx" and args[:1] == ["run"]:
        launcher, rest = "uvx", args[1:]
    elif launcher in _CONTAINER_LAUNCHERS and args[:1] == ["run"]:
        image = _first_positional(args[1:])
        if image is None:
            return None
        if "@sha256:" in image:
            name, digest = image.split("@", 1)
            return "oci", name, digest
        last = image.rsplit("/", 1)[-1]
        if ":" in last:
            name, tag = image.rsplit(":", 1)
            return "oci", name, tag
        return "oci", image, "unpinned"
    if launcher in _NPM_LAUNCHERS:
        spec = _first_positional(rest)
        if spec is None:
            return None
        scope, _, remainder = (
            spec.partition("/") if spec.startswith("@") else ("", "", spec)
        )
        name_part, at, version = remainder.partition("@")
        name = f"{scope}/{name_part}" if scope else name_part
        return "npm", name, version if at and version else "unpinned"
    if launcher in _PYPI_LAUNCHERS:
        spec = _first_positional(rest)
        if spec is None:
            return None
        for separator in ("==", "@"):
            if separator in spec:
                name, version = spec.split(separator, 1)
                return "pypi", name, version
        return "pypi", spec, "unpinned"
    return None


def _tools_digest(context: ScanContext, server: _Server) -> str:
    """Digest of tool names and descriptions from a committed manifest
    beside a repository-local server, or `unknown`."""

    root = context.root.path.resolve()
    candidates: list[Path] = []
    for value in ([server.command] if server.command else []) + server.args:
        if value.startswith(("-", "/", "~")) or "://" in value or "/" not in value:
            continue
        target = (root / value).resolve()
        if not target.is_relative_to(root):
            continue
        candidates.append(target if target.is_dir() else target.parent)
    for directory in candidates:
        for filename in _TOOL_MANIFESTS:
            manifest = directory / filename
            if not manifest.is_file():
                continue
            try:
                payload = aa.load_json_object(manifest)
            except aa.ConfigLoadError:
                continue
            tools = payload.get("tools")
            if not isinstance(tools, list) or not tools:
                continue
            pairs = sorted(
                (str(tool.get("name", "")), str(tool.get("description", "")))
                for tool in tools[: aa.MAX_ENTRIES]
                if isinstance(tool, dict)
            )
            encoded = json.dumps(pairs, ensure_ascii=False, separators=(",", ":"))
            return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return "unknown"


def _attributes(context: ScanContext, server: _Server) -> dict[str, str]:
    args = _redacted_args(server.args)
    attributes: dict[str, str] = {
        "transport": "stdio" if server.command else "http",
        "declaration_digest": "",
        "tools_digest": _tools_digest(context, server),
    }
    if server.command:
        attributes["command"] = aa.authority_text(server.command)
        if args:
            attributes["args"] = aa.authority_text(" ".join(args))
        package = _package_identity(server.command, server.args)
        if package is not None:
            registry, name, version = package
            attributes["package_registry"] = registry
            attributes["package"] = aa.authority_text(name) if name else "unknown"
            attributes["package_version"] = aa.authority_text(version)
    if server.url:
        attributes["url_host"] = aa.url_host(server.url)
    if server.env_names:
        attributes["env_names"] = aa.authority_text(",".join(server.env_names))
    if server.header_names:
        attributes["header_names"] = aa.authority_text(",".join(server.header_names))
    if server.disabled:
        attributes["disabled"] = "true"
    canonical = {
        "command": server.command and aa.authority_text(server.command),
        "args": args,
        "url": server.url and aa.authority_text(server.url),
        "env_names": server.env_names,
        "header_names": server.header_names,
    }
    encoded = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    attributes["declaration_digest"] = (
        "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    )
    return attributes


def _build_node(
    context: ScanContext,
    relative_path: str,
    server: _Server,
    evidence: tuple[Evidence, ...],
) -> Node:
    """Raises `ValueError` (pydantic's `ValidationError` is a subclass)
    for any entry that cannot become a valid node -- missing transport,
    or any field failing canonical validation. The caller converts this
    into a diagnostic rather than letting hostile repository content
    crash discovery."""

    if server.command:
        subtype = "mcp-server-stdio"
        code_execution: bool | None = True
        external_communication: bool | None = None
    elif server.url:
        subtype = "mcp-server-http"
        code_execution = None
        external_communication = True
    else:
        raise ValueError("neither a command nor a url is declared")
    if not server.name:
        raise ValueError("the server has no name")

    identity_material = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path,
            in_document_key=server.name,
        ),
    )
    return Node(
        id=node_id(identity_material),
        type=NodeType.TOOL,
        subtype=subtype,
        name=server.name,
        attributes=_attributes(context, server),
        security_attributes=SecurityAttributes(
            code_execution=code_execution,
            external_communication=external_communication,
            permission_scopes=tuple(f"env:{key}" for key in server.env_names),
        ),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


@dataclass(slots=True)
class McpFileResult:
    """One configuration file's servers and what accompanies them."""

    nodes: list[Node] = field(default_factory=list)
    servers: list[_Server] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    input_ids: list[str] = field(default_factory=list)


def _read_file(context: ScanContext, relative_path: str) -> McpFileResult:
    location = _location_for(relative_path)
    assert location is not None
    evidence = (Evidence(adapter=_NAME, path=relative_path),)
    result = McpFileResult()
    try:
        payload = _load(context.root.path / relative_path, location.dialect)
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
        RecursionError,
        yaml.YAMLError,
        tomllib.TOMLDecodeError,
    ):
        result.diagnostics.append(
            _malformed_diagnostic(evidence, "the file could not be read as UTF-8 JSON")
            if location.dialect not in {"codex", "continue-yaml"}
            else _malformed_diagnostic(evidence, "the file could not be read")
        )
        return result

    entries, reason = _servers_in(payload, location.dialect)
    if entries is None:
        result.diagnostics.append(_malformed_diagnostic(evidence, reason or "unknown"))
        return result
    if location.dialect == "vscode" and isinstance(payload, dict):
        inputs = payload.get("inputs")
        if isinstance(inputs, list):
            result.input_ids = sorted(
                str(item["id"])
                for item in inputs
                if isinstance(item, dict) and "id" in item
            )
    if len(entries) > aa.MAX_ENTRIES:
        result.diagnostics.append(
            aa.bound_exceeded_diagnostic(
                adapter=_NAME, path=relative_path, what="servers"
            )
        )
        entries = entries[: aa.MAX_ENTRIES]
    for server_name, entry in entries:
        if not isinstance(entry, dict):
            result.diagnostics.append(
                _malformed_diagnostic(evidence, "a server entry is not a JSON object")
            )
            continue
        server = _server_from_entry(server_name, entry, location.dialect)
        try:
            result.nodes.append(_build_node(context, relative_path, server, evidence))
            result.servers.append(server)
        except ValueError:
            result.diagnostics.append(
                _malformed_diagnostic(
                    evidence, "a server entry could not be represented"
                )
            )
    return result


def discover_mcp_config(
    context: ScanContext, relative_path: str
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    """Return the server nodes and diagnostics for one MCP configuration
    file, exactly as `McpServerAdapter` emits them.

    Exposed for host adapters that reference servers by name (Claude
    Code's `enabledMcpjsonServers` and related keys). They
    emit the identical node so the runner merges it with this adapter's
    copy, and an edge to it never dangles even if this adapter fails.
    """

    result = _read_file(context, relative_path)
    return tuple(result.nodes), tuple(result.diagnostics)


def tool_approval_node(
    *,
    adapter: str,
    declaring_path: str,
    server: Node,
    tool: str,
    source_key: str,
    evidence: tuple[Evidence, ...],
) -> tuple[Node, Edge]:
    """A per-tool approval: a permission rule allowing `tool` on
    `server` without a prompt, and the `permitted-by` edge from the
    server to it. `tool == "*"` is a wildcard over every tool."""

    wildcard = tool == "*"
    node = aa.component_node(
        node_type=NodeType.PERMISSION,
        subtype="permission-rule",
        namespace=_TOOL_APPROVAL_NAMESPACE,
        declaring_path=declaring_path,
        component_key=f"{source_key}:{server.name}:{tool}",
        name=f"auto-approve {server.name}/{tool}",
        attributes={
            "effect": "allow",
            "pattern": aa.authority_text(f"{server.name}/{tool}"),
            "tool": aa.authority_text(tool),
            "server": aa.authority_text(server.name),
            "source": aa.authority_text(source_key),
        },
        security_attributes=SecurityAttributes(
            wildcard=wildcard, approval_present=True, requires_approval=False
        ),
        evidence=evidence,
    )
    edge = aa.edge(
        source=server.id,
        target=node.id,
        relationship=EdgeType.PERMITTED_BY,
        discriminator=f"{declaring_path}#{source_key}:{server.name}:{tool}",
        evidence=evidence,
        security_attributes=SecurityAttributes(
            approval_present=True, requires_approval=False
        ),
    )
    return node, edge


class McpServerAdapter:
    """Discovers MCP server declarations in the committed configuration
    of the agent hosts that read them."""

    name = _NAME
    supported_versions: tuple[str, ...] = _SUPPORTED_VERSIONS

    def detect(self, context: ScanContext) -> DetectionResult:
        return DetectionResult(adapter=self.name, claimed_paths=_claimed_paths(context))

    def discover(self, context: ScanContext) -> DiscoveryResult:
        nodes: list[Node] = []
        edges: list[Edge] = []
        diagnostics: list[Diagnostic] = []
        hosts: dict[str, tuple[_Location, list[Evidence], list[str]]] = {}
        for relative_path in _claimed_paths(context):
            location = _location_for(relative_path)
            assert location is not None
            result = _read_file(context, relative_path)
            nodes.extend(result.nodes)
            diagnostics.extend(result.diagnostics)
            evidence = (Evidence(adapter=_NAME, path=relative_path),)
            for server_node, server in zip(result.nodes, result.servers, strict=True):
                approvals = list(server.auto_approve)
                if server.trust is True:
                    approvals.append("*")
                for tool in sorted(set(approvals)):
                    approval, approval_edge = tool_approval_node(
                        adapter=_NAME,
                        declaring_path=relative_path,
                        server=server_node,
                        tool=tool,
                        source_key="trust"
                        if tool == "*" and server.trust
                        else "autoApprove",
                        evidence=evidence,
                    )
                    nodes.append(approval)
                    edges.append(approval_edge)
            if location.host == CLAUDE_CODE_HOST or (
                not result.nodes and not result.input_ids
            ):
                continue
            entry = hosts.setdefault(location.host, (location, [], []))
            entry[1].append(evidence[0])
            entry[2].extend(result.input_ids)
            host_id = host_node_id(location.host)
            for server_node, server in zip(result.nodes, result.servers, strict=True):
                if server.disabled:
                    continue
                edges.append(
                    aa.edge(
                        source=host_id,
                        target=server_node.id,
                        relationship=EdgeType.INVOKES,
                        discriminator=f"{relative_path}#mcp-server:{server.name}",
                        evidence=evidence,
                        security_attributes=SecurityAttributes(
                            approval_present=True if server.trust else None,
                            requires_approval=False if server.trust else "unknown",
                        ),
                    )
                )
        for host, (location, host_evidence, input_ids) in sorted(hosts.items()):
            attributes = {"docs_snapshot": DOCUMENTATION_SNAPSHOT}
            if input_ids:
                attributes["input_ids"] = aa.authority_text(
                    ",".join(sorted(set(input_ids)))
                )
            if host in _HOSTS_OWNED_ELSEWHERE:
                nodes.append(
                    aa.host_reference_node(
                        host=host,
                        display_name=location.display_name,
                        evidence=host_evidence,
                    )
                )
                continue
            nodes.append(
                aa.host_node(
                    host=host,
                    display_name=location.display_name,
                    evidence=host_evidence,
                    attributes=attributes,
                    bypass_mode=None,
                )
            )
        return DiscoveryResult(
            nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
        )


def inline_server_node(
    context: ScanContext,
    *,
    declaring_path: str,
    name: str,
    entry: dict[str, Any],
    evidence: tuple[Evidence, ...],
) -> Node:
    """Build a server node for a declaration embedded in another file
    (a subagent's or a plugin manifest's `mcpServers`), with exactly the
    fields `McpServerAdapter` records. Raises `ValueError` when the entry
    cannot be represented."""

    return _build_node(
        context,
        declaring_path,
        _server_from_entry(name, entry, "mcpServers"),
        evidence,
    )
