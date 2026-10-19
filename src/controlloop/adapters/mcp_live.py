"""MCP live tool and resource normalization.

**Disclosed risk escalation, read before calling this module.** Every
other adapter in this codebase, including this same MCP integration's
own static half (`controlloop.adapters.mcp`), never starts a process
and never makes a network call -- `mcp.py`'s own module docstring says
so, and a structural test enforces it. This module is the one
deliberate exception: normalizing a live MCP server's actual tool list
is impossible without starting that server. It is therefore:

- **Not part of `DiscoveryAdapter`.** `normalize_live_mcp_server` is a
  standalone function, never invoked by `run_adapters`, and never runs
  inside the shared `adapter_sandbox()` -- carving a subprocess
  exception into that shared primitive would quietly weaken the
  guarantee every other adapter relies on. No CLI command calls this
  function yet; wiring one in is a separate, future, explicit decision.
- **Bounded on its own terms**: the exact declared `command`/`args`
  only (`shell=False`, no string interpolation), a wall-clock timeout
  for the whole exchange, a cap on total bytes read from the
  subprocess, and the process is always terminated afterward.
- **A real, disclosed risk, not "core scanning is side-effect free."**
  This executes third-party-declared code with whatever environment
  the caller supplies -- which may need to include real credential
  values for the server to even start. There is no way to list a live
  server's real tools without running it. Callers decide what
  environment to expose; this module never reads `os.environ` itself.

No `mcp` SDK dependency: the official Python SDK pulls in ~30
transitive packages (a bundled HTTP/SSE server, `starlette`,
`uvicorn`, `cryptography`, `opentelemetry-api`) to support a client
that only needs three JSON-RPC request types over stdio -- MCP's stdio
wire format (JSON-RPC 2.0, one message per line, no embedded newlines,
no Content-Length framing) is simple and stable enough to implement
directly.

Only stdio-transport servers are supported. An HTTP/SSE-transport
server is a genuine network call to a URL, a materially larger and
different risk than a local subprocess with no network egress of its
own, and is out of scope here.

Authorization metadata: MCP's base `initialize`/`tools/list` response
has no standard field for it on a local stdio server (unlike
HTTP-transport MCP's OAuth discovery, itself out of scope). What is
real: the declared environment variable *names* a server references
(never their values -- the same names the static adapter already
captures). This module turns each into an `identity` node (the
credential reference exists) and a `permission` node
(`confidence=Confidence.LOW`: an identity is confirmed, but what it is
actually permitted to do is not), connected by
`authenticates-as`/`permitted-by` edges.

Tool names flow only through `DisplayName`-constrained canonical
fields, which already reject control characters and bound length. Tool
*descriptions* have no free-text home in the canonical `Node` model at
all (evidence is deliberately value-free throughout this codebase);
rather than invent one, a description is validated (must be a string)
but never stored verbatim anywhere.

A tool with a missing or non-object `inputSchema` produces an
`INCOMPLETE-UNPARSED-REGION` diagnostic naming it and is not
represented as a node -- an unsubstantiated claim about its shape is
never asserted as one.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import subprocess
import time
from collections.abc import Mapping, Sequence
from typing import Any

from controlloop.acbom import (
    Confidence,
    Diagnostic,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.acbom.completeness import incomplete_diagnostic
from controlloop.acbom.identity import (
    EdgeIdentityMaterial,
    NodeIdentityMaterial,
    SemanticIdentity,
    edge_id,
    node_id,
)
from controlloop.adapters.framework import DiscoveryResult

_NAME = "mcp-live"
# Matches controlloop.adapters.mcp's own `_NAMESPACE`/identity scheme
# for the server-level node exactly, so a live and a static discovery
# of the same server (same relative_path, same server_name) resolve to
# the same node ID and merge via merge_duplicate_nodes, rather than
# producing two disconnected near-duplicates.
_SERVER_NAMESPACE = "mcp.server"
_LIVE_NAMESPACE = "mcp.server.live"
_PROTOCOL_VERSION = "2025-06-18"
_CLIENT_VERSION = "0.1.0"
_INITIALIZE_ID = 1
_TOOLS_LIST_ID = 2
_RESOURCES_LIST_ID = 3
_DEFAULT_TIMEOUT_SECONDS = 5.0
_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_READ_CHUNK_SIZE = 65536
_TERMINATE_GRACE_SECONDS = 2.0


class _LiveMcpError(Exception):
    """The live exchange could not complete. Always caught inside this
    module and converted into a diagnostic with a fixed, generic
    message -- the message text is authored here, never built from
    subprocess output or an underlying exception's own text, so it can
    never leak anything the server said."""


class _LineReader:
    """Reads newline-delimited messages from a pipe with an overall
    deadline and a total-bytes bound, bypassing Python's own buffered
    wrapper via `os.read` on the raw file descriptor so a byte cap can
    be enforced exactly."""

    def __init__(self, fileno: int, max_bytes: int) -> None:
        self._fileno = fileno
        self._max_bytes = max_bytes
        self._buffer = bytearray()
        self._total_read = 0

    def read_line(self, deadline: float) -> bytes:
        while True:
            newline_index = self._buffer.find(b"\n")
            if newline_index != -1:
                line = bytes(self._buffer[:newline_index])
                del self._buffer[: newline_index + 1]
                return line

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _LiveMcpError("timed out waiting for a response")
            ready, _, _ = select.select([self._fileno], [], [], remaining)
            if not ready:
                raise _LiveMcpError("timed out waiting for a response")

            chunk = os.read(self._fileno, _READ_CHUNK_SIZE)
            if not chunk:
                raise _LiveMcpError("the server closed its output unexpectedly")
            self._total_read += len(chunk)
            if self._total_read > self._max_bytes:
                raise _LiveMcpError("the server's output exceeded the size bound")
            self._buffer.extend(chunk)


def _send(process: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    try:
        process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        process.stdin.flush()
    except (BrokenPipeError, OSError) as error:
        raise _LiveMcpError("the server closed its input unexpectedly") from error


def _receive(reader: _LineReader, deadline: float, expected_id: int) -> dict[str, Any]:
    line = reader.read_line(deadline)
    try:
        message = json.loads(line)
    except json.JSONDecodeError as error:
        raise _LiveMcpError(
            "the server sent a response that was not valid JSON"
        ) from error
    if not isinstance(message, dict) or message.get("id") != expected_id:
        raise _LiveMcpError("the server sent an unexpected response")
    if "error" in message:
        raise _LiveMcpError("the server returned a JSON-RPC error")
    result = message.get("result")
    return result if isinstance(result, dict) else {}


def _exchange(
    process: subprocess.Popen[bytes], reader: _LineReader, deadline: float
) -> tuple[dict[str, Any], dict[str, Any]]:
    _send(
        process,
        {
            "jsonrpc": "2.0",
            "id": _INITIALIZE_ID,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "controlloop", "version": _CLIENT_VERSION},
            },
        },
    )
    _receive(reader, deadline, _INITIALIZE_ID)

    _send(
        process,
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )

    _send(
        process,
        {"jsonrpc": "2.0", "id": _TOOLS_LIST_ID, "method": "tools/list", "params": {}},
    )
    tools_result = _receive(reader, deadline, _TOOLS_LIST_ID)

    _send(
        process,
        {
            "jsonrpc": "2.0",
            "id": _RESOURCES_LIST_ID,
            "method": "resources/list",
            "params": {},
        },
    )
    resources_result = _receive(reader, deadline, _RESOURCES_LIST_ID)

    return tools_result, resources_result


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=_TERMINATE_GRACE_SECONDS)


def _live_failure_diagnostic(
    evidence: tuple[Evidence, ...], server_name: str, reason: str
) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-ADAPTER-FAILURE",
        message=f"live MCP normalization of {server_name!r} failed: {reason}.",
        evidence=evidence,
    )


def _malformed_tool_diagnostic(
    evidence: tuple[Evidence, ...], server_name: str, tool_name: str
) -> Diagnostic:
    return incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message=(
            f"a tool declared by {server_name!r} could not be represented: "
            f"{tool_name!r} has no usable input schema."
        ),
        evidence=evidence,
    )


def _server_node(
    server_name: str, relative_path: str, evidence: tuple[Evidence, ...]
) -> Node:
    identity_material = NodeIdentityMaterial(
        node_type=NodeType.TOOL,
        namespace=_SERVER_NAMESPACE,
        semantic_identity=SemanticIdentity(
            source_path=relative_path, in_document_key=server_name
        ),
    )
    return Node(
        id=node_id(identity_material),
        type=NodeType.TOOL,
        subtype="mcp-server-stdio",
        name=server_name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _live_node(
    node_type: NodeType,
    subtype: str,
    relative_path: str,
    in_document_key: str,
    name: str,
    evidence: tuple[Evidence, ...],
    *,
    confidence: Confidence = Confidence.HIGH,
    security_attributes: SecurityAttributes | None = None,
) -> Node | None:
    try:
        identity_material = NodeIdentityMaterial(
            node_type=node_type,
            namespace=_LIVE_NAMESPACE,
            semantic_identity=SemanticIdentity(
                source_path=relative_path, in_document_key=in_document_key
            ),
        )
        return Node(
            id=node_id(identity_material),
            type=node_type,
            subtype=subtype,
            name=name,
            security_attributes=security_attributes or SecurityAttributes(),
            confidence=confidence,
            evidence=evidence,
        )
    except ValueError:
        return None


def _live_edge(
    relationship_type: EdgeType,
    source: Node,
    target: Node,
    discriminator: str,
    evidence: tuple[Evidence, ...],
) -> Edge:
    edge_material = EdgeIdentityMaterial(
        relationship_type=relationship_type,
        source_id=source.id,
        target_id=target.id,
        relationship_discriminator=discriminator,
    )
    return Edge(
        id=edge_id(edge_material),
        source=source.id,
        target=target.id,
        type=relationship_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=evidence,
    )


def _normalize_tools(
    server_name: str,
    server_node: Node,
    relative_path: str,
    tools: list[Any],
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Edge], list[Diagnostic]]:
    nodes: list[Node] = []
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            continue
        input_schema = tool.get("inputSchema")
        if not isinstance(input_schema, dict):
            diagnostics.append(_malformed_tool_diagnostic(evidence, server_name, name))
            continue

        tool_node = _live_node(
            NodeType.TOOL,
            "mcp-live-tool",
            relative_path,
            f"{server_name}:tool:{name}",
            name,
            evidence,
        )
        if tool_node is None:
            diagnostics.append(_malformed_tool_diagnostic(evidence, server_name, name))
            continue

        nodes.append(tool_node)
        edges.append(
            _live_edge(
                EdgeType.INVOKES,
                server_node,
                tool_node,
                f"mcp-live:tool:{name}",
                evidence,
            )
        )

    return nodes, edges, diagnostics


def _normalize_resources(
    server_name: str,
    server_node: Node,
    relative_path: str,
    resources: list[Any],
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []

    for resource in resources:
        if not isinstance(resource, dict):
            continue
        uri = resource.get("uri")
        name = resource.get("name") if isinstance(resource.get("name"), str) else uri
        if not isinstance(uri, str) or not uri or not isinstance(name, str) or not name:
            continue

        resource_node = _live_node(
            NodeType.RESOURCE,
            "mcp-live-resource",
            relative_path,
            f"{server_name}:resource:{uri}",
            name,
            evidence,
        )
        if resource_node is None:
            continue

        nodes.append(resource_node)
        # MCP's base resources capability is read-only: there is no
        # declared-write concept in the protocol, so every resource is
        # connected by a reads edge, never writes.
        edges.append(
            _live_edge(
                EdgeType.READS,
                server_node,
                resource_node,
                f"mcp-live:resource:{uri}",
                evidence,
            )
        )

    return nodes, edges


def _normalize_authorization(
    server_name: str,
    server_node: Node,
    relative_path: str,
    declared_env_var_names: Sequence[str],
    evidence: tuple[Evidence, ...],
) -> tuple[list[Node], list[Edge]]:
    nodes: list[Node] = []
    edges: list[Edge] = []

    for var_name in declared_env_var_names:
        identity_node = _live_node(
            NodeType.IDENTITY,
            "mcp-live-identity",
            relative_path,
            f"{server_name}:identity:{var_name}",
            var_name,
            evidence,
        )
        if identity_node is None:
            continue

        permission_node = _live_node(
            NodeType.PERMISSION,
            "mcp-live-permission",
            relative_path,
            f"{server_name}:permission:{var_name}",
            f"{var_name} permission",
            evidence,
            confidence=Confidence.LOW,
        )
        if permission_node is None:
            continue

        nodes.append(identity_node)
        nodes.append(permission_node)
        edges.append(
            _live_edge(
                EdgeType.AUTHENTICATES_AS,
                server_node,
                identity_node,
                f"mcp-live:identity:{var_name}",
                evidence,
            )
        )
        edges.append(
            _live_edge(
                EdgeType.PERMITTED_BY,
                identity_node,
                permission_node,
                f"mcp-live:permission:{var_name}",
                evidence,
            )
        )

    return nodes, edges


def normalize_live_mcp_server(
    server_name: str,
    command: str,
    args: Sequence[str],
    env: Mapping[str, str],
    declared_env_var_names: Sequence[str] = (),
    *,
    relative_path: str,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> DiscoveryResult:
    """Starts `command`/`args` as a stdio MCP server, lists its tools
    and resources, and normalizes the result. Never raises: any
    failure -- the process could not start, timed out, sent a
    malformed response, or exceeded the byte bound -- becomes an
    `INCOMPLETE-ADAPTER-FAILURE` diagnostic. The process is always
    terminated before this function returns, on every path.
    """

    evidence = (Evidence(adapter=_NAME, path=relative_path),)
    deadline = time.monotonic() + timeout

    try:
        process = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(env),
            bufsize=0,
            shell=False,
        )
    except OSError:
        return DiscoveryResult(
            diagnostics=(
                _live_failure_diagnostic(
                    evidence, server_name, "the server process could not be started"
                ),
            )
        )

    try:
        assert process.stdout is not None
        reader = _LineReader(process.stdout.fileno(), max_bytes)
        tools_result, resources_result = _exchange(process, reader, deadline)
    except _LiveMcpError as error:
        return DiscoveryResult(
            diagnostics=(_live_failure_diagnostic(evidence, server_name, str(error)),)
        )
    finally:
        _terminate(process)

    server_node = _server_node(server_name, relative_path, evidence)
    nodes: list[Node] = [server_node]
    edges: list[Edge] = []
    diagnostics: list[Diagnostic] = []

    tools = tools_result.get("tools")
    tool_nodes, tool_edges, tool_diagnostics = _normalize_tools(
        server_name,
        server_node,
        relative_path,
        tools if isinstance(tools, list) else [],
        evidence,
    )
    nodes.extend(tool_nodes)
    edges.extend(tool_edges)
    diagnostics.extend(tool_diagnostics)

    resources = resources_result.get("resources")
    resource_nodes, resource_edges = _normalize_resources(
        server_name,
        server_node,
        relative_path,
        resources if isinstance(resources, list) else [],
        evidence,
    )
    nodes.extend(resource_nodes)
    edges.extend(resource_edges)

    auth_nodes, auth_edges = _normalize_authorization(
        server_name, server_node, relative_path, declared_env_var_names, evidence
    )
    nodes.extend(auth_nodes)
    edges.extend(auth_edges)

    return DiscoveryResult(
        nodes=tuple(nodes), edges=tuple(edges), diagnostics=tuple(diagnostics)
    )
