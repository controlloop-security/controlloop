"""Tests for controlloop.adapters.mcp_live.

Every test spawns the real stub MCP server (`tests/fixtures/stub_mcp_server.py`)
as a genuine subprocess -- never a mocked transport -- so these tests
exercise the actual JSON-RPC client code, process bounds, and
termination behavior.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from controlloop.acbom import EdgeType, NodeType
from controlloop.acbom.identity import NodeIdentityMaterial, SemanticIdentity, node_id
from controlloop.adapters.framework import DiscoveryResult
from controlloop.adapters.mcp_live import normalize_live_mcp_server

_STUB_SERVER_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "stub_mcp_server.py"
)


def _write_config(tmp_path: Path, config: dict[str, object]) -> Path:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    return config_path


def _run(
    tmp_path: Path,
    config: dict[str, object],
    *,
    declared_env_var_names: tuple[str, ...] = (),
    timeout: float = 5.0,
    max_bytes: int = 10 * 1024 * 1024,
) -> DiscoveryResult:
    config_path = _write_config(tmp_path, config)
    return normalize_live_mcp_server(
        "test-server",
        sys.executable,
        [str(_STUB_SERVER_PATH), str(config_path)],
        env={},
        declared_env_var_names=declared_env_var_names,
        relative_path=".mcp.json",
        timeout=timeout,
        max_bytes=max_bytes,
    )


def test_tools_are_normalized_with_invokes_edges(tmp_path: Path) -> None:
    """Each tool becomes a node with an invokes edge from the server."""
    result = _run(
        tmp_path,
        {
            "mode": "normal",
            "tools": [
                {
                    "name": "search",
                    "description": "Search the index",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
        },
    )

    tool_nodes = [n for n in result.nodes if n.subtype == "mcp-live-tool"]
    assert [n.name for n in tool_nodes] == ["search"]
    invokes_edges = [e for e in result.edges if e.type is EdgeType.INVOKES]
    assert len(invokes_edges) == 1
    assert invokes_edges[0].target == tool_nodes[0].id


def test_server_node_matches_static_adapter_identity(tmp_path: Path) -> None:
    """The live server node reuses the same identity scheme as the
    static MCP server adapter, so the two merge rather than duplicate."""
    result = _run(tmp_path, {"mode": "normal", "tools": []})

    server_nodes = [n for n in result.nodes if n.subtype == "mcp-server-stdio"]
    assert len(server_nodes) == 1

    expected_id = node_id(
        NodeIdentityMaterial(
            node_type=NodeType.TOOL,
            namespace="mcp.server",
            semantic_identity=SemanticIdentity(
                source_path=".mcp.json", in_document_key="test-server"
            ),
        )
    )
    assert server_nodes[0].id == expected_id


def test_resources_produce_reads_edges(tmp_path: Path) -> None:
    """MCP's base resources capability is read-only."""
    result = _run(
        tmp_path,
        {
            "mode": "normal",
            "resources": [
                {"uri": "file:///data.csv", "name": "data", "mimeType": "text/csv"}
            ],
        },
    )

    resource_nodes = [n for n in result.nodes if n.type is NodeType.RESOURCE]
    assert len(resource_nodes) == 1
    reads_edges = [e for e in result.edges if e.type is EdgeType.READS]
    assert len(reads_edges) == 1
    assert reads_edges[0].target == resource_nodes[0].id
    assert not any(e.type is EdgeType.WRITES for e in result.edges)


def test_declared_env_vars_become_identity_and_permission_nodes(
    tmp_path: Path,
) -> None:
    """A declared environment-variable name becomes an identity node and
    a permission node."""
    result = _run(tmp_path, {"mode": "normal"}, declared_env_var_names=("API_KEY",))

    identity_nodes = [n for n in result.nodes if n.type is NodeType.IDENTITY]
    permission_nodes = [n for n in result.nodes if n.type is NodeType.PERMISSION]
    assert len(identity_nodes) == 1
    assert len(permission_nodes) == 1
    assert any(e.type is EdgeType.AUTHENTICATES_AS for e in result.edges)
    assert any(e.type is EdgeType.PERMITTED_BY for e in result.edges)


def test_missing_input_schema_produces_a_diagnostic_not_a_dropped_tool(
    tmp_path: Path,
) -> None:
    """A tool without an input schema is a diagnostic, not a silently
    dropped tool."""
    result = _run(
        tmp_path,
        {
            "mode": "normal",
            "tools": [{"name": "broken-tool", "description": "x"}],
        },
    )

    assert not any(n.subtype == "mcp-live-tool" for n in result.nodes)
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-UNPARSED-REGION"
    assert "broken-tool" in result.diagnostics[0].message


def test_hostile_tool_name_never_reaches_raw_output(tmp_path: Path) -> None:
    """Control characters are rejected structurally by DisplayName,
    not passed through."""
    planted = "tool\x01\x02hostile"
    result = _run(
        tmp_path,
        {
            "mode": "normal",
            "tools": [
                {"name": planted, "inputSchema": {"type": "object"}},
            ],
        },
    )

    assert not any(n.subtype == "mcp-live-tool" for n in result.nodes)
    assert len(result.diagnostics) == 1
    assert planted not in repr(result)


def test_malformed_response_produces_a_diagnostic_not_a_crash(tmp_path: Path) -> None:
    result = _run(tmp_path, {"mode": "malformed"})

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_crashing_server_produces_a_diagnostic_not_a_crash(tmp_path: Path) -> None:
    result = _run(tmp_path, {"mode": "crash"})

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_hanging_server_times_out_and_is_terminated(tmp_path: Path) -> None:
    """A server that never responds is terminated at the timeout
    rather than hanging the caller forever."""
    started = time.monotonic()

    result = _run(tmp_path, {"mode": "hang", "hang_seconds": 30}, timeout=0.5)

    elapsed = time.monotonic() - started
    assert elapsed < 10
    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_oversized_response_is_bounded_not_read_unboundedly(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        {"mode": "oversized", "oversized_bytes": 2048},
        max_bytes=1024,
    )

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_nonexistent_command_produces_a_diagnostic_not_a_crash(tmp_path: Path) -> None:
    result = normalize_live_mcp_server(
        "test-server",
        "/nonexistent/definitely-not-a-real-command",
        [],
        env={},
        relative_path=".mcp.json",
    )

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].code == "INCOMPLETE-ADAPTER-FAILURE"


def test_process_is_terminated_after_a_successful_exchange(tmp_path: Path) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def _capturing_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process: subprocess.Popen[bytes] = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    with patch(
        "controlloop.adapters.mcp_live.subprocess.Popen", side_effect=_capturing_popen
    ):
        _run(tmp_path, {"mode": "normal", "tools": []})

    assert len(spawned) == 1
    assert spawned[0].poll() is not None


def test_process_is_terminated_after_a_hang_timeout(tmp_path: Path) -> None:
    spawned: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def _capturing_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process: subprocess.Popen[bytes] = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    with patch(
        "controlloop.adapters.mcp_live.subprocess.Popen", side_effect=_capturing_popen
    ):
        _run(tmp_path, {"mode": "hang", "hang_seconds": 30}, timeout=0.5)

    assert len(spawned) == 1
    assert spawned[0].poll() is not None


def test_result_is_deterministic(tmp_path: Path) -> None:
    config: dict[str, object] = {
        "mode": "normal",
        "tools": [{"name": "search", "inputSchema": {"type": "object"}}],
        "resources": [{"uri": "file:///a.txt", "name": "a"}],
    }

    first = _run(tmp_path, config)
    second = _run(tmp_path, config)

    assert first == second
