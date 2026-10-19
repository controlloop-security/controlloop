"""Tests for McpServerAdapter."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from controlloop.acbom import Confidence, NodeType
from controlloop.adapters import McpServerAdapter, ScanContext, run_adapters
from controlloop.repository import resolve_repository_root

_PLANTED_ENV_VALUE = "sk-planted-secret-shaped-value-abc123"
_PLANTED_HEADER_VALUE = "Bearer planted-secret-shaped-token-xyz"


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write_config(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        target.write_text(payload)
    else:
        target.write_text(json.dumps(payload))


@pytest.mark.parametrize(
    "relative_path", [".mcp.json", ".vscode/mcp.json", ".cursor/mcp.json"]
)
def test_each_known_location_is_detected(tmp_path: Path, relative_path: str) -> None:
    """MCP server configurations in standard client configuration
    locations within the repository are discovered."""
    _write_config(tmp_path, relative_path, {"mcpServers": {}})

    detection = McpServerAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == (relative_path,)


def test_an_unrelated_location_is_not_detected(tmp_path: Path) -> None:
    _write_config(tmp_path, "mcp.json", {"mcpServers": {}})  # not a known location

    detection = McpServerAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == ()


def test_stdio_server_is_represented_with_the_right_transport(tmp_path: Path) -> None:
    """Transport and launch shape are captured."""
    _write_config(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": _PLANTED_ENV_VALUE},
                }
            }
        },
    )

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.type is NodeType.TOOL
    assert node.subtype == "mcp-server-stdio"
    assert node.name == "github"
    assert node.confidence is Confidence.HIGH
    assert node.security_attributes.code_execution is True
    assert node.security_attributes.external_communication is None
    assert node.security_attributes.permission_scopes == ("env:GITHUB_TOKEN",)


def test_http_server_is_represented_with_the_right_transport(tmp_path: Path) -> None:
    _write_config(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": _PLANTED_HEADER_VALUE},
                }
            }
        },
    )

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    node = result.nodes[0]
    assert node.subtype == "mcp-server-http"
    assert node.security_attributes.code_execution is None
    assert node.security_attributes.external_communication is True
    # headers content is never inspected at all -- not even the key names
    assert node.security_attributes.permission_scopes == ()


def test_env_value_never_appears_anywhere_in_the_result(tmp_path: Path) -> None:
    """An environment-variable reference is recorded as a reference;
    its value is never read or emitted."""
    _write_config(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "env": {"GITHUB_TOKEN": _PLANTED_ENV_VALUE},
                },
                "remote": {
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": _PLANTED_HEADER_VALUE},
                },
            }
        },
    )

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    serialized = repr(result)
    assert _PLANTED_ENV_VALUE not in serialized
    assert _PLANTED_HEADER_VALUE not in serialized
    assert "env:GITHUB_TOKEN" in serialized  # the reference itself is kept


def test_adapter_module_imports_neither_subprocess_nor_socket() -> None:
    """Structural: the adapter's own code contains no path to
    launching a process or opening a connection, independent of
    adapter_sandbox also denying both at runtime."""
    import controlloop.adapters.mcp as mcp_module

    source = Path(mcp_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }

    assert "subprocess" not in imported_modules
    assert "socket" not in imported_modules


def test_servers_are_never_launched_or_connected_to(tmp_path: Path) -> None:
    """End to end: a real run through the sandboxed runner
    completes without any process or network activity being possible."""
    _write_config(
        tmp_path,
        ".mcp.json",
        {"mcpServers": {"github": {"command": "npx", "args": ["-y", "whatever"]}}},
    )

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert result.diagnostics == ()


@pytest.mark.parametrize(
    ("relative_path", "payload", "reason_fragment"),
    [
        (".mcp.json", "{not valid json", "could not be read"),
        (".mcp.json", ["not", "an", "object"], "top level is not"),
        (".mcp.json", {"mcpServers": "not-an-object"}, "no mcpServers object"),
        (
            ".mcp.json",
            {"mcpServers": {"bad": "not-an-object"}},
            "not a JSON object",
        ),
        (
            ".mcp.json",
            {"mcpServers": {"neither": {"args": ["only-args-no-command-or-url"]}}},
            "could not be represented",
        ),
    ],
    ids=[
        "invalid-json",
        "non-object-file",
        "non-object-servers",
        "non-object-entry",
        "no-transport",
    ],
)
def test_malformed_input_produces_a_diagnostic_not_a_crash(
    tmp_path: Path, relative_path: str, payload: object, reason_fragment: str
) -> None:
    """A malformed server entry produces a diagnostic and an unknown,
    not a dropped server -- and never a crash."""
    _write_config(tmp_path, relative_path, payload)

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "INCOMPLETE-UNPARSED-REGION"
    assert diagnostic.incomplete is True
    assert reason_fragment in diagnostic.message


def test_a_malformed_entry_does_not_drop_a_valid_sibling(tmp_path: Path) -> None:
    """A server is never dropped just because another entry in the
    same file is malformed."""
    _write_config(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "good": {"command": "npx"},
                "bad": {"nonsense": True},
            }
        },
    )

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert result.nodes[0].name == "good"
    assert len(result.diagnostics) == 1


def test_result_is_deterministic_across_repeated_runs(tmp_path: Path) -> None:
    _write_config(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "a": {"command": "npx"},
                "b": {"url": "https://example.com/mcp"},
            }
        },
    )
    _write_config(tmp_path, ".vscode/mcp.json", {"mcpServers": {"c": {"command": "x"}}})
    context = _context(tmp_path)

    first = run_adapters([McpServerAdapter()], context)
    second = run_adapters([McpServerAdapter()], context)

    assert first == second
    assert [node.id for node in first.nodes] == sorted(node.id for node in first.nodes)


@pytest.mark.parametrize(
    ("relative_path", "text"),
    [
        (".codex/config.toml", 'approval_policy = "on-request"\n'),
        (".gemini/settings.json", json.dumps({"tools": {"allowed": ["read_file"]}})),
        ("opencode.json", json.dumps({"theme": "dark"})),
        (".continue/config.json", json.dumps({"models": []})),
    ],
    ids=["codex", "gemini-cli", "opencode", "continue"],
)
def test_a_general_settings_file_with_no_server_section_is_complete(
    tmp_path: Path, relative_path: str, text: str
) -> None:
    """A benign corpus showed a plain Codex or Gemini CLI settings file
    reported as incomplete. The server section is optional there, so its
    absence declares no servers."""

    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert result.diagnostics == ()


def test_a_dedicated_mcp_file_with_no_server_section_is_still_reported(
    tmp_path: Path,
) -> None:
    _write_config(tmp_path, ".cursor/mcp.json", {"theme": "dark"})

    result = run_adapters([McpServerAdapter()], _context(tmp_path))

    assert [diagnostic.code for diagnostic in result.diagnostics] == [
        "INCOMPLETE-UNPARSED-REGION"
    ]
