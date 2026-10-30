"""Tests for MCP server identity and approval surfaces across hosts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, NodeType, host_node_id
from controlloop.adapters import McpServerAdapter, ScanContext, run_adapters
from controlloop.adapters.framework import DiscoveryResult
from controlloop.diff.compute import diff_nodes
from controlloop.diff.models import ChangeKind
from controlloop.repository import resolve_repository_root

_SECRET_ENV = "planted-env-value-1e2d"
_SECRET_HEADER = "planted-header-value-9c8b"
_SECRET_ARG = "planted-arg-secret-77aa"
_GITHUB_TOKEN = "ghp_" + "R" * 36


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload if isinstance(payload, str) else json.dumps(payload))


def _run(tmp_path: Path) -> DiscoveryResult:
    return run_adapters([McpServerAdapter()], _context(tmp_path))


def _servers(result: DiscoveryResult) -> dict[str, Node]:
    return {
        node.name: node
        for node in result.nodes
        if (node.subtype or "").startswith("mcp-server")
    }


def _server(tmp_path: Path, entry: Mapping[str, object], name: str = "s") -> Node:
    _write(tmp_path, ".mcp.json", {"mcpServers": {name: entry}})
    return _servers(_run(tmp_path))[name]


# --- Identity fields ------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "registry", "package", "version"),
    [
        ("npx", ["-y", "postmark-mcp@1.0.16"], "npm", "postmark-mcp", "1.0.16"),
        (
            "npx",
            ["-y", "@scope/server@2.1.0", "--flag"],
            "npm",
            "@scope/server",
            "2.1.0",
        ),
        ("npx", ["@scope/server"], "npm", "@scope/server", "unpinned"),
        ("bunx", ["pkg@0.1.0"], "npm", "pkg", "0.1.0"),
        ("pnpm", ["dlx", "pkg@3.0.0"], "npm", "pkg", "3.0.0"),
        ("uvx", ["mcp-server-fetch==1.2.3"], "pypi", "mcp-server-fetch", "1.2.3"),
        ("uvx", ["--from", "git+x", "tool"], "pypi", "git+x", "unpinned"),
        ("uvx", ["--from", "srv==0.6.1", "srv", "mcp"], "pypi", "srv", "0.6.1"),
        ("uvx", ["--from=srv==0.6.1", "srv"], "pypi", "srv", "0.6.1"),
        ("uvx", ["--from", "other==1.0", "srv"], "pypi", "other", "1.0"),
        ("uvx", ["--from", "srv>=1", "srv"], "pypi", "srv>=1", "unpinned"),
        ("uvx", ["srv", "--from", "x==1"], "pypi", "srv", "unpinned"),
        ("uvx", ["srv@0.6.1", "mcp"], "pypi", "srv", "0.6.1"),
        ("uvx", ["srv===2.0"], "pypi", "srv", "2.0"),
        (
            "uvx",
            ["--from", "git+https://github.com/acme/srv@v1.2", "srv"],
            "pypi",
            "git+https://github.com/acme/srv",
            "v1.2",
        ),
        (
            "uvx",
            ["--from", "git+ssh://git@github.com/acme/srv", "srv"],
            "pypi",
            "git+ssh://git@github.com/acme/srv",
            "unpinned",
        ),
        ("pipx", ["run", "srv@4.0"], "pypi", "srv", "4.0"),
        ("pipx", ["run", "--spec", "srv==4.0", "srv"], "pypi", "srv", "4.0"),
        (
            "docker",
            ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/acme/mcp:1.4"],
            "oci",
            "ghcr.io/acme/mcp",
            "1.4",
        ),
        (
            "docker",
            ["run", "-i", "acme/mcp@sha256:" + "a" * 64],
            "oci",
            "acme/mcp",
            "sha256:" + "a" * 64,
        ),
        ("/usr/local/bin/npx", ["-y", "pkg@1.0.0"], "npm", "pkg", "1.0.0"),
    ],
)
def test_the_launched_package_and_version_are_recorded(
    tmp_path: Path,
    command: str,
    args: list[str],
    registry: str,
    package: str,
    version: str,
) -> None:
    node = _server(tmp_path, {"command": command, "args": args})

    assert node.attributes["package_registry"] == registry
    assert node.attributes["package"] == package
    assert node.attributes["package_version"] == version


def test_a_plain_command_records_no_package(tmp_path: Path) -> None:
    node = _server(tmp_path, {"command": "node", "args": ["server.js"]})

    assert "package" not in node.attributes
    assert node.attributes["command"] == "node"
    assert node.attributes["args"] == "server.js"
    assert node.attributes["transport"] == "stdio"


def test_a_remote_server_records_its_host_and_header_names_only(tmp_path: Path) -> None:
    node = _server(
        tmp_path,
        {
            "url": f"https://user:{_SECRET_ARG}@mcp.example.com/v1?key={_SECRET_ARG}",
            "headers": {"Authorization": _SECRET_HEADER},
        },
    )

    assert node.attributes["url_host"] == "mcp.example.com"
    assert node.attributes["header_names"] == "Authorization"
    assert node.attributes["transport"] == "http"


def test_key_value_arguments_keep_only_the_key(tmp_path: Path) -> None:
    node = _server(
        tmp_path,
        {
            "command": "srv",
            "args": [
                f"--api-key={_SECRET_ARG}",
                f"REGION=eu-{_SECRET_ARG}",
                "${env:X}",
            ],
        },
    )

    args = node.attributes["args"]
    assert _SECRET_ARG not in args
    assert "--api-key=<redacted>" in args
    assert "REGION=<redacted>" in args


@pytest.mark.parametrize(
    ("args", "shown"),
    [
        (["srv==0.6.1", "mcp"], "srv==0.6.1 mcp"),
        (["--from", "srv==0.6.1", "srv"], "--from srv==0.6.1 srv"),
        (["--from=srv==0.6.1", "srv"], "--from=srv==0.6.1 srv"),
    ],
)
def test_the_launched_requirement_is_not_redacted(
    tmp_path: Path, args: list[str], shown: str
) -> None:
    node = _server(tmp_path, {"command": "uvx", "args": args})

    assert node.attributes["args"] == shown


def test_key_value_arguments_after_the_requirement_stay_redacted(
    tmp_path: Path,
) -> None:
    node = _server(
        tmp_path,
        {
            "command": "uvx",
            "args": ["--from", "srv==1.0", "srv", f"TOKEN=={_SECRET_ARG}"],
        },
    )

    assert _SECRET_ARG not in node.attributes["args"]
    assert node.attributes["args"] == "--from srv==1.0 srv TOKEN=<redacted>"


def test_the_declaration_digest_changes_with_the_declaration_only(
    tmp_path: Path,
) -> None:
    def digest(entry: Mapping[str, object], where: Path) -> str:
        return _server(where, entry).attributes["declaration_digest"]

    base: dict[str, object] = {
        "command": "npx",
        "args": ["pkg@1.0.0"],
        "env": {"TOKEN": "one"},
    }
    same_shape_other_value: dict[str, object] = {
        "command": "npx",
        "args": ["pkg@1.0.0"],
        "env": {"TOKEN": "two"},
    }
    different: dict[str, object] = {
        "command": "npx",
        "args": ["pkg@1.0.1"],
        "env": {"TOKEN": "one"},
    }

    assert digest(base, tmp_path / "a") == digest(
        same_shape_other_value, tmp_path / "b"
    )
    assert digest(base, tmp_path / "a") != digest(different, tmp_path / "c")
    assert digest(base, tmp_path / "a").startswith("sha256:")


# --- A same-name change is a change ----------------------------------------


@pytest.mark.parametrize(
    "after",
    [
        {"command": "npx", "args": ["-y", "postmark-mcp@1.0.16"]},
        {"command": "uvx", "args": ["postmark-mcp==1.0.15"]},
        {"command": "npx", "args": ["-y", "postmark-mcp@1.0.15", "--extra"]},
        {"command": "npx", "args": ["-y", "postmark-mcp@1.0.15"], "env": {"NEW": "x"}},
    ],
    ids=["version", "command", "arguments", "declaration"],
)
def test_a_server_with_an_unchanged_name_but_changed_identity_diffs_as_changed(
    tmp_path: Path, after: dict[str, object]
) -> None:
    before_node = _server(
        tmp_path / "before",
        {"command": "npx", "args": ["-y", "postmark-mcp@1.0.15"]},
        "postmark",
    )
    after_node = _server(tmp_path / "after", after, "postmark")

    assert before_node.id == after_node.id
    changes = diff_nodes((before_node,), (after_node,))

    assert [change.kind for change in changes] == [ChangeKind.CHANGED]


def test_an_identical_declaration_is_not_a_change(tmp_path: Path) -> None:
    entry = {"command": "npx", "args": ["-y", "postmark-mcp@1.0.15"]}
    before = _server(tmp_path / "before", entry, "postmark")
    after = _server(tmp_path / "after", entry, "postmark")

    assert diff_nodes((before,), (after,)) == ()


# --- Tool manifests --------------------------------------------------------


def test_a_committed_tool_manifest_contributes_a_tools_digest(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "servers/mail/manifest.json",
        {"name": "mail", "tools": [{"name": "send", "description": "Send mail"}]},
    )
    first = _server(tmp_path, {"command": "node", "args": ["servers/mail/index.js"]})
    _write(
        tmp_path,
        "servers/mail/manifest.json",
        {
            "name": "mail",
            "tools": [{"name": "send", "description": "Send mail and BCC"}],
        },
    )
    second = _servers(_run(tmp_path))["s"]

    assert first.attributes["tools_digest"].startswith("sha256:")
    assert first.attributes["tools_digest"] != second.attributes["tools_digest"]


def test_no_tool_manifest_is_unknown_never_no_tools(tmp_path: Path) -> None:
    node = _server(tmp_path, {"command": "npx", "args": ["pkg@1.0.0"]})

    assert node.attributes["tools_digest"] == "unknown"


def test_a_manifest_outside_the_repository_is_never_read(tmp_path: Path) -> None:
    node = _server(tmp_path, {"command": "node", "args": ["../outside/index.js"]})

    assert node.attributes["tools_digest"] == "unknown"


# --- Other hosts' declarations ---------------------------------------------


@pytest.mark.parametrize(
    ("relative_path", "content", "host", "names"),
    [
        (
            ".vscode/mcp.json",
            {"servers": {"a": {"type": "stdio", "command": "npx"}}},
            "vscode",
            ["a"],
        ),
        (
            ".cursor/mcp.json",
            {"mcpServers": {"a": {"command": "npx"}}},
            "cursor",
            ["a"],
        ),
        (
            ".gemini/settings.json",
            {"mcpServers": {"a": {"httpUrl": "https://g.example.com"}}},
            "gemini-cli",
            ["a"],
        ),
        (
            ".kiro/settings/mcp.json",
            {"mcpServers": {"a": {"command": "uvx", "args": ["x"]}}},
            "kiro",
            ["a"],
        ),
        (".roo/mcp.json", {"mcpServers": {"a": {"command": "npx"}}}, "roo", ["a"]),
        (
            "config/cline_mcp_settings.json",
            {"mcpServers": {"a": {"command": "npx"}}},
            "cline",
            ["a"],
        ),
        (
            ".continue/config.json",
            {"mcpServers": [{"name": "a", "command": "npx"}]},
            "continue",
            ["a"],
        ),
        (
            ".continue/config.yaml",
            "mcpServers:\n  - name: a\n    command: npx\n",
            "continue",
            ["a"],
        ),
        (
            ".windsurf/mcp.json",
            {"mcpServers": {"a": {"serverUrl": "https://w.example.com"}}},
            "windsurf",
            ["a"],
        ),
        (
            "opencode.json",
            {"mcp": {"a": {"type": "local", "command": ["npx", "pkg@1.0.0"]}}},
            "opencode",
            ["a"],
        ),
        (
            ".codex/config.toml",
            '[mcp_servers.a]\ncommand = "npx"\nargs = ["pkg@1.0.0"]\n',
            "codex",
            ["a"],
        ),
    ],
)
def test_each_hosts_declarations_are_discovered_with_their_host(
    tmp_path: Path, relative_path: str, content: object, host: str, names: list[str]
) -> None:
    _write(tmp_path, relative_path, content)

    result = _run(tmp_path)
    servers = _servers(result)
    hosts = [node for node in result.nodes if node.subtype == "host"]

    assert sorted(servers) == names
    assert [node.attributes["host"] for node in hosts] == [host]
    assert hosts[0].type is NodeType.AGENT
    host_id = host_node_id(host)
    for server in servers.values():
        assert any(
            edge.source == host_id
            and edge.target == server.id
            and edge.type is EdgeType.INVOKES
            for edge in result.edges
        )


def test_dot_mcp_json_hosts_are_left_to_the_claude_code_adapter(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"a": {"command": "npx"}}})

    result = _run(tmp_path)

    assert [node.subtype for node in result.nodes] == ["mcp-server-stdio"]
    assert result.edges == ()


def test_vscode_inputs_record_ids_never_values(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".vscode/mcp.json",
        {
            "inputs": [
                {
                    "type": "promptString",
                    "id": "api-key",
                    "password": True,
                    "description": _SECRET_ARG,
                }
            ],
            "servers": {"a": {"command": "npx", "env": {"KEY": "${input:api-key}"}}},
        },
    )

    result = _run(tmp_path)
    (host,) = [node for node in result.nodes if node.subtype == "host"]

    assert host.attributes["input_ids"] == "api-key"
    assert _SECRET_ARG not in result.model_dump_json()


def test_a_disabled_server_is_recorded_but_not_invoked(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".roo/mcp.json",
        {"mcpServers": {"off": {"command": "npx", "disabled": True}}},
    )

    result = _run(tmp_path)
    (server,) = _servers(result).values()

    assert server.attributes["disabled"] == "true"
    assert not any(edge.target == server.id for edge in result.edges)


# --- Per-tool approval -----------------------------------------------------


@pytest.mark.parametrize(
    ("relative_path", "field"),
    [
        (".kiro/settings/mcp.json", "autoApprove"),
        (".roo/mcp.json", "alwaysAllow"),
        ("cline_mcp_settings.json", "alwaysAllow"),
    ],
)
def test_auto_approve_lists_become_per_tool_permissions(
    tmp_path: Path, relative_path: str, field: str
) -> None:
    _write(
        tmp_path,
        relative_path,
        {"mcpServers": {"git": {"command": "npx", field: ["status", "push"]}}},
    )

    result = _run(tmp_path)
    (server,) = _servers(result).values()
    rules = [node for node in result.nodes if node.subtype == "permission-rule"]

    assert sorted(node.attributes["tool"] for node in rules) == ["push", "status"]
    for rule in rules:
        assert rule.security_attributes.approval_present is True
        assert rule.security_attributes.requires_approval is False
        assert rule.security_attributes.wildcard is False
        (edge,) = [e for e in result.edges if e.target == rule.id]
        assert edge.source == server.id
        assert edge.type is EdgeType.PERMITTED_BY


def test_gemini_trust_is_a_wildcard_approval_of_every_tool(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gemini/settings.json",
        {"mcpServers": {"fs": {"command": "npx", "trust": True}}},
    )

    result = _run(tmp_path)
    (rule,) = [node for node in result.nodes if node.subtype == "permission-rule"]

    assert rule.attributes["tool"] == "*"
    assert rule.security_attributes.wildcard is True
    host_edge = next(edge for edge in result.edges if edge.type is EdgeType.INVOKES)
    assert host_edge.security_attributes.approval_present is True


# --- Privacy, malformed input, determinism ----------------------------------


def test_no_env_header_or_secret_shaped_argument_value_appears_anywhere(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "a": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "srv@1.0.0",
                        "--token",
                        _GITHUB_TOKEN,
                        f"--password={_SECRET_ARG}",
                    ],
                    "env": {"TOKEN": _SECRET_ENV},
                },
                "b": {
                    "url": "https://h.example.com",
                    "headers": {"X-Key": _SECRET_HEADER},
                },
            }
        },
    )
    _write(
        tmp_path,
        ".codex/config.toml",
        f'[mcp_servers.c]\ncommand = "srv"\nenv = {{ KEY = "{_SECRET_ENV}" }}\n',
    )

    rendered = _run(tmp_path).model_dump_json()

    for canary in (_SECRET_ENV, _SECRET_HEADER, _SECRET_ARG, _GITHUB_TOKEN):
        assert canary not in rendered


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        (".codex/config.toml", "[mcp_servers.a\ncommand = "),
        (".continue/config.yaml", "mcpServers: [unclosed"),
        (".vscode/mcp.json", "{ not json"),
        (".gemini/settings.json", {"mcpServers": "x"}),
    ],
)
def test_malformed_files_in_new_locations_are_diagnostics(
    tmp_path: Path, relative_path: str, content: object
) -> None:
    _write(tmp_path, relative_path, content)

    result = _run(tmp_path)

    assert result.nodes == ()
    assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]


def test_output_is_identical_across_runs_and_key_order(tmp_path: Path) -> None:
    entry = {"command": "npx", "args": ["pkg@1.0.0"], "env": {"B": "1", "A": "2"}}
    reordered = {"env": {"A": "2", "B": "1"}, "args": ["pkg@1.0.0"], "command": "npx"}
    _write(tmp_path / "one", ".kiro/settings/mcp.json", {"mcpServers": {"s": entry}})
    _write(
        tmp_path / "two", ".kiro/settings/mcp.json", {"mcpServers": {"s": reordered}}
    )

    first = _run(tmp_path / "one")
    assert first == _run(tmp_path / "one")
    assert first.model_dump_json() == _run(tmp_path / "two").model_dump_json()
