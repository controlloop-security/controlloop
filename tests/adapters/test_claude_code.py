"""Tests for ClaudeCodeSettingsAdapter."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from controlloop.acbom import (
    MAX_ATTRIBUTE_VALUE_LENGTH,
    EdgeType,
    NodeType,
    host_node_id,
)
from controlloop.adapters import (
    ClaudeCodeSettingsAdapter,
    DiscoveryResult,
    McpServerAdapter,
    ScanContext,
    claude_code,
    run_adapters,
)
from controlloop.adapters.agent_authority import classify_permission_rule
from controlloop.repository import resolve_repository_root

_SECRET_ENV_VALUE = "planted-env-value-should-never-appear-91f2"
_SECRET_TOKEN = "ghp_" + "Q" * 36
_SECRET_PROMPT = "PLANTED PROMPT BODY THAT IS PROTECTED CONTENT"
_SECRET_HEADER = "planted-header-value-7c3e"
_SECRET_FLAG = "planted-flag-value-55aa"

_HOST_ID = host_node_id("claude-code")


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload if isinstance(payload, str) else json.dumps(payload))


def _run(tmp_path: Path, *, with_mcp_adapter: bool = False) -> DiscoveryResult:
    adapters: list[object] = [ClaudeCodeSettingsAdapter()]
    if with_mcp_adapter:
        adapters.append(McpServerAdapter())
    return run_adapters(adapters, _context(tmp_path))  # type: ignore[arg-type]


def _by_subtype(result: DiscoveryResult, subtype: str) -> list:  # type: ignore[type-arg]
    return [node for node in result.nodes if node.subtype == subtype]


def _host(result: DiscoveryResult):  # type: ignore[no-untyped-def]
    hosts = _by_subtype(result, "host")
    assert len(hosts) == 1
    return hosts[0]


def _codes(result: DiscoveryResult) -> list[str]:
    return [diagnostic.code for diagnostic in result.diagnostics]


# --- Detection and the one host -------------------------------------------


def test_shared_settings_file_is_detected(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/settings.json", {})

    detection = ClaudeCodeSettingsAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == (".claude/settings.json",)


def test_both_files_make_one_host_with_both_files_as_evidence(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/settings.json", {"permissions": {"defaultMode": "plan"}})
    _write(
        tmp_path,
        ".claude/settings.local.json",
        {"permissions": {"defaultMode": "acceptEdits"}},
    )

    result = _run(tmp_path)
    host = _host(result)

    assert host.id == _HOST_ID
    assert host.type is NodeType.AGENT
    assert {evidence.path for evidence in host.evidence} == {
        ".claude/settings.json",
        ".claude/settings.local.json",
    }
    # The local file takes precedence for a single-valued setting.
    assert host.attributes["default_mode"] == "acceptEdits"
    assert host.attributes["docs_snapshot"] == claude_code.DOCUMENTATION_SNAPSHOT


def test_an_ignored_local_settings_file_is_not_read(tmp_path: Path) -> None:
    """The local file counts only when it is part of the repository.
    Claude Code itself adds it to `.gitignore`; the walker honours that,
    so an ignored local file is skipped."""

    _write(tmp_path, ".gitignore", ".claude/settings.local.json\n")
    _write(tmp_path, ".claude/settings.json", {})
    _write(
        tmp_path, ".claude/settings.local.json", {"permissions": {"allow": ["Bash"]}}
    )

    result = _run(tmp_path)

    assert {evidence.path for evidence in _host(result).evidence} == {
        ".claude/settings.json"
    }
    assert _by_subtype(result, "permission-rule") == []


@pytest.mark.parametrize(
    "relative_path",
    [
        ".claude/settings.json.bak",
        "claude/settings.json",
        ".claude/other.json",
        "CLAUDE.md",
    ],
)
def test_near_miss_paths_are_not_claimed(tmp_path: Path, relative_path: str) -> None:
    _write(
        tmp_path,
        relative_path,
        {"hooks": {}} if relative_path.endswith(".json") else "x",
    )

    assert ClaudeCodeSettingsAdapter().detect(_context(tmp_path)).claimed_paths == ()
    assert _run(tmp_path).nodes == ()


# --- Hooks ----------------------------------------------------------------


def _settings_with_hooks(
    handlers: list[dict[str, object]], event: str = "PreToolUse"
) -> dict[str, object]:
    return {"hooks": {event: [{"matcher": "Bash", "hooks": handlers}]}}


def test_a_command_hook_is_code_execution_with_event_and_bounded_command(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        _settings_with_hooks(
            [{"type": "command", "command": "node .github/setup.js"}], "SessionStart"
        ),
    )

    result = _run(tmp_path)
    (hook,) = _by_subtype(result, "hook")

    assert hook.type is NodeType.TOOL
    assert hook.security_attributes.code_execution is True
    assert hook.attributes["event"] == "SessionStart"
    assert hook.attributes["hook_type"] == "command"
    assert hook.attributes["command"] == "node .github/setup.js"
    invokes = [edge for edge in result.edges if edge.target == hook.id]
    assert [(edge.source, edge.type) for edge in invokes] == [
        (_HOST_ID, EdgeType.INVOKES)
    ]


def test_exec_form_args_are_part_of_the_command(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        _settings_with_hooks(
            [
                {
                    "type": "command",
                    "command": "python3",
                    "args": ["scripts/check.py", "--fast"],
                }
            ]
        ),
    )

    (hook,) = _by_subtype(_run(tmp_path), "hook")

    assert hook.attributes["command"] == "python3 scripts/check.py --fast"


@pytest.mark.parametrize(
    ("handler", "code_execution", "external"),
    [
        ({"type": "http", "url": "https://hooks.example.com/x"}, False, True),
        ({"type": "prompt", "prompt": "Is this safe?"}, False, None),
        ({"type": "agent", "prompt": "Verify"}, "unknown", None),
        ({"type": "mcp_tool", "server": "scanner", "tool": "scan"}, "unknown", None),
    ],
)
def test_other_hook_types_carry_their_type_and_classification(
    tmp_path: Path, handler: dict[str, object], code_execution: object, external: object
) -> None:
    _write(tmp_path, ".claude/settings.json", _settings_with_hooks([handler]))

    (hook,) = _by_subtype(_run(tmp_path), "hook")

    assert hook.attributes["hook_type"] == handler["type"]
    assert hook.security_attributes.code_execution == code_execution
    assert hook.security_attributes.external_communication == external


def test_an_http_hook_records_only_the_url_host_and_header_names(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        _settings_with_hooks(
            [
                {
                    "type": "http",
                    "url": f"https://user:{_SECRET_FLAG}@hooks.example.com/path?key={_SECRET_FLAG}",
                    "headers": {"X-Api-Key": _SECRET_HEADER},
                }
            ]
        ),
    )

    (hook,) = _by_subtype(_run(tmp_path), "hook")

    assert hook.attributes["url_host"] == "hooks.example.com"
    assert hook.attributes["header_names"] == "X-Api-Key"


def test_an_unknown_event_and_handler_type_still_produce_a_node_and_a_diagnostic(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"FutureEvent": [{"hooks": [{"type": "teleport", "command": "x"}]}]}},
    )

    result = _run(tmp_path)

    (hook,) = _by_subtype(result, "hook")
    assert hook.security_attributes.code_execution == "unknown"
    assert "INCOMPLETE-UNRECOGNIZED-KEY" in _codes(result)
    message = next(
        d.message for d in result.diagnostics if d.code == "INCOMPLETE-UNRECOGNIZED-KEY"
    )
    assert "hooks.FutureEvent" in message


def test_every_documented_event_is_recognized(tmp_path: Path) -> None:
    hooks = {
        event: [{"hooks": [{"type": "command", "command": "true"}]}]
        for event in sorted(claude_code.HOOK_EVENTS)
    }
    _write(tmp_path, ".claude/settings.json", {"hooks": hooks})

    result = _run(tmp_path)

    assert len(_by_subtype(result, "hook")) == len(claude_code.HOOK_EVENTS) == 33
    assert result.diagnostics == ()


# --- Helper commands ------------------------------------------------------


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("apiKeyHelper", "./get-key.sh"),
        ("awsAuthRefresh", "aws sso login"),
        ("awsCredentialExport", "./export.sh"),
        ("gcpAuthRefresh", "gcloud auth login"),
        ("otelHeadersHelper", "./otel.sh"),
        ("processWrapper", "/opt/launcher"),
        ("statusLine", {"type": "command", "command": "jq -r .model"}),
        ("subagentStatusLine", {"type": "command", "command": "./rows.sh"}),
        ("fileSuggestion", {"type": "command", "command": "./files.sh"}),
        ("policyHelper", {"path": "/usr/local/bin/policy", "timeoutMs": 5000}),
    ],
)
def test_helper_commands_are_code_execution_invoked_by_the_host(
    tmp_path: Path, setting: str, value: object
) -> None:
    _write(tmp_path, ".claude/settings.json", {setting: value})

    result = _run(tmp_path)
    (helper,) = _by_subtype(result, "helper-command")

    assert helper.attributes["setting"] == setting
    assert helper.security_attributes.code_execution is True
    assert any(
        edge.source == _HOST_ID
        and edge.target == helper.id
        and edge.type is EdgeType.INVOKES
        for edge in result.edges
    )


# --- Permission rules -----------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "wildcard"),
    [
        ("Bash", True),
        ("Bash(*)", True),
        ("Bash(npm run *)", True),
        ("Bash(git:*)", True),
        ("Bash(npm test)", False),
        ("PowerShell(Get-*)", True),
        ("Read(**)", True),
        ("Read(./src/**)", False),
        ("WebFetch", True),
        ("WebFetch(domain:example.com)", False),
        ("mcp__github", True),
        ("mcp__github__*", True),
        ("mcp__github__create_issue", False),
        ("mcp__*", True),
        ("*", True),
    ],
)
def test_wildcard_classification_follows_the_documented_rule_syntax(
    rule: str, wildcard: bool
) -> None:
    assert classify_permission_rule(rule)[1] is wildcard


def test_allow_ask_and_deny_rules_become_permission_nodes_with_edges(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "permissions": {
                "allow": ["Bash(*)"],
                "ask": ["Bash(git push *)"],
                "deny": ["Read(./.env)"],
            }
        },
    )

    result = _run(tmp_path)
    rules = {
        node.attributes["effect"]: node
        for node in _by_subtype(result, "permission-rule")
    }

    assert set(rules) == {"allow", "ask", "deny"}
    assert rules["allow"].attributes["pattern"] == "Bash(*)"
    assert rules["allow"].security_attributes.wildcard is True
    edge_types = {
        node.attributes["effect"]: next(
            edge.type for edge in result.edges if edge.target == node.id
        )
        for node in rules.values()
    }
    assert edge_types == {
        "allow": EdgeType.PERMITTED_BY,
        "ask": EdgeType.CONSTRAINED_BY,
        "deny": EdgeType.CONSTRAINED_BY,
    }


# --- Modes, directories, env ----------------------------------------------


@pytest.mark.parametrize(
    ("mode", "bypass"),
    [
        ("bypassPermissions", True),
        ("acceptEdits", False),
        ("plan", False),
        ("someday", "unknown"),
    ],
)
def test_default_mode_sets_bypass_mode_on_the_host(
    tmp_path: Path, mode: str, bypass: object
) -> None:
    _write(tmp_path, ".claude/settings.json", {"permissions": {"defaultMode": mode}})

    host = _host(_run(tmp_path))

    assert host.attributes["default_mode"] == mode
    assert host.security_attributes.bypass_mode == bypass


def test_mode_and_sandbox_flags_are_host_attributes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "disableAllHooks": True,
            "disableSkillShellExecution": True,
            "permissions": {"disableBypassPermissionsMode": "disable"},
            "sandbox": {"enabled": False, "allowUnsandboxedCommands": True},
        },
    )

    attributes = _host(_run(tmp_path)).attributes

    assert attributes["disable_all_hooks"] == "true"
    assert attributes["disable_skill_shell_execution"] == "true"
    assert attributes["disable_bypass_permissions_mode"] == "disable"
    assert attributes["sandbox_enabled"] == "false"
    assert attributes["sandbox_allow_unsandboxed_commands"] == "true"


def test_additional_directories_are_resources_read_and_written(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "permissions": {
                "additionalDirectories": ["../shared", "/home/someone/private"]
            }
        },
    )

    result = _run(tmp_path)
    directories = _by_subtype(result, "additional-directory")

    assert sorted(node.attributes["path"] for node in directories) == [
        "../shared",
        "<outside-repository>",
    ]
    for node in directories:
        assert node.type is NodeType.RESOURCE
        assert {edge.type for edge in result.edges if edge.target == node.id} == {
            EdgeType.READS,
            EdgeType.WRITES,
        }
    assert "/home/someone" not in json.dumps(
        [node.model_dump(mode="json") for node in result.nodes]
    )


def test_env_records_names_never_values(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {"env": {"B_TOKEN": _SECRET_ENV_VALUE, "A_NAME": "x"}},
    )

    result = _run(tmp_path)

    assert _host(result).attributes["env_names"] == "A_NAME,B_TOKEN"
    assert _SECRET_ENV_VALUE not in result.model_dump_json()


# --- Plugins, marketplaces, MCP approval keys -----------------------------


@pytest.mark.parametrize(
    ("source", "pinned"),
    [
        ({"source": "github", "repo": "acme/plugins"}, False),
        ({"source": "github", "repo": "acme/plugins", "ref": "main"}, False),
        ({"source": "github", "repo": "acme/plugins", "sha": "a" * 40}, True),
        (
            {"source": "git", "url": "https://git.example.com/p.git", "ref": "b" * 40},
            True,
        ),
        ({"source": "directory", "path": "./plugins"}, True),
        ({"source": "directory", "path": "/opt/plugins"}, "unknown"),
        ({"source": "url", "url": "https://example.com/marketplace.json"}, False),
    ],
)
def test_marketplace_source_and_pin_status(
    tmp_path: Path, source: dict[str, object], pinned: object
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {"extraKnownMarketplaces": {"team": {"source": source}}},
    )

    (marketplace,) = _by_subtype(_run(tmp_path), "marketplace")

    assert marketplace.attributes["source_type"] == source["source"]
    assert marketplace.security_attributes.pinned == pinned


def test_enabled_plugins_attach_to_the_host_and_their_marketplace(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "enabledPlugins": {"fmt@team": True, "old@team": False},
            "extraKnownMarketplaces": {
                "team": {"source": {"source": "github", "repo": "acme/p"}}
            },
        },
    )

    result = _run(tmp_path)
    plugins = {node.name: node for node in _by_subtype(result, "plugin")}
    (marketplace,) = _by_subtype(result, "marketplace")

    assert set(plugins) == {"plugin fmt@team", "plugin old@team"}
    assert plugins["plugin fmt@team"].security_attributes.pinned == "unknown"
    invoked = {
        edge.target
        for edge in result.edges
        if edge.source == _HOST_ID and edge.type is EdgeType.INVOKES
    }
    assert plugins["plugin fmt@team"].id in invoked
    assert plugins["plugin old@team"].id not in invoked
    assert any(
        edge.source == plugins["plugin fmt@team"].id and edge.target == marketplace.id
        for edge in result.edges
    )


def test_a_marketplace_headers_helper_is_a_helper_command(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "extraKnownMarketplaces": {
                "corp": {
                    "source": {
                        "source": "url",
                        "url": "https://plugins.example.com/m.json",
                        "headers": {"Authorization": _SECRET_HEADER},
                        "headersHelper": "./print-headers.sh",
                    }
                }
            }
        },
    )

    result = _run(tmp_path)
    (helper,) = _by_subtype(result, "helper-command")

    assert helper.attributes["setting"] == "headersHelper"
    assert _SECRET_HEADER not in result.model_dump_json()


def test_mcp_approvals_link_to_the_same_server_node_the_mcp_adapter_emits(
    tmp_path: Path,
) -> None:
    """One edge per project server from the host, carrying the approval
    state; a rejection wins over an approval; the server node is the MCP
    adapter's own, merged rather than duplicated."""

    _write(
        tmp_path,
        ".mcp.json",
        {
            "mcpServers": {
                "files": {"command": "npx", "args": ["mcp-files"]},
                "mail": {"command": "npx", "args": ["mcp-mail"]},
                "both": {"command": "npx", "args": ["mcp-both"]},
                "quiet": {"command": "npx", "args": ["mcp-quiet"]},
            }
        },
    )
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "enabledMcpjsonServers": ["files", "both"],
            "disabledMcpjsonServers": ["mail", "both"],
        },
    )

    result = _run(tmp_path, with_mcp_adapter=True)
    servers = {
        node.name: node for node in result.nodes if node.subtype == "mcp-server-stdio"
    }

    assert sorted(servers) == ["both", "files", "mail", "quiet"]

    def host_edges(name: str) -> list:  # type: ignore[type-arg]
        return [
            edge
            for edge in result.edges
            if edge.source == _HOST_ID and edge.target == servers[name].id
        ]

    (files_edge,) = host_edges("files")
    assert files_edge.type is EdgeType.INVOKES
    assert files_edge.security_attributes.approval_present is True
    assert files_edge.security_attributes.wildcard is False
    for rejected in ("mail", "both"):
        assert [edge.type for edge in host_edges(rejected)] == [EdgeType.CONSTRAINED_BY]
    (quiet_edge,) = host_edges("quiet")
    assert quiet_edge.type is EdgeType.INVOKES
    assert quiet_edge.security_attributes.requires_approval is True
    assert quiet_edge.security_attributes.approval_present is False


def test_mcp_json_alone_makes_a_claude_code_host(tmp_path: Path) -> None:
    """The declaring host appears even without settings."""

    _write(tmp_path, ".mcp.json", {"mcpServers": {"files": {"command": "npx"}}})

    result = _run(tmp_path)
    host = _host(result)

    assert {evidence.path for evidence in host.evidence} == {".mcp.json"}
    assert any(edge.source == _HOST_ID for edge in result.edges)


def test_an_mcp_allow_rule_is_a_per_tool_approval_on_its_server(tmp_path: Path) -> None:
    """`mcp__<server>__<tool>` allow rules attach to the
    server they name, with the server name normalized as Claude Code
    does (`.` and spaces become `_`)."""

    _write(tmp_path, ".mcp.json", {"mcpServers": {"my.server": {"command": "npx"}}})
    _write(
        tmp_path,
        ".claude/settings.json",
        {"permissions": {"allow": ["mcp__my_server__send", "mcp__other__x"]}},
    )

    result = _run(tmp_path)
    (server,) = [node for node in result.nodes if node.subtype == "mcp-server-stdio"]
    rules = {
        node.attributes["pattern"]: node
        for node in _by_subtype(result, "permission-rule")
    }
    approved = [
        edge.target
        for edge in result.edges
        if edge.source == server.id and edge.type is EdgeType.PERMITTED_BY
    ]

    assert approved == [rules["mcp__my_server__send"].id]


def test_enable_all_project_servers_is_a_wildcard_approval(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".mcp.json",
        {"mcpServers": {"a": {"command": "x"}, "b": {"url": "https://b.example.com"}}},
    )
    _write(tmp_path, ".claude/settings.json", {"enableAllProjectMcpServers": True})

    result = _run(tmp_path)
    approvals = [
        edge
        for edge in result.edges
        if edge.type is EdgeType.INVOKES and edge.security_attributes.approval_present
    ]

    assert len(approvals) == 2
    assert all(edge.security_attributes.wildcard is True for edge in approvals)


def test_an_unresolved_server_name_is_a_diagnostic_not_a_dangling_edge(
    tmp_path: Path,
) -> None:
    _write(tmp_path, ".claude/settings.json", {"enabledMcpjsonServers": ["ghost"]})

    result = _run(tmp_path)
    node_ids = {node.id for node in result.nodes}

    assert "INCOMPLETE-UNRESOLVED-REFERENCE" in _codes(result)
    assert all(
        edge.source in node_ids and edge.target in node_ids for edge in result.edges
    )


def test_server_command_and_url_entries_become_rules(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "allowedMcpServers": [{"serverUrl": "https://*.example.com/*"}],
            "deniedMcpServers": [{"serverCommand": ["npx", "evil"]}],
        },
    )

    rules = {
        node.attributes["effect"]: node
        for node in _by_subtype(_run(tmp_path), "permission-rule")
    }

    assert rules["allow"].security_attributes.wildcard is True
    assert rules["deny"].security_attributes.wildcard is False


# --- Unknown keys and the pinned key set ----------------------------------


def test_unknown_keys_produce_one_diagnostic_naming_each_key_path(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "brandNewKey": 1,
            "permissions": {"futurePermission": True},
            "sandbox": {"network": {"newKnob": 1}},
        },
    )

    result = _run(tmp_path)
    diagnostics = [
        d for d in result.diagnostics if d.code == "INCOMPLETE-UNRECOGNIZED-KEY"
    ]

    assert len(diagnostics) == 1
    for key in (
        "brandNewKey",
        "permissions.futurePermission",
        "sandbox.network.newKnob",
    ):
        assert key in diagnostics[0].message
    assert diagnostics[0].incomplete is True


def test_documented_keys_produce_no_unknown_diagnostic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "$schema": "https://json.schemastore.org/claude-code-settings.json",
            "model": "opus",
            "theme": "dark",
            "includeCoAuthoredBy": False,
        },
    )

    assert _run(tmp_path).diagnostics == ()


def test_the_key_set_is_pinned_and_reported() -> None:
    from controlloop.adapters import AGENT_HOST_DOCUMENTATION_SNAPSHOTS

    assert claude_code.DOCUMENTATION_SNAPSHOT == "2026-10-17"
    assert AGENT_HOST_DOCUMENTATION_SNAPSHOTS["claude-code"] == "2026-10-17"
    # 184 top-level keys with their own heading in the settings reference
    # on 2026-10-17, plus `$schema` and `remote` (documented only through
    # its child `remote.defaultEnvironmentId`). Changing the set means
    # re-reading the reference and moving DOCUMENTATION_SNAPSHOT.
    assert len(claude_code._TOP_LEVEL_KEYS) == 186


# --- Malformed input, isolation, no execution -----------------------------


@pytest.mark.parametrize(
    "content",
    ["{ not json", "[1, 2, 3]", '"just a string"', '{"a": /* unterminated', "\udcff"],
)
def test_malformed_settings_become_a_diagnostic(tmp_path: Path, content: str) -> None:
    target = tmp_path / ".claude/settings.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(content.encode("utf-8", "surrogateescape"))

    result = _run(tmp_path)

    assert result.nodes == ()
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]


def test_jsonc_comments_and_trailing_commas_are_read(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        (
            "{\n  // a comment\n"
            '  "permissions": {"allow": ["Bash(npm test)",],}, /* block */\n'
            '  "env": {"URL": "http://x//y"},\n}'
        ),
    )

    result = _run(tmp_path)

    assert [
        node.attributes["pattern"] for node in _by_subtype(result, "permission-rule")
    ] == ["Bash(npm test)"]
    assert result.diagnostics == ()


def test_a_broken_local_file_does_not_discard_the_shared_one(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {"permissions": {"allow": ["Bash(npm test)"]}},
    )
    _write(tmp_path, ".claude/settings.local.json", "{ broken")

    result = _run(tmp_path)

    assert len(_by_subtype(result, "permission-rule")) == 1
    assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)


@pytest.mark.parametrize(
    "payload",
    [
        {"hooks": []},
        {"hooks": {"Stop": "x"}},
        {"hooks": {"Stop": [{"hooks": "x"}]}},
        {"hooks": {"Stop": [{"hooks": [1]}]}},
        {"permissions": {"allow": "Bash"}},
        {"permissions": {"allow": [1, ""]}},
        {"apiKeyHelper": 7},
        {"statusLine": {"type": "command"}},
        {"enabledPlugins": {"x@y": "yes"}},
        {"env": ["A"]},
    ],
)
def test_wrong_typed_values_become_diagnostics_not_crashes(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    _write(tmp_path, ".claude/settings.json", payload)

    result = _run(tmp_path)

    assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)
    assert "INCOMPLETE-ADAPTER-FAILURE" not in _codes(result)


def test_the_module_imports_no_process_or_network_primitive() -> None:
    for module in ("claude_code.py", "agent_authority.py"):
        source = (Path(claude_code.__file__).parent / module).read_text(
            encoding="utf-8"
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in (
                node.names
                if isinstance(node, ast.Import)
                else [ast.alias(name=node.module or "")]
            )
        }
        assert not imported & {
            "subprocess",
            "socket",
            "urllib",
            "http",
            "requests",
            "os",
        }


def test_discovery_runs_inside_the_adapter_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner wraps discovery in `adapter_sandbox`; a hook command is
    recorded as data and never reaches a process call."""

    import subprocess

    calls: list[object] = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    _write(
        tmp_path,
        ".claude/settings.json",
        _settings_with_hooks([{"type": "command", "command": "touch pwned"}]),
    )

    result = _run(tmp_path)

    assert calls == []
    assert not (tmp_path / "pwned").exists()
    assert "INCOMPLETE-ADAPTER-FAILURE" not in _codes(result)


# --- Boundary, determinism, privacy ---------------------------------------


def test_entries_past_the_bound_are_disclosed(tmp_path: Path) -> None:
    rules = [f"Bash(task-{i})" for i in range(600)]
    _write(tmp_path, ".claude/settings.json", {"permissions": {"allow": rules}})

    result = _run(tmp_path)

    assert len(_by_subtype(result, "permission-rule")) == 512
    assert "INCOMPLETE-BOUND-EXCEEDED" in _codes(result)


def test_an_oversized_command_is_truncated_at_the_declared_bound(
    tmp_path: Path,
) -> None:
    command = "echo " + "a" * 4096 + " TAIL-NOT-RECORDED"
    _write(
        tmp_path,
        ".claude/settings.json",
        _settings_with_hooks([{"type": "command", "command": command}]),
    )

    (hook,) = _by_subtype(_run(tmp_path), "hook")

    assert len(hook.attributes["command"]) == MAX_ATTRIBUTE_VALUE_LENGTH
    assert "TAIL-NOT-RECORDED" not in hook.attributes["command"]


def test_reformatting_and_key_order_do_not_change_the_result(tmp_path: Path) -> None:
    payload = {
        "permissions": {"deny": ["Read(./.env)"], "allow": ["Bash(npm test)"]},
        "hooks": {"Stop": [{"hooks": [{"command": "say done", "type": "command"}]}]},
        "apiKeyHelper": "./k.sh",
    }
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write(first, ".claude/settings.json", json.dumps(payload))
    reordered = {key: payload[key] for key in reversed(list(payload))}
    _write(
        second, ".claude/settings.json", json.dumps(reordered, indent=4, sort_keys=True)
    )

    assert _run(first).model_dump_json() == _run(second).model_dump_json()


def test_protected_values_never_appear_anywhere_in_the_result(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/settings.json",
        {
            "env": {"SERVICE_TOKEN": _SECRET_ENV_VALUE},
            "apiKeyHelper": f"echo {_SECRET_TOKEN}",
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "prompt", "prompt": _SECRET_PROMPT},
                            {
                                "type": "command",
                                "command": f"deploy --token={_SECRET_FLAG}",
                            },
                            {
                                "type": "command",
                                "command": f"API_KEY={_SECRET_FLAG} ./run.sh",
                            },
                            {
                                "type": "command",
                                "command": f"deploy --key {_SECRET_FLAG}",
                            },
                            {
                                "type": "http",
                                "url": "https://h.example.com",
                                "headers": {"Authorization": _SECRET_HEADER},
                            },
                        ]
                    }
                ]
            },
            _SECRET_FLAG: "an unknown key whose value is never echoed",
        },
    )

    rendered = _run(tmp_path).model_dump_json()

    for canary in (
        _SECRET_ENV_VALUE,
        _SECRET_TOKEN,
        _SECRET_PROMPT,
        _SECRET_HEADER,
        "an unknown key",
    ):
        assert canary not in rendered
    # The flag values are scrubbed from commands; the unknown key's
    # name is configuration structure and is named in the diagnostic.
    assert f"--token={_SECRET_FLAG}" not in rendered
    assert f"API_KEY={_SECRET_FLAG}" not in rendered
    assert f"--key {_SECRET_FLAG}" not in rendered
