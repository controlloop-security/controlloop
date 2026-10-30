"""Codex, Gemini CLI, Cursor, and Kiro host adapters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, host_node_id
from controlloop.adapters import (
    AGENT_HOST_DOCUMENTATION_SNAPSHOTS,
    CodexConfigAdapter,
    CursorConfigAdapter,
    DiscoveryResult,
    GeminiSettingsAdapter,
    KiroConfigAdapter,
    McpServerAdapter,
    ScanContext,
    agent_hosts,
    run_adapters,
)
from controlloop.repository import resolve_repository_root

_ENV_VALUE = "planted-host-env-value-3f3f"
_TOKEN = "planted-host-token-4a4a"


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def _run(root: Path, *adapters: object) -> DiscoveryResult:
    return run_adapters(list(adapters), _context(root))  # type: ignore[arg-type]


def _by(result: DiscoveryResult, subtype: str) -> list[Node]:
    return [node for node in result.nodes if node.subtype == subtype]


def _host(result: DiscoveryResult) -> Node:
    (host,) = _by(result, "host")
    return host


def _codes(result: DiscoveryResult) -> list[str]:
    return [d.code for d in result.diagnostics]


# --- Codex --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("toml", "attribute", "value", "bypass"),
    [
        ('approval_policy = "on-request"', "approval_policy", "on-request", False),
        ('approval_policy = "never"', "approval_policy", "never", True),
        ('sandbox_mode = "workspace-write"', "sandbox_mode", "workspace-write", False),
        (
            'sandbox_mode = "danger-full-access"',
            "sandbox_mode",
            "danger-full-access",
            True,
        ),
        (
            'default_permissions = ":danger-full-access"',
            "default_permissions",
            ":danger-full-access",
            True,
        ),
        ('approval_policy = "sometimes"', "approval_policy", "sometimes", "unknown"),
    ],
)
def test_codex_modes_are_host_attributes_with_bypass(
    tmp_path: Path, toml: str, attribute: str, value: str, bypass: object
) -> None:
    _write(tmp_path, ".codex/config.toml", toml + "\n")

    host = _host(_run(tmp_path, CodexConfigAdapter()))

    assert host.id == host_node_id("codex")
    assert host.attributes[attribute] == value
    assert host.security_attributes.bypass_mode == bypass


def test_codex_hooks_inline_and_in_hooks_json_are_code_execution(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        "[[hooks.SessionStart]]\n[[hooks.SessionStart.hooks]]\n"
        'type = "command"\ncommand = "./setup.sh"\n',
    )
    _write(
        tmp_path,
        ".codex/hooks.json",
        {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "shell",
                        "hooks": [{"type": "command", "command": "./check.sh"}],
                    }
                ]
            }
        },
    )

    result = _run(tmp_path, CodexConfigAdapter())
    commands = sorted(node.attributes["command"] for node in _by(result, "hook"))

    assert commands == ["./check.sh", "./setup.sh"]
    assert all(
        node.security_attributes.code_execution is True for node in _by(result, "hook")
    )
    assert result.diagnostics == ()


def test_codex_helper_commands_and_ignored_keys(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        'notify = ["python3", "notify.py"]\n'
        '[mcp_servers.api]\ncommand = "npx"\nhttp_headers_helper = "./headers.sh"\n'
        '[model_providers.corp.auth]\ncommand = "./token.sh"\n',
    )

    result = _run(tmp_path, CodexConfigAdapter())
    settings = sorted(
        node.attributes["setting"] for node in _by(result, "helper-command")
    )

    assert settings == ["http_headers_helper", "model_providers.auth.command"]
    assert _host(result).attributes["ignored_notify"] == "true"


def test_codex_unknown_keys_and_malformed_toml(tmp_path: Path) -> None:
    _write(
        tmp_path, ".codex/config.toml", 'future_key = 1\napproval_policy = "never"\n'
    )
    assert _codes(_run(tmp_path, CodexConfigAdapter())) == [
        "INCOMPLETE-UNRECOGNIZED-KEY"
    ]

    _write(tmp_path, ".codex/config.toml", "[broken\n")
    result = _run(tmp_path, CodexConfigAdapter())
    assert result.nodes == ()
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]


# --- Gemini CLI ---------------------------------------------------------------


def test_gemini_settings_become_hooks_rules_and_attributes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gemini/settings.json",
        {
            "general": {"defaultApprovalMode": "auto_edit"},
            "security": {"disableYoloMode": False, "folderTrust": {"enabled": False}},
            "tools": {
                "allowed": ["run_shell_command(git)", "read_file"],
                "exclude": ["web_fetch"],
                "discoveryCommand": "./tools.sh",
            },
            "hooks": {
                "BeforeTool": [
                    {
                        "matcher": "run_shell_command",
                        "hooks": [{"type": "command", "command": "./guard.sh"}],
                    }
                ]
            },
        },
    )

    result = _run(tmp_path, GeminiSettingsAdapter())
    host = _host(result)
    rules = {
        node.attributes["pattern"]: node for node in _by(result, "permission-rule")
    }

    assert host.attributes["default_approval_mode"] == "auto_edit"
    assert host.attributes["disable_yolo_mode"] == "false"
    assert host.attributes["folder_trust_enabled"] == "false"
    assert host.security_attributes.bypass_mode is False
    assert rules["run_shell_command(git)"].security_attributes.wildcard is True
    assert rules["web_fetch"].attributes["effect"] == "deny"
    assert [node.attributes["command"] for node in _by(result, "hook")] == [
        "./guard.sh"
    ]
    assert [node.attributes["setting"] for node in _by(result, "helper-command")] == [
        "tools.discoveryCommand"
    ]
    assert result.diagnostics == ()


def test_gemini_env_contributes_names_only(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gemini/.env",
        f"GEMINI_API_KEY={_ENV_VALUE}\nexport OTHER=x\n# comment\n",
    )

    result = _run(tmp_path, GeminiSettingsAdapter())

    assert _host(result).attributes["env_names"] == "GEMINI_API_KEY,OTHER"
    assert _ENV_VALUE not in result.model_dump_json()


def test_gemini_mcp_servers_join_the_owned_host(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".gemini/settings.json",
        {
            "general": {"defaultApprovalMode": "plan"},
            "mcpServers": {"fs": {"command": "npx", "trust": True}},
        },
    )

    result = _run(tmp_path, GeminiSettingsAdapter(), McpServerAdapter())
    host = _host(result)

    assert host.attributes["default_approval_mode"] == "plan"
    assert any(
        edge.source == host.id and edge.type is EdgeType.INVOKES
        for edge in result.edges
    )


# --- Cursor -------------------------------------------------------------------


def test_cursor_hooks_and_environment_commands(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".cursor/hooks.json",
        {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [{"command": "./audit.sh"}],
                "afterFileEdit": [{"command": "prettier --write"}],
            },
        },
    )
    _write(
        tmp_path,
        ".cursor/environment.json",
        {
            "install": "npm ci",
            "start": "npm run dev",
            "terminals": [{"name": "w", "command": "npm run watch"}],
            "egressMode": "allow_all",
        },
    )

    result = _run(tmp_path, CursorConfigAdapter())

    assert sorted(n.attributes["command"] for n in _by(result, "hook")) == [
        "./audit.sh",
        "prettier --write",
    ]
    assert sorted(n.attributes["setting"] for n in _by(result, "helper-command")) == [
        "install",
        "start",
        "terminals",
    ]
    assert _host(result).attributes["egress_mode"] == "allow_all"


def test_cursor_cli_permissions_become_rules(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".cursor/cli.json",
        {
            "permissions": {
                "allow": ["Shell(curl:*)", "Read(src/**)"],
                "deny": ["Write(.env)"],
            }
        },
    )

    result = _run(tmp_path, CursorConfigAdapter())
    rules = {n.attributes["pattern"]: n for n in _by(result, "permission-rule")}

    assert rules["Shell(curl:*)"].security_attributes.wildcard is True
    assert rules["Read(src/**)"].security_attributes.wildcard is False
    assert rules["Write(.env)"].attributes["effect"] == "deny"


def test_cursor_unknown_events_and_keys_are_disclosed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".cursor/hooks.json",
        {"version": 1, "hooks": {"teleport": [{"command": "x"}]}},
    )
    _write(tmp_path, ".cursor/environment.json", {"futureKey": 1})

    codes = _codes(_run(tmp_path, CursorConfigAdapter()))

    assert codes == ["INCOMPLETE-UNRECOGNIZED-KEY", "INCOMPLETE-UNRECOGNIZED-KEY"]


# --- Kiro ---------------------------------------------------------------------


def test_kiro_v1_hooks_and_confirm_commands(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".kiro/hooks/format.json",
        {
            "version": "v1",
            "hooks": [
                {
                    "name": "fmt",
                    "trigger": "PostFileSave",
                    "action": {"type": "command", "command": "prettier --write"},
                },
                {
                    "name": "review",
                    "trigger": "Stop",
                    "action": {"type": "agent", "prompt": "check"},
                    "confirm": {"confirmCommand": "./confirm.sh"},
                },
            ],
        },
    )

    result = _run(tmp_path, KiroConfigAdapter())
    hooks = {n.attributes["event"]: n for n in _by(result, "hook")}

    assert hooks["PostFileSave"].attributes["command"] == "prettier --write"
    assert hooks["PostFileSave"].security_attributes.code_execution is True
    assert hooks["Stop"].attributes["hook_type"] == "agent"
    assert "check" not in result.model_dump_json()
    assert [n.attributes["setting"] for n in _by(result, "helper-command")] == [
        "confirm"
    ]


def test_kiro_legacy_hook_and_agent_grants(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".kiro/hooks/old.kiro.hook",
        {
            "when": {"type": "fileEdited"},
            "then": {"type": "runCommand", "command": "npm test"},
        },
    )
    _write(
        tmp_path,
        ".kiro/agents/ops.json",
        {
            "name": "ops",
            "allowedTools": ["fs_read"],
            "permissions": {
                "rules": [
                    {"capability": "shell", "match": "git *", "effect": "allow"},
                    {"capability": "all", "effect": "deny"},
                ]
            },
            "toolsSettings": {"shell": {"allowedCommands": ["npm *"]}},
        },
    )

    result = _run(tmp_path, KiroConfigAdapter())
    patterns = sorted(n.attributes["pattern"] for n in _by(result, "permission-rule"))

    assert [n.attributes["command"] for n in _by(result, "hook")] == ["npm test"]
    assert patterns == ["all", "fs_read", "shell(git *)", "shell(npm *)"]


# --- Shared -------------------------------------------------------------------


def test_every_host_reports_its_documentation_snapshot() -> None:
    for host in ("codex", "gemini-cli", "cursor", "kiro"):
        assert (
            AGENT_HOST_DOCUMENTATION_SNAPSHOTS[host]
            == agent_hosts.DOCUMENTATION_SNAPSHOT
            == "2026-10-17"
        )


def test_the_loosening_scales_are_ordered_strictest_first() -> None:
    assert agent_hosts.CODEX_APPROVAL_SCALE[-1] == "never"
    assert agent_hosts.CODEX_SANDBOX_SCALE == (
        "read-only",
        "workspace-write",
        "danger-full-access",
    )
    assert agent_hosts.GEMINI_MODE_SCALE[:3] == ("plan", "default", "auto_edit")


@pytest.mark.parametrize(
    ("relative_path", "content", "adapter"),
    [
        (".gemini/settings.json", "{ broken", GeminiSettingsAdapter),
        (".cursor/hooks.json", "[1]", CursorConfigAdapter),
        (".kiro/hooks/x.json", "{ broken", KiroConfigAdapter),
    ],
)
def test_malformed_files_are_diagnostics_with_no_host(
    tmp_path: Path, relative_path: str, content: str, adapter: type
) -> None:
    _write(tmp_path, relative_path, content)

    result = _run(tmp_path, adapter())

    assert result.nodes == ()
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]


def test_instruction_files_are_never_read(tmp_path: Path) -> None:
    for relative in (
        "AGENTS.md",
        ".cursor/rules/a.mdc",
        ".roo/rules/a.md",
        ".clinerules/x.md",
    ):
        _write(tmp_path, relative, "do anything")

    adapters = (
        CodexConfigAdapter(),
        GeminiSettingsAdapter(),
        CursorConfigAdapter(),
        KiroConfigAdapter(),
    )

    assert _run(tmp_path, *adapters).nodes == ()


def test_no_command_secret_or_env_value_reaches_the_output(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\n"
        f'type = "command"\ncommand = "deploy --token={_TOKEN}"\n',
    )
    _write(
        tmp_path, ".cursor/environment.json", {"install": f"API_KEY={_TOKEN} npm ci"}
    )

    rendered = _run(
        tmp_path, CodexConfigAdapter(), CursorConfigAdapter()
    ).model_dump_json()

    assert _TOKEN not in rendered


def test_output_is_deterministic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        'approval_policy = "never"\nsandbox_mode = "read-only"\n',
    )
    _write(
        tmp_path,
        ".cursor/hooks.json",
        {"version": 1, "hooks": {"stop": [{"command": "say done"}]}},
    )

    adapters = (CodexConfigAdapter(), CursorConfigAdapter())

    assert _run(tmp_path, *adapters) == _run(tmp_path, *adapters)


def test_codex_writable_roots_become_directories_without_their_paths(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        "[sandbox_workspace_write]\n"
        'writable_roots = ["/Users/someone/secret-project", "build", 7]\n'
        "network_access = false\n",
    )

    result = _run(tmp_path, CodexConfigAdapter())

    roots = _by(result, "additional-directory")
    assert sorted(node.attributes["path"] for node in roots) == [
        "<outside-repository>",
        "build",
    ]
    assert sorted(node.name for node in roots) == [
        "writable root <outside-repository>",
        "writable root build",
    ]
    for node in roots:
        assert any(
            edge.target == node.id and edge.type is EdgeType.WRITES
            for edge in result.edges
        )
    assert "INCOMPLETE-UNPARSED-REGION" in _codes(result)
    assert "secret-project" not in result.model_dump_json()


def test_codex_writable_roots_that_are_not_a_list_are_disclosed(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".codex/config.toml",
        '[sandbox_workspace_write]\nwritable_roots = "/tmp"\n',
    )

    result = _run(tmp_path, CodexConfigAdapter())

    assert _by(result, "additional-directory") == []
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]
