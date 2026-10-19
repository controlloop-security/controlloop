"""Tests for ClaudeCodeComponentsAdapter."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, NodeType, host_node_id
from controlloop.adapters import (
    ClaudeCodeComponentsAdapter,
    ClaudeCodeSettingsAdapter,
    DiscoveryResult,
    ScanContext,
    run_adapters,
)
from controlloop.repository import resolve_repository_root

_HOST_ID = host_node_id("claude-code")
_PROMPT = "PLANTED PROTECTED PROMPT BODY 7f7f"
_DESCRIPTION = "PLANTED DESCRIPTION TEXT 8a8a"
_ENV_VALUE = "planted-inline-env-value-9b9b"
_TOKEN = "planted-shell-token-1c1c"


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, content: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def _md(frontmatter: str, body: str = "") -> str:
    return f"---\n{textwrap.dedent(frontmatter).strip()}\n---\n{body}"


def _run(tmp_path: Path, *extra: object) -> DiscoveryResult:
    adapters = [ClaudeCodeComponentsAdapter(), *extra]
    return run_adapters(adapters, _context(tmp_path))  # type: ignore[arg-type]


def _by(result: DiscoveryResult, subtype: str) -> list[Node]:
    return [node for node in result.nodes if node.subtype == subtype]


def _targets(result: DiscoveryResult, source: str, edge_type: EdgeType) -> set[str]:
    return {
        e.target for e in result.edges if e.source == source and e.type is edge_type
    }


# --- Skills -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("relative_path", "expected_name"),
    [
        (".claude/skills/deploy/SKILL.md", "skill deploy"),
        (".agents/skills/review/SKILL.md", "skill review"),
        (".github/skills/triage/SKILL.md", "skill triage"),
        (".claude/skills/group/nested/SKILL.md", "skill nested"),
        (".claude/commands/ship.md", "skill ship"),
    ],
)
def test_skills_and_commands_are_invoked_by_the_host(
    tmp_path: Path, relative_path: str, expected_name: str
) -> None:
    _write(tmp_path, relative_path, "Just instructions.\n")

    result = _run(tmp_path)
    (skill,) = _by(result, "skill")

    assert skill.name == expected_name
    assert skill.type is NodeType.TOOL
    assert skill.id in _targets(result, _HOST_ID, EdgeType.INVOKES)
    assert [node.id for node in _by(result, "host")] == [_HOST_ID]


def test_the_frontmatter_name_wins_over_the_directory(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/skills/dir/SKILL.md", _md("name: real-name"))

    assert _by(_run(tmp_path), "skill")[0].name == "skill real-name"


@pytest.mark.parametrize(
    ("allowed", "expected"),
    [
        ("Bash(git *) Read", ["Bash(git *)", "Read"]),
        ("Bash(gh pr *), Edit", ["Bash(gh pr *)", "Edit"]),
        ("[Read, Grep]", ["Grep", "Read"]),
    ],
)
def test_allowed_tools_become_rules_the_skill_is_permitted_by(
    tmp_path: Path, allowed: str, expected: list[str]
) -> None:
    _write(
        tmp_path,
        ".claude/skills/s/SKILL.md",
        _md(f"allowed-tools: {allowed}\ndisallowed-tools: AskUserQuestion"),
    )

    result = _run(tmp_path)
    (skill,) = _by(result, "skill")
    rules = {n.id: n for n in _by(result, "permission-rule")}
    allowed_patterns = sorted(
        rules[t].attributes["pattern"]
        for t in _targets(result, skill.id, EdgeType.PERMITTED_BY)
    )
    denied = [
        rules[t].attributes["pattern"]
        for t in _targets(result, skill.id, EdgeType.CONSTRAINED_BY)
    ]

    assert allowed_patterns == expected
    assert denied == ["AskUserQuestion"]


# --- Skill hooks and shell lines --------------------------------------------


def test_skill_hooks_and_shell_lines_are_code_execution(tmp_path: Path) -> None:
    body = (
        "Context: !`git log -5`\n"
        "Not a command: KEY=!`ignored`\n"
        "```!\nnode --version\ngit status\n```\n"
    )
    _write(
        tmp_path,
        ".claude/skills/s/SKILL.md",
        _md(
            """
            hooks:
              PreToolUse:
                - matcher: Bash
                  hooks:
                    - type: command
                      command: ./check.sh
            """,
            body,
        ),
    )

    result = _run(tmp_path)
    (skill,) = _by(result, "skill")
    (hook,) = _by(result, "hook")
    shells = sorted(n.attributes["command"] for n in _by(result, "helper-command"))

    assert hook.attributes["command"] == "./check.sh"
    assert hook.id in _targets(result, skill.id, EdgeType.INVOKES)
    assert shells == ["git log -5", "git status", "node --version"]
    assert all(
        n.security_attributes.code_execution is True
        for n in _by(result, "helper-command")
    )


def test_no_body_or_description_text_is_recorded(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/skills/s/SKILL.md",
        _md(
            f"description: {_DESCRIPTION}\nallowed-tools: Read",
            f"{_PROMPT}\nRun: !`deploy --token={_TOKEN}`\n",
        ),
    )

    rendered = _run(tmp_path).model_dump_json()

    for canary in (_PROMPT, _DESCRIPTION, _TOKEN):
        assert canary not in rendered


# --- Subagents --------------------------------------------------------------


def test_a_subagent_is_delegated_to_with_its_grants_and_mode(tmp_path: Path) -> None:
    _write(tmp_path, ".mcp.json", {"mcpServers": {"github": {"command": "npx"}}})
    _write(tmp_path, ".claude/skills/deploy/SKILL.md", "x")
    _write(
        tmp_path,
        ".claude/agents/ops.md",
        _md(
            f"""
            name: ops
            tools: Read, Bash(kubectl *)
            disallowedTools: Write
            permissionMode: bypassPermissions
            skills: [deploy]
            mcpServers:
              - github
              - inline:
                  command: npx
                  args: ["-y", "ops-mcp@1.0.0"]
                  env:
                    TOKEN: {_ENV_VALUE}
            hooks:
              Stop:
                - hooks:
                    - type: command
                      command: say done
            """,
            _PROMPT,
        ),
    )

    result = _run(tmp_path)
    (subagent,) = _by(result, "subagent")
    servers = {
        n.name: n for n in result.nodes if (n.subtype or "").startswith("mcp-server")
    }

    assert subagent.type is NodeType.AGENT
    assert subagent.id in _targets(result, _HOST_ID, EdgeType.DELEGATES_TO)
    assert subagent.attributes["permission_mode"] == "bypassPermissions"
    assert subagent.security_attributes.bypass_mode is True
    invoked = _targets(result, subagent.id, EdgeType.INVOKES)
    assert {servers["github"].id, servers["inline"].id} <= invoked
    assert _by(result, "skill")[0].id in invoked
    assert _by(result, "hook")[0].id in invoked
    patterns = sorted(n.attributes["pattern"] for n in _by(result, "permission-rule"))
    assert patterns == ["Bash(kubectl *)", "Read", "Write"]
    rendered = result.model_dump_json()
    assert _ENV_VALUE not in rendered
    assert _PROMPT not in rendered


def test_a_subagent_without_tools_inherits(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/agents/a.md", _md("name: a\ndescription: d"))

    (subagent,) = _by(_run(tmp_path), "subagent")

    assert subagent.attributes["tools"] == "inherit"
    assert subagent.security_attributes.bypass_mode is None


def test_an_unknown_named_server_is_a_diagnostic(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/agents/a.md", _md("name: a\nmcpServers: [ghost]"))

    result = _run(tmp_path)

    assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNRESOLVED-REFERENCE"]


# --- Plugins and marketplaces -----------------------------------------------


def _plugin(tmp_path: Path, root: str = "plugins/fmt/") -> None:
    _write(
        tmp_path,
        f"{root}.claude-plugin/plugin.json",
        {
            "name": "fmt",
            "mcpServers": {"db": {"command": "uvx", "args": ["db-mcp==2.0"]}},
            "lspServers": {
                "go": {"command": "gopls", "extensionToLanguage": {".go": "go"}}
            },
        },
    )
    _write(
        tmp_path,
        f"{root}hooks/hooks.json",
        {
            "hooks": {
                "PostToolUse": [{"hooks": [{"type": "command", "command": "prettier"}]}]
            }
        },
    )
    _write(
        tmp_path, f"{root}skills/lint/SKILL.md", _md("allowed-tools: Bash(eslint *)")
    )
    _write(
        tmp_path,
        f"{root}agents/helper.md",
        _md("name: helper\npermissionMode: bypassPermissions\nhooks: {}"),
    )
    _write(tmp_path, f"{root}bin/fmt", "#!/bin/sh\n")


def test_a_plugin_carries_its_components_and_attaches_to_the_host(
    tmp_path: Path,
) -> None:
    _plugin(tmp_path)

    result = _run(tmp_path)
    (plugin,) = _by(result, "plugin")
    under_plugin = _targets(result, plugin.id, EdgeType.INVOKES) | _targets(
        result, plugin.id, EdgeType.DELEGATES_TO
    )

    assert plugin.id in _targets(result, _HOST_ID, EdgeType.INVOKES)
    assert plugin.attributes["source_type"] == "local"
    assert plugin.security_attributes.pinned is True
    kinds = sorted(n.subtype or "" for n in result.nodes if n.id in under_plugin)
    assert kinds == [
        "helper-command",
        "helper-command",
        "hook",
        "mcp-server-stdio",
        "skill",
        "subagent",
    ]
    settings = sorted(n.attributes["setting"] for n in _by(result, "helper-command"))
    assert settings == ["lspServers", "plugin-bin"]


def test_plugin_subagents_ignore_hooks_servers_and_mode(tmp_path: Path) -> None:
    _plugin(tmp_path)

    (subagent,) = _by(_run(tmp_path), "subagent")

    assert subagent.security_attributes.bypass_mode is None
    assert subagent.attributes["ignored_in_plugin"] == "hooks,permissionMode"


def test_a_skill_directory_with_a_plugin_manifest_is_a_plugin(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/skills/kit/.claude-plugin/plugin.json", {"name": "kit"})
    _write(tmp_path, ".claude/skills/kit/SKILL.md", "x")

    result = _run(tmp_path)

    assert [n.name for n in _by(result, "plugin")] == ["plugin kit"]
    assert _by(result, "skill") == []


@pytest.mark.parametrize(
    ("source", "source_type", "pinned", "code_execution"),
    [
        ("./plugins/fmt", "directory", True, "unknown"),
        ({"source": "github", "repo": "a/b"}, "github", False, "unknown"),
        (
            {"source": "github", "repo": "a/b", "sha": "c" * 40},
            "github",
            True,
            "unknown",
        ),
        (
            {"source": "git-subdir", "url": "https://x/r.git", "path": "p"},
            "git-subdir",
            False,
            "unknown",
        ),
        (
            {"source": "archive", "url": "https://x/p.zip", "sha256": "d" * 64},
            "archive",
            True,
            "unknown",
        ),
        ({"source": "command", "command": "./build.sh"}, "command", False, True),
    ],
)
def test_marketplace_plugins_record_source_and_pin(
    tmp_path: Path,
    source: object,
    source_type: str,
    pinned: object,
    code_execution: object,
) -> None:
    _write(
        tmp_path,
        ".claude-plugin/marketplace.json",
        {"name": "acme", "plugins": [{"name": "p", "source": source}]},
    )

    result = _run(tmp_path)
    (plugin,) = _by(result, "plugin")
    (marketplace,) = _by(result, "marketplace")

    assert plugin.attributes["source_type"] == source_type
    assert plugin.security_attributes.pinned == pinned
    assert plugin.security_attributes.code_execution == code_execution
    assert marketplace.id in _targets(result, plugin.id, EdgeType.RECEIVES_FROM)


# --- Malformed input, ownership, determinism --------------------------------


def test_unparseable_frontmatter_still_records_the_skill(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/skills/s/SKILL.md", "---\nname: [unclosed\n---\nbody\n")

    result = _run(tmp_path)

    assert [n.name for n in _by(result, "skill")] == ["skill s"]
    assert [d.code for d in result.diagnostics] == ["INCOMPLETE-UNPARSED-REGION"]


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        (".claude-plugin/plugin.json", "{ not json"),
        (".claude-plugin/marketplace.json", {"plugins": "x"}),
        (".claude/agents/a.md", "no frontmatter at all"),
    ],
)
def test_malformed_manifests_are_diagnostics_not_crashes(
    tmp_path: Path, relative_path: str, content: object
) -> None:
    _write(tmp_path, relative_path, content)

    result = _run(tmp_path)

    assert "INCOMPLETE-UNPARSED-REGION" in [d.code for d in result.diagnostics]
    assert "INCOMPLETE-ADAPTER-FAILURE" not in [d.code for d in result.diagnostics]


def test_an_unknown_hook_event_in_frontmatter_is_disclosed(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".claude/skills/s/SKILL.md",
        _md(
            """
            hooks:
              FutureEvent:
                - hooks:
                    - type: command
                      command: x
            """
        ),
    )

    codes = [d.code for d in _run(tmp_path).diagnostics]

    assert codes == ["INCOMPLETE-UNRECOGNIZED-KEY"]


def test_the_host_folds_into_the_settings_adapters_host(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/settings.json", {"permissions": {"defaultMode": "plan"}})
    _write(tmp_path, ".claude/skills/s/SKILL.md", "x")

    result = _run(tmp_path, ClaudeCodeSettingsAdapter())
    (host,) = _by(result, "host")

    assert host.attributes["default_mode"] == "plan"


def test_output_is_deterministic(tmp_path: Path) -> None:
    _plugin(tmp_path)
    _write(tmp_path, ".claude/skills/a/SKILL.md", _md("allowed-tools: Read Grep"))

    assert _run(tmp_path) == _run(tmp_path)
