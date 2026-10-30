"""The Roo Code custom modes adapter: `.roomodes` tool groups as rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from controlloop.acbom import EdgeType, Node, host_node_id
from controlloop.adapters import (
    AGENT_HOST_DOCUMENTATION_SNAPSHOTS,
    ALL_ADAPTERS,
    DiscoveryResult,
    McpServerAdapter,
    RooModesAdapter,
    ScanContext,
    agent_hosts,
    run_adapters,
)
from controlloop.repository import resolve_repository_root

_PROMPT = "planted-roo-role-definition-7c7c"

_YAML = f"""\
customModes:
  - slug: docs-writer
    name: Docs Writer
    roleDefinition: {_PROMPT}
    whenToUse: {_PROMPT}
    customInstructions: {_PROMPT}
    groups:
      - read
      - - edit
        - fileRegex: \\.md$
          description: Markdown only
      - command
"""

_JSON = {
    "customModes": [
        {
            "slug": "docs-writer",
            "name": "Docs Writer",
            "roleDefinition": _PROMPT,
            "groups": [
                "read",
                ["edit", {"fileRegex": "\\.md$", "description": "Markdown only"}],
                "command",
            ],
        }
    ]
}


def _write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if isinstance(content, str) else json.dumps(content))


def _run(root: Path, *adapters: object) -> DiscoveryResult:
    context = ScanContext(root=resolve_repository_root(root))
    return run_adapters(list(adapters), context)  # type: ignore[arg-type]


def _by(result: DiscoveryResult, subtype: str) -> list[Node]:
    return [node for node in result.nodes if node.subtype == subtype]


def _rules(result: DiscoveryResult) -> dict[str, Node]:
    return {node.attributes["pattern"]: node for node in _by(result, "permission-rule")}


def _codes(result: DiscoveryResult) -> list[str]:
    return [d.code for d in result.diagnostics]


@pytest.mark.parametrize("content", [_YAML, _JSON], ids=["yaml", "json"])
def test_each_mode_is_a_subagent_and_each_group_a_rule(
    tmp_path: Path, content: object
) -> None:
    _write(tmp_path, ".roomodes", content)

    result = _run(tmp_path, RooModesAdapter())

    assert result.diagnostics == ()
    (mode,) = _by(result, "subagent")
    assert mode.name == "mode Docs Writer"
    assert mode.attributes["slug"] == "docs-writer"
    assert mode.attributes["groups"] == "read,edit,command"
    assert sorted(_rules(result)) == ["command", "edit(\\.md$)", "read"]
    (host,) = _by(result, "host")
    assert host.id == host_node_id("roo")


def test_command_and_mcp_are_wildcards(tmp_path: Path) -> None:
    """Roo does not scope `command` per command or `mcp` per server."""

    _write(
        tmp_path,
        ".roomodes",
        {"customModes": [{"slug": "ops", "groups": ["command", "mcp", "browser"]}]},
    )

    rules = _rules(_run(tmp_path, RooModesAdapter()))

    assert rules["command"].security_attributes.wildcard is True
    assert rules["command"].security_attributes.code_execution is True
    assert rules["mcp"].security_attributes.wildcard is True
    assert rules["browser"].security_attributes.wildcard is True
    assert rules["browser"].security_attributes.external_communication is True


def test_an_edit_file_regex_is_recorded_never_evaluated(tmp_path: Path) -> None:
    _write(tmp_path, ".roomodes", _YAML)

    rules = _rules(_run(tmp_path, RooModesAdapter()))

    assert rules["edit(\\.md$)"].attributes["tool"] == "edit"
    assert rules["edit(\\.md$)"].security_attributes.wildcard is False
    assert rules["read"].security_attributes.wildcard is False


def test_an_unrestricted_edit_is_a_wildcard(tmp_path: Path) -> None:
    _write(tmp_path, ".roomodes", {"customModes": [{"slug": "a", "groups": ["edit"]}]})

    rules = _rules(_run(tmp_path, RooModesAdapter()))

    assert rules["edit"].security_attributes.wildcard is True


def test_each_rule_is_held_by_the_host_and_linked_from_its_mode(
    tmp_path: Path,
) -> None:
    _write(tmp_path, ".roomodes", _YAML)

    result = _run(tmp_path, RooModesAdapter())

    (mode,) = _by(result, "subagent")
    host_id = host_node_id("roo")
    for rule in _by(result, "permission-rule"):
        sources = {
            edge.source
            for edge in result.edges
            if edge.target == rule.id and edge.type is EdgeType.PERMITTED_BY
        }
        assert sources == {host_id, mode.id}
    assert any(
        edge.source == host_id
        and edge.target == mode.id
        and edge.type is EdgeType.DELEGATES_TO
        for edge in result.edges
    )


def test_the_mode_joins_the_host_the_mcp_adapter_owns(tmp_path: Path) -> None:
    _write(tmp_path, ".roomodes", _YAML)
    _write(
        tmp_path,
        ".roo/mcp.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "files@1.0.0"]}}},
    )

    result = _run(tmp_path, RooModesAdapter(), McpServerAdapter())

    (host,) = _by(result, "host")
    assert host.attributes["docs_snapshot"] == "2026-10-17"
    assert {item.path for item in host.evidence} == {".roomodes", ".roo/mcp.json"}


def test_mcp_output_is_unchanged_without_a_roomodes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".roo/mcp.json",
        {"mcpServers": {"files": {"command": "npx", "args": ["-y", "files@1.0.0"]}}},
    )

    alone = _run(tmp_path, McpServerAdapter())
    together = _run(tmp_path, RooModesAdapter(), McpServerAdapter())

    assert alone == together


@pytest.mark.parametrize(
    "content",
    ["customModes: [unclosed", "- just\n- a list\n", "{ broken json"],
    ids=["broken-yaml", "top-level-list", "broken-json"],
)
def test_a_malformed_file_is_a_diagnostic_with_no_host(
    tmp_path: Path, content: str
) -> None:
    _write(tmp_path, ".roomodes", content)

    result = _run(tmp_path, RooModesAdapter())

    assert result.nodes == ()
    assert _codes(result) == ["INCOMPLETE-UNPARSED-REGION"]


def test_unknown_keys_and_groups_are_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        ".roomodes",
        {
            "customModes": [
                {"slug": "a", "groups": ["read", "teleport"], "color": "blue"}
            ],
            "version": 2,
        },
    )

    result = _run(tmp_path, RooModesAdapter())

    (diagnostic,) = result.diagnostics
    assert diagnostic.code == "INCOMPLETE-UNRECOGNIZED-KEY"
    for key in ("version", "customModes.a.color", "customModes.a.groups.teleport"):
        assert key in diagnostic.message
    assert sorted(_rules(result)) == ["read"]


@pytest.mark.parametrize(
    ("modes", "reason"),
    [
        ({"customModes": "not a list"}, "customModes is not a list"),
        ({"customModes": [{"name": "no slug"}]}, "no valid slug"),
        ({"customModes": [{"slug": "a"}, {"slug": "a"}]}, "share a slug"),
        ({"customModes": [{"slug": "a", "groups": ["read", "read"]}]}, "twice"),
    ],
)
def test_entries_that_cannot_be_read_are_disclosed(
    tmp_path: Path, modes: object, reason: str
) -> None:
    _write(tmp_path, ".roomodes", modes)

    result = _run(tmp_path, RooModesAdapter())

    assert any(
        d.code == "INCOMPLETE-UNPARSED-REGION" and reason in d.message
        for d in result.diagnostics
    )


def test_prompt_text_never_reaches_the_output(tmp_path: Path) -> None:
    _write(tmp_path, ".roomodes", _YAML)

    rendered = _run(tmp_path, RooModesAdapter()).model_dump_json()

    assert _PROMPT not in rendered


def test_a_roomodes_outside_the_root_is_not_claimed(tmp_path: Path) -> None:
    """The documentation names `.roomodes` at the project root only."""

    _write(tmp_path, ".roo/.roomodes", _YAML)
    _write(tmp_path, "sub/.roomodes", _YAML)

    assert _run(tmp_path, RooModesAdapter()).nodes == ()


def test_the_documentation_snapshot_is_reported() -> None:
    assert (
        AGENT_HOST_DOCUMENTATION_SNAPSHOTS["roo-code"]
        == agent_hosts.ROO_MODES_DOCUMENTATION_SNAPSHOT
        == "2026-10-29"
    )
    assert RooModesAdapter in ALL_ADAPTERS


def test_output_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, ".roomodes", _YAML)

    assert _run(tmp_path, RooModesAdapter()) == _run(tmp_path, RooModesAdapter())
