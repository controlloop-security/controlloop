"""Hook and helper scripts carry a digest of the file they run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from controlloop.acbom import Node
from controlloop.adapters import (
    ClaudeCodeComponentsAdapter,
    ClaudeCodeSettingsAdapter,
    CursorConfigAdapter,
    DiscoveryResult,
    ScanContext,
    run_adapters,
)
from controlloop.adapters.script_digest import script_reference
from controlloop.repository import TraversalBounds, resolve_repository_root

_SCRIPT = b"#!/bin/sh\necho planted-script-body-5d5d\n"


def _write(root: Path, relative_path: str, content: object) -> None:
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content if isinstance(content, str) else json.dumps(content))


def _hook(root: Path, command: str) -> None:
    _write(
        root,
        ".claude/settings.json",
        {
            "hooks": {
                "SessionStart": [{"hooks": [{"type": "command", "command": command}]}]
            }
        },
    )


def _run(root: Path, *adapters: object) -> DiscoveryResult:
    context = ScanContext(root=resolve_repository_root(root))
    return run_adapters(list(adapters), context)  # type: ignore[arg-type]


def _hook_node(result: DiscoveryResult) -> Node:
    (node,) = [node for node in result.nodes if node.subtype == "hook"]
    return node


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(
    "command",
    [
        ".claude/hooks/setup.sh",
        "./.claude/hooks/setup.sh",
        '"$CLAUDE_PROJECT_DIR"/.claude/hooks/setup.sh --quiet',
        "bash .claude/hooks/setup.sh",
        "sh -e .claude/hooks/setup.sh",
        "uv run python .claude/hooks/setup.sh",
        "npx ./.claude/hooks/setup.sh",
        "FORCE=1 env bash .claude/hooks/setup.sh && echo done",
    ],
)
def test_a_script_in_the_repository_records_its_digest(
    tmp_path: Path, command: str
) -> None:
    _write(tmp_path, ".claude/hooks/setup.sh", _SCRIPT)
    _hook(tmp_path, command)

    node = _hook_node(_run(tmp_path, ClaudeCodeSettingsAdapter()))

    assert node.attributes["script_path"] == ".claude/hooks/setup.sh"
    assert node.attributes["script_digest"] == _sha(_SCRIPT)


@pytest.mark.parametrize(
    "command",
    [
        "prettier --write .",
        "npx prettier --write .",
        "python -c 'print(1)'",
        "node -e 'console.log(1)'",
        "curl https://example.invalid/install.sh",
        "python -m black .",
    ],
)
def test_a_command_that_runs_no_repository_file_records_nothing(
    tmp_path: Path, command: str
) -> None:
    _hook(tmp_path, command)

    node = _hook_node(_run(tmp_path, ClaudeCodeSettingsAdapter()))

    assert "script_digest" not in node.attributes
    assert "script_path" not in node.attributes


@pytest.mark.parametrize(
    "command", ["/usr/local/bin/audit.sh", "~/hooks/audit.sh", "../shared/audit.sh"]
)
def test_a_path_outside_the_root_is_unknown_with_a_diagnostic(
    tmp_path: Path, command: str
) -> None:
    _hook(tmp_path, command)

    result = _run(tmp_path, ClaudeCodeSettingsAdapter())

    node = _hook_node(result)
    assert node.attributes["script_digest"] == "unknown"
    assert node.attributes["script_path"] == "<outside-repository>"
    (diagnostic,) = [
        d for d in result.diagnostics if d.code == "SCRIPT-OUTSIDE-REPOSITORY"
    ]
    assert diagnostic.incomplete is False
    assert "audit" not in diagnostic.message


def test_an_oversize_script_is_unknown(tmp_path: Path) -> None:
    """The walker never lists a file over its byte bound, so the file is
    never opened."""

    oversize = TraversalBounds().max_file_size_bytes + 1
    _write(tmp_path, "scripts/big.sh", b"#" * oversize)
    _hook(tmp_path, "bash scripts/big.sh")

    node = _hook_node(_run(tmp_path, ClaudeCodeSettingsAdapter()))

    assert node.attributes["script_path"] == "scripts/big.sh"
    assert node.attributes["script_digest"] == "unknown"


def test_a_missing_script_is_unknown(tmp_path: Path) -> None:
    _hook(tmp_path, "node dist/hook.js")

    node = _hook_node(_run(tmp_path, ClaudeCodeSettingsAdapter()))

    assert node.attributes["script_digest"] == "unknown"


def test_a_symlink_that_escapes_the_root_is_never_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.sh").write_bytes(_SCRIPT)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "scripts").mkdir()
    (root / "scripts" / "link.sh").symlink_to(outside / "real.sh")
    _hook(root, "bash scripts/link.sh")

    node = _hook_node(_run(root, ClaudeCodeSettingsAdapter()))

    assert node.attributes["script_digest"] == "unknown"


def test_a_skill_shell_line_and_a_plugin_bin_record_digests(tmp_path: Path) -> None:
    _write(tmp_path, "scripts/context.py", b"print('context')\n")
    _write(
        tmp_path,
        ".claude/skills/review/SKILL.md",
        "---\nname: review\n---\nContext: !`python scripts/context.py`\n",
    )
    _write(tmp_path, "plugins/kit/.claude-plugin/plugin.json", {"name": "kit"})
    _write(tmp_path, "plugins/kit/bin/b-tool", b"#!/bin/sh\necho b\n")
    _write(tmp_path, "plugins/kit/bin/a-tool", b"#!/bin/sh\necho a\n")

    result = _run(tmp_path, ClaudeCodeComponentsAdapter())

    helpers = {
        node.attributes["setting"]: node
        for node in result.nodes
        if node.subtype == "helper-command"
    }
    shell = helpers["skill-shell"]
    assert shell.attributes["script_path"] == "scripts/context.py"
    assert shell.attributes["script_digest"] == _sha(b"print('context')\n")
    plugin_bin = helpers["plugin-bin"]
    assert plugin_bin.attributes["script_path"] == "plugins/kit/bin/"
    expected = "\n".join(
        [
            f"a-tool {_sha(b'#!/bin/sh' + bytes([10]) + b'echo a' + bytes([10]))}",
            f"b-tool {_sha(b'#!/bin/sh' + bytes([10]) + b'echo b' + bytes([10]))}",
        ]
    )
    assert plugin_bin.attributes["script_digest"] == _sha(expected.encode())


def test_other_hosts_record_digests_too(tmp_path: Path) -> None:
    _write(tmp_path, "scripts/notify.sh", _SCRIPT)
    _write(
        tmp_path,
        ".cursor/hooks.json",
        {"version": 1, "hooks": {"stop": [{"command": "./scripts/notify.sh"}]}},
    )

    node = _hook_node(_run(tmp_path, CursorConfigAdapter()))

    assert node.attributes["script_digest"] == _sha(_SCRIPT)


def test_no_script_content_reaches_the_output(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/hooks/setup.sh", _SCRIPT)
    _hook(tmp_path, "bash .claude/hooks/setup.sh")

    rendered = _run(tmp_path, ClaudeCodeSettingsAdapter()).model_dump_json()

    assert "planted-script-body" not in rendered


def test_the_digest_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/hooks/setup.sh", _SCRIPT)
    _hook(tmp_path, "bash .claude/hooks/setup.sh")

    first = _run(tmp_path, ClaudeCodeSettingsAdapter())
    second = _run(tmp_path, ClaudeCodeSettingsAdapter())

    assert first == second


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("python3 -u tools/x.py", "tools/x.py"),
        ("uv run tools/x.py", "tools/x.py"),
        ("uv sync", None),
        ("git status", None),
        ("bash", None),
        ("'unterminated", None),
    ],
)
def test_script_reference(command: str, expected: str | None) -> None:
    assert script_reference(command) == expected
