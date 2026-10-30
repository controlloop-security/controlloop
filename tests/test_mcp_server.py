"""`controlloop mcp`: the local, read-only MCP server.

Three kinds of evidence, matching the security posture the server's
module docstring states:

- protocol: a conformance smoke test of the methods it implements, both
  in-process and over a real stdio subprocess;
- behaviour: every tool against a real git repository whose feature
  branch adds a `SessionStart` hook, compared with the CLI's own JSON;
- guarantees: no network (this suite's socket-denial harness plus a
  repository that enables Team), no file written in the workspace, and
  no path or revision that escapes it.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner as TyperRunner

from controlloop import __version__
from controlloop.cli import app
from controlloop.exit_codes import ExitCode
from controlloop.mcp_server import (
    MAX_MESSAGE_BYTES,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS,
    CliOutcome,
    Server,
)

typer_runner = TyperRunner()

_HOOK = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": "node .github/setup.js"}]}
        ]
    }
}
_STATEMENT = (
    "This change gives Claude Code the power to run `node .github/setup.js` on "
    "every session start (`.claude/settings.json`, hook `SessionStart`). "
    "No approval is recorded."
)


def _git(path: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t.com", "-c", "user.name=t", *args],
        cwd=path,
        check=True,
        capture_output=True,
    )


def _repository(root: Path) -> Path:
    """`main` holds the baseline; the checked-out `feature` adds a hook."""

    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("baseline\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "baseline")
    _git(root, "checkout", "-q", "-b", "feature")
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps(_HOOK))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add a hook")
    return root


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _request(method: str, params: dict[str, Any] | None = None, id_: int = 1) -> bytes:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        message["params"] = params
    return json.dumps(message).encode()


def _call(server: Server, name: str, **arguments: object) -> dict[str, Any]:
    reply = server.handle_line(
        _request("tools/call", {"name": name, "arguments": arguments})
    )
    assert reply is not None
    assert "result" in reply, reply
    result: dict[str, Any] = reply["result"]
    return result


def _stub(stdout: str = "{}", exit_code: int = 0) -> Any:
    calls: list[list[str]] = []

    def run(args: list[str], cwd: Path) -> CliOutcome:
        calls.append(args)
        return CliOutcome(exit_code=exit_code, stdout=stdout, stderr="")

    run.calls = calls  # type: ignore[attr-defined]
    return run


class TestProtocol:
    """The lifecycle and tool methods, without running any command."""

    def test_initialize_echoes_a_supported_version(self, tmp_path: Path) -> None:
        server = Server(tmp_path, run_cli=_stub())

        reply = server.handle_line(
            _request("initialize", {"protocolVersion": "2025-03-26"})
        )

        assert reply is not None
        result = reply["result"]
        assert result["protocolVersion"] == "2025-03-26"
        assert result["capabilities"] == {"tools": {"listChanged": False}}
        assert result["serverInfo"]["name"] == "controlloop"
        assert result["serverInfo"]["version"] == __version__
        assert "ControlLoop Team" in result["instructions"]

    def test_initialize_offers_the_newest_version_otherwise(
        self, tmp_path: Path
    ) -> None:
        server = Server(tmp_path, run_cli=_stub())

        reply = server.handle_line(
            _request("initialize", {"protocolVersion": "1999-01-01"})
        )

        assert reply is not None
        assert reply["result"]["protocolVersion"] == SUPPORTED_PROTOCOL_VERSIONS[0]

    def test_ping(self, tmp_path: Path) -> None:
        reply = Server(tmp_path, run_cli=_stub()).handle_line(_request("ping", id_=7))

        assert reply == {"jsonrpc": "2.0", "id": 7, "result": {}}

    def test_tools_list_names_four_read_only_tools(self, tmp_path: Path) -> None:
        reply = Server(tmp_path, run_cli=_stub()).handle_line(_request("tools/list"))

        assert reply is not None
        tools = reply["result"]["tools"]
        assert [tool["name"] for tool in tools] == ["gate", "diff", "bom", "rules"]
        for tool in tools:
            assert tool["description"]
            assert tool["inputSchema"]["type"] == "object"
            assert tool["inputSchema"]["additionalProperties"] is False
            assert tool["annotations"]["readOnlyHint"] is True
            assert tool["annotations"]["destructiveHint"] is False
            assert tool["annotations"]["openWorldHint"] is False

    def test_notifications_get_no_reply(self, tmp_path: Path) -> None:
        server = Server(tmp_path, run_cli=_stub())

        for method in ("notifications/initialized", "notifications/cancelled"):
            line = json.dumps({"jsonrpc": "2.0", "method": method}).encode()
            assert server.handle_line(line) is None

    @pytest.mark.parametrize(
        ("line", "code"),
        [
            (b"{not json", -32700),
            (b"\xff\xfe", -32700),
            (b"[]", -32600),
            (b'{"id": 1, "method": "ping"}', -32600),
            (b'{"jsonrpc": "2.0", "id": true, "method": "ping"}', -32600),
            (b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []}', -32602),
            (b'{"jsonrpc": "2.0", "id": 1, "method": "resources/list"}', -32601),
        ],
    )
    def test_malformed_messages_get_the_standard_error(
        self, tmp_path: Path, line: bytes, code: int
    ) -> None:
        reply = Server(tmp_path, run_cli=_stub()).handle_line(line)

        assert reply is not None
        assert reply["error"]["code"] == code

    @pytest.mark.parametrize(
        "params",
        [
            {"name": "scan", "arguments": {}},
            {"name": "gate", "arguments": {"evidence_path": "x.json"}},
            {"name": "gate", "arguments": []},
            {"name": "rules", "arguments": {"all": "yes"}},
        ],
    )
    def test_invalid_tool_calls_are_refused(
        self, tmp_path: Path, params: dict[str, Any]
    ) -> None:
        run = _stub()
        reply = Server(tmp_path, run_cli=run).handle_line(
            _request("tools/call", params)
        )

        assert reply is not None
        assert reply["error"]["code"] == -32602
        assert run.calls == []

    def test_serve_answers_each_line_and_stops_at_end_of_input(
        self, tmp_path: Path
    ) -> None:
        reader = io.BytesIO(
            _request("ping", id_=1)
            + b"\n\n"
            + b"x" * (MAX_MESSAGE_BYTES + 10)
            + b"\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/x"}).encode()
            + b"\n"
            + _request("ping", id_=2)
            + b"\n"
        )
        writer = io.StringIO()

        code = Server(tmp_path, run_cli=_stub()).serve(reader, writer)

        assert code == ExitCode.PASS
        replies = [json.loads(line) for line in writer.getvalue().splitlines()]
        assert [reply.get("id") for reply in replies] == [1, None, 2]
        assert replies[1]["error"]["code"] == -32700

    def test_a_tool_result_carries_structured_and_text_content(
        self, tmp_path: Path
    ) -> None:
        server = Server(tmp_path, run_cli=_stub(stdout='{"verdict": "passed"}'))

        result = _call(server, "gate")

        structured = result["structuredContent"]
        assert structured["result"] == {"verdict": "passed"}
        assert structured["exit_code"] == 0
        assert structured["exit_meaning"] == "passed"
        assert structured["command"] == "controlloop gate . --format json"
        assert json.loads(result["content"][0]["text"]) == structured
        assert result["isError"] is False

    @pytest.mark.parametrize(
        ("stdout", "exit_code", "is_error"),
        [
            ('{"verdict": "deployment_blocked"}', 1, False),
            ('{"verdict": "incomplete"}', 3, False),
            ("", 2, True),
            ("not json", 0, True),
            ("", 5, True),
        ],
    )
    def test_is_error_marks_only_failures_to_answer(
        self, tmp_path: Path, stdout: str, exit_code: int, is_error: bool
    ) -> None:
        server = Server(tmp_path, run_cli=_stub(stdout=stdout, exit_code=exit_code))

        assert _call(server, "gate")["isError"] is is_error


class TestWorkspaceBoundary:
    """No argument reaches outside the directory the server was given."""

    def test_paths_outside_the_workspace_are_refused(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "escape").symlink_to(tmp_path)
        run = _stub()
        server = Server(workspace, run_cli=run)

        for path in ("..", "../workspace/..", str(tmp_path), "escape", "a\x00b", ""):
            reply = server.handle_line(
                _request("tools/call", {"name": "bom", "arguments": {"path": path}})
            )
            assert reply is not None
            assert reply["error"]["code"] == -32602, path
        assert run.calls == []

    def test_a_subdirectory_is_passed_as_an_absolute_path(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        run = _stub()

        _call(Server(tmp_path, run_cli=run), "bom", path="sub")

        assert run.calls == [["bom", str((tmp_path / "sub").resolve())]]

    @pytest.mark.parametrize(
        "revision",
        ["--upload-pack=touch x", "-c", "main;rm", "a b", "$(id)", "x" * 300],
    )
    def test_option_shaped_revisions_are_refused(
        self, tmp_path: Path, revision: str
    ) -> None:
        run = _stub()
        server = Server(tmp_path, run_cli=run)

        for name, argument in (("gate", "default_branch"), ("diff", "baseline")):
            reply = server.handle_line(
                _request(
                    "tools/call", {"name": name, "arguments": {argument: revision}}
                )
            )
            assert reply is not None
            assert reply["error"]["code"] == -32602
        assert run.calls == []

    @pytest.mark.parametrize("revision", ["main", "origin/main", "HEAD~1", "v1.2.3"])
    def test_ordinary_revisions_pass_through(
        self, tmp_path: Path, revision: str
    ) -> None:
        run = _stub()

        _call(Server(tmp_path, run_cli=run), "diff", baseline=revision)

        assert run.calls[0][-2:] == ["--baseline", revision]

    def test_a_baseline_file_must_be_inside_the_workspace(self, tmp_path: Path) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "acbom.json").write_text("{}")
        (tmp_path / "outside.json").write_text("{}")
        run = _stub()
        server = Server(workspace, run_cli=run)

        _call(server, "diff", baseline="acbom.json")
        reply = server.handle_line(
            _request(
                "tools/call",
                {"name": "diff", "arguments": {"baseline": "../outside.json"}},
            )
        )

        assert run.calls[0][-1] == str((workspace / "acbom.json").resolve())
        assert reply is not None
        assert reply["error"]["code"] == -32602

    def test_the_workspace_must_be_an_existing_directory(self, tmp_path: Path) -> None:
        (tmp_path / "file").write_text("x")

        with pytest.raises(OSError):
            Server(tmp_path / "missing")
        with pytest.raises(OSError):
            Server(tmp_path / "file")


class TestToolsAgainstARealRepository:
    """Each tool runs the real command and returns its own JSON."""

    def test_gate_reports_the_blocked_hook(self, tmp_path: Path) -> None:
        root = _repository(tmp_path)

        result = _call(Server(root), "gate", default_branch="main")

        structured = result["structuredContent"]
        assert structured["exit_code"] == ExitCode.POLICY_FAIL
        assert structured["exit_meaning"] == "blocked or review required"
        report = structured["result"]
        assert report["verdict"] == "deployment_blocked"
        (entry,) = report["authority_delta"]["entries"]
        assert entry["statement"] == _STATEMENT
        assert [finding["rule_id"] for finding in report["findings"]] == [
            "policy.agent-hook-command-change"
        ]
        assert result["isError"] is False

    def test_gate_result_is_the_cli_evidence_artifact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _repository(tmp_path / "repo")
        evidence = tmp_path / "evidence.json"
        monkeypatch.chdir(root)

        cli = typer_runner.invoke(
            app,
            ["gate", str(root), "--format", "json", "--evidence-path", str(evidence)],
        )
        result = _call(Server(root), "gate")

        assert result["structuredContent"]["result"] == json.loads(cli.stdout)

    def test_diff_bom_and_rules(self, tmp_path: Path) -> None:
        root = _repository(tmp_path)
        server = Server(root)

        diff = _call(server, "diff", baseline="main")["structuredContent"]
        bom = _call(server, "bom")["structuredContent"]
        rules = _call(server, "rules", all=True)["structuredContent"]

        assert diff["exit_code"] == ExitCode.PASS
        assert diff["result"]["authority_delta"]["entries"][0]["statement"] == (
            _STATEMENT
        )
        assert bom["exit_code"] == ExitCode.PASS
        assert any(node["type"] == "agent" for node in bom["result"]["nodes"])
        assert rules["exit_code"] == ExitCode.PASS
        hook_rule = next(
            rule
            for rule in rules["result"]["rules"]
            if rule["id"] == "policy.agent-hook-command-change"
        )
        assert hook_rule["documentation_url"].startswith("https://")

    def test_no_tool_writes_a_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _repository(tmp_path / "repo")
        elsewhere = tmp_path / "cwd"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        before = _snapshot(root)
        server = Server(root)

        for name, arguments in (
            ("gate", {}),
            ("gate", {"default_branch": "main"}),
            ("diff", {"baseline": "main"}),
            ("bom", {}),
            ("rules", {}),
        ):
            _call(server, name, **arguments)

        assert _snapshot(root) == before
        assert list(elsewhere.iterdir()) == []

    def test_an_unexpected_exception_is_an_internal_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("secret detail")

        monkeypatch.setattr("controlloop.cli.build_acbom_document", explode)

        result = _call(Server(tmp_path), "bom")

        structured = result["structuredContent"]
        assert structured["exit_code"] == ExitCode.INTERNAL_ERROR
        assert result["isError"] is True
        assert "secret detail" not in result["content"][0]["text"]
        assert any("CLI-INTERNAL-ERROR" in line for line in structured["stderr"])


class TestNoNetwork:
    """Team is forced off, so even a Team-enabled repository makes no
    platform request. The suite's harness denies every socket, so a
    connection attempt would fail the call rather than pass silently."""

    def test_a_team_enabled_repository_stays_on_the_community_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _repository(tmp_path)
        (root / "controlloop.toml").write_text(
            "team_enabled = true\n"
            'team_endpoint = "https://app.controlloop.example"\n'
            'team_organization_id = "00000000-0000-4000-8000-000000000001"\n'
            'team_project_id = "00000000-0000-4000-8000-000000000002"\n'
        )
        monkeypatch.setenv("CONTROLLOOP_TEAM_TOKEN", "clp_test_token")
        monkeypatch.delenv("CONTROLLOOP_TEAM_ENABLED", raising=False)

        result = _call(Server(root), "gate", default_branch="main")

        structured = result["structuredContent"]
        assert structured["exit_code"] == ExitCode.POLICY_FAIL
        assert structured["result"]["team"] is None
        assert not any("CLI-TEAM" in line for line in structured["stderr"])
        # The caller's environment is restored after the call.
        assert os.environ["CONTROLLOOP_TEAM_TOKEN"] == "clp_test_token"
        assert "CONTROLLOOP_TEAM_ENABLED" not in os.environ

    def test_the_same_repository_would_reach_for_the_network_through_the_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Negative control: without the server's override, the CLI takes
        the Team path for this configuration, so the test above is not
        passing merely because Team was never configured."""

        root = _repository(tmp_path)
        (root / "controlloop.toml").write_text(
            "team_enabled = true\n"
            'team_endpoint = "https://app.controlloop.example"\n'
            'team_organization_id = "00000000-0000-4000-8000-000000000001"\n'
            'team_project_id = "00000000-0000-4000-8000-000000000002"\n'
        )
        monkeypatch.setenv("CONTROLLOOP_TEAM_TOKEN", "clp_test_token")
        monkeypatch.chdir(root)

        cli = typer_runner.invoke(
            app,
            [
                "gate",
                str(root),
                "--evidence-path",
                str(tmp_path / "evidence.json"),
                "--default-branch",
                "main",
            ],
        )

        assert "CLI-TEAM" in cli.stderr or cli.exception is not None


class TestStdioSubprocess:
    """The installed entry point, over real pipes."""

    def test_handshake_and_tools_list(self, tmp_path: Path) -> None:
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "rules", "arguments": {}},
            },
        ]

        completed = subprocess.run(
            [sys.executable, "-m", "controlloop", "mcp", str(tmp_path)],
            input="".join(json.dumps(message) + "\n" for message in messages),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert completed.returncode == 0, completed.stderr
        replies = [json.loads(line) for line in completed.stdout.splitlines()]
        assert [reply["id"] for reply in replies] == [1, 2, 3]
        assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
        assert len(replies[1]["result"]["tools"]) == len(TOOLS)
        assert replies[2]["result"]["structuredContent"]["exit_code"] == 0

    def test_a_missing_workspace_is_invalid_input(self, tmp_path: Path) -> None:
        result = typer_runner.invoke(app, ["mcp", str(tmp_path / "missing")])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "the workspace must be an existing directory" in result.stderr
