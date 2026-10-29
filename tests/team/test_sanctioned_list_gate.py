"""`controlloop gate` with Team enabled enforces the sanctioned list on the
authority delta, including approved components' optional constraints, and
uploads what it judged as envelope 1.1.0.

Each test commits a baseline on `main`, adds one MCP server on a branch
(the authority delta), and runs the real command with only the socket
faked. A new pinned server's own identity finding is `medium` and does
not block, so the verdict here is decided by
`policy.unsanctioned-agent-component`.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from factories import ENDPOINT, ORGANIZATION_ID, PROJECT_ID, TOKEN
from pytest import MonkeyPatch
from test_gate_integration import (
    _ACCEPTED,
    _ENTITLED,
    _POLICY,
    _json,
    _ScriptedTransport,
)
from typer.testing import CliRunner, Result

from controlloop import cli as cli_module
from controlloop.cli import app
from controlloop.exit_codes import ExitCode
from controlloop.team.config import TOKEN_ENVIRONMENT_VARIABLE

runner = CliRunner()
_RULE = "policy.unsanctioned-agent-component"
_SERVER = {"command": "npx", "args": ["-y", "@acme/docs-mcp@1.4.2", "./docs"]}


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _repository(root: Path) -> None:
    settings = (
        "team_enabled = true\n"
        f'team_endpoint = "{ENDPOINT}"\n'
        f'team_organization_id = "{ORGANIZATION_ID}"\n'
        f'team_project_id = "{PROJECT_ID}"\n'
    )
    (root / "controlloop.toml").write_text(settings)
    (root / "README.md").write_text("A project.\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    _git(root, "checkout", "-q", "-b", "change")
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": _SERVER}}))
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add a server")


def _gate(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    *,
    approved: list[dict[str, Any]],
    rules: list[dict[str, Any]] | None = None,
    bundle_version: str = "7",
    exceptions: list[dict[str, Any]] | None = None,
    transports: list[_ScriptedTransport] | None = None,
) -> tuple[Result, dict[str, Any]]:
    _repository(tmp_path)
    policy = {
        **_POLICY,
        "organization_bundle_version": bundle_version,
        "merge_semantics_version": "1.1.0",
        "rules": rules or [],
        "approved_components": approved,
    }
    transport = _ScriptedTransport(
        {
            "/entitlement": _json(_ENTITLED),
            "/effective-policy": _json(policy),
            "/active-exceptions": _json(exceptions or []),
            "/scans": _json(_ACCEPTED, status=202),
        }
    )
    if transports is not None:
        transports.append(transport)
    monkeypatch.setattr(cli_module, "UrllibTransport", lambda: transport)
    monkeypatch.setenv(TOKEN_ENVIRONMENT_VARIABLE, TOKEN)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "gate",
            str(tmp_path),
            "--default-branch",
            "main",
            "--evidence-path",
            str(tmp_path / "evidence.json"),
        ],
    )
    evidence = json.loads((tmp_path / "evidence.json").read_text())
    return result, evidence


def _unsanctioned(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in evidence["findings"] if f["rule_id"] == _RULE]


def _approved(**constraints: Any) -> list[dict[str, Any]]:
    return [{"type": "mcp_server", "name_pattern": "docs", **constraints}]


class TestJudged:
    def test_a_sanctioned_server_produces_no_finding(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        result, evidence = _gate(
            tmp_path,
            monkeypatch,
            approved=_approved(package="@acme/docs-mcp", version_range="1.4.x"),
        )

        assert result.exit_code == ExitCode.PASS
        assert _unsanctioned(evidence) == []
        (judgment,) = evidence["team"]["sanction_judgments"]
        assert judgment["state"] == "sanctioned"
        assert judgment["judged_by_policy_version"] == "7"

    def test_a_version_outside_the_range_requires_review(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        result, evidence = _gate(
            tmp_path,
            monkeypatch,
            approved=_approved(package="@acme/docs-mcp", version_range="2.x"),
        )

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        assert evidence["verdict"] == "review_required"
        (finding,) = _unsanctioned(evidence)
        assert finding["severity"] == "medium"
        assert "organization policy version 7" in finding["message"]
        assert "(constraint `version_range`)" in finding["message"]
        (judgment,) = evidence["team"]["sanction_judgments"]
        assert (judgment["state"], judgment["failed_constraint"]) == (
            "unsanctioned",
            "version_range",
        )

    def test_an_empty_list_approves_nothing(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        result, evidence = _gate(tmp_path, monkeypatch, approved=[])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        (finding,) = _unsanctioned(evidence)
        assert "(constraint `name`)" in finding["message"]

    def test_a_severity_floor_makes_it_fail(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """The bundle, not the CLI, decides how strictly it applies."""

        result, evidence = _gate(
            tmp_path,
            monkeypatch,
            approved=[],
            rules=[{"rule_id": _RULE, "enabled": True, "severity_floor": "high"}],
        )

        assert result.exit_code == ExitCode.POLICY_FAIL
        assert evidence["verdict"] == "deployment_blocked"
        (finding,) = _unsanctioned(evidence)
        assert finding["severity"] == "high"


class TestUnevaluated:
    def test_no_published_bundle_judges_nothing_and_says_so(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        result, evidence = _gate(tmp_path, monkeypatch, approved=[], bundle_version="")

        assert result.exit_code == ExitCode.PASS
        assert _unsanctioned(evidence) == []
        assert evidence["team"]["sanction_note"].startswith("unevaluated:")
        (judgment,) = evidence["team"]["sanction_judgments"]
        assert judgment["state"] == "unevaluated"


class TestExceptions:
    def test_an_exception_lets_it_through_and_an_expired_one_does_not(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        (tmp_path / "a").mkdir()
        _, first = _gate(tmp_path / "a", monkeypatch, approved=[])
        (finding,) = _unsanctioned(first)

        (tmp_path / "b").mkdir()
        result, _ = _gate(
            tmp_path / "b",
            monkeypatch,
            approved=[],
            exceptions=[
                {
                    "finding_fingerprint": finding["id"],
                    "expires_at": "2999-01-01T00:00:00Z",
                }
            ],
        )
        assert result.exit_code == ExitCode.PASS

        (tmp_path / "c").mkdir()
        result, _ = _gate(
            tmp_path / "c",
            monkeypatch,
            approved=[],
            exceptions=[
                {
                    "finding_fingerprint": finding["id"],
                    "expires_at": "2000-01-01T00:00:00Z",
                }
            ],
        )
        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        assert "expired" in result.output


class TestEvidence:
    def test_the_approved_list_and_its_digest_are_recorded(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _, evidence = _gate(
            tmp_path,
            monkeypatch,
            approved=_approved(package="@acme/docs-mcp", version_range="1.4.x"),
        )

        team = evidence["team"]
        assert team["approved_components"] == [
            {
                "type": "mcp_server",
                "name_pattern": "docs",
                "package": "@acme/docs-mcp",
                "version_range": "1.4.x",
                "digest": None,
                "command_pattern": None,
                "pin_required": None,
            }
        ]
        assert team["approved_components_digest"].startswith("sha256:")
        assert team["merge_semantics_version"] == "1.2.0"

    def test_a_repository_approval_does_not_clear_an_organization_judgment(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        (tmp_path / "controlloop.yaml").write_text(
            'schema_version: "1.0.0"\nowner: team\napprovals:\n'
            "  - capability: docs\n    approver: someone\n"
        )

        result, evidence = _gate(tmp_path, monkeypatch, approved=[])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        (finding,) = _unsanctioned(evidence)
        assert finding["severity"] == "medium"


class TestUpload:
    """The gate uploads envelope 1.1.0 with the components it
    judged and the authority delta."""

    def test_the_envelope_is_1_1_0_and_names_the_judged_component(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        transports: list[_ScriptedTransport] = []
        _gate(
            tmp_path,
            monkeypatch,
            approved=_approved(package="@acme/docs-mcp", version_range="1.4.x"),
            transports=transports,
        )

        (upload,) = [
            call for call in transports[0].calls if str(call["url"]).endswith("/scans")
        ]
        assert isinstance(upload["body"], bytes)
        envelope = json.loads(upload["body"])
        assert envelope["envelope_version"] == "1.1.0"
        (server,) = [c for c in envelope["components"] if c["type"] == "mcp_server"]
        assert server["name"] == "docs"
        assert server["attributes"]["package"] == "@acme/docs-mcp"
        assert server["attributes"]["version"] == "1.4.2"
        (entry,) = [
            e for e in envelope["authority_delta"] if e["grant"] == "mcp_server"
        ]
        assert entry["kind"] == "added"
        assert entry["evidence_path"] == ".mcp.json"
        assert entry["component_stable_id"] == server["stable_id"]


class TestCommunityAndPrivacy:
    def test_a_community_gate_never_loads_the_rule(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _repository(tmp_path)
        (tmp_path / "controlloop.toml").unlink()
        transport = _ScriptedTransport({})
        monkeypatch.setattr(cli_module, "UrllibTransport", lambda: transport)
        monkeypatch.chdir(tmp_path)

        runner.invoke(
            app,
            [
                "gate",
                str(tmp_path),
                "--default-branch",
                "main",
                "--evidence-path",
                str(tmp_path / "evidence.json"),
            ],
        )

        evidence = json.loads((tmp_path / "evidence.json").read_text())
        assert transport.calls == []
        assert _unsanctioned(evidence) == []
        assert evidence["team"] is None

    def test_a_secret_in_a_grant_reaches_no_judgment_or_finding(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        secret = "ghp_" + "S" * 36
        _SERVER["args"] = ["-y", "@acme/docs-mcp@1.4.2", f"--token={secret}"]
        try:
            result, evidence = _gate(tmp_path, monkeypatch, approved=[])
        finally:
            _SERVER["args"] = ["-y", "@acme/docs-mcp@1.4.2", "./docs"]

        assert _unsanctioned(evidence)
        assert secret not in json.dumps(evidence)
        assert secret not in result.output

    def test_a_secret_in_a_grant_reaches_no_upload(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        secret = "ghp_" + "U" * 36
        transports: list[_ScriptedTransport] = []
        _SERVER["args"] = ["-y", "@acme/docs-mcp@1.4.2", f"--token={secret}"]
        try:
            _gate(tmp_path, monkeypatch, approved=[], transports=transports)
        finally:
            _SERVER["args"] = ["-y", "@acme/docs-mcp@1.4.2", "./docs"]

        bodies = [call["body"] for call in transports[0].calls if call["body"]]
        assert bodies
        for body in bodies:
            assert isinstance(body, bytes)
            assert secret.encode() not in body
