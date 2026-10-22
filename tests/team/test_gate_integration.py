"""End-to-end `controlloop gate` runs with Team enabled.

Everything else in this directory tests a piece. This file runs the real
command through `CliRunner` and asserts on what a user actually gets: the
exit code, the diagnostics on standard error, and the evidence file on
disk.

The only thing faked is the socket. `controlloop.cli` constructs
`UrllibTransport()` at one point, and these tests replace that one name
with a scripted `FakeTransport`, so the entire command path -- config
resolution, entitlement, merge, exceptions, evaluation, evidence, upload
-- is the real one. Nothing here weakens the suite's autouse offline
harness; a request that escaped the fake would still raise.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from factories import ENDPOINT, ORGANIZATION_ID, PROJECT_ID, TOKEN
from golden_fixtures import FIXTURES
from pytest import MonkeyPatch
from typer.testing import CliRunner, Result

from controlloop import cli as cli_module
from controlloop.cli import app
from controlloop.exit_codes import ExitCode
from controlloop.reporting import CURRENT_EVIDENCE_SCHEMA_VERSION
from controlloop.team.config import TOKEN_ENVIRONMENT_VARIABLE
from controlloop.team.transport import HttpResponse, TransportError

runner = CliRunner()

_ENTITLED = {
    "state": "entitled",
    "project_id": PROJECT_ID,
    "checked_at": "2026-09-02T12:00:00Z",
    "cache_seconds": 300,
}
_NOT_ENTITLED = {**_ENTITLED, "state": "not_entitled"}
_GRACE = {**_ENTITLED, "state": "grace"}

_POLICY = {
    "project_id": PROJECT_ID,
    "organization_bundle_version": "7",
    "merge_semantics_version": "1.0.0",
    "rules": [],
    "approved_components": [],
    "computed_at": "2026-09-02T12:00:00Z",
}

_ACCEPTED = {"scan_id": PROJECT_ID, "duplicate": False}


class _ScriptedTransport:
    """A `FakeTransport` that answers by URL rather than by position.

    Positional scripting is fine when a test drives one client method.
    A whole `gate` run makes several requests whose order is exactly what
    is under test, so answering by path keeps a test readable and lets it
    assert the order separately, from `calls`.
    """

    def __init__(self, answers: dict[str, object]) -> None:
        self.answers = answers
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout_seconds: float,
    ) -> HttpResponse:
        self.calls.append({"method": method, "url": url, "body": body})
        for suffix, answer in self.answers.items():
            if url.endswith(suffix):
                if isinstance(answer, TransportError):
                    raise answer
                assert isinstance(answer, HttpResponse)
                return answer
        raise AssertionError(f"unscripted request: {method} {url}")

    def paths(self) -> list[str]:
        return [str(call["url"]).rsplit("/", 1)[-1] for call in self.calls]


def _json(payload: object, *, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(payload).encode())


def _git_init(root: Path) -> None:
    """Make `root` a real git checkout with one commit.

    Needed because the envelope carries a commit SHA and `controlloop.bom`
    records the literal `"unknown"` for a directory that is not a git
    checkout -- in which case the gate correctly *skips* the upload. That
    is real behavior worth having its own test (below), but it is not the
    behavior these tests are about, and a plain `tmp_path` would silently
    give every one of them the skip path instead of the upload path.

    Runs `git` as a subprocess, which the offline harness permits: it
    denies sockets, not processes, and `git init` touches no network.
    """

    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=tests@example.invalid",
            "-c",
            "user.name=tests",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        cwd=root,
        check=True,
    )


def _team_repository(root: Path, **overrides: object) -> None:
    """A real fixture repository with Team enabled in its own config."""

    FIXTURES["agent-with-ceiling-breach"](root)
    settings: dict[str, object] = {
        "team_enabled": True,
        "team_endpoint": ENDPOINT,
        "team_organization_id": ORGANIZATION_ID,
        "team_project_id": PROJECT_ID,
    }
    settings.update(overrides)
    lines = []
    for key, value in settings.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f'{key} = "{value}"')
    (root / "controlloop.toml").write_text("\n".join(lines) + "\n")
    _git_init(root)


def _run(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    transport: _ScriptedTransport,
    *,
    token: str | None = TOKEN,
) -> Result:
    monkeypatch.setattr(cli_module, "UrllibTransport", lambda: transport)
    monkeypatch.delenv(TOKEN_ENVIRONMENT_VARIABLE, raising=False)
    if token is not None:
        monkeypatch.setenv(TOKEN_ENVIRONMENT_VARIABLE, token)
    monkeypatch.chdir(tmp_path)
    return runner.invoke(
        app,
        ["gate", str(tmp_path), "--evidence-path", str(tmp_path / "evidence.json")],
    )


def _evidence(tmp_path: Path) -> dict[str, object]:
    document = json.loads((tmp_path / "evidence.json").read_text())
    assert isinstance(document, dict)
    return document


class TestTeamOffIsUnchanged:
    """Without Team configured, the gate makes no request and a stray token
    does not switch on the paid path, at the command level."""

    def test_a_repository_without_team_makes_no_request(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        FIXTURES["agent-with-ceiling-breach"](tmp_path)
        transport = _ScriptedTransport({})
        monkeypatch.setattr(cli_module, "UrllibTransport", lambda: transport)
        monkeypatch.setenv(TOKEN_ENVIRONMENT_VARIABLE, TOKEN)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app,
            [
                "gate",
                str(tmp_path),
                "--evidence-path",
                str(tmp_path / "evidence.json"),
            ],
        )

        assert result.exit_code != ExitCode.ENTITLEMENT
        assert transport.calls == []
        assert _evidence(tmp_path)["team"] is None

    def test_a_stray_token_does_not_switch_on_the_paid_path(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """The concrete failure: a `CONTROLLOOP_TEAM_TOKEN` inherited from
        another job in the same runner."""

        FIXTURES["single-agent"](tmp_path)
        transport = _ScriptedTransport({})
        monkeypatch.setattr(cli_module, "UrllibTransport", lambda: transport)
        monkeypatch.setenv(TOKEN_ENVIRONMENT_VARIABLE, TOKEN)
        monkeypatch.setenv("CONTROLLOOP_TEAM_ENDPOINT", ENDPOINT)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app,
            [
                "gate",
                str(tmp_path),
                "--evidence-path",
                str(tmp_path / "evidence.json"),
            ],
        )

        assert result.exit_code == ExitCode.PASS
        assert transport.calls == []


class TestEntitlement:
    def test_a_not_entitled_project_exits_four(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport({"/entitlement": _json(_NOT_ENTITLED)})

        result = _run(tmp_path, monkeypatch, transport)

        assert result.exit_code == ExitCode.ENTITLEMENT
        assert "not entitled" in result.output
        assert transport.paths() == ["entitlement"]

    def test_a_not_entitled_project_writes_no_evidence(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """ "No partial paid behavior" reaches the filesystem too: the run
        stopped before it had a verdict, so there is nothing to attest."""

        _team_repository(tmp_path)
        transport = _ScriptedTransport({"/entitlement": _json(_NOT_ENTITLED)})

        _run(tmp_path, monkeypatch, transport)

        assert not (tmp_path / "evidence.json").exists()

    def test_grace_proceeds_to_a_real_verdict(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_GRACE),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        result = _run(tmp_path, monkeypatch, transport)

        assert result.exit_code != ExitCode.ENTITLEMENT
        assert "grace period" in result.output

    def test_a_missing_token_is_exit_two_naming_the_variable(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport({})

        result = _run(tmp_path, monkeypatch, transport, token=None)

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert TOKEN_ENVIRONMENT_VARIABLE in result.output
        assert transport.calls == []

    def test_a_malformed_endpoint_is_exit_two_naming_the_key(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path, team_endpoint="http://platform.example")
        transport = _ScriptedTransport({})

        result = _run(tmp_path, monkeypatch, transport)

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert "team_endpoint" in result.output


class TestRequestOrder:
    def test_entitlement_precedes_policy_which_precedes_upload(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """The ordering requirement, asserted against real traffic."""

        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        assert transport.paths() == [
            "entitlement",
            "effective-policy",
            "active-exceptions",
            "scans",
        ]

    def test_the_upload_is_a_post_of_the_envelope(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        upload = transport.calls[-1]
        assert upload["method"] == "POST"
        assert upload["body"] is not None
        body = upload["body"]
        assert isinstance(body, bytes)
        payload = json.loads(body.decode())
        assert payload["envelope_version"] == "1.0.0"
        assert len(payload["commit_sha"]) == 40


class TestEvidence:
    def test_the_team_block_is_recorded(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        team = _evidence(tmp_path)["team"]
        assert isinstance(team, dict)
        assert team["organization_bundle_version"] == "7"
        assert team["merge_semantics_version"] == "1.1.0"
        assert team["policy_source"] == "fetched"
        assert team["entitlement_state"] == "entitled"

    def test_the_evidence_never_contains_the_token(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        assert TOKEN not in (tmp_path / "evidence.json").read_text()

    def test_the_current_schema_version_is_recorded(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        assert _evidence(tmp_path)["schema_version"] == CURRENT_EVIDENCE_SCHEMA_VERSION


class TestExceptionsAtTheCommandLevel:
    def _findings(self, tmp_path: Path) -> list[dict[str, object]]:
        findings = _evidence(tmp_path)["findings"]
        assert isinstance(findings, list)
        return findings

    def test_an_unexpired_exception_stops_its_finding_blocking(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        baseline = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )
        blocked = _run(tmp_path, monkeypatch, baseline)
        assert blocked.exit_code == ExitCode.POLICY_FAIL
        fingerprints = [finding["id"] for finding in self._findings(tmp_path)]
        assert fingerprints

        excepted = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json(
                    [
                        {
                            "finding_fingerprint": fingerprint,
                            "expires_at": "2099-01-01T00:00:00Z",
                        }
                        for fingerprint in fingerprints
                    ]
                ),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )
        result = _run(tmp_path, monkeypatch, excepted)

        assert result.exit_code == ExitCode.PASS
        # A pass that only an approval allowed says so, finding by finding.
        for fingerprint in fingerprints:
            assert f"({fingerprint}) until 2099-01-01" in result.output
        assert result.output.count("organization exception applied to") == len(
            fingerprints
        )

    def test_an_expired_exception_re_blocks_and_names_the_date(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """An expired exception visibly re-blocks with the expiry date in
        the output -- the whole point being that a build which broke because an
        approval lapsed says so on the run that broke."""

        _team_repository(tmp_path)
        baseline = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )
        _run(tmp_path, monkeypatch, baseline)
        fingerprints = [finding["id"] for finding in self._findings(tmp_path)]

        expired = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json(
                    [
                        {
                            "finding_fingerprint": fingerprint,
                            "expires_at": "2020-03-04T00:00:00Z",
                        }
                        for fingerprint in fingerprints
                    ]
                ),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )
        result = _run(tmp_path, monkeypatch, expired)

        assert result.exit_code == ExitCode.POLICY_FAIL
        assert "expired on 2020-03-04" in result.output


class TestUploadNeverChangesTheVerdict:
    """A failed or refused upload never changes the gate's verdict."""

    @pytest.mark.parametrize(
        "scans_answer",
        [
            TransportError("down"),
            _json({}, status=401),
            _json({}, status=400),
        ],
        ids=["unreachable", "rejected-token", "bad-request"],
    )
    def test_an_upload_failure_leaves_the_exit_code_alone(
        self, tmp_path: Path, monkeypatch: MonkeyPatch, scans_answer: object
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": scans_answer,
            }
        )

        result = _run(tmp_path, monkeypatch, transport)

        assert result.exit_code == ExitCode.POLICY_FAIL
        assert "Team upload failed" in result.output

    def test_an_upload_failure_still_wrote_evidence(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """Evidence is written before the upload is attempted, so a
        platform outage never costs a team its local record."""

        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": TransportError("down"),
            }
        )

        _run(tmp_path, monkeypatch, transport)

        assert (tmp_path / "evidence.json").is_file()

    def test_a_replay_is_reported_as_such(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        _team_repository(tmp_path)
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(_POLICY),
                "/active-exceptions": _json([]),
                "/scans": _json({"scan_id": PROJECT_ID, "duplicate": True}, status=202),
            }
        )

        result = _run(tmp_path, monkeypatch, transport)

        assert "replay" in result.output


class TestPolicyRejectionIsReported:
    """A weakening repository policy is reported with the rule it weakens
    and the organization policy version."""

    def test_a_weakening_repository_config_is_named_with_its_rule_and_version(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        # `policy.broad-permission` is chosen deliberately: it is a real
        # registered rule that the *rule pack* does not mark mandatory, so
        # a repository is allowed to disable it locally. The organization
        # bundle marking it mandatory is what creates the conflict this
        # test is about.
        #
        # A rule the rule pack already marks mandatory would not work:
        # `validate_disabled_rules` refuses it with exit 2 before the Team
        # path runs at all. That is correct, and it means the two
        # mandatory-rule mechanisms compose rather than overlap -- the
        # rule pack protects what ControlLoop itself considers
        # non-negotiable, and an organization bundle extends that set for
        # its own repositories.
        rule_id = "policy.broad-permission"
        mandatory = {
            **_POLICY,
            "rules": [{"rule_id": rule_id, "enabled": True, "mandatory": True}],
        }
        _team_repository(tmp_path, disabled_rules=rule_id)
        # `disabled_rules` is a TOML array, not a string -- rewrite that
        # one line rather than teach the helper a special case.
        text = (tmp_path / "controlloop.toml").read_text()
        (tmp_path / "controlloop.toml").write_text(
            text.replace(
                f'disabled_rules = "{rule_id}"',
                f'disabled_rules = ["{rule_id}"]',
            )
        )
        transport = _ScriptedTransport(
            {
                "/entitlement": _json(_ENTITLED),
                "/effective-policy": _json(mandatory),
                "/active-exceptions": _json([]),
                "/scans": _json(_ACCEPTED, status=202),
            }
        )

        result = _run(tmp_path, monkeypatch, transport)

        assert rule_id in result.output
        assert "version 7" in result.output
        assert "mandatory" in result.output
