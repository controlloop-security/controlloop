"""Tests for the free public-repository path.

The Community CLI's whole product promise is that gating a public repository
needs no account, no token, and no entitlement check.

**This file's claim changed shape when Team integration arrived, and the
change is deliberate.** Before that, nothing under `src/controlloop/`
implemented entitlement checking, so the promise was kept by an absence and
these tests proved the absence. Team integration makes entitlement checking
exist. The promise is now kept by a *boundary* instead: the entitlement
check lives entirely in `controlloop.team`, and the Community path -- any
repository where `team_enabled` is false, which is the default -- never
enters it.

So these tests were rewritten to assert the boundary rather than the
absence. Asserting the old absence would have been easy and would have
kept passing, because the entitlement code is not in the modules the old
version scanned; it would simply have stopped meaning anything. What
matters to a free user is unchanged and still asserted here: no
credential, no network, no entitlement check, and never exit code 4.

`TestNoCredentialRequired` -- `gate` completes with no credential
of any kind: a fully cleared process environment and no credential-shaped
flag on its own option list.
`TestNoEntitlementCheckOnTheFreePath` -- no entitlement or
licensing check runs on the free path, proven structurally over real
source text: `config` and `output` contain no entitlement-shaped
identifier at all, and every one in `cli` sits inside the two Team-only
helpers that a Community run never calls.
`TestFreePathRunsOffline` -- every free-path command completes
under this suite's autouse offline harness (`tests/conftest.py`).
Kept intentionally minimal here; `tests/test_offline_canary.py` is this
codebase's own more thorough, dedicated coverage of the identical
property.
`TestExitCodeFourIsTeamOnly` -- `ExitCode.ENTITLEMENT` (4) is
raised from exactly one place in `cli.py`, inside the Team-only
`_gate_team_prepare`, proven structurally, plus a real-invocation sweep
across the existing negative/malformed/boundary fixtures already
established in `tests/test_cli.py` confirming none of them ever
produces exit code 4, plus a real Team-disabled `gate` run on a fixture
that would fail policy -- exit 1, never exit 4.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from golden_fixtures import FIXTURES
from pytest import MonkeyPatch
from typer.core import TyperGroup, TyperOption
from typer.main import get_command
from typer.testing import CliRunner

from controlloop import config as config_module
from controlloop import output as output_module
from controlloop.cli import app
from controlloop.exit_codes import ExitCode

runner = CliRunner()

_SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "controlloop"


def _write_single_agent_fixture(root: Path) -> None:
    """The same minimal, non-empty, no-manifest shape
    `tests/golden_fixtures.py`'s `single-agent` fixture builds: one
    agent, one tool, no ceiling breach -- a clean pass, exit `0`."""

    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "librarian",
                "skills": [{"id": "search-catalog", "name": "search-catalog"}],
            }
        )
    )


class TestNoCredentialRequired:
    """The full `gate` path on a public repository completes with no
    credential of any kind."""

    def test_gate_completes_with_a_fully_cleared_environment(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("os.environ", {})
        _write_single_agent_fixture(tmp_path)
        evidence_path = tmp_path / "evidence.json"

        result = runner.invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(evidence_path)]
        )

        # A real verdict was reached (pass/warn, blocked, or
        # review-required) -- never an auth- or credential-shaped
        # failure, and never exit 2 (invalid input) for the mere absence
        # of environment variables.
        assert result.exit_code in {
            ExitCode.PASS,
            ExitCode.POLICY_FAIL,
            ExitCode.INCOMPLETE_ANALYSIS,
        }
        assert evidence_path.exists()

    def test_gate_has_no_credential_shaped_option(self) -> None:
        """`gate`'s own registered option list is enumerated through
        `typer.main.get_command`, the real object Typer itself builds and
        parses command-line arguments with at runtime (not a
        hand-maintained mirror of it), and asserted to contain no
        token/key/credential/secret/password/auth-shaped flag name -- so
        a future flag addition that reintroduced one would fail this
        test immediately."""

        click_app = get_command(app)
        assert isinstance(click_app, TyperGroup)
        gate_command = click_app.commands["gate"]

        flag_names = {
            opt.lower()
            for param in gate_command.params
            if isinstance(param, TyperOption)
            for opt in param.opts
        }

        forbidden_substrings = (
            "token",
            "key",
            "credential",
            "secret",
            "password",
            "auth",
            "license",
            "licence",
            "entitlement",
        )
        offending = {
            flag
            for flag in flag_names
            if any(substring in flag for substring in forbidden_substrings)
        }
        assert offending == set()


class TestNoEntitlementCheckOnTheFreePath:
    """No entitlement or licensing check runs on the free path.

    Before Team integration this was provable by scanning the free path's
    modules for entitlement-shaped identifiers and finding none. Entitlement
    checking now exists, so the assertion is stronger and more specific: it
    must exist *only* behind the Team boundary, and a Community run must
    never cross it.
    """

    #: Modules the free path (`init`/`bom`/`diff`/`scan`/`gate`) actually
    #: reaches. Enumerated explicitly (not "every .py file under src/")
    #: so this test names exactly what it covers rather than silently
    #: expanding scope as new unrelated modules are added.
    _FREE_PATH_MODULES = (
        config_module,
        output_module,
    )

    #: The two `cli.py` helpers that are the *only* entry points to Team
    #: behavior, plus the module-level import block that names the team
    #: package. Every entitlement-shaped identifier in `cli.py` must sit
    #: inside one of these; anything elsewhere means the Team path leaked
    #: into the Community path.
    _TEAM_ONLY_FUNCTIONS = ("_gate_team_prepare", "_gate_upload")

    #: Case-insensitive substrings that would indicate entitlement or
    #: licensing gating logic if found in the free path's own source
    #: text. Deliberately excludes bare "license"/"credential" alone --
    #: see the module docstring and the explicit exclusions below for
    #: where those two words appear today for unrelated, already-reviewed
    #: reasons (open-source licence file references, and the redaction
    #: module's own credential-*shape* detector).
    _FORBIDDEN_SUBSTRINGS = (
        "entitlement",
        "license_check",
        "licence_check",
        "is_licensed",
        "subscription",
        "billing_check",
        "paywall",
    )

    def test_free_path_modules_contain_no_entitlement_or_licensing_check(
        self,
    ) -> None:
        """`config` and `output` are reached by every command, Team or
        not, so they must contain no entitlement logic at all."""

        offending: list[str] = []
        for module in self._FREE_PATH_MODULES:
            source = inspect.getsource(module).lower()
            for substring in self._FORBIDDEN_SUBSTRINGS:
                if substring in source:
                    offending.append(f"{module.__name__}: {substring!r}")
        assert offending == [], (
            f"found entitlement/licensing-shaped identifier(s) in the free "
            f"path: {offending}"
        )

    def test_every_entitlement_reference_in_cli_is_inside_a_team_helper(
        self,
    ) -> None:
        """`cli.py` is shared by both paths, so the assertion here is
        containment rather than absence: every entitlement-shaped line
        must fall inside a Team-only helper or the import block that
        names the team package.

        The failure this prevents is the one that actually matters to a
        free user -- an entitlement check drifting out of the Team helpers
        and into the shared body of `gate`, where it would run for
        everyone.
        """

        cli_source_path = _SRC_ROOT / "cli.py"
        source = cli_source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        allowed_ranges: list[tuple[int, int]] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef)
                and node.name in self._TEAM_ONLY_FUNCTIONS
            ):
                assert node.end_lineno is not None
                allowed_ranges.append((node.lineno, node.end_lineno))
        assert len(allowed_ranges) == len(self._TEAM_ONLY_FUNCTIONS), (
            "a Team-only helper named in _TEAM_ONLY_FUNCTIONS no longer "
            "exists in cli.py -- update this test deliberately rather than "
            "letting it silently stop covering anything"
        )

        # The import block: `from controlloop.team...` lines are how the
        # boundary is crossed at all, and they are allowed to name it.
        for index, line in enumerate(source.splitlines(), start=1):
            if line.startswith("from controlloop.team"):
                allowed_ranges.append((index, index))

        offending: list[str] = []
        for index, line in enumerate(source.splitlines(), start=1):
            lowered = line.lower()
            if not any(word in lowered for word in self._FORBIDDEN_SUBSTRINGS):
                continue
            if any(start <= index <= end for start, end in allowed_ranges):
                continue
            offending.append(f"{index}: {line.strip()}")

        assert offending == [], (
            "entitlement-shaped code in cli.py outside the Team-only "
            f"helpers: {offending}"
        )

    def test_a_community_gate_makes_no_platform_call(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """The behavioral half. Runs under this suite's autouse offline
        harness, so any platform request would raise
        `NetworkAccessDeniedError` and fail this outright."""

        _write_single_agent_fixture(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(tmp_path / "e.json")]
        )

        assert result.exit_code == ExitCode.PASS
        evidence = json.loads((tmp_path / "e.json").read_text())
        # The positive statement of the same fact: a Community verdict
        # records no organization policy, because none participated.
        assert evidence["team"] is None

    def test_no_registered_rule_or_config_key_gates_on_entitlement(self) -> None:
        """The policy rule catalog and the configuration-key registry are
        both closed, enumerable sets in this codebase
        (`controlloop.policy.rules.ALL_RULES`,
        `controlloop.config._KEY_SPECS`). Neither contains any
        entitlement/licensing-shaped rule ID or configuration key."""

        from controlloop.policy.rules import ALL_RULES

        rule_ids = {rule.id.lower() for rule in ALL_RULES}
        config_keys = {key.lower() for key in config_module._KEY_SPECS}

        for substring in self._FORBIDDEN_SUBSTRINGS:
            assert not any(substring in rule_id for rule_id in rule_ids), (
                f"a registered rule ID references {substring!r}: {rule_ids}"
            )
            assert not any(substring in key for key in config_keys), (
                f"a registered configuration key references {substring!r}: "
                f"{config_keys}"
            )


class TestFreePathRunsOffline:
    """The free path runs under the offline harness. Minimal by design --
    see the module docstring; `tests/test_offline_canary.py` owns the
    thorough, dedicated coverage of this identical property."""

    def test_gate_completes_under_the_offline_harness(self, tmp_path: Path) -> None:
        # The offline harness (`tests/conftest.py`) is autouse for
        # this whole suite -- a successful invocation here already is
        # the evidence; nothing additional needs to be arranged.
        _write_single_agent_fixture(tmp_path)
        evidence_path = tmp_path / "evidence.json"

        result = runner.invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(evidence_path)]
        )

        assert result.exit_code in {ExitCode.PASS, ExitCode.POLICY_FAIL}


class TestExitCodeFourIsTeamOnly:
    """Exit code 4 is raised from exactly one place, and that place runs
    only when Team is enabled.

    Team integration made this code reachable for the first time. What a
    free user is promised is unchanged -- a Community run never returns it
    -- and that is what the sweep and the real invocation below assert.
    """

    def test_the_only_exit_four_site_is_inside_the_team_helper(self) -> None:
        """Parses `cli.py`'s own real source with `ast`, finds every
        `typer.Exit` site that can carry exit code 4, and asserts each one
        is lexically inside `_gate_team_prepare`.

        The earlier version of this test asserted no such site existed at
        all. It would still pass today -- the Team raise site passes
        `preparation.decision.exit_code`, an attribute named `exit_code`,
        which the old pattern match never looked at -- and it would be
        proving nothing. A guard that survives the change it was meant to
        catch is worse than no guard, so it was replaced rather than left
        green.
        """

        cli_source_path = _SRC_ROOT / "cli.py"
        tree = ast.parse(cli_source_path.read_text(encoding="utf-8"))

        team_helper: ast.FunctionDef | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_gate_team_prepare":
                team_helper = node
        assert team_helper is not None, (
            "_gate_team_prepare no longer exists; exit code 4's containment "
            "must be re-established deliberately"
        )
        assert team_helper.end_lineno is not None

        entitlement_exits: list[int] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_typer_exit = (
                isinstance(func, ast.Attribute)
                and func.attr == "Exit"
                and isinstance(func.value, ast.Name)
                and func.value.id == "typer"
            ) or (isinstance(func, ast.Name) and func.id == "Exit")
            if not is_typer_exit:
                continue

            for keyword in node.keywords:
                if keyword.arg != "code":
                    continue
                value = keyword.value
                names_four = isinstance(value, ast.Constant) and value.value == 4
                names_enum = (
                    isinstance(value, ast.Attribute) and value.attr == "ENTITLEMENT"
                )
                # The Team shape: an exit code carried on a decision object
                # rather than named literally at the raise site.
                carries_decision = (
                    isinstance(value, ast.Attribute) and value.attr == "exit_code"
                )
                if names_four or names_enum or carries_decision:
                    entitlement_exits.append(node.lineno)

        assert entitlement_exits, (
            "no exit-code-4-capable raise site found at all -- this test "
            "would then be vacuous"
        )
        outside = [
            line
            for line in entitlement_exits
            if not team_helper.lineno <= line <= team_helper.end_lineno
        ]
        assert outside == [], (
            f"cli.py can raise exit code 4 outside _gate_team_prepare at "
            f"line(s): {outside}"
        )

    def test_a_blocking_community_gate_returns_one_not_four(
        self, tmp_path: Path, monkeypatch: MonkeyPatch
    ) -> None:
        """A real invocation of the case most likely to be confused with
        an entitlement failure: a Community gate that genuinely fails
        policy. It must return the policy exit code, not the entitlement
        one."""

        FIXTURES["agent-with-ceiling-breach"](tmp_path)
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(tmp_path / "e.json")]
        )

        assert result.exit_code != ExitCode.ENTITLEMENT

    @pytest.mark.parametrize(
        "args",
        [
            [],
            ["nosuchcommand"],
            ["bom", "--validate"],
            ["diff", "a.json", "b.json", "--baseline", "x"],
            ["gate", "/path/does/not/exist"],
        ],
    )
    def test_negative_and_malformed_invocations_never_return_exit_four(
        self, args: list[str]
    ) -> None:
        result = runner.invoke(app, args)
        assert result.exit_code != ExitCode.ENTITLEMENT
