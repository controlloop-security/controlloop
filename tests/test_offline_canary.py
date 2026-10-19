"""Tests for the offline canary.

`tests/conftest.py`'s autouse fixture already denies all socket access
across this whole suite, and `tests/test_offline_harness.py`'s
`TestNetworkDenialRaisesLoudly` already proves a raw, disconnected
`socket.socket()`/`socket.create_connection()` call raises immediately.
This file adds what those do not: the five core commands named
explicitly and individually (not only implied by "the whole suite runs
under the harness"); proof that a violation *deliberately introduced
into a real core command's own call graph* is caught immediately, not
only a call made in isolation; structural proof that this suite's own
CI trigger is what this file claims; and an honest disclosure that
container-image offline verification cannot be attempted because no
container image exists in this repository yet.

The identical "prove the mechanism catches a real violation" logic is
extended once more to this codebase's other core assurance mechanism,
the redaction boundary (`controlloop.redaction`) -- a negative control
complementing `tests/test_redaction.py`'s many existing positive
canaries.
"""

from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest
from conftest import NetworkAccessDeniedError
from golden_fixtures import FIXTURES
from typer.testing import CliRunner

import controlloop.bom as bom_module
from controlloop import redaction
from controlloop.cli import app
from controlloop.exit_codes import ExitCode
from controlloop.repository import resolve_repository_root

runner = CliRunner()

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CI_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: `ci.yml`'s own `cli` job calls this reusable workflow instead of
#: inlining its steps, so the real `uv run pytest` step this suite's own CI
#: execution depends on lives here.
_VERIFY_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "verify.yml"


def _write_fixture(name: str, root: Path) -> None:
    FIXTURES[name](root)


class TestEveryCoreCommandCompletesOffline:
    """`init`, `bom`, `diff`, `scan`, and `gate` all run to
    completion with all network access denied -- named individually,
    each with its own real invocation, under this suite's existing
    autouse offline harness."""

    def test_init_completes_offline(self, tmp_path: Path) -> None:
        _write_fixture("single-agent", tmp_path)

        result = runner.invoke(app, ["init", str(tmp_path), "--dry-run"])

        assert result.exit_code == ExitCode.PASS

    def test_bom_completes_offline(self, tmp_path: Path) -> None:
        _write_fixture("single-agent", tmp_path)

        result = runner.invoke(app, ["bom", str(tmp_path)])

        assert result.exit_code == ExitCode.PASS

    def test_diff_completes_offline(self, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()
        _write_fixture("empty", baseline)
        _write_fixture("single-agent", current)
        baseline_acbom = tmp_path / "baseline.json"
        current_acbom = tmp_path / "current.json"
        runner.invoke(app, ["bom", str(baseline), "--output", str(baseline_acbom)])
        runner.invoke(app, ["bom", str(current), "--output", str(current_acbom)])

        result = runner.invoke(app, ["diff", str(baseline_acbom), str(current_acbom)])

        assert result.exit_code == ExitCode.PASS

    def test_scan_completes_offline(self, tmp_path: Path) -> None:
        _write_fixture("single-agent", tmp_path)

        result = runner.invoke(app, ["scan", str(tmp_path)])

        assert result.exit_code == ExitCode.PASS

    def test_gate_completes_offline(self, tmp_path: Path) -> None:
        _write_fixture("single-agent", tmp_path)
        evidence_path = tmp_path / "evidence.json"

        result = runner.invoke(
            app, ["gate", str(tmp_path), "--evidence-path", str(evidence_path)]
        )

        assert result.exit_code == ExitCode.PASS
        assert evidence_path.exists()


class TestContainerImageOfflineVerification:
    """The container image is verified offline as well as the installed
    package.

    Genuinely blocked, disclosed rather than silently dropped: no Docker
    or containerized build asset exists anywhere in this repository yet,
    so there is no artifact to verify offline.
    """

    @pytest.mark.skip(
        reason=(
            "no container image exists in this repository yet "
            "-- nothing exists to verify offline"
        )
    )
    def test_container_image_runs_a_scan_with_networking_disabled(self) -> None:
        raise AssertionError("unreachable until a container image exists")


class TestDeliberateNetworkCallFailsImmediately:
    """A newly introduced network call in a core path fails CI
    immediately -- proven by deliberately introducing one into a real
    core function's own call graph, not merely calling a raw socket
    function in isolation (already covered by
    `test_offline_harness.py`'s own `TestNetworkDenialRaisesLoudly`)."""

    def test_a_network_call_inside_bom_generation_raises_immediately(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def walk_repository_with_a_deliberately_introduced_network_call(
            *args: object, **kwargs: object
        ) -> object:
            # Simulates a genuine regression: a future change adds an
            # outbound network call somewhere inside repository
            # discovery, before it would otherwise delegate to the real
            # walk. `controlloop.bom.build_acbom_document` calls the
            # module-level name `walk_repository` directly (verified by
            # reading src/controlloop/bom.py before writing this
            # test), so patching it here on `bom_module` exercises the
            # exact call site a real regression would land in. The
            # offline harness raises before this function could ever
            # reach a real network socket, so there is no real
            # connection attempt, and no real `walk_repository` delegate
            # call is needed -- the raise below is the entire point.
            socket.create_connection(("203.0.113.1", 80), timeout=1)
            raise AssertionError("unreachable -- the socket call above always raises")

        monkeypatch.setattr(
            bom_module,
            "walk_repository",
            walk_repository_with_a_deliberately_introduced_network_call,
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hi')\n")
        root = resolve_repository_root(tmp_path)

        with pytest.raises(NetworkAccessDeniedError):
            bom_module.build_acbom_document(root)


class TestSuiteRunsOnEveryPullRequest:
    """The suite runs on every pull request -- asserted
    structurally against the real committed workflow file, rather than
    only narrated."""

    def test_ci_workflow_triggers_on_pull_request(self) -> None:
        assert _CI_WORKFLOW_PATH.is_file()
        text = _CI_WORKFLOW_PATH.read_text(encoding="utf-8")

        assert "pull_request:" in text

    def test_ci_workflow_runs_pytest(self) -> None:
        """The offline harness is autouse across the whole suite
        (`tests/conftest.py`), so the pull-request-triggered `Test`
        step is this suite's real CI execution -- no separate "offline"
        job exists or is needed.

        `ci.yml`'s own `cli` job does not inline that step -- it calls the
        shared reusable workflow `verify.yml`
        (`uses: ./.github/workflows/verify.yml`), which both `ci.yml` and
        `release.yml` call so pull-request CI and the release pipeline's own
        verification stage can never drift apart. This test follows that
        real reference rather than re-inlining the assumption that the step
        lives directly in `ci.yml`."""

        ci_text = _CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "./.github/workflows/verify.yml" in ci_text

        verify_text = _VERIFY_WORKFLOW_PATH.read_text(encoding="utf-8")
        assert "uv run pytest" in verify_text


class TestRedactionCanaryDetectsARealViolation:
    """Companion to the offline tests above, extending the identical "prove
    the mechanism catches a real violation" logic to this codebase's other
    core assurance mechanism, the redaction boundary in `redaction.py`. A
    negative control: `tests/test_redaction.py`'s many existing canaries are
    all positive controls proving current code does not leak; this proves
    the underlying assertion is meaningful by showing what happens when the
    boundary is deliberately bypassed."""

    def test_a_secret_written_outside_redirected_streams_is_not_censored(
        self,
    ) -> None:
        """Deliberately does NOT use `redaction.redirected_streams` --
        this is the point: a raw stream write that never passes through
        the boundary is real, uncensored output. Contrasted directly
        with the next test, which proves the identical secret is
        censored once the boundary is actually applied -- together they
        show the mechanism's assertions are not vacuously true."""

        secret = "AKIAABCDEFGHIJKLMNOP"  # a real matched shape, synthetic value
        raw_stream = io.StringIO()

        print(f"unprotected: {secret}", file=raw_stream)

        assert secret in raw_stream.getvalue()

    def test_the_identical_secret_is_censored_once_the_boundary_applies(self) -> None:
        secret = "AKIAABCDEFGHIJKLMNOP"
        stdout_buffer = io.StringIO()

        with redaction.redirected_streams(target_stdout=stdout_buffer):
            print(f"protected: {secret}")

        assert secret not in stdout_buffer.getvalue()
        assert "controlloop:redacted:sha256:" in stdout_buffer.getvalue()

    def test_scan_json_output_never_contains_a_planted_secret_in_a_repository_name(
        self, tmp_path: Path
    ) -> None:
        """One additional, concrete end-to-end proof at the real command
        surface (not only the redaction primitive in isolation): a
        secret-shaped value planted inside repository content that
        reaches an adapter's own discovered name never survives a real
        `scan --format json` invocation."""

        secret = "AKIAABCDEFGHIJKLMNOP"
        (tmp_path / "agent-card.json").write_text(
            json.dumps(
                {
                    "name": f"agent-{secret}",
                    "skills": [{"id": "search-catalog", "name": "search-catalog"}],
                }
            )
        )

        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])

        assert secret not in result.stdout
        assert secret not in result.stderr
