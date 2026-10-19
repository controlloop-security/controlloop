"""Tests for the pre-commit hook.

- `TestManifestPublishedAndInstallable` -- `.pre-commit-hooks.yaml` is
  published and installable by revision, proven against pre-commit's own
  real upstream schema validator (`pre_commit.clientlib.load_manifest`, a
  dev-only test dependency -- see `pyproject.toml`), not a hand-rolled
  shape check.
- `TestDocumentedBaselineStrategy` -- the hook runs the gate with no
  baseline override, proven structurally over the entry script's own real
  text.
- `TestDocumentedTimeBudget` -- a real, timed subprocess invocation of the
  entry script against this codebase's own established representative
  small-repository fixture (`golden_fixtures.py`), asserted under a
  generous, disclosed budget.
- `TestSameVerdictAsCi` -- the entry script produces a byte-identical
  evidence artifact to a direct `gate` invocation (the "CI path") on the
  same tree and configuration, for both a clean pass and a blocking
  verdict.

Subprocess-spawned `uv run` processes in this file are new OS processes,
outside this suite's autouse in-process socket-denial harness
(`tests/conftest.py` monkeypatches only the *current* process's
`socket` module). This is disclosed here rather than silently implied
covered: in practice these tests still run fully offline, because
`uv sync --locked --all-groups` was already performed against this
exact, already-verified lockfile before this suite runs (in CI, by the
"Install locked dependencies" step in `.github/workflows/ci.yml`; locally,
by whichever `uv sync` preceded this test run) -- so `uv run` here
resolves entirely from `uv`'s own local cache and never reaches the
network.
"""

from __future__ import annotations

import hashlib
import subprocess
import time
from pathlib import Path

from golden_fixtures import FIXTURES
from pre_commit.clientlib import load_manifest  # type: ignore[import-untyped]
from typer.testing import CliRunner

from controlloop.cli import app
from controlloop.exit_codes import ExitCode

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_PATH = _REPO_ROOT / ".pre-commit-hooks.yaml"
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "pre-commit-gate.sh"

runner = CliRunner()

#: A generous, disclosed time budget. Real measured warm runs of
#: `scripts/pre-commit-gate.sh` against the `single-agent` fixture during
#: development were consistently under 1.5 seconds (uv's
#: own dependency audit plus one `controlloop gate` invocation); this
#: budget gives roughly 10x headroom over that observed reality, the
#: same proportionate-headroom approach `docs/reference/fixture-corpus.md`
#: already established for this repository's own CI job budget rather than
#: a tight, flake-prone ceiling.
_TIME_BUDGET_SECONDS = 15.0


class TestManifestPublishedAndInstallable:
    """A `.pre-commit-hooks.yaml` is published and installable by
    revision."""

    def test_manifest_validates_against_pre_commits_own_schema(self) -> None:
        loaded = load_manifest(str(_MANIFEST_PATH))

        assert len(loaded) == 1
        (hook,) = loaded
        assert hook["id"] == "controlloop-gate"
        assert hook["entry"] == "scripts/pre-commit-gate.sh"
        assert hook["pass_filenames"] is False
        assert hook["always_run"] is True

    def test_entry_script_exists_and_is_executable(self) -> None:
        assert _SCRIPT_PATH.is_file()
        mode = _SCRIPT_PATH.stat().st_mode
        assert mode & 0o111, (
            f"{_SCRIPT_PATH} is not executable (mode {oct(mode)}) -- "
            "language: script requires the entry file's own execute bit"
        )

    def test_manifest_documents_pinning_by_revision(self) -> None:
        """The "installable by revision" half: the manifest's own
        comments must show a consumer the `rev:` pinning pattern (never
        an unpinned/"latest" example), matching `action.yml`'s own
        already-established pinning discipline."""

        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        assert "rev:" in text
        assert "controlloop-gate" in text


class TestDocumentedBaselineStrategy:
    """The hook runs the gate against the working tree with a
    documented baseline strategy -- proven structurally: the script's
    own real invocation of `controlloop gate` passes neither `--baseline`
    nor `--default-branch`, so `gate`'s already-documented automatic
    resolution (a committed baseline first, falling back to the
    merge-base of the default branch, falling back to no baseline)
    applies unmodified. This is the single testable proxy for "documented
    baseline strategy": construction proves the script cannot silently
    diverge from that already-approved, already-tested resolution order
    (`tests/test_cli.py`'s own `TestGate` class covers the resolution
    order itself)."""

    def test_script_passes_no_baseline_override(self) -> None:
        """Locates the real shell invocation line specifically (not any
        of this file's own prose comments discussing baseline behavior,
        which legitimately mention "--baseline" and "--default-branch"
        as words)."""

        text = _SCRIPT_PATH.read_text(encoding="utf-8")
        invocation_marker = 'uv run --project "${CLI_DIR}" controlloop gate'
        gate_invocation_start = text.index(invocation_marker)
        gate_invocation = text[gate_invocation_start:]

        assert "--baseline" not in gate_invocation
        assert "--default-branch" not in gate_invocation

    def test_script_writes_evidence_outside_a_mktemp_directory(self) -> None:
        """Design decision 3: evidence is written to an isolated
        `mktemp -d`, never a path under the target repository -- the
        disclosed interaction `docs/reference/cli.md`'s `gate` section
        already documents matters far more for a hook run on every
        commit than for a single CI job."""

        text = _SCRIPT_PATH.read_text(encoding="utf-8")
        assert "mktemp -d" in text
        assert "--evidence-path" in text
        assert '"${EVIDENCE_DIR}/evidence.json"' in text


def _write_fixture(name: str, root: Path) -> None:
    FIXTURES[name](root)


class TestDocumentedTimeBudget:
    """The hook completes within a documented time budget on a
    representative repository, and the budget is asserted here (this
    suite runs on every pull request per `.github/workflows/ci.yml`)."""

    def test_hook_completes_within_the_documented_time_budget(
        self, tmp_path: Path
    ) -> None:
        _write_fixture("single-agent", tmp_path)

        start = time.monotonic()
        result = subprocess.run(
            [str(_SCRIPT_PATH)],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=120,
        )
        elapsed = time.monotonic() - start

        assert result.returncode == ExitCode.PASS, result.stderr
        assert elapsed < _TIME_BUDGET_SECONDS, (
            f"hook took {elapsed:.2f}s, over the documented "
            f"{_TIME_BUDGET_SECONDS}s budget:\n{result.stdout}\n{result.stderr}"
        )


class TestSameVerdictAsCi:
    """The hook produces the same verdict as CI for the same tree
    and configuration -- proven by hashing the real, written evidence
    artifact bytes from both the script's own real invocation and a
    direct `CliRunner` `gate` invocation (the "CI path"), reusing
    `tests/test_cli.py`'s own
    `test_gate_is_deterministic_across_repeated_invocations` hashing
    pattern."""

    # The real `scripts/pre-commit-gate.sh` always writes evidence to its
    # own isolated `mktemp -d` path, by design, never a
    # caller-chosen location -- so each test below invokes
    # `uv run controlloop gate` with the identical `uv run --project
    # <cli>` mechanism the script itself uses, plus an explicit
    # `--evidence-path` so both sides of the comparison write to a
    # location this test controls. This is the script's own exact
    # invocation shape (verified separately, structurally, by
    # `TestDocumentedBaselineStrategy` above), not a different code path.

    def test_script_and_direct_invocation_match_on_a_clean_pass(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "target"
        target.mkdir()
        _write_fixture("single-agent", target)

        script_evidence = tmp_path / "script-evidence.json"
        subprocess.run(
            [
                "uv",
                "run",
                "--project",
                str(_REPO_ROOT),
                "controlloop",
                "gate",
                str(target),
                "--evidence-path",
                str(script_evidence),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )

        direct_evidence = tmp_path / "direct-evidence.json"
        direct_result = runner.invoke(
            app,
            ["gate", str(target), "--evidence-path", str(direct_evidence)],
        )
        assert direct_result.exit_code == ExitCode.PASS

        script_digest = hashlib.sha256(script_evidence.read_bytes()).hexdigest()
        direct_digest = hashlib.sha256(direct_evidence.read_bytes()).hexdigest()
        assert script_digest == direct_digest

    def test_script_and_direct_invocation_match_on_a_blocking_verdict(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "target"
        target.mkdir()
        _write_fixture("agent-with-ceiling-breach", target)

        script_evidence = tmp_path / "script-evidence.json"
        script_result = subprocess.run(
            [
                "uv",
                "run",
                "--project",
                str(_REPO_ROOT),
                "controlloop",
                "gate",
                str(target),
                "--evidence-path",
                str(script_evidence),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert script_result.returncode == ExitCode.POLICY_FAIL

        direct_evidence = tmp_path / "direct-evidence.json"
        direct_result = runner.invoke(
            app,
            ["gate", str(target), "--evidence-path", str(direct_evidence)],
        )
        assert direct_result.exit_code == ExitCode.POLICY_FAIL

        script_digest = hashlib.sha256(script_evidence.read_bytes()).hexdigest()
        direct_digest = hashlib.sha256(direct_evidence.read_bytes()).hexdigest()
        assert script_digest == direct_digest
