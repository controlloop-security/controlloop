"""Tests for `controlloop.baseline.staleness`.

`TestResolveDefaultBranchCommit` and `TestCountCommitsBetween` build real,
local, offline git repositories (mirroring `test_bom.py::TestResolveCommit`'s
own `_init_repo`/`_commit_all` style) rather than mocking `subprocess.run`,
so the exact `git` invocations are exercised for real. The remote used
throughout is a local bare repository reached by filesystem path -- never a
network URL -- so this stays covered by the autouse
`_deny_network_access` socket-denial fixture in `tests/conftest.py`
the same way `test_bom.py`'s git-backed tests already are.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from controlloop.acbom.models import Confidence, Diagnostic, DiagnosticSeverity
from controlloop.baseline.staleness import (
    BASELINE_DIAGNOSTIC_REGISTRY,
    count_commits_between,
    describe_staleness,
    detect_baseline_staleness,
    resolve_default_branch_commit,
)

_BASELINE_PATH = ".controlloop/baseline.json"
_COMMIT_A = "a" * 40
_COMMIT_B = "b" * 40


def _run(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


def _commit_all(path: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@t.com",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            message,
        ],
        cwd=path,
        check=True,
    )
    return _run(["rev-parse", "HEAD"], path)


def _repo_with_bare_origin(tmp_path: Path) -> tuple[Path, Path]:
    """A working checkout with a local bare "remote" reached by filesystem
    path -- never a network URL -- so `git fetch`/`git push` against it
    stay covered by the offline socket-denial fixture."""

    bare = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)

    work = tmp_path / "work"
    work.mkdir()
    _init_repo(work)
    subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=work, check=True)
    return work, bare


class TestResolveDefaultBranchCommit:
    def test_uses_origin_head_symbolic_ref_when_set(self, tmp_path: Path) -> None:
        work, bare = _repo_with_bare_origin(tmp_path)
        (work / "file.txt").write_text("hello\n")
        first_commit = _commit_all(work, "initial")
        subprocess.run(
            ["git", "push", "-q", "origin", "HEAD:main"], cwd=work, check=True
        )
        subprocess.run(
            ["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=bare, check=True
        )
        subprocess.run(
            ["git", "remote", "set-head", "origin", "-a"], cwd=work, check=True
        )
        subprocess.run(["git", "fetch", "-q", "origin"], cwd=work, check=True)

        assert resolve_default_branch_commit(work) == first_commit

    def test_falls_back_to_origin_main_when_origin_head_is_unset(
        self, tmp_path: Path
    ) -> None:
        work, _bare = _repo_with_bare_origin(tmp_path)
        (work / "file.txt").write_text("hello\n")
        first_commit = _commit_all(work, "initial")
        subprocess.run(
            ["git", "push", "-q", "origin", "HEAD:main"], cwd=work, check=True
        )
        subprocess.run(["git", "fetch", "-q", "origin"], cwd=work, check=True)

        assert resolve_default_branch_commit(work) == first_commit

    def test_falls_back_to_origin_master_when_origin_head_is_unset(
        self, tmp_path: Path
    ) -> None:
        work, _bare = _repo_with_bare_origin(tmp_path)
        (work / "file.txt").write_text("hello\n")
        first_commit = _commit_all(work, "initial")
        subprocess.run(
            ["git", "push", "-q", "origin", "HEAD:master"], cwd=work, check=True
        )
        subprocess.run(["git", "fetch", "-q", "origin"], cwd=work, check=True)

        assert resolve_default_branch_commit(work) == first_commit

    def test_returns_none_without_an_origin_remote(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("hello\n")
        _commit_all(tmp_path, "initial")

        assert resolve_default_branch_commit(tmp_path) is None

    def test_returns_none_outside_a_git_checkout(self, tmp_path: Path) -> None:
        assert resolve_default_branch_commit(tmp_path) is None

    def test_returns_none_when_git_is_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PATH", "")

        assert resolve_default_branch_commit(tmp_path) is None


class TestCountCommitsBetween:
    def test_counts_commits_reachable_from_newer_but_not_older(
        self, tmp_path: Path
    ) -> None:
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("v1\n")
        older = _commit_all(tmp_path, "v1")
        (tmp_path / "file.txt").write_text("v2\n")
        _commit_all(tmp_path, "v2")
        (tmp_path / "file.txt").write_text("v3\n")
        newer = _commit_all(tmp_path, "v3")

        assert count_commits_between(tmp_path, older, newer) == 2

    def test_zero_for_identical_commits(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("v1\n")
        commit = _commit_all(tmp_path, "v1")

        assert count_commits_between(tmp_path, commit, commit) == 0

    def test_none_when_older_commit_is_not_in_history(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("v1\n")
        newer = _commit_all(tmp_path, "v1")

        assert count_commits_between(tmp_path, "0" * 40, newer) is None

    def test_none_outside_a_git_checkout(self, tmp_path: Path) -> None:
        assert count_commits_between(tmp_path, _COMMIT_A, _COMMIT_B) is None

    def test_none_when_rev_list_itself_fails(self, tmp_path: Path) -> None:
        """`older` resolves but `newer` does not -- `git rev-list --count`
        then fails even though the earlier `rev-parse --verify older`
        check passed."""

        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("v1\n")
        older = _commit_all(tmp_path, "v1")

        assert count_commits_between(tmp_path, older, "0" * 40) is None

    def test_none_when_rev_list_output_is_not_an_integer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import controlloop.baseline.staleness as staleness_module

        _init_repo(tmp_path)
        (tmp_path / "file.txt").write_text("v1\n")
        commit = _commit_all(tmp_path, "v1")

        real_run_git = staleness_module._run_git

        def _fake_run_git(args: list[str], root_path: Path) -> str | None:
            if args[0] == "rev-list":
                return "not-a-number"
            return real_run_git(args, root_path)

        monkeypatch.setattr(staleness_module, "_run_git", _fake_run_git)

        assert count_commits_between(tmp_path, commit, commit) is None


class TestDetectBaselineStalenessCurrent:
    """Divergence between the baseline commit and the default
    branch commit is reported; identical or within-threshold commits are
    not."""

    def test_identical_commits_are_never_stale(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_A,
            commits_behind=0,
            baseline_path=_BASELINE_PATH,
        )

        assert result is None

    def test_identical_commits_are_never_stale_even_if_commits_behind_is_none(
        self,
    ) -> None:
        """Same-commit is checked before `commits_behind` is consulted at
        all -- a same-commit baseline is never reported unverifiable,
        whatever `commits_behind` happens to be."""

        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_A,
            commits_behind=None,
            baseline_path=_BASELINE_PATH,
        )

        assert result is None

    def test_within_threshold_is_not_stale(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=5,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )

        assert result is None

    def test_exactly_at_threshold_is_not_stale(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=10,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )

        assert result is None

    def test_zero_commits_behind_with_different_commits_is_not_stale(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=0,
            baseline_path=_BASELINE_PATH,
        )

        assert result is None


class TestDetectBaselineStalenessStale:
    """Staleness beyond a configurable threshold produces a
    finding."""

    def test_one_commit_over_threshold_is_stale(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=11,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )

        assert result is not None
        assert result.code == "BASELINE-STALE"
        assert result.severity is DiagnosticSeverity.WARNING
        assert result.confidence is Confidence.HIGH
        assert result.incomplete is False
        assert _COMMIT_A in result.message
        assert _COMMIT_B in result.message
        assert "11" in result.message
        assert "10" in result.message
        assert result.evidence[0].adapter == "baseline-staleness"
        assert result.evidence[0].path == _BASELINE_PATH

    def test_threshold_is_configurable(self) -> None:
        default = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=50,
            baseline_path=_BASELINE_PATH,
        )
        tighter = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=50,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )

        assert default is None
        assert tighter is not None
        assert tighter.code == "BASELINE-STALE"


class TestDetectBaselineStalenessUnverifiable:
    """A baseline describing a commit not present in history is
    reported as unverifiable, distinct from a confident stale/current
    verdict."""

    def test_none_commits_behind_is_unverifiable(self) -> None:
        result = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=None,
            baseline_path=_BASELINE_PATH,
        )

        assert result is not None
        assert result.code == "BASELINE-UNVERIFIABLE"
        assert result.severity is DiagnosticSeverity.WARNING
        assert result.confidence is Confidence.UNKNOWN
        assert result.incomplete is False
        assert _COMMIT_A in result.message


class TestInvalidThreshold:
    def test_zero_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="max_staleness_commits"):
            detect_baseline_staleness(
                baseline_commit=_COMMIT_A,
                default_branch_commit=_COMMIT_B,
                commits_behind=1,
                max_staleness_commits=0,
                baseline_path=_BASELINE_PATH,
            )

    def test_negative_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="max_staleness_commits"):
            detect_baseline_staleness(
                baseline_commit=_COMMIT_A,
                default_branch_commit=_COMMIT_B,
                commits_behind=1,
                max_staleness_commits=-1,
                baseline_path=_BASELINE_PATH,
            )


class TestRegistry:
    def test_contains_exactly_the_two_documented_codes(self) -> None:
        assert set(BASELINE_DIAGNOSTIC_REGISTRY) == {
            "BASELINE-STALE",
            "BASELINE-UNVERIFIABLE",
        }

    def test_every_code_has_a_nonempty_description(self) -> None:
        for description in BASELINE_DIAGNOSTIC_REGISTRY.values():
            assert description.strip() != ""


class TestDescribeStaleness:
    def test_renders_a_single_warning_glyph_line(self) -> None:
        diagnostic = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=11,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )
        assert diagnostic is not None

        line = describe_staleness(diagnostic)

        assert line.startswith("!")
        assert "BASELINE STALE" in line
        assert "\n" not in line


class TestJsonOutput:
    """Structural JSON output: a staleness finding is an
    ordinary canonical `Diagnostic`, serializing and round-tripping
    exactly like any other diagnostic in this codebase."""

    def test_diagnostic_round_trips_through_json(self) -> None:
        diagnostic = detect_baseline_staleness(
            baseline_commit=_COMMIT_A,
            default_branch_commit=_COMMIT_B,
            commits_behind=11,
            max_staleness_commits=10,
            baseline_path=_BASELINE_PATH,
        )
        assert diagnostic is not None

        restored = Diagnostic.model_validate_json(diagnostic.model_dump_json())

        assert restored == diagnostic


class TestDeterminism:
    def test_identical_inputs_produce_an_identical_diagnostic(self) -> None:
        kwargs = {
            "baseline_commit": _COMMIT_A,
            "default_branch_commit": _COMMIT_B,
            "commits_behind": 11,
            "max_staleness_commits": 10,
            "baseline_path": _BASELINE_PATH,
        }

        first = detect_baseline_staleness(**kwargs)  # type: ignore[arg-type]
        second = detect_baseline_staleness(**kwargs)  # type: ignore[arg-type]

        assert first == second
        assert first is not None
        assert second is not None
        assert first.model_dump_json() == second.model_dump_json()
