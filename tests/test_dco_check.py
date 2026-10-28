"""Tests for `scripts/check-dco.sh`, the Developer Certificate of Origin
check `.github/workflows/dco.yml` runs on every pull request.

Each test builds a real repository in a temporary directory, so the check
is exercised against the trailers `git commit -s` actually writes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-dco.sh"
_AUTHOR = ("-c", "user.name=Ada Author", "-c", "user.email=ada@example.invalid")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *_AUTHOR, *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _commit(
    repo: Path, name: str, *, signoff: bool, trailer: str = "", author: str = ""
) -> None:
    (repo / name).write_text(name)
    _git(repo, "add", name)
    message = f"add {name}" + (f"\n\n{trailer}" if trailer else "")
    _git(
        repo,
        "commit",
        "-q",
        *(["-s"] if signoff else []),
        *([f"--author={author}"] if author else []),
        "-m",
        message,
    )


def _check(repo: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_SCRIPT), base, "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    _git(tmp_path, "init", "-q", "-b", "main")
    _commit(tmp_path, "base.txt", signoff=False)
    return tmp_path, _git(tmp_path, "rev-parse", "HEAD")


def test_signed_off_commits_pass(repo: tuple[Path, str]) -> None:
    path, base = repo
    _commit(path, "a.txt", signoff=True)
    _commit(path, "b.txt", signoff=True)

    result = _check(path, base)

    assert result.returncode == 0, result.stdout
    assert "all 2 commit(s) are signed off" in result.stdout


def test_one_unsigned_commit_fails_and_is_named(repo: tuple[Path, str]) -> None:
    path, base = repo
    _commit(path, "a.txt", signoff=True)
    _commit(path, "b.txt", signoff=False)
    unsigned = _git(path, "rev-parse", "HEAD")

    result = _check(path, base)

    assert result.returncode == 1
    assert f"::error::Commit {unsigned[:12]} by <ada@example.invalid>" in result.stdout
    assert "1 of 2 commit(s) are not signed off" in result.stdout
    assert "git rebase --signoff" in result.stdout


def test_a_sign_off_by_someone_else_does_not_count(repo: tuple[Path, str]) -> None:
    path, base = repo
    _commit(
        path,
        "a.txt",
        signoff=False,
        trailer="Signed-off-by: Bob Other <bob@example.invalid>",
    )

    assert _check(path, base).returncode == 1


def test_the_email_match_ignores_case(repo: tuple[Path, str]) -> None:
    path, base = repo
    _commit(
        path,
        "a.txt",
        signoff=False,
        trailer="Signed-off-by: Ada Author <ADA@Example.Invalid>",
    )

    assert _check(path, base).returncode == 0


_DEPENDABOT = "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
_DEPENDABOT_SIGNOFF = "Signed-off-by: dependabot[bot] <support@github.com>"


def test_a_dependabot_commit_with_its_own_sign_off_passes(
    repo: tuple[Path, str],
) -> None:
    """Dependabot authors as its noreply address but signs off as
    support@github.com, exactly as on its pull requests."""

    path, base = repo
    _commit(
        path, "a.txt", signoff=False, trailer=_DEPENDABOT_SIGNOFF, author=_DEPENDABOT
    )

    result = _check(path, base)

    assert result.returncode == 0, result.stdout


def test_a_dependabot_commit_without_a_sign_off_fails(
    repo: tuple[Path, str],
) -> None:
    path, base = repo
    _commit(path, "a.txt", signoff=False, author=_DEPENDABOT)

    assert _check(path, base).returncode == 1


def test_the_dependabot_sign_off_does_not_count_for_anyone_else(
    repo: tuple[Path, str],
) -> None:
    path, base = repo
    _commit(path, "a.txt", signoff=False, trailer=_DEPENDABOT_SIGNOFF)

    assert _check(path, base).returncode == 1


def test_commits_before_the_base_are_not_checked(repo: tuple[Path, str]) -> None:
    """The base commit itself is unsigned, and is outside the range."""

    path, base = repo

    result = _check(path, base)

    assert result.returncode == 0
    assert "all 0 commit(s)" in result.stdout


def test_merge_commits_are_skipped(repo: tuple[Path, str]) -> None:
    path, base = repo
    _git(path, "checkout", "-q", "-b", "topic")
    _commit(path, "a.txt", signoff=True)
    _git(path, "checkout", "-q", "main")
    _commit(path, "b.txt", signoff=True)
    _git(path, "merge", "-q", "--no-ff", "--no-edit", "topic")

    result = _check(path, base)

    assert result.returncode == 0, result.stdout
    assert "all 2 commit(s) are signed off" in result.stdout


def test_wrong_arguments_print_usage() -> None:
    result = subprocess.run(
        ["bash", str(_SCRIPT)], capture_output=True, text=True, check=False
    )

    assert result.returncode == 2
    assert "usage:" in result.stderr
