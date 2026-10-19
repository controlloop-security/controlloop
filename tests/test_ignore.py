"""Tests for `.gitignore`/`.controlloopignore` precedence evaluation.

Covers precedence evaluation at the module level. The guarantee that an
excluded file is never opened, and full walk-level integration (including
the "cannot re-include inside an excluded parent directory" constraint,
which is a property of how `walk_repository` uses this module, not of
`is_ignored` in isolation) are covered in `test_repository.py`.
"""

from __future__ import annotations

from pathlib import Path

from controlloop import ignore


def _level(
    relative_dir: str,
    *,
    gitignore: list[str] | None = None,
    controlloopignore: list[str] | None = None,
) -> ignore.IgnoreLevel:
    return ignore.IgnoreLevel(
        relative_dir=relative_dir,
        gitignore=ignore.compile_exclusions(gitignore or []),
        controlloopignore=ignore.compile_exclusions(controlloopignore or []),
    )


class TestNegationAndDirectoryPatterns:
    def test_negation_re_includes_within_same_level(self) -> None:
        level = _level("", gitignore=["*.log", "!important.log"])

        assert ignore.is_ignored((level,), "debug.log", is_directory=False) is True
        assert ignore.is_ignored((level,), "important.log", is_directory=False) is False

    def test_directory_only_pattern_does_not_match_a_same_named_file(self) -> None:
        level = _level("", gitignore=["build/"])

        assert ignore.is_ignored((level,), "build", is_directory=True) is True
        assert ignore.is_ignored((level,), "build", is_directory=False) is False

    def test_double_star_matches_any_depth(self) -> None:
        level = _level("", gitignore=["a/**/c"])

        assert ignore.is_ignored((level,), "a/c", is_directory=False) is True
        assert ignore.is_ignored((level,), "a/x/y/c", is_directory=False) is True
        assert ignore.is_ignored((level,), "a/x/y/d", is_directory=False) is False


class TestControlloopignoreOverridesGitignore:
    def test_controlloopignore_wins_within_same_level(self) -> None:
        level = _level("", gitignore=["*.log"], controlloopignore=["!*.log"])

        assert ignore.is_ignored((level,), "debug.log", is_directory=False) is False

    def test_gitignore_still_applies_when_controlloopignore_silent(self) -> None:
        level = _level("", gitignore=["*.log"], controlloopignore=["*.tmp"])

        assert ignore.is_ignored((level,), "debug.log", is_directory=False) is True


class TestNestedPrecedence:
    def test_deeper_level_overrides_shallower_for_the_same_path(self) -> None:
        root = _level("", gitignore=["*.log"])
        sub = _level("sub", gitignore=["!a.log"])

        assert ignore.is_ignored((root, sub), "sub/a.log", is_directory=False) is False
        assert ignore.is_ignored((root, sub), "sub/b.log", is_directory=False) is True
        assert ignore.is_ignored((root,), "other/a.log", is_directory=False) is True

    def test_nested_pattern_is_scoped_to_its_own_directory(self) -> None:
        root = _level("")
        sub = _level("sub", gitignore=["cache"])

        assert ignore.is_ignored((root, sub), "sub/cache", is_directory=True) is True
        assert (
            ignore.is_ignored((root, sub), "sub/nested/cache", is_directory=True)
            is True
        )
        assert ignore.is_ignored((root,), "cache", is_directory=True) is False


class TestCommandLineExclusions:
    def test_applied_last_and_can_reinclude(self) -> None:
        level = _level("", gitignore=["*.log"])
        cli = ignore.compile_exclusions(["!important.log"])

        assert (
            ignore.is_ignored(
                (level,), "important.log", is_directory=False, cli_exclusions=cli
            )
            is False
        )
        assert (
            ignore.is_ignored(
                (level,), "debug.log", is_directory=False, cli_exclusions=cli
            )
            is True
        )

    def test_can_exclude_something_not_otherwise_ignored(self) -> None:
        level = _level("")
        cli = ignore.compile_exclusions(["secrets.env"])

        assert (
            ignore.is_ignored(
                (level,), "secrets.env", is_directory=False, cli_exclusions=cli
            )
            is True
        )


class TestLoadIgnoreLevel:
    def test_missing_files_produce_an_empty_level_and_no_problems(
        self, tmp_path: Path
    ) -> None:
        level, problems = ignore.load_ignore_level(tmp_path, "", max_bytes=1000)

        assert level.gitignore is None
        assert level.controlloopignore is None
        assert problems == ()

    def test_loads_real_files_from_disk(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / ".controlloopignore").write_text("!debug.log\n")

        level, problems = ignore.load_ignore_level(tmp_path, "", max_bytes=1000)

        assert problems == ()
        assert ignore.is_ignored((level,), "other.log", is_directory=False) is True
        assert ignore.is_ignored((level,), "debug.log", is_directory=False) is False

    def test_oversized_ignore_file_contributes_no_rules_and_is_reported(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n" + "#padding\n" * 1000)

        level, problems = ignore.load_ignore_level(tmp_path, "", max_bytes=10)

        assert level.gitignore is None
        assert len(problems) == 1
        assert problems[0].name == ".gitignore"
        assert problems[0].status == "too-large"

    def test_malformed_encoding_does_not_crash(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_bytes(b"*.log\n\xff\xfe\x80\n")

        level, problems = ignore.load_ignore_level(tmp_path, "", max_bytes=10_000)

        assert level.gitignore is not None
        assert problems == ()


class TestDeterminism:
    def test_same_inputs_produce_the_same_verdict_every_time(self) -> None:
        level = _level("", gitignore=["*.log", "!important.log", "build/"])

        for _ in range(5):
            assert ignore.is_ignored((level,), "a.log", is_directory=False) is True
            assert (
                ignore.is_ignored((level,), "important.log", is_directory=False)
                is False
            )
