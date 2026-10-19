"""Golden ACBOM, diff, and report baseline comparisons. See
`tests/golden_fixtures.py` for the three synthetic scannable fixtures and
`tests/golden_regenerate.py` for the one documented regeneration command
that produces the
committed files under `tests/fixtures/golden/` this module compares
against.
"""

from __future__ import annotations

import difflib
import os
import tempfile
from pathlib import Path

import pytest
from determinism_support import assert_stable_digest
from golden_fixtures import FIXTURES
from typer.testing import CliRunner

from controlloop.cli import app

_DATA_ROOT = Path(__file__).resolve().parent / "fixtures" / "golden"

_runner = CliRunner()


def _invoke(*args: str) -> str:
    result = _runner.invoke(app, list(args))
    return result.stdout


def _relative_to_cwd(path: Path) -> str:
    return os.path.relpath(path, Path.cwd())


def _assert_matches_golden(actual: str, golden_path: Path) -> None:
    """On a mismatch, the assertion failure itself is a
    readable, line-oriented diff naming exactly what changed -- not
    just "these two strings differ." Reused by every comparison below,
    so readability is proven once, structurally, rather than per
    fixture."""

    golden = golden_path.read_text(encoding="utf-8")
    if actual == golden:
        return

    diff_lines = list(
        difflib.unified_diff(
            golden.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"golden: {golden_path}",
            tofile="actual (freshly rebuilt)",
        )
    )
    raise AssertionError(
        "output no longer matches its committed golden -- if this "
        "change is intentional, regenerate with `uv run python "
        "tests/golden_regenerate.py` from the repository root, inspect the diff by "
        "hand, and commit the result:\n" + "".join(diff_lines)
    )


class TestReadableDiffOnMismatch:
    """The readable diff, proven directly against the comparison helper
    itself (rather than only incidentally, whenever some future real drift
    happens to occur) -- a deliberately mismatched pair must produce a diff
    naming the specific changed line, not just "mismatch"."""

    def test_a_mismatch_names_the_changed_line(self, tmp_path: Path) -> None:
        golden_path = tmp_path / "golden.json"
        golden_path.write_text('{"a": 1, "b": 2}\n', encoding="utf-8")

        with pytest.raises(AssertionError) as excinfo:
            _assert_matches_golden('{"a": 1, "b": 3}\n', golden_path)

        message = str(excinfo.value)
        assert '"b": 2' in message
        assert '"b": 3' in message
        assert "tests/golden_regenerate.py" in message

    def test_identical_content_raises_nothing(self, tmp_path: Path) -> None:
        golden_path = tmp_path / "golden.json"
        golden_path.write_text("identical\n", encoding="utf-8")

        _assert_matches_golden("identical\n", golden_path)


class TestGoldenAcbomAndReport:
    """Each fixture's freshly rebuilt ACBOM and report match
    their committed golden exactly, byte for byte."""

    @pytest.mark.parametrize("name", sorted(FIXTURES))
    def test_acbom_matches_golden(self, name: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / name
            fixture_root.mkdir()
            FIXTURES[name](fixture_root)

            actual = _invoke("bom", str(fixture_root))

        _assert_matches_golden(actual, _DATA_ROOT / name / "acbom.json")

    @pytest.mark.parametrize("name", sorted(FIXTURES))
    def test_report_matches_golden(self, name: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_root = Path(tmp) / name
            fixture_root.mkdir()
            FIXTURES[name](fixture_root)

            actual = _invoke("scan", str(fixture_root), "--format", "json")

        _assert_matches_golden(actual, _DATA_ROOT / name / "report.json")

    def test_diff_matches_golden(self) -> None:
        empty_acbom = _DATA_ROOT / "empty" / "acbom.json"
        single_agent_acbom = _DATA_ROOT / "single-agent" / "acbom.json"

        actual = _invoke(
            "diff",
            _relative_to_cwd(empty_acbom),
            _relative_to_cwd(single_agent_acbom),
            "--format",
            "json",
        )

        _assert_matches_golden(
            actual, _DATA_ROOT / "diff-empty-to-single-agent" / "report.json"
        )


class TestStableAcrossRepeatedBuilds:
    """The repeated-build dimension, proven by direct reuse of the
    determinism harness in `tests/determinism_support.py` -- this module
    is that harness's first real external consumer. Cross-platform/
    locale/timezone/`PYTHONHASHSEED` stability itself is inherited from
    that harness's own guarantee, not re-proven here."""

    def test_single_agent_acbom_digest_is_stable_across_five_builds(
        self, tmp_path: Path
    ) -> None:
        from controlloop.bom import build_acbom_document
        from controlloop.repository import resolve_repository_root

        FIXTURES["single-agent"](tmp_path)
        root = resolve_repository_root(tmp_path)

        assert_stable_digest(lambda: build_acbom_document(root), runs=5)
