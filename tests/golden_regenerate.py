"""The one documented command that regenerates every golden file under
`tests/fixtures/golden/`.

    uv run python tests/golden_regenerate.py

Run from the repository root. Never imported or executed by `pytest`
collection: this file is not named `test_*.py` (pytest's own collection
convention skips it), and its regeneration logic additionally sits behind an
`if __name__ == "__main__":` guard, so even a direct import (for example by
`test_golden_baselines.py`, which imports only `FIXTURES` from
`golden_fixtures.py`, never anything from this module) would run nothing.

Lives directly in `tests/` (a flat sibling of `golden_fixtures.py`,
`test_golden_baselines.py`, and `determinism_support.py`), not in its own
subdirectory: this codebase has no precedent anywhere for a test module
importing a *parent* directory's sibling module by bare name (pytest's own
rootless import mode only reliably makes a module's own directory
importable, not its ancestors), and `test_golden_baselines.py` needs exactly
that for `determinism_support.assert_stable_digest`. Keeping every file in
this feature at the same directory level as `determinism_support.py` avoids
relying on collection-order-dependent sys.path side effects.

Captures the real CLI's own stdout through `typer.testing.CliRunner`
(`controlloop bom`, `controlloop diff`, `controlloop scan`) -- the same
real, user-facing command surface a genuine output drift would actually
reach a user through, not an internal function call one layer removed from
it.

After running this script, inspect every changed file under
`tests/fixtures/golden/` by hand before committing -- this script
regenerates the comparison target; it does not by itself confirm the
new output is correct.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from golden_fixtures import FIXTURES
from typer.testing import CliRunner

from controlloop.cli import app

_DATA_ROOT = Path(__file__).resolve().parent / "fixtures" / "golden"

_runner = CliRunner()


def _relative_to_cwd(path: Path) -> str:
    """`diff`'s own two-ACBOM-file mode embeds its two path arguments
    verbatim in `DiffReport.baseline_description`. Passing an absolute path
    would bake this checkout's own filesystem location into a committed
    golden file, breaking reproducibility the moment the repository is
    cloned somewhere else. Every verified command in this repository is
    already run from the repository root (an established convention), so a
    path relative to the current working directory is stable across
    checkouts as long as that convention holds -- the same assumption
    `test_golden_baselines.py` relies on to reproduce this exact invocation
    for comparison."""

    return os.path.relpath(path, Path.cwd())


def _invoke(*args: str) -> str:
    result = _runner.invoke(app, list(args))
    return result.stdout


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def regenerate() -> None:
    acbom_paths: dict[str, Path] = {}

    with tempfile.TemporaryDirectory() as tmp:
        for name, builder in FIXTURES.items():
            fixture_root = Path(tmp) / name
            fixture_root.mkdir()
            builder(fixture_root)

            acbom = _invoke("bom", str(fixture_root))
            _write(_DATA_ROOT / name / "acbom.json", acbom)

            report = _invoke("scan", str(fixture_root), "--format", "json")
            _write(_DATA_ROOT / name / "report.json", report)

            acbom_paths[name] = _DATA_ROOT / name / "acbom.json"

        diff_report = _invoke(
            "diff",
            _relative_to_cwd(acbom_paths["empty"]),
            _relative_to_cwd(acbom_paths["single-agent"]),
            "--format",
            "json",
        )
        _write(_DATA_ROOT / "diff-empty-to-single-agent" / "report.json", diff_report)

    print(f"Regenerated goldens for: {', '.join(sorted(FIXTURES))}, plus one diff.")


if __name__ == "__main__":
    regenerate()
