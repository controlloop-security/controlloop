"""Tests for `action-scripts/blast_radius_summary.py`.

The script lives outside the `controlloop` package (it is invoked directly
by `action.yml`, never imported), so it is exercised the same way
`action.yml` itself does: as a real subprocess, given a real file path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "action-scripts" / "blast_radius_summary.py"
)


def _run(sarif_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), str(sarif_path)],
        capture_output=True,
        text=True,
        check=False,
    )


class TestBlastRadiusSummary:
    def test_prints_each_embedded_line(self, tmp_path: Path) -> None:
        sarif_path = tmp_path / "results.sarif"
        sarif_path.write_text(
            json.dumps(
                {
                    "runs": [
                        {
                            "properties": {
                                "controlloop": {
                                    "blastRadius": [
                                        "• headline",
                                        "  hop 1",
                                    ]
                                }
                            }
                        }
                    ]
                }
            )
        )

        result = _run(sarif_path)

        assert result.returncode == 0
        assert result.stdout == "• headline\n  hop 1\n"

    def test_missing_property_prints_nothing_and_exits_zero(
        self, tmp_path: Path
    ) -> None:
        sarif_path = tmp_path / "results.sarif"
        sarif_path.write_text(json.dumps({"runs": [{}]}))

        result = _run(sarif_path)

        assert result.returncode == 0
        assert result.stdout == ""

    def test_missing_file_prints_nothing_and_exits_zero(self, tmp_path: Path) -> None:
        result = _run(tmp_path / "does-not-exist.sarif")

        assert result.returncode == 0
        assert result.stdout == ""

    def test_malformed_json_prints_nothing_and_exits_zero(self, tmp_path: Path) -> None:
        sarif_path = tmp_path / "results.sarif"
        sarif_path.write_text("not json")

        result = _run(sarif_path)

        assert result.returncode == 0
        assert result.stdout == ""
