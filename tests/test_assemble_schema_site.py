"""Tests for `release-scripts/assemble_schema_site.py`.

Mirrors `test_release_scripts.py`'s own precedent: this script lives outside
the `controlloop` package (invoked directly by
`.github/workflows/release.yml`, never imported), so it is exercised as a
real subprocess against real file paths under `tmp_path`. It performs no
network access, so this file is unaffected by (and does not need to
participate in) `conftest.py`'s autouse offline-denial fixture, the same
reasoning `test_release_scripts.py` already documents for its own subprocess
calls.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "release-scripts" / "assemble_schema_site.py"
_REAL_SCHEMAS_ROOT = _REPO_ROOT / "src" / "controlloop" / "schemas"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _write_schema(root: Path, family: str, version: str, schema_id: str) -> Path:
    directory = root / family / version
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{family}.schema.json"
    path.write_text(f'{{"$id": "{schema_id}", "type": "object"}}')
    return path


class TestAssembleSchemaSitePositive:
    def test_copies_every_family_and_version_it_finds(self, tmp_path: Path) -> None:
        schemas_root = tmp_path / "schemas"
        _write_schema(
            schemas_root, "acbom", "1.0.0", "https://schemas.controlloop.ai/x"
        )
        _write_schema(
            schemas_root, "acbom", "1.1.0", "https://schemas.controlloop.ai/y"
        )
        _write_schema(
            schemas_root, "manifest", "1.0.0", "https://schemas.controlloop.ai/z"
        )
        output = tmp_path / "site"

        result = _run(["--schemas-root", str(schemas_root), "--output", str(output)])

        assert result.returncode == 0, result.stderr
        assert (output / "acbom" / "1.0.0" / "acbom.schema.json").is_file()
        assert (output / "acbom" / "1.1.0" / "acbom.schema.json").is_file()
        assert (output / "manifest" / "1.0.0" / "manifest.schema.json").is_file()

    def test_writes_a_cname_file_for_the_custom_domain(self, tmp_path: Path) -> None:
        schemas_root = tmp_path / "schemas"
        _write_schema(
            schemas_root, "acbom", "1.0.0", "https://schemas.controlloop.ai/x"
        )
        output = tmp_path / "site"

        result = _run(["--schemas-root", str(schemas_root), "--output", str(output)])

        assert result.returncode == 0, result.stderr
        assert (output / "CNAME").read_text(
            encoding="utf-8"
        ) == "schemas.controlloop.ai\n"

    def test_copied_content_is_byte_identical_to_the_source(
        self, tmp_path: Path
    ) -> None:
        schemas_root = tmp_path / "schemas"
        source = _write_schema(
            schemas_root, "acbom", "1.0.0", "https://schemas.controlloop.ai/x"
        )
        output = tmp_path / "site"

        result = _run(["--schemas-root", str(schemas_root), "--output", str(output)])

        assert result.returncode == 0, result.stderr
        copied = output / "acbom" / "1.0.0" / "acbom.schema.json"
        assert copied.read_bytes() == source.read_bytes()

    def test_the_real_packaged_schemas_root_assembles_without_error(
        self, tmp_path: Path
    ) -> None:
        """Not a fixture: this repository's own real, current
        `src/controlloop/schemas/` tree, proving the site assembles from the
        actual artifact the release workflow will publish, not a synthetic
        stand-in."""

        output = tmp_path / "site"

        result = _run(
            ["--schemas-root", str(_REAL_SCHEMAS_ROOT), "--output", str(output)]
        )

        assert result.returncode == 0, result.stderr
        assert (output / "acbom" / "1.0.0" / "acbom.schema.json").is_file()
        assert (output / "acbom" / "1.1.0" / "acbom.schema.json").is_file()
        assert (output / "baseline" / "1.0.0" / "baseline.schema.json").is_file()
        assert (output / "baseline" / "1.1.0" / "baseline.schema.json").is_file()
        assert (output / "evidence" / "1.0.0" / "evidence.schema.json").is_file()
        assert (output / "evidence" / "1.1.0" / "evidence.schema.json").is_file()
        assert (output / "manifest" / "1.0.0" / "manifest.schema.json").is_file()
        assert (output / "report" / "1.0.0" / "report.schema.json").is_file()
        assert (output / "CNAME").is_file()


class TestAssembleSchemaSiteNegative:
    def test_missing_schemas_root_fails_cleanly(self, tmp_path: Path) -> None:
        result = _run(
            [
                "--schemas-root",
                str(tmp_path / "does-not-exist"),
                "--output",
                str(tmp_path / "site"),
            ]
        )

        assert result.returncode == 2
        assert "does not exist" in result.stderr

    def test_empty_schemas_root_refuses_to_publish_nothing(
        self, tmp_path: Path
    ) -> None:
        schemas_root = tmp_path / "schemas"
        schemas_root.mkdir()
        output = tmp_path / "site"

        result = _run(["--schemas-root", str(schemas_root), "--output", str(output)])

        assert result.returncode == 2
        assert "no schema files found" in result.stderr
