"""Tests for `release-scripts/derive_release_metadata.py` and
`release-scripts/changelog_release_notes.py`.

Both scripts live outside the `controlloop` package (invoked directly by
`.github/workflows/release.yml`, never imported), so they are exercised the
same way `action.yml`'s own `blast_radius_summary.py` already is in
`test_action_scripts.py`: as real subprocesses, given real file paths under
`tmp_path`. Neither script performs network access, so these tests are
unaffected by (and do not need to participate in) `conftest.py`'s
autouse offline-denial fixture -- the same reasoning `test_action_scripts.py`
and `determinism_support.py` already document for their own subprocess
calls.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DERIVE_SCRIPT = _REPO_ROOT / "release-scripts" / "derive_release_metadata.py"
_CHANGELOG_SCRIPT = _REPO_ROOT / "release-scripts" / "changelog_release_notes.py"


def _run(script: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def _write_fixture_cli_tree(root: Path, *, package_version: str = "0.2.0") -> Path:
    """A minimal synthetic package tree with exactly the files
    `derive_release_metadata.py` reads: `pyproject.toml`, `policy/
    rulepack.py`, and two files under `src/controlloop` each declaring a
    `CURRENT_*_SCHEMA_VERSION` constant."""
    cli_root = root
    (cli_root / "src" / "controlloop" / "policy").mkdir(parents=True)
    (cli_root / "src" / "controlloop" / "acbom").mkdir(parents=True)

    (cli_root / "pyproject.toml").write_text(
        f'[project]\nname = "controlloop"\nversion = "{package_version}"\n'
    )
    (cli_root / "src" / "controlloop" / "policy" / "rulepack.py").write_text(
        "CURRENT_RULE_PACK = RulePack(\n"
        '    name="controlloop-baseline",\n'
        '    version="0.1.0",\n'
        "    rules=(),\n"
        ")\n"
    )
    (cli_root / "src" / "controlloop" / "acbom" / "versioning.py").write_text(
        'CURRENT_SCHEMA_VERSION = "1.0.0"\n'
    )
    (cli_root / "src" / "controlloop" / "policy" / "thresholds.py").write_text(
        'CURRENT_FINDING_SCHEMA_VERSION = "1.0.0"\n'
    )
    return root


class TestDeriveReleaseMetadataPositive:
    def test_matching_tag_and_version_writes_manifest(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        output = root / "release-manifest.json"

        result = _run(
            _DERIVE_SCRIPT,
            [
                "v0.2.0",
                "--repo-root",
                str(root),
                "--output",
                str(output),
                "--commit-sha",
                "deadbeef",
            ],
        )

        assert result.returncode == 0, result.stderr
        manifest = json.loads(output.read_text())
        assert manifest["tag"] == "v0.2.0"
        assert manifest["package_version"] == "0.2.0"
        assert manifest["commit_sha"] == "deadbeef"
        assert manifest["rule_pack"] == {
            "name": "controlloop-baseline",
            "version": "0.1.0",
        }
        assert manifest["schema_versions"] == {
            "acbom": "1.0.0",  # from the bare CURRENT_SCHEMA_VERSION
            "finding": "1.0.0",
        }

    def test_stdout_also_contains_the_manifest(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="1.0.0")

        result = _run(
            _DERIVE_SCRIPT,
            ["v1.0.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 0, result.stderr
        printed = json.loads(result.stdout)
        assert printed["package_version"] == "1.0.0"


class TestDeriveReleaseMetadataNegative:
    def test_tag_version_drift_fails_with_specific_message(
        self, tmp_path: Path
    ) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.3.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "does not match" in result.stderr
        assert "0.3.0" in result.stderr
        assert "0.2.0" in result.stderr

    def test_disagreeing_schema_constants_fail(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        # A second file declares the same constant name with a different
        # value -- must be caught, never silently overwritten.
        (root / "src" / "controlloop" / "acbom" / "versioning2.py").write_text(
            'CURRENT_SCHEMA_VERSION = "2.0.0"\n'
        )

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "disagrees across the source tree" in result.stderr


class TestDeriveReleaseMetadataMalformed:
    def test_tag_missing_leading_v_is_rejected(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")

        result = _run(
            _DERIVE_SCRIPT,
            ["0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "does not match the required vX.Y.Z shape" in result.stderr

    def test_prerelease_suffix_is_rejected(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0-rc1", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "does not match the required vX.Y.Z shape" in result.stderr

    def test_malformed_pyproject_toml_fails_cleanly(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        (root / "pyproject.toml").write_text("this is not [ valid toml")

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "not valid TOML" in result.stderr
        assert "Traceback" not in result.stderr

    def test_missing_pyproject_toml_fails_cleanly(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        (root / "pyproject.toml").unlink()

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "could not read" in result.stderr

    def test_missing_rule_pack_metadata_fails_cleanly(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        (root / "src" / "controlloop" / "policy" / "rulepack.py").write_text(
            "# no CURRENT_RULE_PACK here\n"
        )

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "could not find CURRENT_RULE_PACK" in result.stderr


class TestDeriveReleaseMetadataBoundary:
    def test_zero_version_is_accepted(self, tmp_path: Path) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.0.0")

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.0.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 0, result.stderr

    def test_no_schema_constants_found_fails_rather_than_emitting_empty(
        self, tmp_path: Path
    ) -> None:
        root = _write_fixture_cli_tree(tmp_path, package_version="0.2.0")
        for path in (root / "src" / "controlloop").rglob("*.py"):
            if path.name != "rulepack.py":
                path.write_text("# nothing here\n")

        result = _run(
            _DERIVE_SCRIPT,
            ["v0.2.0", "--repo-root", str(root), "--commit-sha", "abc123"],
        )

        assert result.returncode == 1
        assert "no CURRENT_*_SCHEMA_VERSION constants found" in result.stderr


class TestChangelogReleaseNotesPositive:
    def test_extracts_matching_section_body(self, tmp_path: Path) -> None:
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n"
            "## [Unreleased]\n\n"
            "### Added\n\n"
            "- Something still in progress.\n\n"
            "## [0.2.0] - 2026-08-21\n\n"
            "### Added\n\n"
            "- The release pipeline.\n\n"
            "## [0.1.0] - 2026-08-01\n\n"
            "### Added\n\n"
            "- Initial scaffold.\n"
        )

        result = _run(_CHANGELOG_SCRIPT, ["0.2.0", "--changelog", str(changelog)])

        assert result.returncode == 0, result.stderr
        assert "The release pipeline." in result.stdout
        assert "Initial scaffold." not in result.stdout
        assert "still in progress" not in result.stdout

    def test_last_section_in_file_is_extracted_to_end_of_file(
        self, tmp_path: Path
    ) -> None:
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [0.3.0] - 2026-08-22\n\n- Final entry.\n"
        )

        result = _run(_CHANGELOG_SCRIPT, ["0.3.0", "--changelog", str(changelog)])

        assert result.returncode == 0, result.stderr
        assert "Final entry." in result.stdout


class TestChangelogReleaseNotesNegative:
    def test_missing_version_heading_fails(self, tmp_path: Path) -> None:
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text("# Changelog\n\n## [Unreleased]\n\n- Draft.\n")

        result = _run(_CHANGELOG_SCRIPT, ["0.2.0", "--changelog", str(changelog)])

        assert result.returncode == 1
        assert "has no '## [0.2.0]' heading" in result.stderr

    def test_empty_section_fails(self, tmp_path: Path) -> None:
        changelog = tmp_path / "CHANGELOG.md"
        changelog.write_text(
            "# Changelog\n\n## [0.2.0] - 2026-08-21\n\n## [0.1.0] - 2026-08-01\n\n- x\n"
        )

        result = _run(_CHANGELOG_SCRIPT, ["0.2.0", "--changelog", str(changelog)])

        assert result.returncode == 1
        assert "has no entries" in result.stderr


class TestChangelogReleaseNotesMalformed:
    def test_missing_changelog_file_fails_cleanly(self, tmp_path: Path) -> None:
        result = _run(
            _CHANGELOG_SCRIPT,
            ["0.2.0", "--changelog", str(tmp_path / "does-not-exist.md")],
        )

        assert result.returncode == 1
        assert "could not read" in result.stderr
        assert "Traceback" not in result.stderr
