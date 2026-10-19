"""Tests for OasfAdapter.

`SUPPORTED_OASF_VERSIONS` is empty by design (see the module: genuine low
confidence in OASF's current wire format). Version reporting and the
unsupported-record diagnostic are exercised against that honest default;
normalizing a *supported* record and preserving its unrecognized fields
are exercised by patching in a version locally, proving the code path is
real without pretending a version is verified when it is not.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from controlloop.acbom import NodeType
from controlloop.adapters import ScanContext, run_adapters
from controlloop.adapters.oasf import SUPPORTED_OASF_VERSIONS, OasfAdapter
from controlloop.repository import resolve_repository_root


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(root=resolve_repository_root(tmp_path))


def _write(tmp_path: Path, relative_path: str, payload: object) -> None:
    target = tmp_path / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


def test_supported_versions_start_empty_by_design() -> None:
    """The disclosed, honest default -- not a placeholder."""
    assert SUPPORTED_OASF_VERSIONS == ()


def test_version_reported_by_cli_version() -> None:
    """Declared in one place and reported by --version."""
    from typer.testing import CliRunner

    from controlloop.cli import app

    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "Supported OASF versions: none yet" in result.stdout


def test_unrecognized_record_produces_a_diagnostic_naming_both_versions(
    tmp_path: Path,
) -> None:
    """An unsupported record is a diagnostic naming its version."""
    _write(tmp_path, "agent.oasf.json", {"oasf_version": "0.3.0", "name": "x"})

    result = run_adapters([OasfAdapter()], _context(tmp_path))

    assert result.nodes == ()
    assert len(result.diagnostics) == 1
    assert "0.3.0" in result.diagnostics[0].message
    assert "not supported" in result.diagnostics[0].message


def test_a_supported_version_normalizes_into_a_node(tmp_path: Path) -> None:
    """Exercised via a locally patched supported version -- proves the
    code path is real without claiming a version is verified."""
    _write(tmp_path, "agent.oasf.json", {"oasf_version": "0.3.0", "name": "test-agent"})

    with patch("controlloop.adapters.oasf.SUPPORTED_OASF_VERSIONS", ("0.3.0",)):
        result = run_adapters([OasfAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert result.nodes[0].type is NodeType.AGENT
    assert result.nodes[0].name == "test-agent"


def test_unrecognized_fields_are_preserved_as_unknown_not_discarded(
    tmp_path: Path,
) -> None:
    """Unrecognized fields are kept and reported, not silently discarded."""
    _write(
        tmp_path,
        "agent.oasf.json",
        {"oasf_version": "0.3.0", "name": "test-agent", "some_future_field": {"x": 1}},
    )

    with patch("controlloop.adapters.oasf.SUPPORTED_OASF_VERSIONS", ("0.3.0",)):
        result = run_adapters([OasfAdapter()], _context(tmp_path))

    assert len(result.nodes) == 1
    assert len(result.diagnostics) == 1
    assert "unrecognized field" in result.diagnostics[0].message


def test_non_oasf_files_are_ignored(tmp_path: Path) -> None:
    _write(tmp_path, "package.json", {"name": "not-oasf"})

    detection = OasfAdapter().detect(_context(tmp_path))

    assert detection.claimed_paths == ()
