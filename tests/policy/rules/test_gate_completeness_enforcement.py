"""Tests for `controlloop gate`'s completeness-enforcement policy,
asserted end to end through the real `gate` Typer command.

Placed in this directory specifically to import this package's own
`_helpers.py` fixture-building helpers directly (this repository's
pytest import mode is rootless -- each test module's own directory is
inserted on `sys.path`, so `_helpers` is only importable from a module
that lives alongside it). The fixture containing a dynamic registration
is built with the exact same helpers
(`acbom`/`agent_node`/`tool_node`/`invokes_edge`/
`dynamic_registration_diagnostic`)
`test_unresolved_dynamic_registration.py::_dynamic_registration_context`
already uses -- not a parallel fixture built from scratch.

That rule module's own docstring discloses that no adapter emits
`INCOMPLETE-DYNAMIC-REGISTRATION` from real repository content yet, so
`controlloop.cli.build_acbom_document` is monkeypatched to return the
fixture document directly, and the real `gate` command is driven through
`typer.testing.CliRunner` from there -- proving the real
`_gate_classify`/`resolve_policy_config`/`EvidenceArtifact` composition,
not a synthetic shortcut around it.
"""

from __future__ import annotations

import json
from pathlib import Path

from _helpers import (
    acbom,
    agent_node,
    dynamic_registration_diagnostic,
    hex_id,
    invokes_edge,
    tool_node,
)
from pytest import MonkeyPatch
from typer.testing import CliRunner

from controlloop import cli as cli_module
from controlloop.acbom.models import ACBOMDocument, Confidence
from controlloop.cli import app
from controlloop.config import CONFIG_FILENAME
from controlloop.exit_codes import ExitCode
from controlloop.reporting import EvidenceArtifact
from controlloop.repository import RepositoryRoot, TraversalBounds

runner = CliRunner()

_AGENT_ID = hex_id("agent", "a")
_TOOL_ID = hex_id("tool", "b")
_EDGE_ID = hex_id("edge", "c")
_DIAGNOSTIC_CODE = "INCOMPLETE-DYNAMIC-REGISTRATION"


def _dynamic_registration_document() -> ACBOMDocument:
    """The exact fixture shape
    `test_unresolved_dynamic_registration.py::_dynamic_registration_context`
    already established: an agent, an `invokes` edge to a
    `Confidence.UNKNOWN` tool, and a dynamic-registration diagnostic
    sharing the tool's own evidence location."""

    agent = agent_node(_AGENT_ID, name="dispatch-agent")
    tool = tool_node(
        _TOOL_ID,
        name="dynamic-tool",
        confidence=Confidence.UNKNOWN,
        path="server.py",
        line_start=42,
    )
    edge = invokes_edge(_EDGE_ID, source=_AGENT_ID, target=_TOOL_ID)
    diagnostic = dynamic_registration_diagnostic(path="server.py", line_start=42)
    return acbom(nodes=(agent, tool), edges=(edge,), diagnostics=(diagnostic,))


def _patch_dynamic_registration_document(monkeypatch: MonkeyPatch) -> None:
    def _fake_build_acbom_document(
        root: RepositoryRoot, *, bounds: TraversalBounds
    ) -> ACBOMDocument:
        return _dynamic_registration_document()

    monkeypatch.setattr(cli_module, "build_acbom_document", _fake_build_acbom_document)


class TestPositiveWarnByDefault:
    """Incomplete analysis produces a warning and exit 0 by default."""

    def test_dynamic_registration_warns_and_exits_pass(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.verdict == "passed_with_warnings"
        assert artifact.completeness_enforcement == "warn"
        assert artifact.completeness_enforcement_source == "default"


class TestPositiveEnforcementOptIn:
    """Enabling completeness enforcement causes incomplete analysis to
    return exit 3."""

    def test_dynamic_registration_blocks_when_enforced(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.verdict == "review_required"
        assert artifact.completeness_enforcement == "enforce"
        assert artifact.completeness_enforcement_source == "repository file"

    def test_environment_variable_enables_enforcement(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CONTROLLOOP_COMPLETENESS_ENFORCEMENT", "enforce")
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.completeness_enforcement_source == "environment"


class TestReasonsAlwaysListed:
    """The reasons analysis was incomplete are always listed regardless of
    the setting."""

    def test_completeness_reasons_are_identical_in_both_modes(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _patch_dynamic_registration_document(monkeypatch)
        warn_result = runner.invoke(app, ["gate", "--format", "json"])
        warn_artifact = EvidenceArtifact.model_validate_json(warn_result.stdout)

        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )
        enforce_result = runner.invoke(app, ["gate", "--format", "json"])
        enforce_artifact = EvidenceArtifact.model_validate_json(enforce_result.stdout)

        assert warn_artifact.completeness != ()
        assert enforce_artifact.completeness != ()
        assert warn_artifact.completeness == enforce_artifact.completeness
        for artifact in (warn_artifact, enforce_artifact):
            assert any(
                diagnostic.code == _DIAGNOSTIC_CODE
                for diagnostic in artifact.completeness
            )


class TestSettingStatedInResult:
    """The active setting is stated in the gate result, in both --format
    json (the evidence artifact) and --format text (the rendered
    summary)."""

    def test_text_format_states_the_default_setting(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.PASS
        assert "Completeness enforcement: warn (default)" in result.stdout
        assert "Evidence:" in result.stdout

    def test_text_format_states_the_enforced_setting(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        assert "Completeness enforcement: enforce (repository file)" in result.stdout


class TestNegativeAndMalformed:
    def test_unknown_completeness_enforcement_value_exits_invalid_input(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "sometimes"\n'
        )
        _patch_dynamic_registration_document(monkeypatch)

        result = runner.invoke(app, ["gate"])

        assert result.exit_code == ExitCode.INVALID_INPUT
        assert result.stdout == ""
        assert not (tmp_path / "evidence.json").exists()


class TestBoundary:
    def test_a_repository_with_no_incompleteness_is_unaffected_by_the_setting(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """A repository with nothing incomplete never enters the
        `analysis_incomplete` branch at all -- `completeness_enforcement`
        is inert either way, and the outcome is a clean pass regardless."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / CONFIG_FILENAME).write_text(
            'completeness_enforcement = "enforce"\n'
        )

        result = runner.invoke(app, ["gate", "--format", "json"])

        assert result.exit_code == ExitCode.PASS
        artifact = EvidenceArtifact.model_validate_json(result.stdout)
        assert artifact.verdict == "passed"
        assert artifact.completeness == ()


class TestDeterminism:
    """Carried forward from the gate's own determinism tests: identical
    input produces an identical verdict and an identical artifact digest,
    including under the new enforced setting."""

    def test_enforced_mode_is_deterministic_across_repeated_invocations(
        self, monkeypatch: MonkeyPatch, tmp_path: Path
    ) -> None:
        """Mirrors `TestGate::test_gate_is_deterministic_across_repeated_
        invocations`'s own isolation pattern: both evidence paths are
        written *outside* the scanned repository directory, since
        writing inside it would make the second run see the first run's
        own artifact as part of the repository -- not actually proving
        determinism."""
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / CONFIG_FILENAME).write_text('completeness_enforcement = "enforce"\n')
        evidence_dir = tmp_path / "evidence-out"
        evidence_dir.mkdir()
        monkeypatch.chdir(repo)
        _patch_dynamic_registration_document(monkeypatch)

        first = runner.invoke(
            app, ["gate", "--evidence-path", str(evidence_dir / "run1.json")]
        )
        second = runner.invoke(
            app, ["gate", "--evidence-path", str(evidence_dir / "run2.json")]
        )

        assert first.exit_code == second.exit_code == ExitCode.INCOMPLETE_ANALYSIS
        first_bytes = (evidence_dir / "run1.json").read_bytes()
        second_bytes = (evidence_dir / "run2.json").read_bytes()
        assert first_bytes == second_bytes
        first_artifact = json.loads(first_bytes)
        second_artifact = json.loads(second_bytes)
        assert first_artifact["verdict"] == second_artifact["verdict"]
        assert (
            first_artifact["completeness_enforcement"]
            == second_artifact["completeness_enforcement"]
        )
