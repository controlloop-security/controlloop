"""Tests for controlloop.acbom.completeness.

Mirrors the registry-consistency and deterministic-summary test shapes
already established in tests/test_repository.py for
DIAGNOSTIC_REGISTRY/summarize_skips, at the ACBOM layer.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from controlloop.acbom import (
    INCOMPLETE_DIAGNOSTIC_REGISTRY,
    ACBOMDocument,
    Confidence,
    Diagnostic,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
    completeness_summary,
    compute_digest,
    incomplete_diagnostic,
    with_digest,
)
from controlloop.cli import app

_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def _document(diagnostics: tuple[Diagnostic, ...]) -> ACBOMDocument:
    agent = Node(
        id=f"clp:agent:sha256:{'a' * 64}",
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="a2a", path="agent-card.json", line_start=1),),
    )
    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(agent,),
        edges=(),
        diagnostics=diagnostics,
        digest=_PLACEHOLDER_DIGEST,
    )


class TestRegistry:
    def test_every_code_matches_the_diagnostic_code_pattern(self) -> None:
        assert all(
            _CODE_PATTERN.fullmatch(code) for code in INCOMPLETE_DIAGNOSTIC_REGISTRY
        )

    def test_every_description_is_nonempty(self) -> None:
        assert all(
            description.strip()
            for description in INCOMPLETE_DIAGNOSTIC_REGISTRY.values()
        )

    def test_registry_names_every_known_incompleteness_category(self) -> None:
        """Unresolved references, dynamic registration, unparsed regions,
        and bound-exceeded regions each get their own code, as do an
        isolated adapter failure, a manifest declaration discovery could
        not corroborate, and a transitive capability traversal that
        detected and stopped a cycle."""
        assert set(INCOMPLETE_DIAGNOSTIC_REGISTRY) == {
            "INCOMPLETE-UNRESOLVED-REFERENCE",
            "INCOMPLETE-DYNAMIC-REGISTRATION",
            "INCOMPLETE-UNPARSED-REGION",
            "INCOMPLETE-BOUND-EXCEEDED",
            "INCOMPLETE-ADAPTER-FAILURE",
            "INCOMPLETE-UNVERIFIED-DECLARATION",
            "INCOMPLETE-CYCLE-DETECTED",
            "INCOMPLETE-UNRECOGNIZED-KEY",
        }


class TestIncompleteDiagnostic:
    @pytest.mark.parametrize("code", tuple(INCOMPLETE_DIAGNOSTIC_REGISTRY))
    def test_every_registered_code_constructs_a_valid_diagnostic(
        self, code: str
    ) -> None:
        diagnostic = incomplete_diagnostic(
            code=code,
            message="A capability could not be fully analyzed.",
            evidence=(Evidence(adapter="fixture", path="input.json"),),
        )

        assert diagnostic.incomplete is True
        assert diagnostic.confidence is Confidence.UNKNOWN
        assert diagnostic.code == code

    def test_every_registered_code_round_trips_through_a_document(self) -> None:
        for code in INCOMPLETE_DIAGNOSTIC_REGISTRY:
            diagnostic = incomplete_diagnostic(
                code=code,
                message="A capability could not be fully analyzed.",
                evidence=(Evidence(adapter="fixture", path="input.json"),),
            )
            document = with_digest(_document((diagnostic,)))

            round_tripped = ACBOMDocument.model_validate_json(
                document.model_dump_json()
            )

            assert round_tripped.diagnostics[0].code == code
            assert round_tripped.diagnostics[0].incomplete is True

    @pytest.mark.parametrize(
        "code",
        ["BOGUS-CODE", "not-a-valid-code"],
        ids=["well-formed-but-unregistered", "malformed"],
    )
    def test_any_non_registered_code_is_rejected(self, code: str) -> None:
        """The registry check runs before any code ever reaches
        `Diagnostic` construction, so a malformed code and a
        well-formed-but-unregistered one are both caught here, with the
        same clear message -- neither reaches the model layer."""
        with pytest.raises(ValueError, match="not a registered incompleteness code"):
            incomplete_diagnostic(
                code=code,
                message="A capability could not be fully analyzed.",
                evidence=(Evidence(adapter="fixture", path="input.json"),),
            )


class TestCompletenessSummary:
    def test_filters_out_complete_diagnostics(self) -> None:
        incomplete = incomplete_diagnostic(
            code="INCOMPLETE-UNPARSED-REGION",
            message="A region could not be parsed.",
            evidence=(Evidence(adapter="fixture", path="a.json"),),
        )
        complete = Diagnostic(
            code="ORDINARY-INFO",
            severity=incomplete.severity,
            message="An ordinary, complete-analysis diagnostic.",
            confidence=Confidence.HIGH,
            incomplete=False,
            evidence=(Evidence(adapter="fixture", path="b.json"),),
        )
        document = _document((complete, incomplete))

        summary = completeness_summary(document)

        assert summary == (incomplete,)

    def test_empty_when_no_diagnostics_are_incomplete(self) -> None:
        document = _document(())

        assert completeness_summary(document) == ()

    def test_ordering_is_deterministic_regardless_of_input_order(self) -> None:
        first = incomplete_diagnostic(
            code="INCOMPLETE-UNRESOLVED-REFERENCE",
            message="A reference could not be resolved.",
            evidence=(Evidence(adapter="fixture", path="z.json"),),
        )
        second = incomplete_diagnostic(
            code="INCOMPLETE-BOUND-EXCEEDED",
            message="A bound was exceeded.",
            evidence=(Evidence(adapter="fixture", path="a.json"),),
        )

        forward = completeness_summary(_document((first, second)))
        reverse = completeness_summary(_document((second, first)))

        assert forward == reverse
        assert [diagnostic.evidence[0].path for diagnostic in forward] == [
            "a.json",
            "z.json",
        ]


_DYNAMIC_REGISTRATION_MODULE = """\
from agents import Agent

support_agent = Agent(name="Support", tools=load_tools_from_config())
"""


def test_dynamically_registered_tool_fixture_produces_a_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A repository whose agent builds its tool list at runtime produces
    an unknown and a `policy.unresolved-dynamic-registration` finding
    naming the file and the agent, end to end through `scan`, rather
    than only a raw diagnostic.

    The OpenAI Agents SDK adapter reads the call in `tools=` as a
    dynamic registration, keeps an `"unknown"` tool node at
    `Confidence.UNKNOWN`, and links it to the diagnostic by line.
    """

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "desk"\nversion = "0.1.0"\n'
        'dependencies = ["openai-agents>=0.2.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "desk.py").write_text(_DYNAMIC_REGISTRATION_MODULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["scan", "--format", "json"])

    report = json.loads(result.stdout)
    assert "INCOMPLETE-DYNAMIC-REGISTRATION" in {
        diagnostic["code"] for diagnostic in report["diagnostics"]
    }
    findings = [
        finding
        for finding in report["findings"]
        if finding["rule_id"] == "policy.unresolved-dynamic-registration"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "medium"
    assert "unresolved-tools:Support" in finding["message"]
    assert {"path": "desk.py", "line_start": 3} in [
        {"path": item["path"], "line_start": item["line_start"]}
        for item in finding["evidence"]
    ]


def test_completeness_state_changes_the_digest() -> None:
    """Completeness state is part of the canonical serialization
    and therefore of the digest."""
    incomplete = incomplete_diagnostic(
        code="INCOMPLETE-UNPARSED-REGION",
        message="A region could not be parsed.",
        evidence=(Evidence(adapter="fixture", path="a.json"),),
    )
    with_incompleteness = with_digest(_document((incomplete,)))
    without_incompleteness = with_digest(_document(()))

    assert compute_digest(with_incompleteness) != compute_digest(without_incompleteness)
