"""Tests for controlloop.reporting.cyclonedx."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource

from controlloop.acbom import (
    ACBOMDocument,
    Confidence,
    Diagnostic,
    DiagnosticSeverity,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Generator,
    Node,
    NodeType,
    Repository,
    SecurityAttributes,
)
from controlloop.reporting.cyclonedx import (
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    render_cyclonedx,
)

_CLI_ROOT = Path(__file__).resolve().parents[2]
_FIXTURES = _CLI_ROOT / "tests/fixtures/cyclonedx"


def _load(name: str) -> dict[str, object]:
    return cast(dict[str, object], json.loads((_FIXTURES / name).read_text()))


_BOM_SCHEMA = _load("bom-1.6.schema.json")
_SPDX_SCHEMA = _load("spdx.schema.json")
_JSF_SCHEMA = _load("jsf-0.82.schema.json")
_REGISTRY: Registry = Registry().with_resources(
    [
        (cast(str, _SPDX_SCHEMA["$id"]), Resource.from_contents(_SPDX_SCHEMA)),
        (cast(str, _JSF_SCHEMA["$id"]), Resource.from_contents(_JSF_SCHEMA)),
    ]
)
_VALIDATOR = Draft7Validator(_BOM_SCHEMA, registry=_REGISTRY)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'c' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'d' * 64}"
_INVOKES_EDGE_ID = f"clp:edge:sha256:{'e' * 64}"
_PERMITTED_BY_EDGE_ID = f"clp:edge:sha256:{'f' * 64}"
_PLACEHOLDER_DIGEST = f"sha256:{'0' * 64}"


def _evidence(*, path: str) -> Evidence:
    return Evidence(adapter="a2a", path=path, line_start=1)


def _list_of_dicts(bom: dict[str, object], key: str) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], bom[key])


def _document() -> ACBOMDocument:
    """One of every projectable node type (agent, tool, resource), one
    unrepresentable node type (identity), a representable edge
    (invokes, between two projected nodes), and an unrepresentable edge
    (permitted-by, ending at the unrepresentable identity node) --
    enough to exercise every branch of `render_cyclonedx`."""

    agent = Node(
        id=_AGENT_ID,
        type=NodeType.AGENT,
        name="Refund agent",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="agent-card.json"),),
    )
    tool = Node(
        id=_TOOL_ID,
        type=NodeType.TOOL,
        name="Refund tool",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="mcp/tools.json"),),
    )
    resource = Node(
        id=_RESOURCE_ID,
        type=NodeType.RESOURCE,
        name="Customer database",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="mcp/tools.json"),),
    )
    identity = Node(
        id=_IDENTITY_ID,
        type=NodeType.IDENTITY,
        name="Service account",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="agent-card.json"),),
    )
    invokes = Edge(
        id=_INVOKES_EDGE_ID,
        source=_AGENT_ID,
        target=_TOOL_ID,
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="agent-card.json"),),
    )
    permitted_by = Edge(
        id=_PERMITTED_BY_EDGE_ID,
        source=_AGENT_ID,
        target=_IDENTITY_ID,
        type=EdgeType.PERMITTED_BY,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(_evidence(path="agent-card.json"),),
    )
    diagnostics = (
        Diagnostic(
            code="INCOMPLETE-UNPARSED-REGION",
            severity=DiagnosticSeverity.WARNING,
            message="one region could not be parsed",
            confidence=Confidence.MEDIUM,
            incomplete=True,
            evidence=(_evidence(path="agent-card.json"),),
        ),
    )

    return ACBOMDocument(
        schema_version="1.0.0",
        generator=Generator(name="controlloop", version="0.1.0"),
        repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
        nodes=(agent, tool, resource, identity),
        edges=(invokes, permitted_by),
        diagnostics=diagnostics,
        digest=_PLACEHOLDER_DIGEST,
    )


class TestBomStructure:
    """A complete, schema-valid CycloneDX 1.6 BOM."""

    def test_bom_format_and_spec_version(self) -> None:
        bom, _ = render_cyclonedx(_document())

        assert bom["bomFormat"] == CYCLONEDX_BOM_FORMAT == "CycloneDX"
        assert bom["specVersion"] == CYCLONEDX_SPEC_VERSION == "1.6"

    def test_validates_against_the_real_cyclonedx_1_6_schema(self) -> None:
        bom, _ = render_cyclonedx(_document())

        errors = list(_VALIDATOR.iter_errors(bom))

        assert errors == [], [error.message for error in errors]

    def test_empty_document_still_produces_a_valid_bom(self) -> None:
        empty = ACBOMDocument(
            schema_version="1.0.0",
            generator=Generator(name="controlloop", version="0.1.0"),
            repository=Repository(commit="abc123", root_digest=f"sha256:{'d' * 64}"),
            nodes=(),
            edges=(),
            diagnostics=(),
            digest=_PLACEHOLDER_DIGEST,
        )

        bom, lossy = render_cyclonedx(empty)

        assert list(_VALIDATOR.iter_errors(bom)) == []
        assert "components" not in bom
        assert "dependencies" not in bom
        assert lossy == ()


class TestComponentProjection:
    """Node types map to their nearest CycloneDX component type;
    types with no representation are named, not silently dropped."""

    def test_agent_tool_and_resource_each_project_to_a_component(self) -> None:
        bom, _ = render_cyclonedx(_document())

        components = {c["bom-ref"]: c for c in _list_of_dicts(bom, "components")}
        assert components[_AGENT_ID]["type"] == "application"
        assert components[_AGENT_ID]["name"] == "Refund agent"
        assert components[_TOOL_ID]["type"] == "library"
        assert components[_RESOURCE_ID]["type"] == "data"

    def test_identity_node_has_no_component_and_is_reported_lossy(self) -> None:
        bom, lossy = render_cyclonedx(_document())

        component_refs = {c["bom-ref"] for c in _list_of_dicts(bom, "components")}
        assert _IDENTITY_ID not in component_refs
        assert any(_IDENTITY_ID in message for message in lossy)


class TestDependencyProjection:
    """Dependency-shaped edges become `dependencies`;
    everything else is reported lossy, never dropped silently."""

    def test_invokes_edge_becomes_a_dependency(self) -> None:
        bom, _ = render_cyclonedx(_document())

        dependencies = {
            d["ref"]: d["dependsOn"] for d in _list_of_dicts(bom, "dependencies")
        }
        assert dependencies[_AGENT_ID] == [_TOOL_ID]

    def test_permitted_by_edge_is_reported_lossy_not_dropped_silently(self) -> None:
        _, lossy = render_cyclonedx(_document())

        assert any(_PERMITTED_BY_EDGE_ID in message for message in lossy)
        assert any("permitted-by" in message for message in lossy)


class TestReducedProjectionExcludesE142Fields:
    """Fields the reduced projection excludes (evidence locations,
    diagnostics, confidence grades) are absent from the output, asserted
    directly against the rendered structure."""

    def test_no_evidence_object_appears_anywhere(self) -> None:
        bom, _ = render_cyclonedx(_document())

        serialized = json.dumps(bom)

        assert "agent-card.json" not in serialized
        assert "mcp/tools.json" not in serialized
        assert "line_start" not in serialized
        assert "parser" not in serialized
        assert "schema_id" not in serialized

    def test_no_diagnostic_or_confidence_appears_anywhere(self) -> None:
        bom, _ = render_cyclonedx(_document())

        serialized = json.dumps(bom)

        assert "INCOMPLETE-UNPARSED-REGION" not in serialized
        assert "one region could not be parsed" not in serialized
        assert "confidence" not in serialized


class TestDeterminism:
    """Identical input produces byte-identical output -- no embedded
    timestamp or other non-deterministic field."""

    def test_repeated_renders_are_byte_identical(self) -> None:
        first, _ = render_cyclonedx(_document())
        second, _ = render_cyclonedx(_document())

        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_no_timestamp_field_anywhere(self) -> None:
        bom, _ = render_cyclonedx(_document())

        assert "timestamp" not in json.dumps(bom)
