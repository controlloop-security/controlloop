"""Tests for `controlloop.manifest.annotation`.

The point of this module is that before it, no real repository scan
could classify any capability as material: `compute_blast_radius`
always returned `None`, and every golden report carried
`"blast_radius": null`. So the load-bearing tests here are not just
"the field parses" -- they are that a declared tool actually reaches
`classify_material_capability` and produces a real blast-radius
statement, and that a repository declaring nothing is byte-identical to
before.

Everything here is in-process: no socket, no subprocess, no clock
(offline evidence for the annotation path itself).
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from controlloop.acbom import (
    Confidence,
    Edge,
    EdgeStatus,
    EdgeType,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
    Sensitivity,
)
from controlloop.capability.blast_radius import (
    compute_blast_radius,
    describe_blast_radius,
)
from controlloop.capability.taxonomy import (
    MaterialCapabilityClass,
    classify_material_capability,
)
from controlloop.manifest import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    ManifestDocument,
    ToolCapabilityDeclaration,
    ToolLoggingDeclaration,
)
from controlloop.manifest.annotation import annotate_tool_capabilities

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_OTHER_TOOL_ID = f"clp:tool:sha256:{'c' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'d' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'e' * 64}"

_EVIDENCE = (Evidence(adapter="manifest", path="controlloop.yaml"),)

#: The real reference agent's own tool name -- a human display name with
#: spaces, which is exactly why `ToolCapabilityDeclaration.tool` is
#: `SafeText` and not `SafeIdentifier`.
_REFUND_TOOL_NAME = "Issue a refund"


def _manifest(**overrides: object) -> ManifestDocument:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "support-eng",
    }
    payload.update(overrides)
    return ManifestDocument.model_validate_json(json.dumps(payload))


def _node(
    node_id: str,
    node_type: NodeType,
    name: str,
    attributes: SecurityAttributes | None = None,
) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=attributes or SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="a2a", path="agent-card.json"),),
    )


def _invokes_edge() -> Edge:
    return Edge(
        id=_EDGE_ID,
        source=_AGENT_ID,
        target=_TOOL_ID,
        type=EdgeType.INVOKES,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="a2a", path="agent-card.json"),),
    )


def _graph() -> tuple[Node, ...]:
    return (
        _node(_AGENT_ID, NodeType.AGENT, "widgetworks-order-support-agent"),
        _node(_TOOL_ID, NodeType.TOOL, _REFUND_TOOL_NAME),
        _node(_OTHER_TOOL_ID, NodeType.TOOL, "Look up an order"),
    )


class TestAnnotationMechanics:
    def test_declared_attributes_are_applied_to_the_matching_tool(self) -> None:
        manifest = _manifest(
            tool_capabilities=[
                {
                    "tool": _REFUND_TOOL_NAME,
                    "financial_action": True,
                    "read_only": False,
                    "sensitivity": "confidential",
                }
            ]
        )

        nodes, diagnostics = annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)

        annotated = next(node for node in nodes if node.id == _TOOL_ID)
        assert annotated.security_attributes.financial_action is True
        assert annotated.security_attributes.read_only is False
        assert annotated.security_attributes.sensitivity is Sensitivity.CONFIDENTIAL
        assert diagnostics == ()

    def test_unmatched_tools_are_left_completely_untouched(self) -> None:
        original = _graph()
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "destructive": True}]
        )

        nodes, _ = annotate_tool_capabilities(original, manifest, _EVIDENCE)

        assert next(n for n in nodes if n.id == _OTHER_TOOL_ID) == original[2]
        assert next(n for n in nodes if n.id == _AGENT_ID) == original[0]

    def test_an_omitted_attribute_never_asserts_false(self) -> None:
        """Declaring nothing about an attribute must leave the discovered
        value alone -- it is not the same as declaring `False`."""
        discovered = SecurityAttributes(code_execution=True)
        nodes = (_node(_TOOL_ID, NodeType.TOOL, _REFUND_TOOL_NAME, discovered),)
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "financial_action": True}]
        )

        annotated, _ = annotate_tool_capabilities(nodes, manifest, _EVIDENCE)

        assert annotated[0].security_attributes.code_execution is True
        assert annotated[0].security_attributes.destructive is None

    def test_discovered_data_classifications_are_merged_not_replaced(self) -> None:
        discovered = SecurityAttributes(data_classifications=("pii",))
        nodes = (_node(_TOOL_ID, NodeType.TOOL, _REFUND_TOOL_NAME, discovered),)
        manifest = _manifest(
            tool_capabilities=[
                {"tool": _REFUND_TOOL_NAME, "data_classes": ["payment-card"]}
            ]
        )

        annotated, _ = annotate_tool_capabilities(nodes, manifest, _EVIDENCE)

        assert annotated[0].security_attributes.data_classifications == (
            "pii",
            "payment-card",
        )

    def test_only_tool_nodes_are_eligible(self) -> None:
        """An agent or resource sharing a tool's name is never annotated."""
        nodes = (
            _node(_RESOURCE_ID, NodeType.RESOURCE, _REFUND_TOOL_NAME),
            _node(_TOOL_ID, NodeType.TOOL, _REFUND_TOOL_NAME),
        )
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "financial_action": True}]
        )

        annotated, _ = annotate_tool_capabilities(nodes, manifest, _EVIDENCE)

        assert annotated[0].security_attributes.financial_action is None
        assert annotated[1].security_attributes.financial_action is True

    def test_unknown_is_preserved_as_unknown(self) -> None:
        """`"unknown"` must survive to the taxonomy, which ranks
        `UNCLASSIFIED` worst of all -- never collapsed to True/False."""
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "destructive": "unknown"}]
        )

        nodes, _ = annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)

        annotated = next(node for node in nodes if node.id == _TOOL_ID)
        assert annotated.security_attributes.destructive == "unknown"
        assert MaterialCapabilityClass.UNCLASSIFIED in classify_material_capability(
            annotated.security_attributes, edge_type=EdgeType.INVOKES
        )


class TestAdditivityAndIdentity:
    """The two properties that make this change safe to ship."""

    def test_no_manifest_returns_the_input_unchanged(self) -> None:
        original = _graph()

        nodes, diagnostics = annotate_tool_capabilities(original, None, _EVIDENCE)

        assert nodes is original
        assert diagnostics == ()

    def test_a_manifest_declaring_nothing_returns_the_input_unchanged(self) -> None:
        """A repository that adopts no `tool_capabilities` must produce a
        byte-identical ACBOM to one built before this feature existed."""
        original = _graph()

        nodes, diagnostics = annotate_tool_capabilities(
            original, _manifest(), _EVIDENCE
        )

        assert nodes is original
        assert diagnostics == ()

    def test_annotation_never_changes_a_node_id(self) -> None:
        """Security attributes must never be identity input. Asserted
        directly rather than assumed, because a change here would
        silently invalidate every committed baseline."""
        original = _graph()
        manifest = _manifest(
            tool_capabilities=[
                {
                    "tool": _REFUND_TOOL_NAME,
                    "destructive": True,
                    "financial_action": True,
                    "sensitivity": "restricted",
                }
            ]
        )

        annotated, _ = annotate_tool_capabilities(original, manifest, _EVIDENCE)

        assert [node.id for node in annotated] == [node.id for node in original]

    def test_annotation_is_deterministic(self) -> None:
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "financial_action": True}]
        )

        first, first_diagnostics = annotate_tool_capabilities(
            _graph(), manifest, _EVIDENCE
        )
        second, second_diagnostics = annotate_tool_capabilities(
            _graph(), manifest, _EVIDENCE
        )

        assert first == second
        assert first_diagnostics == second_diagnostics


class TestUndiscoveredDeclarations:
    def test_a_declaration_naming_an_unknown_tool_is_diagnosed(self) -> None:
        """Never a silent no-op: a repository that misspells a tool name
        must be told, or it will believe it declared something it did
        not."""
        manifest = _manifest(
            tool_capabilities=[{"tool": "Refund anything", "destructive": True}]
        )

        nodes, diagnostics = annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)

        assert nodes == _graph()
        assert len(diagnostics) == 1
        assert diagnostics[0].incomplete is True
        assert "did not find" in diagnostics[0].message

    def test_diagnostics_are_ordered_deterministically(self) -> None:
        manifest = _manifest(
            tool_capabilities=[
                {"tool": "zzz-missing"},
                {"tool": "aaa-missing"},
            ]
        )

        _, diagnostics = annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)

        assert len(diagnostics) == 2
        assert (
            diagnostics == annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)[1]
        )


class TestReachesBlastRadius:
    """The actual point of tool annotation, end to end through the real
    capability layer -- not a unit test of the mapping."""

    def _statement_lines(self, manifest: ManifestDocument | None) -> tuple[str, ...]:
        nodes, _ = annotate_tool_capabilities(_graph(), manifest, _EVIDENCE)
        return describe_blast_radius(compute_blast_radius(nodes, (_invokes_edge(),)))

    def test_undeclared_tool_reaches_no_material_capability(self) -> None:
        """The behavior without a declaration, pinned so a regression is
        visible."""
        assert self._statement_lines(None) == ("• no material capability is reachable",)

    def test_a_declared_financial_tool_produces_a_real_blast_radius(self) -> None:
        """The exact sentence a real `controlloop scan` now prints for
        the reference agent, asserted byte for byte."""
        manifest = _manifest(
            tool_capabilities=[{"tool": _REFUND_TOOL_NAME, "financial_action": True}]
        )

        assert self._statement_lines(manifest) == (
            "! WORST REACHABLE  financial-action: "
            "widgetworks-order-support-agent can invoke Issue a refund",
        )


class TestLoggingDeclarationAcceptsDisplayNames:
    """Manifest schema 1.1.0 widened `ToolLoggingDeclaration.tool` from
    `SafeIdentifier` to `SafeText`. Without that, declaring a tool
    privileged via `tool_capabilities` created a dead end:
    `policy.missing-action-logging` demands a `logged_tools` entry that
    an identifier-only field could not express for any a2a skill."""

    def test_a_display_name_with_spaces_is_accepted(self) -> None:
        manifest = _manifest(
            logged_tools=[
                {"tool": _REFUND_TOOL_NAME, "audit_path": "logs/refund-audit.log"}
            ]
        )

        assert manifest.logged_tools == (
            ToolLoggingDeclaration(
                tool=_REFUND_TOOL_NAME, audit_path="logs/refund-audit.log"
            ),
        )

    @pytest.mark.parametrize("value", ["", "with\x00null", "with\nnewline"])
    def test_malformed_tool_names_are_still_rejected(self, value: str) -> None:
        with pytest.raises(ValidationError):
            ToolCapabilityDeclaration.model_validate_json(
                json.dumps({"tool": value, "destructive": True})
            )
