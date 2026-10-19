"""End to end: a manifest naming a discovered node by its real display name
must actually *match* it.

Parsing is not the bug being fixed. Before the fix the manifest failed to
parse at all, so a parse-only test would go green while the rules still
never matched anything. Every test here therefore drives a real rule against
a real graph and asserts the finding it should now produce.

`a2a.py` takes a skill node's `name` from the card's own `name` field,
so `Void an invoice` is what discovery actually produces for a
realistically-named tool -- not an exotic edge case.
"""

from __future__ import annotations

import hashlib
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
)
from controlloop.manifest import CURRENT_MANIFEST_SCHEMA_VERSION, ManifestDocument
from controlloop.manifest.ceiling import effective_ceiling
from controlloop.manifest.reconciliation import reconcile_manifest

_AGENT_NAME = "Invoice agent"
_TOOL_NAME = "Void an invoice"
_PEER_NAME = "Billing escalation agent"

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'b' * 64}"
_PEER_ID = f"clp:agent:sha256:{'c' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'d' * 64}"
_EVIDENCE = (Evidence(adapter="a2a", path="agent-card.json"),)


def _manifest(**sections: object) -> ManifestDocument:
    payload: dict[str, object] = {
        "schema_version": CURRENT_MANIFEST_SCHEMA_VERSION,
        "owner": "billing-eng",
    }
    payload.update(sections)
    return ManifestDocument.model_validate_json(json.dumps(payload))


def _node(node_id: str, node_type: NodeType, name: str) -> Node:
    return Node(
        id=node_id,
        type=node_type,
        name=name,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


def _edge(source: str, target: str, edge_type: EdgeType) -> Edge:
    return Edge(
        id=(
            "clp:edge:sha256:"
            + hashlib.sha256(
                f"{source}|{target}|{edge_type.value}".encode()
            ).hexdigest()
        ),
        source=source,
        target=target,
        type=edge_type,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=_EVIDENCE,
    )


class TestCeilingMatchesDisplayNames:
    """The defect's headline case, and the one that mattered most --
    the ceiling is the product's differentiator."""

    def test_effective_ceiling_resolves_an_agent_named_with_spaces(self) -> None:
        manifest = _manifest(
            ceilings=[{"agent": _AGENT_NAME, "prohibited_resources": [_TOOL_NAME]}]
        )

        ceiling = effective_ceiling(_AGENT_NAME, manifest)

        assert ceiling.prohibited_resources == (_TOOL_NAME,)

    def test_a_prohibited_resource_with_spaces_is_carried_through(self) -> None:
        manifest = _manifest(
            ceilings=[
                {
                    "agent": _AGENT_NAME,
                    "prohibited_resources": [_TOOL_NAME],
                    "prohibited_delegation_targets": [_PEER_NAME],
                    "prohibited_external_destinations": ["Third party processor"],
                }
            ]
        )

        ceiling = effective_ceiling(_AGENT_NAME, manifest)

        assert _TOOL_NAME in ceiling.prohibited_resources
        assert _PEER_NAME in ceiling.prohibited_delegation_targets
        assert "Third party processor" in ceiling.prohibited_external_destinations

    def test_a_repository_wide_ceiling_still_unions_with_spaced_names(self) -> None:
        manifest = _manifest(
            ceilings=[
                {"prohibited_resources": ["Delete everything"]},
                {"agent": _AGENT_NAME, "prohibited_resources": [_TOOL_NAME]},
            ]
        )

        ceiling = effective_ceiling(_AGENT_NAME, manifest)

        assert set(ceiling.prohibited_resources) == {_TOOL_NAME, "Delete everything"}


class TestReconciliationMatchesDisplayNames:
    """`reconcile_manifest` matches by `Node.name` throughout, so every
    declaration it reads had the same defect."""

    def _graph(self) -> tuple[tuple[Node, ...], tuple[Edge, ...]]:
        nodes = (
            _node(_AGENT_ID, NodeType.AGENT, _AGENT_NAME),
            _node(_PEER_ID, NodeType.AGENT, _PEER_NAME),
            _node(_TOOL_ID, NodeType.TOOL, _TOOL_NAME),
            _node(_RESOURCE_ID, NodeType.RESOURCE, "Customer ledger"),
        )
        edges = (
            _edge(_AGENT_ID, _TOOL_ID, EdgeType.WRITES),
            _edge(_AGENT_ID, _PEER_ID, EdgeType.DELEGATES_TO),
        )
        return nodes, edges

    def test_a_prohibited_capability_named_with_spaces_is_detected(self) -> None:
        """Before the fix this declaration could not be written at all, so
        the contradiction went unreported."""
        nodes, edges = self._graph()
        manifest = _manifest(
            prohibited_capabilities=[
                {"agent": _AGENT_NAME, "edge_type": "writes", "target": _TOOL_NAME}
            ]
        )

        diagnostics = reconcile_manifest(manifest, nodes, edges)

        assert any("prohibited capability" in d.message for d in diagnostics)

    def test_an_allowed_delegation_named_with_spaces_suppresses_the_contradiction(
        self,
    ) -> None:
        nodes, edges = self._graph()
        manifest = _manifest(
            allowed_delegation=[{"agent": _AGENT_NAME, "targets": [_PEER_NAME]}]
        )

        diagnostics = reconcile_manifest(manifest, nodes, edges)

        assert not any("delegation target outside" in d.message for d in diagnostics)

    def test_a_delegation_target_outside_the_spaced_allow_list_is_reported(
        self,
    ) -> None:
        nodes, edges = self._graph()
        manifest = _manifest(
            allowed_delegation=[{"agent": _AGENT_NAME, "targets": ["Someone else"]}]
        )

        diagnostics = reconcile_manifest(manifest, nodes, edges)

        assert any("delegation target outside" in d.message for d in diagnostics)

    def test_a_data_classification_naming_a_real_resource_is_corroborated(
        self,
    ) -> None:
        nodes, edges = self._graph()
        manifest = _manifest(
            data_classification=[
                {"resource": "Customer ledger", "sensitivity": "confidential"}
            ]
        )

        diagnostics = reconcile_manifest(manifest, nodes, edges)

        assert not any("data classification" in d.message for d in diagnostics)

    def test_a_data_classification_naming_nothing_is_still_flagged(self) -> None:
        """Widening must not turn a real unverified-declaration signal
        into silence."""
        nodes, edges = self._graph()
        manifest = _manifest(
            data_classification=[
                {"resource": "No such resource", "sensitivity": "confidential"}
            ]
        )

        diagnostics = reconcile_manifest(manifest, nodes, edges)

        assert any("data classification" in d.message for d in diagnostics)


class TestIdentifierFieldsStayNarrow:
    """Over-widening would be its own defect."""

    @pytest.mark.parametrize(
        "section",
        [
            {"trust_boundaries": [{"name": "has a space", "agents": ["a"]}]},
            {"approvals": [{"capability": "c", "approver": "has a space"}]},
            {"logged_tools": [{"tool": "t", "audit_path": "has a space"}]},
        ],
    )
    def test_fields_that_name_no_node_still_reject_spaces(
        self, section: dict[str, object]
    ) -> None:
        with pytest.raises(ValidationError):
            _manifest(**section)
