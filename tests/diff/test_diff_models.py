"""Tests for controlloop.diff.models."""

from __future__ import annotations

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
from controlloop.diff import (
    CURRENT_DIFF_SCHEMA_VERSION,
    ChangeKind,
    DiffResult,
    EdgeChange,
    EffectiveAuthorityChange,
    NodeChange,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'b' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"


def _node() -> Node:
    return Node(
        id=_AGENT_ID,
        type=NodeType.AGENT,
        name="x",
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


def _edge() -> Edge:
    return Edge(
        id=_EDGE_ID,
        source=_AGENT_ID,
        target=_RESOURCE_ID,
        type=EdgeType.READS,
        status=EdgeStatus.DIRECT,
        security_attributes=SecurityAttributes(),
        confidence=Confidence.HIGH,
        evidence=(Evidence(adapter="mcp", path="a.json"),),
    )


class TestChangeKind:
    def test_has_exactly_the_four_documented_states(self) -> None:
        assert {member.value for member in ChangeKind} == {
            "added",
            "removed",
            "changed",
            "unknown",
        }


class TestNodeChange:
    def test_added_has_no_before(self) -> None:
        change = NodeChange(kind=ChangeKind.ADDED, node_id=_AGENT_ID, after=_node())

        assert change.before is None
        assert change.after is not None

    def test_is_frozen_and_forbids_extra_fields(self) -> None:
        change = NodeChange(kind=ChangeKind.ADDED, node_id=_AGENT_ID, after=_node())

        with pytest.raises(ValidationError):
            change.kind = ChangeKind.REMOVED

        with pytest.raises(ValidationError):
            NodeChange.model_validate(
                {
                    "kind": ChangeKind.ADDED,
                    "node_id": _AGENT_ID,
                    "after": _node(),
                    "extra_field": "not allowed",
                }
            )


class TestEdgeChange:
    def test_removed_has_no_after(self) -> None:
        change = EdgeChange(kind=ChangeKind.REMOVED, edge_id=_EDGE_ID, before=_edge())

        assert change.before is not None
        assert change.after is None


class TestEffectiveAuthorityChange:
    def test_carries_the_narrowed_key_not_permitting_identity(self) -> None:
        change = EffectiveAuthorityChange(
            kind=ChangeKind.ADDED,
            agent_id=_AGENT_ID,
            action=EdgeType.READS,
            resource_id=_RESOURCE_ID,
        )

        assert change.agent_id == _AGENT_ID
        assert change.action is EdgeType.READS
        assert change.resource_id == _RESOURCE_ID


class TestDiffResult:
    def test_is_empty_true_when_every_collection_is_empty(self) -> None:
        result = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(),
            edge_changes=(),
            effective_authority_changes=(),
        )

        assert result.is_empty is True

    def test_is_empty_false_when_any_collection_is_nonempty(self) -> None:
        result = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(
                NodeChange(kind=ChangeKind.ADDED, node_id=_AGENT_ID, after=_node()),
            ),
            edge_changes=(),
            effective_authority_changes=(),
        )

        assert result.is_empty is False

    def test_round_trips_through_json(self) -> None:
        result = DiffResult(
            schema_version=CURRENT_DIFF_SCHEMA_VERSION,
            node_changes=(
                NodeChange(kind=ChangeKind.ADDED, node_id=_AGENT_ID, after=_node()),
            ),
            edge_changes=(
                EdgeChange(kind=ChangeKind.REMOVED, edge_id=_EDGE_ID, before=_edge()),
            ),
            effective_authority_changes=(
                EffectiveAuthorityChange(
                    kind=ChangeKind.UNKNOWN,
                    agent_id=_AGENT_ID,
                    action=EdgeType.READS,
                    resource_id=_RESOURCE_ID,
                ),
            ),
        )

        restored = DiffResult.model_validate_json(result.model_dump_json())

        assert restored == result
