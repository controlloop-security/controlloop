"""Tests for controlloop.capability.models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from controlloop.acbom import Confidence, EdgeType, Evidence, NodeType
from controlloop.capability import (
    CURRENT_CAPABILITY_SCHEMA_VERSION,
    CapabilityPath,
    EffectiveAuthorityEntry,
    PathHop,
)

_AGENT_ID = f"clp:agent:sha256:{'a' * 64}"
_RESOURCE_ID = f"clp:resource:sha256:{'b' * 64}"
_IDENTITY_ID = f"clp:identity:sha256:{'c' * 64}"
_TOOL_ID = f"clp:tool:sha256:{'d' * 64}"
_OTHER_TOOL_ID = f"clp:tool:sha256:{'e' * 64}"
_EDGE_ID = f"clp:edge:sha256:{'1' * 64}"


def _entry(**overrides: object) -> EffectiveAuthorityEntry:
    payload: dict[str, object] = {
        "schema_version": CURRENT_CAPABILITY_SCHEMA_VERSION,
        "agent_id": _AGENT_ID,
        "action": EdgeType.READS,
        "resource_id": _RESOURCE_ID,
        "confidence": Confidence.HIGH,
        "evidence": (Evidence(adapter="mcp", path="a.json"),),
    }
    payload.update(overrides)
    return EffectiveAuthorityEntry.model_validate(payload)


@pytest.mark.parametrize("action", [EdgeType.READS, EdgeType.WRITES, EdgeType.INVOKES])
def test_resource_action_types_validate(action: EdgeType) -> None:
    """Reads, writes, and invokes are valid resource actions."""
    entry = _entry(action=action)

    assert entry.action is action


@pytest.mark.parametrize(
    "action",
    [
        EdgeType.DELEGATES_TO,
        EdgeType.AUTHENTICATES_AS,
        EdgeType.PERMITTED_BY,
        EdgeType.CONSTRAINED_BY,
        EdgeType.RECEIVES_FROM,
    ],
)
def test_structural_edge_types_are_rejected_as_actions(action: EdgeType) -> None:
    """Only reads/writes/invokes represent an action on a resource;
    structural edge types are rejected at the model level."""
    with pytest.raises(ValidationError):
        _entry(action=action)


def test_permitting_identity_defaults_to_none() -> None:
    """Unknown, not a fabricated identity."""
    entry = _entry()

    assert entry.permitting_identity_id is None


def test_permitting_identity_can_be_declared() -> None:
    entry = _entry(permitting_identity_id=_IDENTITY_ID)

    assert entry.permitting_identity_id == _IDENTITY_ID


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _entry(raw_source="leaked")


def _hop(**overrides: object) -> PathHop:
    payload: dict[str, object] = {
        "edge_id": _EDGE_ID,
        "edge_type": EdgeType.INVOKES,
        "source_id": _AGENT_ID,
        "target_id": _TOOL_ID,
        "evidence": (Evidence(adapter="mcp", path="a.json"),),
    }
    payload.update(overrides)
    return PathHop.model_validate(payload)


def _path(**overrides: object) -> CapabilityPath:
    payload: dict[str, object] = {
        "schema_version": CURRENT_CAPABILITY_SCHEMA_VERSION,
        "agent_id": _AGENT_ID,
        "target_id": _TOOL_ID,
        "target_type": NodeType.TOOL,
        "hops": (_hop(),),
        "confidence": Confidence.HIGH,
    }
    payload.update(overrides)
    return CapabilityPath.model_validate(payload)


@pytest.mark.parametrize(
    "target_type",
    [
        NodeType.TOOL,
        NodeType.RESOURCE,
        NodeType.IDENTITY,
        NodeType.PERMISSION,
        NodeType.DATA_CLASS,
    ],
)
def test_capability_path_target_categories_validate(target_type: NodeType) -> None:
    """Each capability target category is a valid path target."""
    path = _path(target_type=target_type)

    assert path.target_type is target_type


@pytest.mark.parametrize("target_type", [NodeType.AGENT, NodeType.TRIGGER])
def test_non_capability_target_types_are_rejected(target_type: NodeType) -> None:
    """Agent and trigger nodes are not a capability path's target
    category."""
    with pytest.raises(ValidationError):
        _path(target_type=target_type)


def test_capability_path_names_its_hops() -> None:
    """A capability path names the edges it traverses."""
    path = _path()

    assert path.hops[0].edge_id == _EDGE_ID
    assert path.hops[0].edge_type is EdgeType.INVOKES


def test_hops_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        _path(hops=())


def test_first_hop_must_originate_at_the_agent() -> None:
    with pytest.raises(ValidationError):
        _path(hops=(_hop(source_id=_OTHER_TOOL_ID),))


def test_last_hop_must_terminate_at_the_target() -> None:
    with pytest.raises(ValidationError):
        _path(hops=(_hop(target_id=_OTHER_TOOL_ID),))


def test_two_contiguous_hops_validate() -> None:
    """A genuine two-hop chain is accepted."""
    first_hop = _hop(source_id=_AGENT_ID, target_id=_OTHER_TOOL_ID)
    second_hop = _hop(
        edge_id=f"clp:edge:sha256:{'2' * 64}",
        source_id=_OTHER_TOOL_ID,
        target_id=_TOOL_ID,
    )

    path = _path(hops=(first_hop, second_hop))

    assert len(path.hops) == 2


def test_non_contiguous_hops_are_rejected() -> None:
    """A "path" whose hops do not actually connect is a model-level error,
    not just an unusual compute-function output."""
    first_hop = _hop(source_id=_AGENT_ID, target_id=_OTHER_TOOL_ID)
    # Second hop does not start where the first hop ended.
    disconnected_second_hop = _hop(
        edge_id=f"clp:edge:sha256:{'2' * 64}",
        source_id=_AGENT_ID,
        target_id=_TOOL_ID,
    )

    with pytest.raises(ValidationError):
        _path(hops=(first_hop, disconnected_second_hop))
