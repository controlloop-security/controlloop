"""Immutable canonical models for effective authority and capability
paths, schema version 1.0.0.

See docs/reference/effective-authority-model.md, written before
`EffectiveAuthorityEntry`. Mirrors the ACBOM's own model discipline
(`extra="forbid", frozen=True, strict=True`).
"""

from __future__ import annotations

from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from controlloop.acbom import Confidence, EdgeType, NodeType
from controlloop.acbom.models import EdgeId, EvidenceCollection, NodeId, SemanticVersion

CURRENT_CAPABILITY_SCHEMA_VERSION = "1.0.0"

#: The only edge types that represent an agent taking an action on a
#: resource, as opposed to describing the graph's structure (delegation,
#: authentication, permission grants, policy boundaries, or receipt).
_ACTION_EDGE_TYPES = frozenset({EdgeType.READS, EdgeType.WRITES, EdgeType.INVOKES})

#: The five target-node categories a direct capability path may reach.
_CAPABILITY_PATH_TARGET_TYPES = frozenset(
    {
        NodeType.TOOL,
        NodeType.RESOURCE,
        NodeType.IDENTITY,
        NodeType.PERMISSION,
        NodeType.DATA_CLASS,
    }
)


class _CapabilityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class EffectiveAuthorityEntry(_CapabilityModel):
    """One agent-to-action-on-resource fact, with the identity that
    permits it if known. `permitting_identity_id=None` means the
    permitting identity is unknown, never that no identity grants the
    action."""

    schema_version: SemanticVersion
    agent_id: NodeId
    action: EdgeType
    resource_id: NodeId
    permitting_identity_id: NodeId | None = None
    confidence: Confidence
    evidence: EvidenceCollection

    @model_validator(mode="after")
    def validate_action_is_a_resource_action(self) -> Self:
        if self.action not in _ACTION_EDGE_TYPES:
            raise ValueError(
                f"{self.action!r} does not represent an agent action on a "
                "resource; only reads, writes, and invokes are allowed here"
            )
        return self


class PathHop(_CapabilityModel):
    """One edge traversed on a capability path, carried explicitly so
    every path element resolves to its own evidence, not just the
    path's endpoints."""

    edge_id: EdgeId
    edge_type: EdgeType
    source_id: NodeId
    target_id: NodeId
    evidence: EvidenceCollection


class CapabilityPath(_CapabilityModel):
    """A path from an agent to a tool, resource, identity, permission,
    or data-class node, naming the full sequence of hops that produced
    it. `hops` is plural and ordered so a direct path (one hop) and a
    bounded transitive path (more than one) share one shape."""

    schema_version: SemanticVersion
    agent_id: NodeId
    target_id: NodeId
    target_type: NodeType
    hops: Annotated[tuple[PathHop, ...], Field(min_length=1)]
    confidence: Confidence

    @model_validator(mode="after")
    def validate_target_type_is_a_capability_category(self) -> Self:
        if self.target_type not in _CAPABILITY_PATH_TARGET_TYPES:
            raise ValueError(
                f"{self.target_type!r} is not one of the five capability "
                "path target categories: tool, resource, identity, "
                "permission, data-class"
            )
        return self

    @model_validator(mode="after")
    def validate_hops_end_at_the_target(self) -> Self:
        if self.hops[0].source_id != self.agent_id:
            raise ValueError("the first hop must originate at agent_id")
        if self.hops[-1].target_id != self.target_id:
            raise ValueError("the last hop must terminate at target_id")
        return self

    @model_validator(mode="after")
    def validate_hops_form_a_contiguous_chain(self) -> Self:
        """A multi-hop path is a genuine walk, not just endpoints that
        happen to agree -- each hop's target must be the next hop's
        source."""

        for earlier, later in zip(self.hops, self.hops[1:], strict=False):
            if earlier.target_id != later.source_id:
                raise ValueError(
                    "hops do not form a contiguous chain: "
                    f"{earlier.target_id!r} != {later.source_id!r}"
                )
        return self
