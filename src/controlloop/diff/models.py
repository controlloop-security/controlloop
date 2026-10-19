"""Immutable canonical models for change classification, schema version
1.0.0.

See docs/reference/diff-output-format.md, written before this model so
that a versioned contract was defined before implementation. Mirrors
`controlloop.capability.models`'s own model discipline (`extra="forbid",
frozen=True, strict=True`) and schema-versioning convention (a bare
`CURRENT_*_SCHEMA_VERSION` constant, no packaged JSON schema file --
this is a computed report, not a persisted artifact, the same position
`controlloop.capability`'s own models are in).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import (
    Edge,
    EdgeId,
    EdgeType,
    Node,
    NodeId,
    NodeType,
    SemanticVersion,
)
from controlloop.capability.models import CapabilityPath, EffectiveAuthorityEntry

CURRENT_DIFF_SCHEMA_VERSION = "1.0.0"


class _DiffModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class ChangeKind(StrEnum):
    """One of the four states every node, edge, and effective capability
    be classified into against a baseline.

    `UNKNOWN` is deliberately distinct from `REMOVED`: it means the same
    identity is present on both sides, and confidently known on the
    baseline side, but its current-side confidence dropped to
    `Confidence.UNKNOWN` -- analysis could no longer confirm what it
    once confirmed, which is not the same claim as "this no longer
    exists." An identity present in the baseline and genuinely absent
    from the current side -- vanished entirely, not merely downgraded --
    is `REMOVED`, without exception; this module does not speculate
    about *why* an identity disappeared (a real removal vs. an unrelated
    analysis gap), since nothing in this module connects a vanished key
    back to a specific incompleteness diagnostic.
    """

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNKNOWN = "unknown"


class NodeChange(_DiffModel):
    """One node's classification against the baseline. `before` and
    `after` are the full node on each side where present -- `None` on
    the side where the node's stable ID (`controlloop.acbom.identity`)
    is absent."""

    kind: ChangeKind
    node_id: NodeId
    before: Node | None = None
    after: Node | None = None


class EdgeChange(_DiffModel):
    """One edge's classification against the baseline, the same shape as
    `NodeChange`, keyed by the edge's own stable ID."""

    kind: ChangeKind
    edge_id: EdgeId
    before: Edge | None = None
    after: Edge | None = None


class EffectiveAuthorityChange(_DiffModel):
    """One effective-capability fact's classification against the
    baseline.

    Keyed by `(agent_id, action, resource_id)` -- deliberately *not*
    including `permitting_identity_id`, unlike
    `EffectiveAuthorityEntry`'s own dedup key
    (`BaselineDocument.validate_effective_authority_is_deduplicated`).
    The capability this reports on is "this agent can act on this
    resource"; which identity permits it and how confidently are
    properties *of* that capability's current state, not a separate
    fact. Keying on the narrower triple is what makes the "confidence
    dropped to unknown" rule work: an agent's fact that keeps existing
    but loses its permitting identity (confidence drops to
    `Confidence.UNKNOWN`) is one `UNKNOWN` entry, not a `REMOVED` entry
    for the old identity paired with an unrelated `ADDED` entry for the
    same fact now missing one.
    """

    kind: ChangeKind
    agent_id: NodeId
    action: EdgeType
    resource_id: NodeId
    before: EffectiveAuthorityEntry | None = None
    after: EffectiveAuthorityEntry | None = None


class CapabilityPathChange(_DiffModel):
    """One bounded transitive capability path's classification against
    the baseline. A change that adds authority only transitively is
    summarized as gained authority, with its path.

    Keyed by the path's own full edge-ID chain (`tuple(hop.edge_id for
    hop in path.hops)`), not by `(agent_id, target_id)` alone --
    `controlloop.capability.compute.compute_transitive_capability_paths`
    can legitimately return more than one distinct path to the same
    target (different routes through the graph), each its own fact, so
    collapsing them onto a shared key would silently drop real paths
    rather than reporting each one."""

    kind: ChangeKind
    agent_id: NodeId
    target_id: NodeId
    target_type: NodeType
    before: CapabilityPath | None = None
    after: CapabilityPath | None = None


class DiffResult(_DiffModel):
    """Complete change classification of one ACBOM graph against
    another. Every collection is deterministically ordered (see
    `controlloop.diff.compute`'s own sort keys) and contains only
    entries whose classification is `ADDED`, `REMOVED`, `CHANGED`, or
    `UNKNOWN` -- an identity unchanged on both sides is never
    represented at all, which is what makes "an identical repository
    against its own baseline produces an empty diff" a structural
    property of this model rather than a separate case callers must
    filter for themselves."""

    schema_version: SemanticVersion
    node_changes: tuple[NodeChange, ...]
    edge_changes: tuple[EdgeChange, ...]
    effective_authority_changes: tuple[EffectiveAuthorityChange, ...]

    @property
    def is_empty(self) -> bool:
        return not (
            self.node_changes or self.edge_changes or self.effective_authority_changes
        )
