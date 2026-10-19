"""Change classification.

`compute_diff` classifies every node, edge, and effective-capability
fact of a "current" ACBOM graph against a "baseline" one into exactly
one of four states (`controlloop.diff.models.ChangeKind`): added,
removed, changed, or unknown. It takes already-discovered nodes and
edges on both sides rather than performing any discovery, analysis, or
comparison-target resolution itself -- the same compute/impure-boundary
split `controlloop.capability.compute` and `controlloop.bom` already
follow. A caller comparing two full ACBOMs passes both documents'
`nodes`/`edges` directly; a caller comparing a live scan against a
compact `BaselineDocument` (which carries no nodes or edges at all, only
`effective_authority`) can call `diff_effective_authority` on its own,
passing `BaselineDocument.effective_authority` as `baseline_entries` --
no CLI command does either yet, matching every other `controlloop.diff`-
adjacent module's own current position.

`diff_transitive_capability_paths` extends the same four-state
classification to bounded multi-hop capability paths
(`controlloop.capability.compute.compute_transitive_capability_paths`),
reusing `_classify` unchanged -- `CapabilityPath` carries its own
`confidence` field, so the "confidence dropped to unknown" rule applies
identically here with no new logic.
"""

from __future__ import annotations

from collections.abc import Mapping

from controlloop.acbom.models import Confidence, Edge, EdgeType, Node
from controlloop.capability.compute import compute_effective_authority
from controlloop.capability.models import CapabilityPath, EffectiveAuthorityEntry
from controlloop.diff.models import (
    CURRENT_DIFF_SCHEMA_VERSION,
    CapabilityPathChange,
    ChangeKind,
    DiffResult,
    EdgeChange,
    EffectiveAuthorityChange,
    NodeChange,
)

_EffectiveAuthorityKey = tuple[str, EdgeType, str]
_CapabilityPathKey = tuple[str, ...]
_Classifiable = Node | Edge | EffectiveAuthorityEntry | CapabilityPath

#: Excluded from the equality comparison below: evidence records *where*
#: a definition was discovered (adapter, path, line numbers), never
#: *what* it is. A node or edge that only moved in its source file or
#: was reformatted keeps the same stable ID
#: (`controlloop.acbom.identity`) and, because this field is excluded
#: here too, is not reported as a change at all -- not even `CHANGED`.
_IDENTITY_STABLE_EXCLUDED_FIELDS: set[str] = {"evidence"}


def _classify(
    before: _Classifiable | None, after: _Classifiable | None
) -> ChangeKind | None:
    """The one rule every domain below applies: absent on one side is
    `ADDED`/`REMOVED`; present on both, identical once evidence is set
    aside, is unchanged (`None`, meaning "omit from the diff"); present
    on both and otherwise different is `CHANGED`, unless the only thing
    that changed is a confident baseline value going to
    `Confidence.UNKNOWN` on the current side, which is `UNKNOWN`, never
    `REMOVED` or an ordinary `CHANGED`.

    `before is None and after is None` never happens in practice --
    callers only invoke this for a key present in at least one side.
    """

    if before is None and after is not None:
        return ChangeKind.ADDED
    if before is not None and after is None:
        return ChangeKind.REMOVED
    if before is None or after is None:
        return None

    if (
        before.confidence is not Confidence.UNKNOWN
        and after.confidence is Confidence.UNKNOWN
    ):
        return ChangeKind.UNKNOWN
    if before.model_dump(exclude=_IDENTITY_STABLE_EXCLUDED_FIELDS) == after.model_dump(
        exclude=_IDENTITY_STABLE_EXCLUDED_FIELDS
    ):
        return None
    return ChangeKind.CHANGED


def diff_nodes(
    baseline_nodes: tuple[Node, ...], current_nodes: tuple[Node, ...]
) -> tuple[NodeChange, ...]:
    """Classify every node by its stable ID: a node ID encodes only
    type, namespace, and semantic identity
    (`controlloop.acbom.identity`), never evidence, line numbers,
    security attributes, or confidence -- so a definition that only
    moved or was reformatted keeps its ID and is never reported as a
    change by this function."""

    baseline_by_id: Mapping[str, Node] = {node.id: node for node in baseline_nodes}
    current_by_id: Mapping[str, Node] = {node.id: node for node in current_nodes}

    changes = []
    for node_id in baseline_by_id.keys() | current_by_id.keys():
        before = baseline_by_id.get(node_id)
        after = current_by_id.get(node_id)
        kind = _classify(before, after)
        if kind is not None:
            changes.append(
                NodeChange(kind=kind, node_id=node_id, before=before, after=after)
            )

    return tuple(sorted(changes, key=lambda change: (change.node_id, change.kind)))


def diff_edges(
    baseline_edges: tuple[Edge, ...], current_edges: tuple[Edge, ...]
) -> tuple[EdgeChange, ...]:
    """Classify every edge by its stable ID, the same shape as
    `diff_nodes`: an edge ID encodes relationship type, source, target,
    and an adapter-supplied discriminator only, never evidence or
    confidence."""

    baseline_by_id: Mapping[str, Edge] = {edge.id: edge for edge in baseline_edges}
    current_by_id: Mapping[str, Edge] = {edge.id: edge for edge in current_edges}

    changes = []
    for edge_id in baseline_by_id.keys() | current_by_id.keys():
        before = baseline_by_id.get(edge_id)
        after = current_by_id.get(edge_id)
        kind = _classify(before, after)
        if kind is not None:
            changes.append(
                EdgeChange(kind=kind, edge_id=edge_id, before=before, after=after)
            )

    return tuple(sorted(changes, key=lambda change: (change.edge_id, change.kind)))


def _effective_authority_key(
    entry: EffectiveAuthorityEntry,
) -> _EffectiveAuthorityKey:
    return (entry.agent_id, entry.action, entry.resource_id)


def diff_effective_authority(
    baseline_entries: tuple[EffectiveAuthorityEntry, ...],
    current_entries: tuple[EffectiveAuthorityEntry, ...],
) -> tuple[EffectiveAuthorityChange, ...]:
    """Classify every effective-capability fact, keyed by `(agent_id,
    action, resource_id)` -- deliberately narrower than
    `EffectiveAuthorityEntry`'s own dedup key, which also includes
    `permitting_identity_id`. Which identity permits a capability, and
    how confidently, are properties of that capability's current state,
    not a separate fact: keying on the triple is what makes the
    "confidence dropped to unknown" rule work, so a capability that
    keeps existing but loses its permitting identity
    (`permitting_identity_id` becomes `None`, `confidence` drops to
    `Confidence.UNKNOWN`) is reported as one `UNKNOWN` entry, never as a
    `REMOVED` entry for the old identity paired with an unrelated
    `ADDED` entry for the same fact now missing one."""

    baseline_by_key: Mapping[_EffectiveAuthorityKey, EffectiveAuthorityEntry] = {
        _effective_authority_key(entry): entry for entry in baseline_entries
    }
    current_by_key: Mapping[_EffectiveAuthorityKey, EffectiveAuthorityEntry] = {
        _effective_authority_key(entry): entry for entry in current_entries
    }

    changes = []
    for key in baseline_by_key.keys() | current_by_key.keys():
        agent_id, action, resource_id = key
        before = baseline_by_key.get(key)
        after = current_by_key.get(key)
        kind = _classify(before, after)
        if kind is not None:
            changes.append(
                EffectiveAuthorityChange(
                    kind=kind,
                    agent_id=agent_id,
                    action=action,
                    resource_id=resource_id,
                    before=before,
                    after=after,
                )
            )

    return tuple(
        sorted(
            changes,
            key=lambda change: (
                change.agent_id,
                str(change.action),
                change.resource_id,
                change.kind,
            ),
        )
    )


def _capability_path_key(path: CapabilityPath) -> _CapabilityPathKey:
    return tuple(hop.edge_id for hop in path.hops)


def diff_transitive_capability_paths(
    baseline_paths: tuple[CapabilityPath, ...],
    current_paths: tuple[CapabilityPath, ...],
) -> tuple[CapabilityPathChange, ...]:
    """Classify every bounded transitive capability path, keyed by the
    path's own full edge-ID chain --
    `controlloop.capability.compute.compute_transitive_capability_paths`
    can return more than one distinct path to the same `(agent_id,
    target_id)` pair (different routes through the graph), so this
    deliberately does not narrow the key the way
    `diff_effective_authority` narrows its own: each route is its own
    fact, not an alternate view of one shared fact."""

    baseline_by_key: Mapping[_CapabilityPathKey, CapabilityPath] = {
        _capability_path_key(path): path for path in baseline_paths
    }
    current_by_key: Mapping[_CapabilityPathKey, CapabilityPath] = {
        _capability_path_key(path): path for path in current_paths
    }

    changes: list[tuple[_CapabilityPathKey, CapabilityPathChange]] = []
    for key in baseline_by_key.keys() | current_by_key.keys():
        before = baseline_by_key.get(key)
        after = current_by_key.get(key)
        kind = _classify(before, after)
        if kind is not None:
            reference = after if after is not None else before
            assert reference is not None
            changes.append(
                (
                    key,
                    CapabilityPathChange(
                        kind=kind,
                        agent_id=reference.agent_id,
                        target_id=reference.target_id,
                        target_type=reference.target_type,
                        before=before,
                        after=after,
                    ),
                )
            )

    return tuple(
        change
        for _key, change in sorted(
            changes,
            key=lambda item: (
                item[1].agent_id,
                item[1].target_id,
                item[0],
                item[1].kind,
            ),
        )
    )


def compute_diff(
    *,
    baseline_nodes: tuple[Node, ...],
    baseline_edges: tuple[Edge, ...],
    current_nodes: tuple[Node, ...],
    current_edges: tuple[Edge, ...],
) -> DiffResult:
    """Classify a full ACBOM graph's nodes, edges, and effective
    capabilities against a baseline graph's. Effective authority is
    computed fresh from each side's own `nodes`/`edges` via
    `compute_effective_authority` -- never taken as an input -- so a
    baseline's own `effective_authority` field is not, and cannot be,
    silently substituted for one this function derives itself.

    An identical repository against its own baseline (identical nodes
    and edges on both sides) produces a `DiffResult` with `is_empty`
    `True`: every node, edge, and derived effective-authority entry
    compares equal to itself, so `_classify` returns `None` for every
    key and nothing is appended to any collection. Every returned
    collection is deterministically ordered regardless of input order
    (see each `diff_*` function's own sort key)."""

    baseline_effective_authority = compute_effective_authority(
        baseline_nodes, baseline_edges
    )
    current_effective_authority = compute_effective_authority(
        current_nodes, current_edges
    )

    return DiffResult(
        schema_version=CURRENT_DIFF_SCHEMA_VERSION,
        node_changes=diff_nodes(baseline_nodes, current_nodes),
        edge_changes=diff_edges(baseline_edges, current_edges),
        effective_authority_changes=diff_effective_authority(
            baseline_effective_authority, current_effective_authority
        ),
    )
