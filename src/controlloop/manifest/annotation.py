"""Applies `ManifestDocument.tool_capabilities` onto discovered tool
nodes.

## Why this exists

`controlloop.capability.taxonomy.classify_material_capability` decides
whether a capability is material from the **target node's** own
`SecurityAttributes`. No shipped offline adapter sets `destructive`,
`financial_action`, `read_only`, or `sensitivity` on anything; the two
attributes adapters do set (`code_execution` on an MCP server,
`external_communication` on an external delegation target) sit on nodes
no agent has an edge to. Before this module, no real repository scan
could classify any capability as material, so `compute_blast_radius`
always returned `None`, the material change summary was always empty,
and the capability reduction report could never name a class.

## What it does and does not do

This module only ever *supplements* a discovered node's
`SecurityAttributes`, exactly like `reconciliation.py`'s stated
"declarations supplement discovered evidence and never delete a
discovered capability." Specifically:

- Only `NodeType.TOOL` nodes are eligible.
- Matching is by `Node.name`, the same human-writable identifier
  `reconcile_manifest`, `ToolLoggingDeclaration`, and the
  capability-ceiling rule already match on. Content-addressed IDs are
  hashes nobody can write into YAML.
- An attribute the declaration leaves as `None` is not applied at all --
  the discovered value survives untouched. Declaring nothing about a
  tool is never the same as declaring `False` about it.
- `permission_scopes` and `data_classifications` are *merged* with what
  discovery already found (deduplicated, order-stable), never replaced,
  so an IAM-derived scope cannot be erased by a manifest declaration.
- A declaration naming a tool discovery did not find yields an
  `unverified` diagnostic, never a silent no-op.
- Node IDs are untouched. The identity rules forbid security
  attributes as identity input, so annotation cannot move an ID -- a
  property `tests/manifest/test_annotation.py` asserts directly rather
  than assuming.

Pure and deterministic: no clock, no filesystem, no network, no
randomness. `controlloop.bom.build_acbom_document` is the only caller.
"""

from __future__ import annotations

from controlloop.acbom import (
    Diagnostic,
    Evidence,
    Node,
    NodeType,
    SecurityAttributes,
)
from controlloop.manifest.models import ManifestDocument, ToolCapabilityDeclaration
from controlloop.manifest.reconciliation import unverified_diagnostic

#: Every `SecurityAttributes` field a declaration may set directly. Each
#: name is identical on `ToolCapabilityDeclaration` and on
#: `SecurityAttributes`, so the mapping is a plain attribute copy rather
#: than a translation table that could drift.
_SCALAR_FIELDS = (
    "destructive",
    "financial_action",
    "code_execution",
    "external_communication",
    "read_only",
    "privileged",
    "requires_approval",
    "sensitivity",
)


def _merged_data_classifications(
    attributes: SecurityAttributes, declaration: ToolCapabilityDeclaration
) -> tuple[str, ...]:
    """Union of discovered and declared classes, order-stable and
    deduplicated: discovered first, then declared ones not already
    present. Never replaces what discovery found."""

    merged = list(attributes.data_classifications)
    for declared in declaration.data_classes:
        if declared not in merged:
            merged.append(declared)
    return tuple(merged)


def _annotated_attributes(
    attributes: SecurityAttributes, declaration: ToolCapabilityDeclaration
) -> SecurityAttributes:
    updates: dict[str, object] = {}
    for field in _SCALAR_FIELDS:
        declared = getattr(declaration, field)
        if declared is not None:
            updates[field] = declared

    merged_classes = _merged_data_classifications(attributes, declaration)
    if merged_classes != attributes.data_classifications:
        updates["data_classifications"] = merged_classes

    if not updates:
        return attributes
    return attributes.model_copy(update=updates)


def annotate_tool_capabilities(
    nodes: tuple[Node, ...],
    manifest: ManifestDocument | None,
    evidence: tuple[Evidence, ...],
) -> tuple[tuple[Node, ...], tuple[Diagnostic, ...]]:
    """Return `nodes` with every matching tool node's
    `SecurityAttributes` supplemented by `manifest.tool_capabilities`,
    plus one `unverified` diagnostic per declaration naming a tool
    discovery did not find.

    `manifest` of `None`, or a manifest declaring no tool capabilities,
    returns `nodes` unchanged and no diagnostics -- so a repository that
    declares nothing produces a byte-identical ACBOM to one built before
    this feature existed.
    """

    if manifest is None or not manifest.tool_capabilities:
        return nodes, ()

    declarations_by_name: dict[str, list[ToolCapabilityDeclaration]] = {}
    for declaration in manifest.tool_capabilities:
        declarations_by_name.setdefault(declaration.tool, []).append(declaration)

    matched: set[str] = set()
    annotated: list[Node] = []
    for node in nodes:
        declarations = (
            declarations_by_name.get(node.name) if node.type is NodeType.TOOL else None
        )
        if not declarations:
            annotated.append(node)
            continue

        matched.add(node.name)
        attributes = node.security_attributes
        # More than one declaration for the same tool name is applied in
        # declaration order, so a later one deliberately wins -- the same
        # last-write-wins reading a human gives a YAML list.
        for declaration in declarations:
            attributes = _annotated_attributes(attributes, declaration)
        annotated.append(
            node
            if attributes == node.security_attributes
            else node.model_copy(update={"security_attributes": attributes})
        )

    diagnostics = tuple(
        unverified_diagnostic(
            evidence,
            "a declared tool capability names a tool discovery did not find",
        )
        for name in sorted(declarations_by_name)
        if name not in matched
    )
    return tuple(annotated), diagnostics
