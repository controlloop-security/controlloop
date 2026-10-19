"""Render an unwritten, human-reviewable draft `controlloop.yaml` from
already-discovered ACBOM nodes/edges.

Deliberately hand-constructs YAML text rather than using a generic
dict-to-YAML dumper: `manifest.parser.load_manifest` (the one schema
validator this manifest has) is `yaml.safe_load` plus pydantic
validation, and this repository's only YAML dependency (`pyyaml`)
cannot emit comments. Every value that becomes a YAML scalar is written
via `json.dumps`, since a JSON double-quoted string is also a valid
YAML double-quoted scalar -- this sidesteps hand-rolled YAML escaping
(a discovered name containing `:` or `#` cannot corrupt the document)
without adding a new dependency such as `ruamel.yaml`. This module
reuses `Node.name` verbatim for agent identity instead of a derived
slug: `manifest.ceiling.ceiling_policy_boundary_nodes_and_edges`
already matches a manifest declaration against discovery by exact
`Node.name` string equality, not a hash or a slug -- inventing a
different identifier here would silently break that match for every
agent whose name happens not to already satisfy `SafeIdentifier`.

Every discovered display-name string this module places into a comment
is passed through `_escape_hostile_characters` first, mirroring
`controlloop.repository`'s own handling of the same threat for
evidence paths: `DisplayName` (the type `Node.name` carries) only
rejects the ASCII control range and DEL, not a Unicode bidi/format
character such as a right-to-left override, so a hostile agent-card
`"name"` field could otherwise visually reorder or hide surrounding
comment text in a reviewer's editor. Names that already satisfy
`SafeIdentifier`'s tight character class (used verbatim as the real
`agents:` list value) cannot carry such a character, since that
character class excludes it structurally; the escaping here exists for
the *comment* text, which -- for transparency about what was found and
excluded -- still names every discovered agent, including ones whose
raw name does not qualify as a safe identifier.

The `ceilings:` section follows the same discipline:
`controlloop.manifest.ceiling.propose_starter_ceiling` derives real,
schema-valid `CapabilityCeiling` entries from the same discovered
nodes/edges, and this module renders them plus their disclosure
comments (starting-point marking, low-confidence separation, and the
categories that could not be derived at all) using the same
`_yaml_string`/`_escape_hostile_characters` machinery already
established above.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Sequence

from controlloop.acbom import Edge, EdgeType, Node, NodeType
from controlloop.manifest.ceiling import StarterCeilingProposal, propose_starter_ceiling
from controlloop.manifest.models import (
    CURRENT_MANIFEST_SCHEMA_VERSION,
    CapabilityCeiling,
)

# Mirrors controlloop.acbom.models.SafeIdentifier's own character class
# and length bound exactly (that Annotated type is not itself importable
# as a plain regex) -- used only to decide whether a discovered
# Node.name can be reused verbatim as a manifest agent identifier, never
# to reject or alter the underlying node.
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
_SAFE_IDENTIFIER_MAX_LENGTH = 256

# Same hostile-category set controlloop.repository._escape_hostile_characters
# uses for evidence paths: Cc/Cf (control and bidi/format, e.g. a
# right-to-left override) and Cs (a lone surrogate). Applied to every
# discovered name embedded in a comment, since DisplayName's own pattern
# does not exclude these.
_HOSTILE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})

_OWNER_PLACEHOLDER = "TODO-owner"
_TRUST_BOUNDARY_NAME_PLACEHOLDER = "TODO-trust-boundary-name"


def _is_safe_identifier(value: str) -> bool:
    return (
        len(value) <= _SAFE_IDENTIFIER_MAX_LENGTH
        and _SAFE_IDENTIFIER_PATTERN.match(value) is not None
    )


def _escape_hostile_characters(text: str) -> str:
    """Replace control and Unicode bidi/format characters with a
    printable `<U+XXXX>` marker before `text` is placed into a comment.
    See the module docstring for why this is needed even though
    `DisplayName` already bounds `text`."""

    return "".join(
        f"<U+{ord(character):04X}>"
        if unicodedata.category(character) in _HOSTILE_UNICODE_CATEGORIES
        else character
        for character in text
    )


def _yaml_string(value: str) -> str:
    """A JSON double-quoted string is a valid YAML double-quoted
    scalar -- reused here instead of hand-rolled YAML escaping.
    `ensure_ascii=False` keeps ordinary Unicode names human-readable in
    the rendered file; the escaping this module performs for hostile
    Unicode happens separately, in `_escape_hostile_characters`, before
    text reaches a comment -- this function is only ever called with a
    value already known safe (a `SafeIdentifier`-conformant agent name,
    or a fixed literal this module defines itself)."""

    return json.dumps(value, ensure_ascii=False)


def _yaml_string_list(values: Sequence[str]) -> str:
    """A JSON array of double-quoted strings is a valid YAML flow
    sequence -- the same trick `_yaml_string` uses for one scalar,
    extended to a list. Only ever called with values this module
    already knows are safe: an `EdgeType`'s fixed string value (a
    `StrEnum`, so already a `str` instance) or a `SafeIdentifier`
    -conformant agent name, never untrusted display text."""

    return json.dumps(list(values), ensure_ascii=False)


def _tools_invoked_by(
    agent_id: str, edges: tuple[Edge, ...], tool_names_by_id: dict[str, str]
) -> list[str]:
    return sorted(
        {
            tool_names_by_id[edge.target]
            for edge in edges
            if edge.type is EdgeType.INVOKES
            and edge.source == agent_id
            and edge.target in tool_names_by_id
        }
    )


def _delegation_pairs(nodes: tuple[Node, ...], edges: tuple[Edge, ...]) -> list[str]:
    """Delegation-shaped relationships ControlLoop observed between two
    discovered agents -- informational only (surfaced as a comment
    under `allowed_delegation`), never written as an approved entry:
    declaring a delegation target permitted is a human policy decision,
    not a mirror of what discovery happened to find."""

    agent_names_by_id = {
        node.id: node.name for node in nodes if node.type is NodeType.AGENT
    }
    pairs = {
        (agent_names_by_id[edge.source], agent_names_by_id[edge.target])
        for edge in edges
        if edge.type is EdgeType.DELEGATES_TO
        and edge.source in agent_names_by_id
        and edge.target in agent_names_by_id
    }
    return [
        f"{_escape_hostile_characters(source)} -> {_escape_hostile_characters(target)}"
        for source, target in sorted(pairs)
    ]


def _header_lines() -> list[str]:
    return [
        "# controlloop.yaml",
        "# ControlLoop security manifest -- generated by `controlloop init`.",
        "#",
        "# This file was drafted from what ControlLoop could discover in",
        "# this repository. Every field below is present, even where",
        "# ControlLoop could not determine a value -- those are marked TODO",
        "# with a comment explaining what to supply. Nothing here is",
        "# enforced until you review it: `controlloop init` never evaluates",
        "# policy.",
        "#",
        f"# Manifest schema version {CURRENT_MANIFEST_SCHEMA_VERSION}.",
    ]


def _owner_lines() -> list[str]:
    return [
        "# TODO: owner",
        "# ControlLoop cannot determine who is accountable for this",
        "# repository's agents. Replace the placeholder below with an",
        "# identifier for the responsible team or individual (for",
        '# example: "platform-security" or "jane.doe").',
        f"owner: {_yaml_string(_OWNER_PLACEHOLDER)}",
    ]


def _trust_boundaries_lines(
    included: list[tuple[Node, list[str]]], excluded_names: list[str]
) -> list[str]:
    lines = [
        "trust_boundaries:",
        "  # TODO: trust boundary name",
        '  # Rename "TODO-trust-boundary-name" below to describe this',
        '  # boundary (for example: "production", "internal-tools").',
        "  # ControlLoop cannot determine how your agents should be",
        "  # grouped into trust boundaries.",
    ]
    if included:
        lines.append("  # Discovered candidate agents (from repository discovery):")
        for node, tools in included:
            safe_name = _escape_hostile_characters(node.name)
            tools_text = (
                f"tools observed: {', '.join(tools)}" if tools else "no tools observed"
            )
            lines.append(f"  #   - {safe_name}  ({tools_text})")
    elif not excluded_names:
        lines.append(
            "  # ControlLoop discovered no candidate agents in this repository."
        )
        lines.append("  # Add each agent you want ControlLoop to track by name.")
    if excluded_names:
        count = len(excluded_names)
        lines.append(
            f"  # {count} discovered agent(s) could not be listed automatically "
            "below: their names contain"
        )
        lines.append(
            "  # characters this manifest's identifier format disallows (only "
            "letters, digits, and"
        )
        lines.append("  # . _ : / @ + - are allowed, no spaces). Found, by name:")
        for excluded_name in excluded_names:
            lines.append(f"  #   - {excluded_name}")
        lines.append(
            "  # Add each one manually below once you have chosen a safe "
            "identifier for it."
        )
    lines.append(f"  - name: {_yaml_string(_TRUST_BOUNDARY_NAME_PLACEHOLDER)}")
    if included:
        lines.append("    agents:")
        for node, _tools in included:
            lines.append(f"      - {_yaml_string(node.name)}")
    else:
        lines.append("    agents: []")
    return lines


def _empty_list_field_lines(field_name: str, comment_lines: list[str]) -> list[str]:
    lines = [f"# TODO: {field_name}"]
    lines.extend(f"# {line}" for line in comment_lines)
    lines.append(f"{field_name}: []")
    return lines


def _allowed_delegation_lines(
    nodes: tuple[Node, ...], edges: tuple[Edge, ...]
) -> list[str]:
    lines = [
        "# TODO: allowed_delegation",
        "# ControlLoop cannot determine which delegation targets are",
        "# actually permitted -- declaring one here is a policy decision,",
        "# not a mirror of what was discovered. Add one entry per agent",
        "# you want to allow to delegate, for example:",
        '#   - agent: "agent-a"',
        '#     targets: ["agent-b"]',
    ]
    pairs = _delegation_pairs(nodes, edges)
    if pairs:
        lines.append(
            "# ControlLoop observed these delegation-shaped relationships "
            "(reference only, not yet approved):"
        )
        lines.extend(f"#   - {pair}" for pair in pairs)
    lines.append("allowed_delegation: []")
    return lines


def _ceiling_entry_lines(ceiling: CapabilityCeiling) -> list[str]:
    """Renders one proposed `CapabilityCeiling` entry. `agent`,
    `prohibited_actions`, and `prohibited_delegation_targets` are
    `propose_starter_ceiling`'s real derived values; the remaining
    three fields are always empty here (see `_ceiling_lines`'s header
    disclosure for why) and written explicitly rather than omitted, so
    a reviewer sees every schema field for this entry, not just the
    ones ControlLoop could derive."""

    return [
        f"  - agent: {_yaml_string(ceiling.agent or '')}",
        f"    prohibited_actions: {_yaml_string_list(ceiling.prohibited_actions)}",
        "    prohibited_delegation_targets: "
        f"{_yaml_string_list(ceiling.prohibited_delegation_targets)}",
        "    prohibited_resources: []",
        "    prohibited_external_destinations: []",
        "    prohibited_data_classes: []",
    ]


def _ceiling_lines(
    proposal: StarterCeilingProposal,
    *,
    has_safe_agents: bool,
    has_excluded_agents: bool,
) -> list[str]:
    """Renders the `ceilings:` section: a starter proposal derived from
    current direct effective authority, always marked as a starting point,
    with low-confidence discoveries disclosed separately and the categories
    this analysis could never derive disclosed explicitly."""

    lines = [
        "# TODO: ceilings",
        "# This section is a STARTING POINT, not an approved security",
        "# boundary -- review every entry below before relying on it.",
        "# ControlLoop proposed each prohibited_actions and",
        "# prohibited_delegation_targets value from what this scan",
        "# actually observed: an action or delegation target is only",
        "# proposed as prohibited when this scan found zero evidence of",
        "# it, so adopting this section unchanged does not conflict with",
        "# anything found in this scan.",
        "#",
        "# ControlLoop cannot determine prohibited_resources,",
        "# prohibited_external_destinations, or prohibited_data_classes",
        "# from repository discovery alone: these describe things never",
        "# observed (a resource never touched, a domain never contacted,",
        "# a data class never seen), which static analysis has no way to",
        "# enumerate. They are left as empty TODO lists below -- that is",
        '# an incomplete analysis, not a considered "nothing to prohibit"',
        "# answer.",
    ]

    if has_excluded_agents:
        lines.append("#")
        lines.append("# Ceiling proposals are limited to the safely-identified")
        lines.append("# agents listed under trust_boundaries above; see the")
        lines.append("# exclusion note there for agents not covered here.")

    if proposal.low_confidence_actions or proposal.low_confidence_delegations:
        lines.append("#")
        lines.append("# ControlLoop observed the following only at low or unknown")
        lines.append("# confidence. They are neither prohibited above (doing so")
        lines.append("# could immediately conflict with this scan) nor treated as")
        lines.append("# a confidently reviewed grant -- review each one and either")
        lines.append("# approve it or add it to a prohibited_* field above:")
        for action in proposal.low_confidence_actions:
            agent = _escape_hostile_characters(action.agent_name)
            resource = _escape_hostile_characters(action.resource_name)
            lines.append(
                f"#   - {agent} {action.action.value} {resource} "
                f"({action.confidence.value} confidence)"
            )
        for delegation in proposal.low_confidence_delegations:
            agent = _escape_hostile_characters(delegation.agent_name)
            target = _escape_hostile_characters(delegation.target_name)
            lines.append(
                f"#   - {agent} may delegate to {target} "
                f"({delegation.confidence.value} confidence)"
            )

    if not has_safe_agents:
        if not has_excluded_agents:
            lines.append("#")
            lines.append(
                "# ControlLoop discovered no candidate agents to propose a ceiling for."
            )
        # else: the exclusion note above already explains why there is
        # no safely-identified agent to propose a ceiling for.
    elif not proposal.ceilings:
        lines.append("#")
        lines.append("# Every discovered agent already exercises every action type")
        lines.append("# ControlLoop tracks, and no other discovered agent exists to")
        lines.append("# restrict delegation to -- nothing meaningful to propose yet.")

    if not proposal.ceilings:
        lines.append("ceilings: []")
        return lines

    lines.append("ceilings:")
    for ceiling in proposal.ceilings:
        lines.extend(_ceiling_entry_lines(ceiling))
    return lines


def render_draft_manifest(nodes: tuple[Node, ...], edges: tuple[Edge, ...]) -> str:
    """Render a schema-valid draft `controlloop.yaml` from
    already-discovered `nodes`/`edges` -- the caller is expected to
    have produced these via `controlloop.bom.build_acbom_document`
    over a resolved repository root, exactly as `controlloop init`
    does. Deterministic: identical input, regardless of its original
    ordering, produces byte-identical output, since every collection
    here is explicitly sorted before rendering (`NodeId`/`EdgeId` are
    stable, content-derived identifiers -- see
    `controlloop.acbom.identity` -- so sorting by them is itself
    deterministic).
    """

    agent_nodes = sorted(
        (node for node in nodes if node.type is NodeType.AGENT),
        key=lambda node: node.id,
    )
    tool_names_by_id = {
        node.id: node.name for node in nodes if node.type is NodeType.TOOL
    }

    included: list[tuple[Node, list[str]]] = []
    excluded_names: list[str] = []
    for node in agent_nodes:
        if _is_safe_identifier(node.name):
            included.append((node, _tools_invoked_by(node.id, edges, tool_names_by_id)))
        else:
            excluded_names.append(_escape_hostile_characters(node.name))

    lines: list[str] = []
    lines.extend(_header_lines())
    lines.append("")
    lines.append(f"schema_version: {_yaml_string(CURRENT_MANIFEST_SCHEMA_VERSION)}")
    lines.append("")
    lines.extend(_owner_lines())
    lines.append("")
    lines.extend(_trust_boundaries_lines(included, excluded_names))
    lines.append("")
    lines.extend(
        _empty_list_field_lines(
            "approvals",
            [
                "ControlLoop cannot determine which capabilities have been",
                "approved, or by whom. Add one entry per approved",
                "capability, naming who approved it, for example:",
                '  - capability: "agent-a:invokes:tool-x"',
                '    approver: "jane.doe"',
            ],
        )
    )
    lines.append("")
    lines.extend(
        _empty_list_field_lines(
            "prohibited_capabilities",
            [
                "ControlLoop cannot determine which capabilities an agent",
                "must never hold. Add one entry per prohibition, for",
                "example:",
                '  - agent: "agent-a"',
                '    edge_type: "invokes"',
                '    target: "tool-x"',
            ],
        )
    )
    lines.append("")
    lines.extend(_allowed_delegation_lines(nodes, edges))
    lines.append("")
    lines.extend(
        _empty_list_field_lines(
            "data_classification",
            [
                "ControlLoop cannot determine the sensitivity of the",
                "resources your agents touch. Add one entry per resource,",
                "for example:",
                '  - resource: "customer-database"',
                '    sensitivity: "confidential"',
            ],
        )
    )
    lines.append("")
    proposal = propose_starter_ceiling(
        agent_nodes=tuple(node for node, _tools in included),
        nodes=nodes,
        edges=edges,
    )
    lines.extend(
        _ceiling_lines(
            proposal,
            has_safe_agents=bool(included),
            has_excluded_agents=bool(excluded_names),
        )
    )
    return "\n".join(lines) + "\n"
