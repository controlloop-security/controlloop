"""Material capability taxonomy.

A versioned classification of what makes a capability consequential:
write access, financial action, destructive action, external
communication, sensitive-data access, code execution, and delegation.
Every downstream feature that says "material," "privileged," or "worst
reachable action" resolves to this taxonomy, defined once so each one
does not invent its own severity ladder.

Each class is defined by an already-modeled, observable graph property
-- an existing `SecurityAttributes` boolean/enum field, or the edge
type an edge already carries -- never by matching against a node's or
edge's *name*. `delegates-to` and `writes` are structural, edge-type
checks; the other five read `SecurityAttributes` fields that already
exist on every node and edge (`destructive`, `financial_action`,
`code_execution`, `external_communication`,
`sensitivity`/`data_classifications`, and `read_only` for the
`invokes` case of write access).

`KnownBoolean`'s three states drive classification directly: `True`
classifies positively, `False` or `None` (no assertion made)
classifies negatively for that one class, and the literal `"unknown"`
(an explicit assertion that the fact could not be determined) adds
`MaterialCapabilityClass.UNCLASSIFIED` to the result -- distinct from,
and never collapsed into, an ordinary negative. An unclassifiable
capability is marked as such, never silently treated as harmless.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from controlloop.acbom.models import EdgeType, SecurityAttributes, Sensitivity

#: This taxonomy's own version, independent of the ACBOM/capability
#: package schema versions -- it is a documented, deliberately-changed
#: contract, not itself a serialized model field.
MATERIAL_CAPABILITY_TAXONOMY_VERSION = "1.0.0"


class MaterialCapabilityClass(StrEnum):
    """The taxonomy's eight members: the seven named material
    capability classes, plus `UNCLASSIFIED` for a capability this
    taxonomy could not resolve one way or the other."""

    UNCLASSIFIED = "unclassified"
    DESTRUCTIVE_ACTION = "destructive-action"
    FINANCIAL_ACTION = "financial-action"
    CODE_EXECUTION = "code-execution"
    EXTERNAL_COMMUNICATION = "external-communication"
    SENSITIVE_DATA_ACCESS = "sensitive-data-access"
    DELEGATION = "delegation"
    WRITE_ACCESS = "write-access"


#: The defined ordering, worst first. Grounded in blast radius and
#: reversibility: `DESTRUCTIVE_ACTION` and `FINANCIAL_ACTION` cause
#: direct, often irreversible harm; `CODE_EXECUTION` is an unbounded
#: escalation primitive that can lead to any of the others;
#: `EXTERNAL_COMMUNICATION` risks exfiltration; `SENSITIVE_DATA_ACCESS`
#: is read-level exposure with no action taken yet;`DELEGATION` expands
#: the trust boundary only indirectly, through another agent;
#: `WRITE_ACCESS` to an otherwise unclassified resource is the mildest
#: form of "material." `UNCLASSIFIED` ranks worst of all -- an unknown
#: risk must never be treated as safer than a known one, the same
#: "unknown, never omitted" reasoning this codebase's constitution
#: applies everywhere else.
_SEVERITY_RANK: dict[MaterialCapabilityClass, int] = {
    MaterialCapabilityClass.UNCLASSIFIED: 0,
    MaterialCapabilityClass.DESTRUCTIVE_ACTION: 1,
    MaterialCapabilityClass.FINANCIAL_ACTION: 2,
    MaterialCapabilityClass.CODE_EXECUTION: 3,
    MaterialCapabilityClass.EXTERNAL_COMMUNICATION: 4,
    MaterialCapabilityClass.SENSITIVE_DATA_ACCESS: 5,
    MaterialCapabilityClass.DELEGATION: 6,
    MaterialCapabilityClass.WRITE_ACCESS: 7,
}

_SENSITIVE_LEVELS = frozenset({Sensitivity.CONFIDENTIAL, Sensitivity.RESTRICTED})


def classify_material_capability(
    security_attributes: SecurityAttributes,
    *,
    edge_type: EdgeType | None = None,
) -> frozenset[MaterialCapabilityClass]:
    """Return every material capability class `security_attributes`
    (and, if given, the edge type it was asserted on) definitively
    matches (a capability may hold more than one, and every matched
    class is reported, never just the first or the worst).

    Operates on the primitive evidence every node and edge already
    carries -- not on `CapabilityPath` or `EffectiveAuthorityEntry`
    directly, since neither of those two carries `SecurityAttributes`
    itself. A caller classifying a path or an authority entry looks up
    the relevant node's or edge's own `security_attributes` (and, for
    an edge, its `type`) and passes those here.
    """

    classes: set[MaterialCapabilityClass] = set()
    unclassified = False

    if security_attributes.destructive is True:
        classes.add(MaterialCapabilityClass.DESTRUCTIVE_ACTION)
    elif security_attributes.destructive == "unknown":
        unclassified = True

    if security_attributes.financial_action is True:
        classes.add(MaterialCapabilityClass.FINANCIAL_ACTION)
    elif security_attributes.financial_action == "unknown":
        unclassified = True

    if security_attributes.code_execution is True:
        classes.add(MaterialCapabilityClass.CODE_EXECUTION)
    elif security_attributes.code_execution == "unknown":
        unclassified = True

    if security_attributes.external_communication is True:
        classes.add(MaterialCapabilityClass.EXTERNAL_COMMUNICATION)
    elif security_attributes.external_communication == "unknown":
        unclassified = True

    if security_attributes.sensitivity in _SENSITIVE_LEVELS:
        classes.add(MaterialCapabilityClass.SENSITIVE_DATA_ACCESS)
    elif security_attributes.sensitivity is Sensitivity.UNKNOWN:
        unclassified = True
    if security_attributes.data_classifications:
        classes.add(MaterialCapabilityClass.SENSITIVE_DATA_ACCESS)

    if edge_type is EdgeType.DELEGATES_TO:
        classes.add(MaterialCapabilityClass.DELEGATION)

    if edge_type is EdgeType.WRITES:
        classes.add(MaterialCapabilityClass.WRITE_ACCESS)
    elif edge_type is EdgeType.INVOKES:
        if security_attributes.read_only is False:
            classes.add(MaterialCapabilityClass.WRITE_ACCESS)
        elif security_attributes.read_only == "unknown":
            unclassified = True

    if unclassified:
        classes.add(MaterialCapabilityClass.UNCLASSIFIED)

    return frozenset(classes)


def worst_class(classes: Iterable[MaterialCapabilityClass]) -> MaterialCapabilityClass:
    """Return the single worst class in `classes`, by the taxonomy's
    defined ordering. Raises `ValueError` on an empty input -- there
    is no "worst of nothing," and a caller with no classes to compare
    should not receive a fabricated answer."""

    ordered = sorted(classes, key=lambda member: _SEVERITY_RANK[member])
    if not ordered:
        raise ValueError("worst_class requires at least one class")
    return ordered[0]
