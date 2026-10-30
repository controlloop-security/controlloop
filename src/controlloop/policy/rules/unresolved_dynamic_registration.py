"""Rule: unresolved dynamic tool registration.

Depends on unknown/incomplete representation
(`controlloop.acbom.completeness`'s `INCOMPLETE-DYNAMIC-REGISTRATION`
diagnostic code) and the finding model. See this package's
`missing_action_logging` module docstring for the shared two-layer
`evaluate()`/`findings()` design these rules use.

**The CrewAI, LangGraph, and OpenAI Agents SDK adapters emit
`INCOMPLETE-DYNAMIC-REGISTRATION`** when a `tools=` (or `bind_tools`,
`ToolNode`, `handoffs=`) argument is a comprehension, a call, a splat, a
conditional expression, or a list the module builds with a loop or
appends to, and when an agent's `tools` is appended to after
construction (see `controlloop.adapters.python_registration`).
Recognizing the pattern is adapter work, out of this rule's reach by
architecture (a rule reads only `RuleContext` -- an already-validated
ACBOM, optional diff, optional manifest -- never raw repository
content). This rule's job is narrower and adapter-agnostic: given an
ACBOM that already contains such a diagnostic, surface it as a
policy-level finding rather than leaving it buried in `diagnostics`.
`tests/acbom/test_completeness.py` asserts the finding end to end
through `scan`. Statically enumerable registration
produces no finding, because this rule never fires from a node's mere
existence or low confidence alone -- only from the presence of the
specific `INCOMPLETE-DYNAMIC-REGISTRATION` diagnostic code.

**Two output layers, the same pattern the sibling rules use:**
`evaluate()`'s `RuleObservation`s are built directly from every
matching `Diagnostic` in `context.acbom.diagnostics` -- comprehensive,
no agent attribution required, so every diagnostic is reported
unconditionally. `findings()` is narrower by necessity:
`Finding.affected_agent` and `Finding.capability_path` are both
required, and a bare `Diagnostic` carries neither -- it names no node
or agent at all, deliberately, since "an unresolved reference" or "a
dynamic registration" is exactly the case where no concrete identity
is known. `findings()` therefore correlates a diagnostic to a real,
already-discovered node: a `TOOL` node at `Confidence.UNKNOWN` whose
own evidence shares a `(path, line_start)` location with a
dynamic-registration diagnostic, reached by at least one `invokes`
edge from an agent (giving a valid one-hop `CapabilityPath` via
`compute_direct_capability_paths`). A dynamic-registration diagnostic
with no correlated node at all (the adapter recorded only the
diagnostic, no placeholder node) is still fully covered by
`evaluate()`'s `RuleObservation`s -- a finding naming the location --
just not materializable as a `Finding` under the current schema
without a node to attribute it to."""

from __future__ import annotations

from controlloop.acbom.models import Confidence, Diagnostic, Node, NodeType
from controlloop.capability.compute import compute_direct_capability_paths
from controlloop.findings.models import (
    Finding,
    FindingSeverity,
    finding_from_observation,
)
from controlloop.policy.models import Rule, RuleContext, RuleObservation
from controlloop.policy.rules._shared import documentation_url, node_change_state

RULE_ID = "policy.unresolved-dynamic-registration"
_RULE_VERSION = "1.0.0"
_DOCUMENTATION_URL = documentation_url(RULE_ID)

_DYNAMIC_REGISTRATION_CODE = "INCOMPLETE-DYNAMIC-REGISTRATION"


def _dynamic_registration_diagnostics(context: RuleContext) -> tuple[Diagnostic, ...]:
    return tuple(
        sorted(
            (
                diagnostic
                for diagnostic in context.acbom.diagnostics
                if diagnostic.code == _DYNAMIC_REGISTRATION_CODE
            ),
            key=lambda diagnostic: (
                diagnostic.evidence[0].path or "",
                diagnostic.message,
            ),
        )
    )


def _observation_message(diagnostic: Diagnostic) -> str:
    return (
        f"{diagnostic.message} ControlLoop cannot enumerate what this code "
        "registers; this location is reported as an unknown, never as a pass."
    )


def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]:
    """One `RuleObservation` per `INCOMPLETE-DYNAMIC-REGISTRATION`
    diagnostic already present in `context.acbom.diagnostics`, naming the
    location from the diagnostic's own evidence. Completeness participation
    holds by construction: this rule only ever fires from a diagnostic that
    is already `incomplete=True` and already part of
    `context.acbom.diagnostics`, so
    `controlloop.acbom.completeness.completeness_summary` already reports it
    independent of this rule. A diagnostic with any other code -- including
    an ordinary, statically enumerable discovery -- never produces an
    observation here."""

    return tuple(
        RuleObservation(
            rule_id=RULE_ID,
            message=_observation_message(diagnostic),
            evidence=diagnostic.evidence,
        )
        for diagnostic in _dynamic_registration_diagnostics(context)
    )


RULE = Rule(id=RULE_ID, evaluate=evaluate)


def _dynamic_registration_locations(
    context: RuleContext,
) -> frozenset[tuple[str, int | None]]:
    locations: set[tuple[str, int | None]] = set()
    for diagnostic in _dynamic_registration_diagnostics(context):
        for evidence in diagnostic.evidence:
            if evidence.path is not None:
                locations.add((evidence.path, evidence.line_start))
    return frozenset(locations)


def _is_unresolved_dynamic_registration(
    node: Node, locations: frozenset[tuple[str, int | None]]
) -> bool:
    if node.confidence is not Confidence.UNKNOWN:
        return False
    return any(
        (evidence.path, evidence.line_start) in locations
        for evidence in node.evidence
        if evidence.path is not None
    )


def findings(
    context: RuleContext,
    *,
    rule_version: str = _RULE_VERSION,
    documentation_url_value: str = _DOCUMENTATION_URL,
) -> tuple[Finding, ...]:
    """The `Finding`-producing counterpart to `evaluate()` (see this
    module's own docstring for the disclosed node-correlation
    boundary)."""

    locations = _dynamic_registration_locations(context)
    if not locations:
        return ()

    node_by_id = {node.id: node for node in context.acbom.nodes}
    paths = compute_direct_capability_paths(context.acbom.nodes, context.acbom.edges)

    results: list[Finding] = []
    for path in paths:
        if path.target_type is not NodeType.TOOL:
            continue
        target = node_by_id.get(path.target_id)
        if target is None or not _is_unresolved_dynamic_registration(target, locations):
            continue
        observation = RuleObservation(
            rule_id=RULE_ID,
            message=(
                f"{target.name!r} is registered dynamically and could not be "
                "resolved statically; ControlLoop cannot enumerate what this "
                "code registers"
            ),
            evidence=target.evidence,
        )
        results.append(
            finding_from_observation(
                observation,
                rule_version=rule_version,
                severity=FindingSeverity.MEDIUM,
                confidence=Confidence.UNKNOWN,
                affected_agent=path.agent_id,
                capability_path=path,
                change_state=node_change_state(context.diff, target.id),
                remediation=(
                    "replace dynamic tool registration with a statically "
                    "enumerable declaration, or document the registration "
                    "surface so it can be reviewed manually"
                ),
                documentation_url=documentation_url_value,
            )
        )

    return tuple(sorted(results, key=lambda finding: finding.id))


__all__ = [
    "RULE",
    "RULE_ID",
    "evaluate",
    "findings",
]
