"""Immutable canonical model for a finding.

`controlloop.policy.engine.evaluate` reports a
`RuleObservation` per rule: a rule ID, a message, and evidence -- the
minimum shape needed to prove that engine's own ordering and
determinism guarantees. `Finding`, defined here, is what a
`RuleObservation` becomes once the additional context a rule invocation
carries (severity, confidence, which agent, which capability path,
change state against a baseline, remediation guidance, and a
documentation URL) is attached -- "everything a reviewer needs to judge
it without opening the codebase."
`RuleObservation` is unchanged and unimported here beyond
`finding_from_observation`'s own bridge; see that function's docstring.

Scope boundaries disclosed here:

- `FindingSeverity` is a minimal, five-member field-shape enum. No
  ranking, comparison, or configurable threshold exists here -- that is
  `controlloop.policy.thresholds`'s scope, which builds on this model
  rather than duplicating it.
- `rule_version` validates a semantic-version *shape* only. What
  produces it, whether it must increment on behavior change, and how it
  relates to an independently versioned rule pack are
  `controlloop.policy.rulepack`'s decisions.
- `change_state` mirrors `controlloop.diff.models.ChangeKind`'s four
  members one-for-one and adds a fifth, `not-compared`, rather than
  importing or modifying `ChangeKind` itself -- see `FindingChangeState`
  below for why.
- `documentation_url` is validated for shape only and is never fetched.
  A build-time check that a rule's documentation URL resolves is a
  separate, later concern.

`Confidence`, `SafeIdentifier`, `SafeText`, `SemanticVersion`, and
`EvidenceCollection` are reused verbatim from
`controlloop.acbom.models`; `CapabilityPath` is reused verbatim from
`controlloop.capability.models`. Neither source module is modified
here.

## `affected_agent`/`capability_path` are optional (schema `1.1.0`)

Originally both fields were required with no default: "every finding is
inherently agent-scoped." The hardcoded-secret rule found a real,
disclosed counter-example -- a hardcoded secret in a shared file has no
natural single-agent attribution (it may be reachable by zero, one, or
many agents). So both are optional:
`affected_agent: AgentNodeId | None = None` and
`capability_path: CapabilityPath | None = None` (the second is this
codebase's own necessary consequence of the first, not an independent
decision -- `CapabilityPath.agent_id` is itself a required
real agent node ID, so a repository-scoped finding structurally cannot
carry one). A `model_validator` now enforces a three-way rule: both
`None` (repository-scoped, valid), both present and matching
(agent-scoped, valid, the original behavior, unchanged for every
existing rule), or exactly one present (invalid, rejected). This is an
additive, backward-compatible change -- `CURRENT_FINDING_SCHEMA_VERSION`
moves from `"1.0.0"` to `"1.1.0"` (MINOR, per
`docs/reference/schema-versioning.md`'s general vocabulary: a new
optional field, nothing removed, renamed, retyped, or newly rejected).
See `controlloop.findings.identity.finding_id` for how stable identity
is computed in the new agent-less case, and
`controlloop.policy.rules.hardcoded_secrets` for the one rule that
actually constructs a repository-scoped `Finding` today.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Self

from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from controlloop.acbom.models import (
    Confidence,
    EvidenceCollection,
    SafeIdentifier,
    SafeText,
    SemanticVersion,
)
from controlloop.capability.models import CapabilityPath

if TYPE_CHECKING:
    # Deferred to a `TYPE_CHECKING`-only import, not a module-level one
    # -- mirrors `controlloop.policy.thresholds`'s own identical
    # deferred import of this package for the identical reason (see that
    # module's docstring). `controlloop.policy.rulepack` imports
    # `controlloop.policy.rules` to populate `CURRENT_RULE_PACK`, and
    # every rule module in `controlloop.policy.rules` imports
    # `Finding`/`finding_from_observation` from this module -- a
    # module-level import of `controlloop.policy.models` here, which
    # always triggers the full `controlloop.policy` package `__init__`,
    # would close that cycle for real (this module's own `Finding` class
    # not yet being defined when a rule module reaches back in for it).
    # `finding_from_observation`'s only use of `RuleObservation` is a
    # parameter annotation, made a bare string by `from __future__
    # import annotations` above, so no runtime reference is needed.
    from controlloop.policy.models import RuleObservation

CURRENT_FINDING_SCHEMA_VERSION = "1.1.0"

#: A node ID restricted to the `agent` ACBOM node type, since the
#: "affected agent" is always an agent, never any of the other seven
#: node types `controlloop.acbom.models.NodeId`'s own pattern allows.
#: Deliberately a new, narrower type rather than reusing `NodeId`
#: directly, whose pattern is intentionally open across all eight node
#: type prefixes.
AgentNodeId = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^clp:agent:sha256:[0-9a-f]{64}$",
    ),
]

#: The stable finding identifier shape, produced
#: only by `controlloop.findings.identity.finding_id`. A new content-
#: addressed identifier family, `clp:finding:sha256:<hex>`, distinct
#: from `NodeId`/`EdgeId` (both closed to ACBOM graph component
#: prefixes) rather than overloading either.
FindingId = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^clp:finding:sha256:[0-9a-f]{64}$",
    ),
]

#: A documentation URL's validated shape only -- `https://` anchored,
#: no control characters, length-bounded. Never fetched; see this
#: module's own docstring.
DocumentationUrl = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=len("https://x"),
        max_length=2048,
        pattern=r"^https://[^\x00-\x1f\x7f\s]+$",
    ),
]


class _FindingModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class FindingSeverity(StrEnum):
    """The minimal severity scale a finding requires, in ascending
    declared order. No ranking function, comparison operator, or
    configurable gate threshold is defined here -- see this module's
    own docstring, first scope boundary. `controlloop.policy.thresholds`
    owns that policy layer and consumes this same enum rather than
    defining a parallel one."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingChangeState(StrEnum):
    """How the capability this finding concerns classifies against a
    baseline. Mirrors `controlloop.diff.models.ChangeKind`'s
    four members one-for-one (`ADDED`, `REMOVED`, `CHANGED`, `UNKNOWN`)
    without importing or modifying that type, plus one honest fifth
    state: `NOT_COMPARED`.

    `controlloop.policy.models.RuleContext.diff` is `DiffResult | None`
    -- a rule may run with no baseline at all, and every finding must
    still carry a `change_state`.
    Collapsing "no baseline was compared" into `ChangeKind.UNKNOWN`
    would contradict that member's own documented meaning (a specific
    claim about a completed comparison whose confidence dropped, not an
    absent one) and would violate this repository's "unknown, never
    omitted" invariant -- the same reasoning
    `controlloop.diff.report.ComparisonScope` already applied, in the
    same non-invasive way (a new enum layered on top, not a change to
    `controlloop.diff.models`), to keep "not evaluated" distinct from
    "confirmed unchanged"."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNKNOWN = "unknown"
    NOT_COMPARED = "not-compared"


class Finding(_FindingModel):
    """A complete, self-describing security or policy finding. Frozen,
    `extra="forbid"`, `strict=True`, matching every other
    canonical/computed-report model in this codebase.

    Every core field is required with no default, so omitting any of
    them raises `pydantic.ValidationError` at construction rather than
    producing a partially-populated `Finding`; this codebase has no
    custom validation-error wrapper for that guarantee anywhere else
    (`Node`, `Edge`, `Diagnostic`, `RuleObservation` all rely on
    Pydantic's own strict, defaultless required fields), and this model
    follows the same precedent rather than inventing one.

    `message` is included even though the core field list does not
    separately name it: without it, a `Finding` would name a rule and a
    severity but never describe, in words, what was actually found.

    `id` is a required, precomputed field, not derived by a validator
    on this model -- matching `Node.id`/`Edge.id`'s own precedent of
    being precomputed identity material supplied to a frozen model.
    Construct a `Finding` via `finding_from_observation` (below) for
    the common case, which always computes `id` via
    `controlloop.findings.identity.finding_id` first; a caller may also
    construct one directly, supplying an already-computed `id`.
    """

    schema_version: SemanticVersion
    id: FindingId
    rule_id: SafeIdentifier
    rule_version: SemanticVersion
    message: SafeText
    severity: FindingSeverity
    confidence: Confidence
    affected_agent: AgentNodeId | None = None
    evidence: EvidenceCollection
    capability_path: CapabilityPath | None = None
    change_state: FindingChangeState
    remediation: SafeText
    documentation_url: DocumentationUrl

    @model_validator(mode="after")
    def validate_affected_agent_matches_capability_path(self) -> Self:
        """Three valid shapes only:

        - both `None` -- a repository-scoped finding with no single
          affected agent (for example, a hardcoded secret in a shared
          file);
        - both present, with `affected_agent == capability_path.agent_id`
          -- an agent-scoped finding, the original, unchanged behavior;
        - exactly one present is always rejected -- a finding cannot
          name an agent with no capability path explaining how that
          agent is involved, or evidence a capability path while
          claiming to concern no particular agent.
        """

        if (self.affected_agent is None) != (self.capability_path is None):
            raise ValueError(
                "affected_agent and capability_path must both be present "
                "(agent-scoped) or both be omitted (repository-scoped): "
                f"affected_agent={self.affected_agent!r}, "
                "capability_path="
                f"{('present' if self.capability_path is not None else None)!r}"
            )
        if (
            self.affected_agent is not None
            and self.capability_path is not None
            and self.affected_agent != self.capability_path.agent_id
        ):
            raise ValueError(
                "affected_agent must match capability_path.agent_id: "
                f"{self.affected_agent!r} != {self.capability_path.agent_id!r}"
            )
        return self


def finding_from_observation(
    observation: RuleObservation,
    *,
    rule_version: str,
    severity: FindingSeverity,
    confidence: Confidence,
    affected_agent: str | None = None,
    capability_path: CapabilityPath | None = None,
    change_state: FindingChangeState,
    remediation: str,
    documentation_url: str,
    identity_occurrence: str | None = None,
) -> Finding:
    """Build a `Finding` from one `RuleObservation` plus the additional
    context only a caller has: `RuleObservation` itself has no
    concept of severity, confidence, the affected agent, a capability
    path, or remediation guidance -- none of those are inferable from a
    bare rule ID, message, and evidence.

    `rule_id`, `message`, and `evidence` are copied from `observation`
    unchanged. `id` is always computed via
    `controlloop.findings.identity.finding_id` before construction, so
    this is the one call site that guarantees the identity scheme
    and this model's fields never diverge. This is a convenience
    constructor, not the only valid one: a `Finding` may also be built
    directly via `Finding(...)`, supplying an already-computed `id`,
    the same relationship `controlloop.acbom.identity.node_id` has to
    direct `Node(...)` construction.

    `affected_agent`/`capability_path` default to `None`: omitting both
    builds a repository-scoped `Finding`. In that case,
    `observation.evidence`'s own sanitized `path`s become the identity
    anchor `finding_id` uses in place of a capability path -- see that
    function's own docstring for why. Every existing caller that always
    supplies both keeps its original behavior and its original computed
    `id` unchanged.

    `identity_occurrence` is passed to `finding_id` as its `occurrence`
    for a repository-scoped finding, to tell apart several findings of
    one rule in the same file; it is ignored for an agent-scoped one.
    """

    # Imported here, not at module level: `controlloop.findings.identity`
    # imports `FindingId` from this module (mirroring
    # `controlloop.acbom.identity` importing `NodeId`/`EdgeId` from
    # `controlloop.acbom.models`), so a module-level import here would
    # be circular. By the time this function is actually called both
    # modules are already fully loaded.
    from controlloop.findings.identity import finding_id

    evidence_paths = (
        tuple(item.path for item in observation.evidence if item.path is not None)
        if affected_agent is None
        else ()
    )
    identity = finding_id(
        rule_id=observation.rule_id,
        affected_agent=affected_agent,
        capability_path=capability_path,
        evidence_paths=evidence_paths,
        occurrence=identity_occurrence if affected_agent is None else None,
    )
    return Finding(
        schema_version=CURRENT_FINDING_SCHEMA_VERSION,
        id=identity,
        rule_id=observation.rule_id,
        rule_version=rule_version,
        message=observation.message,
        severity=severity,
        confidence=confidence,
        affected_agent=affected_agent,
        evidence=observation.evidence,
        capability_path=capability_path,
        change_state=change_state,
        remediation=remediation,
        documentation_url=documentation_url,
    )
