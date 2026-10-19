"""Immutable data shapes for the deterministic rule engine.

Pure data only, no evaluation logic -- mirrors `controlloop.diff.models`'s
own split from `controlloop.diff.compute`: this module is not itself
structurally checked for forbidden imports (there is nothing here that
could perform a file write, subprocess call, network access, or model
invocation), `controlloop.policy.engine` is.

`Rule` and `RuleContext` are plain frozen dataclasses, not Pydantic
models, because neither is ever serialized: `Rule` carries a `Callable`,
which is not itself data, and `RuleContext` is an in-memory bundle
assembled fresh for one `evaluate()` call, the same role
`controlloop.repository.TraversalBounds` and
`controlloop.baseline.merge_base.MergeBaseResolution` already play for
their own non-serialized, in-memory-only structures.

`RuleObservation` and `EvaluationResult` are Pydantic models
(`extra="forbid", frozen=True, strict=True`, matching every other
canonical/computed-report model in this codebase) because they are
this engine's actual output and may be serialized by a future caller.

`RuleObservation` is deliberately not named `Finding`: the real
finding model (rule identifier, rule version, severity, confidence,
affected agent, capability path, change state, remediation text,
documentation URL) is `controlloop.findings.models.Finding`, which
depends on this module rather than the reverse and wraps this type
(`finding_from_observation`). `RuleObservation` is the minimum shape
needed to prove that order cannot affect the result and that identical
input produces identical, identically ordered output -- `rule_id`, a
message, and evidence, reusing the ACBOM's own
`Evidence`/`EvidenceCollection` type rather than inventing a second
evidence shape.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import (
    ACBOMDocument,
    Diagnostic,
    EvidenceCollection,
    SafeIdentifier,
    SafeText,
)
from controlloop.diff.authority import AuthorityDelta
from controlloop.diff.models import DiffResult
from controlloop.manifest.models import ManifestDocument
from controlloop.team.sanction import ApprovedEntry


class _PolicyModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class RuleObservation(_PolicyModel):
    """One rule's own report that something in `RuleContext` is worth
    surfacing. Deliberately minimal -- see this module's own docstring
    for why this is not the finding model."""

    rule_id: SafeIdentifier
    message: SafeText
    evidence: EvidenceCollection


class EvaluationResult(_PolicyModel):
    """The complete result of one
    `controlloop.policy.engine.evaluate()` call: every collected
    `RuleObservation`, deterministically ordered regardless of rule
    execution order, plus any diagnostics this engine itself produced
    (currently only `INCOMPLETE-BOUND-EXCEEDED`, reusing
    `controlloop.acbom.completeness`'s existing registry code
    unchanged)."""

    observations: tuple[RuleObservation, ...]
    diagnostics: tuple[Diagnostic, ...]

    @property
    def is_incomplete(self) -> bool:
        """`True` exactly when a configured bound stopped this
        evaluation before it could consider every rule or retain every
        observation -- derived from `diagnostics` rather than stored
        redundantly, the same pattern
        `controlloop.acbom.completeness.completeness_summary` already
        uses for an `ACBOMDocument`'s own diagnostics."""

        return any(diagnostic.incomplete for diagnostic in self.diagnostics)


@dataclass(frozen=True, slots=True)
class RuleContext:
    """The explicit evidence and explicit policy one `evaluate()` call
    exposes to every rule (a rule reads only what is bundled here;
    nothing here grants file, process, network, or model access).

    `acbom` is the complete canonical evidence a rule may read, reused
    whole rather than unpacked into loose `nodes`/`edges` parameters.
    `diff` and `manifest` are optional: not every rule needs a
    baseline comparison or a parsed `controlloop.yaml` to evaluate.
    `policy_version` is an opaque, caller-supplied identifier -- this
    module does not define what produces it or what format it takes;
    the engine's only obligation regarding it is determinism, proven
    by threading it through unchanged.
    """

    acbom: ACBOMDocument
    policy_version: SafeText
    diff: DiffResult | None = None
    manifest: ManifestDocument | None = None
    #: The organization's effective approved list, on a Team gate run only.
    #: `None` on every Community run.
    sanction: SanctionContext | None = None


@dataclass(frozen=True, slots=True)
class SanctionContext:
    """What `policy.unsanctioned-agent-component` judges against.

    `approved` is the effective approved-components list after the
    strengthen-only merge, or `None` when no published policy bundle
    governs the project -- then nothing is judged (`unevaluated`),
    which is never a pass that implies approval. `delta` is the run's
    authority delta: the grants a change adds or changes.
    """

    approved: tuple[ApprovedEntry, ...] | None
    organization_bundle_version: str
    delta: AuthorityDelta | None


@dataclass(frozen=True, slots=True)
class Rule:
    """One rule: a stable, namespaced identifier paired with a pure
    function. Not a class hierarchy -- a future rule author writes one
    ordinary function,
    `def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]`,
    and wraps it here; nothing requires subclassing anything, matching
    the preference for pure functions over object hierarchies in this
    codebase's identity, normalization, diff, and policy behavior."""

    id: SafeIdentifier
    evaluate: Callable[[RuleContext], tuple[RuleObservation, ...]]
    #: Whether this rule reads coding-agent host authority. `False`,
    #: the default, gives the rule a view of the evidence without
    #: agent-authority components; see
    #: `controlloop.policy.authority_scope`. Not part of the rule-pack
    #: fingerprint, which digests the rule's id, `evaluate` source,
    #: and mandatory flag only.
    reads_agent_authority: bool = False


@dataclass(frozen=True, slots=True)
class EvaluationBounds:
    """Configurable resource bounds for
    `controlloop.policy.engine.evaluate`. Both are deterministic,
    count-based proxies -- not wall-clock -- for "bounded in time"
    (`max_rules`: this engine controls exactly how many rules it
    invokes) and "bounded in memory" (`max_observations`: a global,
    cumulative cap on retained output, the same role
    `TraversalBounds.max_total_bytes` plays for repository traversal).
    Defaults are generous, disclosed starting points, not approved
    business thresholds -- every value is overridable per call,
    mirroring `TraversalBounds`'s own precedent and disclaimer.

    Does not, and cannot, preempt a single rule's own unbounded
    internal loop -- see `controlloop.policy.engine`'s module
    docstring for why that limitation is accepted rather than solved
    with a wall-clock or subprocess-based timeout.
    """

    max_rules: int = 1_000
    max_observations: int = 10_000

    def __post_init__(self) -> None:
        for field_name, value in (
            ("max_rules", self.max_rules),
            ("max_observations", self.max_observations),
        ):
            if value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


class RuleSafetyError(RuntimeError):
    """Raised when a rule cannot be verified free of forbidden
    imports, or has no resolvable source module at all. The message
    names only the rule's own `id` and the offending import or module
    name -- both code-level identifiers, never raw repository content
    -- so this is always safe to echo directly."""


class DuplicateRuleIdError(ValueError):
    """Raised when two `Rule`s supplied to the same `evaluate()` call
    share an `id`. The message names the duplicate `id` itself, a
    `SafeIdentifier`-constrained value, safe to echo directly (the
    same reasoning `ManifestDocument.validate_at_most_one_ceiling_per_scope`
    already relies on for its own duplicate-scope error)."""
