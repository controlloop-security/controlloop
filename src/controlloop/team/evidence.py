"""The Team block of the evidence artifact.

`EvidenceArtifact` exists so a verdict stays re-derivable months later
without the source repository. When a verdict was decided partly by an
organization's policy bundle and its exceptions, re-deriving it needs
those inputs recorded too -- otherwise the artifact explains a local
decision and stays silent about the half that came from the platform.

So a Team gate records: the organization bundle version, the merge
semantics version that combined it with repository policy, the repository
delta as it was sent, the effective policy that resulted, every rejection
the merge produced, every exception and its disposition, and the
entitlement state at the time.

Each rule in the effective policy records its `action` when it has one,
and `finding_actions` records, for every finding, the action the gate
took on it and whether that came from the organization's rule or from
the severity threshold.

It also records the sanctioned-list inputs and outputs: each approved
entry with its package, version-range, digest, command-pattern, and
pin constraints, `approved_components_digest` over the effective list,
every sanction judgment of the authority delta with the bundle version
that judged it, and `sanction_note`, which says `unevaluated` when no
published bundle governs the project rather than leaving a reader to
infer a pass.

## Why these are models here rather than the merge's own dataclasses

`controlloop.team.policy` works in frozen dataclasses because the merge is
a hot, pure function that revalidates nothing. `EvidenceArtifact` embeds
only Pydantic models with one shared serialization and validation
discipline (`extra="forbid"`, `frozen=True`, `strict=True`) -- the same
reason `SuppressionRecord` is a model rather than a dataclass. These are
the conversion at that boundary, and `from_merge` is the one place it
happens.

## What is deliberately not recorded

The project token, the endpoint, the organization and project
identifiers. None of them explain a verdict, and an evidence artifact is
a file people attach to tickets and audits. The bundle *version* is what
makes a verdict re-derivable; the tenant's identifiers are not.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from controlloop.team.components import DeltaJudgment
from controlloop.team.exceptions import ExceptionRecord
from controlloop.team.policy import (
    ApprovedComponentSpec,
    MergeRejection,
    MergeResult,
    RuleSpec,
)

#: The note recorded when no published bundle governs the project.
UNEVALUATED_NOTE = (
    "unevaluated: no published organization policy bundle governs this "
    "project, so no agent-authority grant was judged against an approved "
    "list. This is not an approval."
)


class _TeamEvidenceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, strict=True
    )


class PolicyRuleRecord(_TeamEvidenceModel):
    """One rule as the effective policy configured it."""

    rule_id: str
    enabled: bool
    severity_floor: str | None = None
    mandatory: bool = False
    #: Omitted when the rule has none, so a bundle without actions records
    #: exactly what it did before.
    action: str | None = Field(default=None, exclude_if=lambda value: value is None)

    @classmethod
    def from_spec(cls, spec: RuleSpec) -> PolicyRuleRecord:
        return cls(
            rule_id=spec.rule_id,
            enabled=spec.enabled,
            severity_floor=spec.severity_floor,
            mandatory=spec.mandatory,
            action=spec.action,
        )


class FindingActionRecord(_TeamEvidenceModel):
    """The action a Team gate took on one finding.

    `action` is one of `fail`, `require_review`, `warn`, `pass`. `source`
    is `organization` when the rule's organization `action` decided it,
    and `severity_threshold` when the rule has none and the finding's
    severity against `severity_threshold` did. Recorded for a finding a
    suppression or exception kept out of the verdict too; those records
    say why it did not count.
    """

    finding_id: str
    rule_id: str
    action: str
    source: str


class ApprovedComponentRecord(_TeamEvidenceModel):
    """One approved-component entry in the effective policy, with the
    package, version-range, digest, command-pattern, and pin
    constraints it carries."""

    type: str
    name_pattern: str
    package: str | None = None
    version_range: str | None = None
    digest: str | None = None
    command_pattern: str | None = None
    pin_required: bool | None = None

    @classmethod
    def from_spec(cls, spec: ApprovedComponentSpec) -> ApprovedComponentRecord:
        return cls(
            type=spec.type,
            name_pattern=spec.name_pattern,
            package=spec.package,
            version_range=spec.version_range,
            digest=spec.digest,
            command_pattern=spec.command_pattern,
            pin_required=spec.pin_required,
        )


class SanctionJudgmentRecord(_TeamEvidenceModel):
    """How the effective approved list judged one authority-delta
    grant. `failed_constraint` names why an unsanctioned grant was not
    covered: `name` when no entry has its type and name, otherwise the
    first constraint the closest entry's grant did not meet."""

    component_stable_id: str
    component_type: str
    component_name: str
    state: str
    failed_constraint: str | None = None
    judged_by_policy_version: str

    @classmethod
    def from_judgment(
        cls, judged: DeltaJudgment, *, policy_version: str
    ) -> SanctionJudgmentRecord:
        return cls(
            component_stable_id=judged.node.id,
            component_type=judged.component.type,
            component_name=judged.component.name,
            state=judged.judgment.state.value,
            failed_constraint=judged.judgment.failed,
            judged_by_policy_version=policy_version,
        )


def approved_components_digest(entries: Iterable[ApprovedComponentSpec]) -> str:
    """A stable digest of the effective approved list: sorted entries,
    absent constraints left out, compact JSON."""

    canonical = json.dumps(
        sorted(
            (entry.to_mapping() for entry in entries),
            key=lambda item: (str(item["type"]), str(item["name_pattern"])),
        ),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PolicyRejectionRecord(_TeamEvidenceModel):
    """One weakening the merge refused.

    Recorded even though a rejection means the gate did not enforce the
    repository's requested policy: "what was asked for and refused" is
    part of explaining what was enforced.
    """

    rule_id: str
    organization_bundle_version: str
    reason: str

    @classmethod
    def from_rejection(cls, rejection: MergeRejection) -> PolicyRejectionRecord:
        return cls(
            rule_id=rejection.rule_id,
            organization_bundle_version=rejection.organization_bundle_version,
            reason=rejection.reason,
        )


class TeamEvidence(_TeamEvidenceModel):
    """Everything the platform contributed to one verdict.

    `policy_source` says where the effective policy came from: `fetched`
    for a live read, `cache` for a fresh cached copy, `stale_cache` for a
    copy used past its lifetime because the service was unreachable and
    `team_fail_mode` is `open`. That distinction belongs in evidence: a
    verdict decided against a three-day-old bundle is a different fact
    from one decided against the current bundle, and an auditor should not
    have to infer which happened.
    """

    organization_bundle_version: str
    merge_semantics_version: str
    policy_source: str
    entitlement_state: str
    repository_delta: tuple[PolicyRuleRecord, ...] = ()
    effective_policy: tuple[PolicyRuleRecord, ...] = ()
    approved_components: tuple[ApprovedComponentRecord, ...] = ()
    approved_components_digest: str | None = None
    rejections: tuple[PolicyRejectionRecord, ...] = ()
    applied_exceptions: tuple[ExceptionRecord, ...] = ()
    sanction_judgments: tuple[SanctionJudgmentRecord, ...] = ()
    sanction_note: str | None = None
    finding_actions: tuple[FindingActionRecord, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )

    @classmethod
    def from_merge(
        cls,
        *,
        merge: MergeResult,
        organization_bundle_version: str,
        merge_semantics_version: str,
        policy_source: str,
        entitlement_state: str,
        repository_delta: tuple[RuleSpec, ...] = (),
        exception_records: tuple[ExceptionRecord, ...] = (),
        judgments: tuple[DeltaJudgment, ...] = (),
        finding_actions: tuple[FindingActionRecord, ...] = (),
    ) -> TeamEvidence:
        """Build the block from an already-computed merge.

        Composes; computes nothing. That is the same contract
        `EvidenceArtifact` itself keeps with its own inputs.
        """

        return cls(
            organization_bundle_version=organization_bundle_version,
            merge_semantics_version=merge_semantics_version,
            policy_source=policy_source,
            entitlement_state=entitlement_state,
            repository_delta=tuple(
                PolicyRuleRecord.from_spec(spec) for spec in repository_delta
            ),
            effective_policy=tuple(
                PolicyRuleRecord.from_spec(spec) for spec in merge.rules
            ),
            approved_components=tuple(
                ApprovedComponentRecord.from_spec(spec)
                for spec in merge.approved_components
            ),
            approved_components_digest=approved_components_digest(
                merge.approved_components
            ),
            rejections=tuple(
                PolicyRejectionRecord.from_rejection(rejection)
                for rejection in merge.rejections
            ),
            applied_exceptions=exception_records,
            sanction_judgments=tuple(
                SanctionJudgmentRecord.from_judgment(
                    judged, policy_version=organization_bundle_version
                )
                for judged in judgments
            ),
            sanction_note=None if organization_bundle_version else UNEVALUATED_NOTE,
            finding_actions=finding_actions,
        )
