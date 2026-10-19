"""Evidence artifact.

`EvidenceArtifact` is a single retainable artifact that fully explains
a gate verdict after the fact, without access to the source
repository. Like `controlloop.reporting.report.ScanReport`, it
composes already-computed pieces; it computes none of them itself:

- `acbom_digest` -- the current scan's own `ACBOMDocument.digest`.
- `baseline_digest`/`baseline_provenance` -- `BaselineDocument.digest`/
  `.provenance` of whichever baseline the comparison used, or both `None`
  when no baseline was used at all.
- `effective_authority_diff` -- the raw
  `controlloop.diff.models.EffectiveAuthorityChange` tuple
  `diff_effective_authority` produces, distinct from `ScanReport`'s
  higher-level `MaterialChangeSummary` -- this artifact names the
  granular fact-level diff, not its material reclassification. `None`
  exactly when `baseline_digest` is `None`: a diff cannot exist
  without a baseline to compare against (enforced below).
- `findings` (`controlloop.findings`): `None` means no policy was
  evaluated at all, distinct from a real, empty `findings=()` -- the
  same "Unknown, never omitted" distinction `ScanReport` already draws
  for the identical reason.
- `completeness` -- the raw completeness diagnostic tuple
  (`controlloop.acbom.completeness.completeness_summary`'s own return
  shape), not a derived boolean: "completeness state" is the state
  itself, not a summary of it.
- `completeness_enforcement`/`completeness_enforcement_source`: the
  resolved `CompletenessEnforcement` setting that decided whether
  `completeness` alone could produce `verdict=review_required` below,
  and which of `controlloop.config`'s four precedence tiers supplied
  it -- the same `PolicyConfig` field pair
  `controlloop.policy.thresholds.resolve_policy_config` already
  resolves for `severity_threshold`/`low_confidence_action`. Both
  fields carry real, sensible defaults
  (`CompletenessEnforcement.WARN`/`ConfigSource.DEFAULT`) -- see "Why
  the schema version is 1.1.0, not 1.0.0" below.
- `suppressions`
  (`controlloop.policy.suppressions.SuppressionRecord`): every
  declared repo-local suppression's own disposition, the identical
  shape and "always present, never hidden" guarantee
  `controlloop.reporting.report.ScanReport.suppressions` now carries
  -- see that module's own docstring for the full field contract.
  `gate` computes this the same way `scan` does, via
  `controlloop.policy.suppressions.apply_suppressions`, before ever
  calling `evaluate_gate`.
- `verdict` (`controlloop.reporting.terminal.Verdict`): deciding which
  applies is `gate`'s job.
- `versions` (`EvidenceVersions`, below).

`controlloop gate` is the real CLI command that produces one of these, on
every run that reaches a verdict, including a failing one -- see
`docs/reference/cli.md#gate`.

## Why the schema version is 1.1.0, not 1.0.0

Schema 1.1.0 adds two new fields, `completeness_enforcement` and
`completeness_enforcement_source`, to `EvidenceArtifact`. Per
`docs/reference/schema-versioning.md`, a backward-compatible addition
is a MINOR bump -- the identical reasoning, and the identical
precedent,
`controlloop.baseline.models.CURRENT_BASELINE_SCHEMA_VERSION`'s own
1.0.0 -> 1.1.0 bump already established for this codebase. Both new
fields carry real defaults (`CompletenessEnforcement.WARN`,
`ConfigSource.DEFAULT`) so a genuinely older 1.0.0 evidence document --
one written before this field existed -- remains readable by this 1.1.0
model: the two fields simply resolve to their defaults, never a raw
`extra_forbidden`/missing-field error, matching every other model here
that declares `extra="forbid"`.

## Why the schema version is 1.2.0, not 1.1.0

Schema 1.2.0 changes `suppressions`'s element type from a plain,
always-empty `tuple[str, ...]` placeholder to a real
`tuple[SuppressionRecord, ...]` -- the identical change, and the
identical "no real published document could ever be made unreadable by
this" reasoning, `controlloop.reporting.report.ScanReport`'s own 1.0.0
-> 1.1.0 bump documents for the same field on that sibling model. See
that module's own docstring, "Why the schema version is 1.1.0, not
1.0.0," for the full rationale.

## Why the schema version is 1.3.0, not 1.2.0

Schema 1.3.0 adds one field, `team`, carrying the organization policy
version, the repository delta, the effective policy, and every applied
exception -- the inputs that make a *Team* verdict re-derivable, the same
way the fields above make a Community verdict re-derivable.

A MINOR bump by the same rule as the two above: the field defaults to
`None`, so every 1.0.0, 1.1.0, and 1.2.0 evidence document ever written
remains readable by this model despite its `extra="forbid"` config.
`None` is also a real, meaningful value here rather than a placeholder --
it is what a Community gate records, and it means "no organization policy
participated in this verdict," which is exactly what a reader needs to
know about such a run.

## Why the schema version is 1.4.0, not 1.3.0

Schema 1.4.0 adds `authority_delta`, the same section
`controlloop.reporting.report.ScanReport` gained in its 1.2.0: every
grant the change hands an agent, as one plain-language statement each.
A MINOR bump by the same rule: optional, and left out of the
serialized artifact when there is no delta.

## Why the schema version is 1.5.0, not 1.4.0

Schema 1.5.0 extends the `team` block: each approved entry carries its
package, version-range, digest, command-pattern, and pin constraints, and
the block gains `approved_components_digest`, `sanction_judgments`, and
`sanction_note`. All are optional with defaults, so every earlier artifact
still reads -- a MINOR bump.
"""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from controlloop.acbom.models import (
    Diagnostic,
    Generator,
    SemanticVersion,
    Sha256Digest,
)
from controlloop.baseline.models import ApprovalProvenance
from controlloop.config import ConfigSource
from controlloop.diff.models import EffectiveAuthorityChange
from controlloop.findings.models import Finding
from controlloop.policy.suppressions import SuppressionRecord
from controlloop.policy.thresholds import CompletenessEnforcement
from controlloop.reporting.authority import AuthorityDelta
from controlloop.reporting.terminal import Verdict
from controlloop.team.evidence import TeamEvidence

CURRENT_EVIDENCE_SCHEMA_VERSION = "1.5.0"


class _EvidenceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class EvidenceVersions(_EvidenceModel):
    """All component versions: every versioned contract this
    artifact's content depends on, kept as its own model (not a reuse
    of `controlloop.reporting.report.ReportVersions`) so a future
    breaking change to the report schema and to this evidence schema
    remain independent events, the same reasoning
    `BaselineDocument.acbom_schema_version` already documents for
    recording the ACBOM schema version separately from its own."""

    scanner: Generator
    acbom_schema_version: SemanticVersion
    baseline_schema_version: SemanticVersion | None = None
    evidence_schema_version: SemanticVersion
    policy_version: str | None = None


class EvidenceArtifact(_EvidenceModel):
    """The complete evidence artifact. See this module's own docstring
    for why each field is accepted rather than computed here."""

    schema_version: SemanticVersion
    acbom_digest: Sha256Digest
    baseline_digest: Sha256Digest | None
    baseline_provenance: ApprovalProvenance | None
    effective_authority_diff: tuple[EffectiveAuthorityChange, ...] | None
    #: Omitted from the serialized artifact when `None`.
    authority_delta: AuthorityDelta | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    findings: tuple[Finding, ...] | None
    completeness: tuple[Diagnostic, ...]
    completeness_enforcement: CompletenessEnforcement = CompletenessEnforcement.WARN
    completeness_enforcement_source: ConfigSource = ConfigSource.DEFAULT
    suppressions: tuple[SuppressionRecord, ...] = ()
    #: `None` on every Community run, and that is a fact worth recording
    #: rather than an absence: it means no organization policy
    #: participated in this verdict. See
    #: `controlloop.team.evidence.TeamEvidence` for what it carries when
    #: a Team gate produced the verdict, and this module's docstring for
    #: why adding it is a MINOR bump.
    team: TeamEvidence | None = None
    verdict: Verdict
    versions: EvidenceVersions

    @model_validator(mode="after")
    def _validate_diff_requires_a_baseline(self) -> Self:
        """A diff cannot exist without a baseline to compare against
        -- `baseline_digest` and `effective_authority_diff` are both
        `None` or both present, never one without the other. This is
        deliberately not asserted for `baseline_provenance`: a real
        baseline legitimately has no provenance (any baseline
        predating schema 1.1.0, or one where it was never supplied),
        so `baseline_provenance=None` alongside a real
        `baseline_digest` is an ordinary, valid state -- see
        `controlloop.baseline.provenance.describe_provenance`'s own
        docstring for the identical reasoning."""

        if (self.baseline_digest is None) != (self.effective_authority_diff is None):
            raise ValueError(
                "baseline_digest and effective_authority_diff must both be "
                "None or both be present -- a diff cannot exist without a "
                "baseline to compare against"
            )
        return self
