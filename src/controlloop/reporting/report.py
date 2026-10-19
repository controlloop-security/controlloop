"""Stable JSON report envelope.

`ScanReport` composes already-computed pieces into one machine-readable
report, the same discipline `controlloop.reporting.terminal` already
follows for the human-readable rendering of the same content -- this
model computes none of them itself:

- `verdict` (`controlloop.reporting.terminal.Verdict`): deciding *which* of
  the five canonical outcomes applies is `gate`'s job.
- `blast_radius` (`controlloop.capability.blast_radius`).
- `material_changes` (`controlloop.diff.material_summary`): `None`
  means no baseline comparison was attempted at all, distinct from a
  real, successfully computed summary that happens to be empty -- the
  same "Unknown, never omitted" distinction
  `controlloop.reporting.terminal` already draws for the identical
  reason.
- `findings` (`controlloop.findings`): `None` means no policy was evaluated
  at all, distinct from a real, empty `findings=()`.
- `diagnostics` (`controlloop.acbom.models.Diagnostic`): every
  analysis diagnostic accumulated across the whole run. `incomplete`
  (the "completeness state") is a derived property,
  `bool(self.diagnostics)`, rather than a second stored field a caller
  could set inconsistently with `diagnostics` itself.
- `suppressions` (`controlloop.policy.suppressions.SuppressionRecord`):
  every declared repo-local suppression's own disposition -- `active`,
  `expired`, `stale`, or `ceiling-protected` -- always present ("never
  hidden"), computed by
  `controlloop.policy.suppressions.apply_suppressions` and supplied
  unchanged here, the same "pure envelope" discipline every other field
  on this model already follows. Empty when a repository declares no
  suppressions at all, which is not the same as "suppressions were not
  evaluated" -- this field, unlike `findings`/`material_changes`, has no
  `None`/not-evaluated state, because `scan`/`gate` always evaluate
  suppressions (against a possibly-empty declared set) whenever they run
  at all.
- `versions` (`ReportVersions`, below): the scanner's own identity
  plus every versioned contract this report's content depends on.

`controlloop scan` produces one of these on every successful run;
`controlloop gate` composes the richer `EvidenceArtifact` instead
(`controlloop.reporting.evidence`), not this type directly.

"Byte for byte diffable" holds without any dedicated canonicalization
step here: `model_dump_json()` on a Pydantic v2 model already
serializes fields in class-declaration order, deterministically,
matching every other computed-report model in this codebase
(`controlloop.diff.report.DiffReport`,
`controlloop.diff.material_summary.MaterialChangeSummary`). This model
performs no sorting of its own `findings`/`diagnostics` tuples --
supplying them in a canonical order is the responsibility of whichever
future caller assembles a `ScanReport`, the same "pure envelope, not a
compute step" precedent `render_terminal_report` already established
for the identical four (plus diagnostics/versions/suppressions)
pieces. `suppressions` is the one exception: `controlloop.cli`'s
`scan`/`gate` always supply it already sorted, since
`apply_suppressions`'s own return contract already guarantees a
deterministic `(rule_id, target)` order.

## Why the schema version is 1.1.0, not 1.0.0

Schema 1.1.0 changes `suppressions`'s element type from a plain,
always-empty `tuple[str, ...]` placeholder to a real
`tuple[SuppressionRecord, ...]`. Per
`docs/reference/schema-versioning.md`, changing an existing field's
type is ordinarily a MAJOR, breaking change. This one is treated as
MINOR instead, for the same reason the evidence artifact's 1.1.0
treated two brand-new `EvidenceArtifact` fields as MINOR: no release of
ControlLoop has ever been published
(`docs/reference/release-pipeline.md`), so no real external reader has
ever parsed a `ScanReport` with a populated `suppressions` field --
every `ScanReport` ever produced before this change had
`suppressions=()`, and every `ScanReport` this change produces still
defaults to `suppressions=()` when a repository declares none. There is
no real document in existence whose `suppressions` field this change
could make unreadable.

## Why the schema version is 1.2.0, not 1.1.0

Schema 1.2.0 adds `authority_delta`
(`controlloop.reporting.authority.AuthorityDelta`): every grant the
change hands an agent, as one plain-language statement each. A MINOR
bump: the field is optional and is left out of the serialized document
entirely when there is no delta, so a 1.1.0 report and a 1.2.0 report
with no agent authority change are the same bytes apart from their
version strings.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from controlloop.acbom.models import Diagnostic, Generator, SemanticVersion
from controlloop.capability.blast_radius import BlastRadiusStatement
from controlloop.diff.material_summary import MaterialChangeSummary
from controlloop.findings.models import Finding
from controlloop.policy.suppressions import SuppressionRecord
from controlloop.reporting.authority import AuthorityDelta
from controlloop.reporting.terminal import Verdict

CURRENT_REPORT_SCHEMA_VERSION = "1.2.0"


class _ReportModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class ReportVersions(_ReportModel):
    """The report's versions: the scanner's own identity (`Generator`,
    matching the ACBOM envelope's own field of the same shape) plus
    every versioned contract this report's content depends on, so a
    consumer can tell exactly which schema and policy generation to
    expect without inferring it from content shape."""

    scanner: Generator
    acbom_schema_version: SemanticVersion
    report_schema_version: SemanticVersion
    policy_version: str | None = None


class ScanReport(_ReportModel):
    """The complete machine-readable report envelope. See this
    module's own docstring for why each field is accepted rather than
    computed here."""

    schema_version: SemanticVersion
    verdict: Verdict
    blast_radius: BlastRadiusStatement | None
    #: Omitted from the serialized report when `None`.
    authority_delta: AuthorityDelta | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    material_changes: MaterialChangeSummary | None
    findings: tuple[Finding, ...] | None
    diagnostics: tuple[Diagnostic, ...]
    suppressions: tuple[SuppressionRecord, ...] = ()
    versions: ReportVersions

    @property
    def incomplete(self) -> bool:
        """The "completeness state": `True` whenever any diagnostic
        was recorded anywhere during analysis. Derived rather than
        stored, so it can never drift out of sync with `diagnostics`
        itself -- the same discipline `MaterialChangeSummary.is_empty`
        already follows for its own `changes` tuple."""

        return bool(self.diagnostics)
