---
type: reference
title: Stable JSON report format
tags:
  - reference
  - reporting
created: 2026-08-20
---

# Stable JSON report format

**Status: Implemented foundation.** `controlloop.reporting.report`,
described below, and its packaged JSON Schema are implemented and
tested library code. **`controlloop scan --format json` produces one.**
`gate --format json` produces its own `EvidenceArtifact` instead (see
[Evidence artifact format](evidence-artifact-format.md)), never a
`ScanReport`. This page is written and reviewed in the same change as
the behavior it documents.

## What this is

A machine-readable report with a versioned, documented schema that a
consumer can depend on. `ScanReport`
(`controlloop.reporting.report`) is the JSON counterpart to
[the terminal report](terminal-report-format.md): both compose the
same already-computed pieces, but `ScanReport` is the complete
machine-readable envelope `controlloop scan` writes to stdout under
`--format json`, while the terminal renderer produces the
human-oriented text form of a subset of the same content.

## The model

```python
class ScanReport:  # controlloop.reporting.report
    schema_version: str  # SemanticVersion
    verdict: Verdict  # controlloop.reporting.terminal
    blast_radius: BlastRadiusStatement | None
    material_changes: MaterialChangeSummary | None
    findings: tuple[Finding, ...] | None
    diagnostics: tuple[Diagnostic, ...]
    suppressions: tuple[SuppressionRecord, ...] = ()
    versions: ReportVersions

    @property
    def incomplete(self) -> bool: ...  # bool(self.diagnostics)


class ReportVersions:  # controlloop.reporting.report
    scanner: Generator  # name + version
    acbom_schema_version: str
    report_schema_version: str
    policy_version: str | None = None
```

This model computes none of its own content -- see
[Terminal report format](terminal-report-format.md#what-this-is) for
why each piece is accepted rather than recomputed, and the required
field list is satisfied exactly:

- **verdict** -- `Verdict`, unchanged from the terminal renderer.
- **blast-radius statement** -- `blast_radius`.
- **material changes** -- `material_changes`.
- **findings** -- `findings`.
- **completeness state** -- the `incomplete` property, derived from
  `diagnostics` rather than stored separately so it can never drift
  out of sync with the diagnostics it summarizes.
- **suppressions** -- every declared repo-local suppression's own
  disposition (`SuppressionRecord`: `rule_id`, `target`, `reason`,
  `expires_at`, `status`), always present and never hidden --
  `active`, `expired`, `stale`, or `ceiling-protected`. Empty when a repository declares no suppressions at all. See
  [Expiring repo-local suppressions](suppressions.md) for the full
  field contract and matching rules.
- **versions** -- `ReportVersions`.
- **diagnostics** -- `diagnostics`, the raw `Diagnostic` tuple
  `incomplete` is derived from.

## "Not evaluated" versus "confirmed zero" (the completeness invariant)

`material_changes=None` and `findings=None` each mean the corresponding
analysis phase was never attempted at all -- distinct from a real,
successfully computed result that happens to be empty
(`material_changes`'s own `is_empty` property being `True`, or
`findings=()`). This is the same "Unknown, never omitted" distinction
[the terminal renderer](terminal-report-format.md#ordering-and-honest-omission)
already draws for identical reasons, applied here to the JSON
envelope's own optional fields instead of to rendered text lines.

## Published, versioned schema

The current packaged schema is
`src/controlloop/schemas/report/1.2.0/report.schema.json`, a MINOR bump
from `1.1.0` that adds the optional top-level
`authority_delta`, the [authority statement](authority-statement.md).
The field is left out of the document when there is no delta. The
`1.1.0` file is kept unmodified beside it. That version lives at
`src/controlloop/schemas/report/1.1.0/report.schema.json` (a MINOR bump
from `1.0.0`: `suppressions`'s element type changed
from a placeholder `tuple[str, ...]` to a real
`tuple[SuppressionRecord, ...]`; no real report has ever populated that
field with anything but an empty tuple, so no real document is made
unreadable by this change. The prior `1.0.0` file is kept unmodified at
`src/controlloop/schemas/report/1.0.0/report.schema.json`) and is
generated directly from `ScanReport.model_json_schema()` -- unlike the
hand-authored ACBOM schema, this is a disclosed design choice: every
composed model (`BlastRadiusStatement`, `MaterialChangeSummary`,
`Finding`, `Diagnostic`, `ReportVersions`) already declares
`extra="forbid"`, so Pydantic's own generated schema already carries
`additionalProperties: false` at every object level, the same
closed-schema guarantee the hand-authored ACBOM schema enforces by
hand -- at the cost of the ACBOM schema's own hand-written per-field
descriptions. `tests/reporting/generate_report_schema.py` documents
how to regenerate it.

`tests/reporting/test_report_schema.py`:

- Ties the packaged file to a committed SHA-256 digest
  (`test_packaged_schema_matches_its_golden_digest`), the same "golden"
  discipline `test_packaged_schema_matches_its_golden_digest` in
  `tests/acbom/test_versioning.py` already established for the ACBOM
  schema. Any edit to the schema file changes the digest and fails
  this test until the change is deliberately acknowledged.
- Validates a real, generated `ScanReport` instance (including one
  with every optional field `None`/empty) against the packaged schema
  using `jsonschema.Draft202012Validator`, the same external-validator
  library `tests/acbom/test_schema_and_models.py` already uses for
  ACBOM -- "validated in CI," run as part of this repository's own
  test suite.
- Confirms an undeclared property is rejected by the schema.

`schema_version` follows the same MAJOR.MINOR.PATCH policy
[Schema versioning and compatibility policy](schema-versioning.md)
documents for the ACBOM schema. Unlike ACBOM, no
`check_schema_version_compatible`-equivalent runtime reader exists for
`ScanReport` yet: a report is a one-shot output a caller writes and a
consumer parses immediately, not a document re-loaded and version-
checked against a future reader the way a committed ACBOM or baseline
is -- building one is separate, not-yet-implemented work, needed only
if something must read an old report back.

## Canonical, diffable formatting

`model_dump_json()` on a Pydantic v2 model serializes fields in
class-declaration order, deterministically -- no dedicated
canonicalization step exists or is needed here, matching every other
computed-report model in this codebase
(`controlloop.diff.report.DiffReport`,
`controlloop.diff.material_summary.MaterialChangeSummary`). This model
performs no sorting of its own `findings`/`diagnostics` tuples --
supplying them in a canonical order is the responsibility of whichever
future caller assembles a `ScanReport`.

## Privacy

`controlloop.reporting.report` reads no file, subprocess, or network
content of its own -- it only validates and composes already-sanitized
objects a caller passes in, proven structurally by
`tests/test_redaction.py`'s `TestCanary` (the tenth case). Every
composed field is already covered by that same file's earlier canaries
(`Finding`'s free-text fields, in particular, by
`test_finding_rendering_never_surfaces_a_planted_secret`).

## What this does not do

- Compute a `Verdict`, findings, or a material change summary -- see
  [Terminal report format](terminal-report-format.md#what-this-does-not-do).
- Decide which suppressions apply -- that is
  `controlloop.policy.suppressions.apply_suppressions`'s job (see
  [Expiring repo-local suppressions](suppressions.md)); this model only
  carries the already-computed result.
- Read an old `ScanReport` back and check its version compatibility --
  see "Published, versioned schema" above.

## Next steps

- Review [Terminal report format](terminal-report-format.md) for the
  human-readable counterpart to this envelope.
- Review [Diff output format](diff-output-format.md) and
  [Finding model](finding-model.md) for the pieces this envelope
  composes.
- Review [Schema versioning and compatibility policy](schema-versioning.md)
  for the MAJOR.MINOR.PATCH policy this schema follows.
