---
type: reference
title: Evidence artifact format
tags:
  - reference
  - reporting
created: 2026-08-20
---

# Evidence artifact format

**Status: Implemented and wired in.** `controlloop.reporting.evidence`,
described below, and its packaged JSON Schema are implemented and
tested library code. `controlloop gate` is the real CLI command that
produces one, writing it to `--evidence-path` for every run that
reaches a verdict, including a failing one -- see [CLI
reference](cli.md#gate). `scan` does not produce this artifact; it has
its own, distinct `ScanReport` envelope (see [Stable JSON report
format](report-format.md)).

## What this is

A gate run produces a single retainable `evidence.json` that fully
explains the verdict after the fact, without access to the source
repository. `EvidenceArtifact`
(`controlloop.reporting.evidence`) composes already-computed pieces
into that artifact, the same "compose, never compute" discipline
[the terminal renderer](terminal-report-format.md) and
[the JSON report](report-format.md) already follow.

## The model

```python
class EvidenceArtifact:  # controlloop.reporting.evidence
    schema_version: str  # SemanticVersion
    acbom_digest: str  # Sha256Digest
    baseline_digest: str | None  # Sha256Digest
    baseline_provenance: ApprovalProvenance | None  # baseline-artifact-format.md
    effective_authority_diff: tuple[EffectiveAuthorityChange, ...] | None
    findings: tuple[Finding, ...] | None
    completeness: tuple[Diagnostic, ...]
    completeness_enforcement: CompletenessEnforcement = CompletenessEnforcement.WARN
    completeness_enforcement_source: ConfigSource = ConfigSource.DEFAULT
    suppressions: tuple[SuppressionRecord, ...] = ()
    team: TeamEvidence | None = None
    verdict: Verdict  # terminal-report-format.md
    versions: EvidenceVersions


class TeamEvidence:  # controlloop.team.evidence
    organization_bundle_version: str
    merge_semantics_version: str
    policy_source: str  # fetched | cache | stale_cache | none
    entitlement_state: str
    repository_delta: tuple[PolicyRuleRecord, ...] = ()
    effective_policy: tuple[PolicyRuleRecord, ...] = ()
    approved_components: tuple[ApprovedComponentRecord, ...] = ()
    rejections: tuple[PolicyRejectionRecord, ...] = ()
    applied_exceptions: tuple[ExceptionRecord, ...] = ()
    finding_actions: tuple[FindingActionRecord, ...] = ()  # left out when empty


class FindingActionRecord:  # controlloop.team.evidence
    finding_id: str
    rule_id: str
    action: str  # fail | require_review | warn | pass
    source: str  # organization | severity_threshold


class EvidenceVersions:  # controlloop.reporting.evidence
    scanner: Generator
    acbom_schema_version: str
    baseline_schema_version: str | None = None
    evidence_schema_version: str
    policy_version: str | None = None
```

### The `team` block

`None` on every Community run, and that is a fact worth recording rather
than an absence: it means no organization policy participated in this
verdict.

When a Team gate produced the verdict, it carries what the platform
contributed -- the organization bundle version and merge-semantics
version that make the verdict re-derivable, the repository delta as it
was sent, the effective policy that resulted, any weakening the merge
refused, and every exception with its disposition (`applied`, `expired`,
or `unmatched`).

Each effective-policy rule records its organization `action` when it has
one, and `finding_actions` records the action the gate took on every
finding: `fail`, `require_review`, `warn`, or `pass`. Its `source` is
`organization` when the rule's action decided it, and
`severity_threshold` when the rule has no action and the finding's
severity against `severity_threshold` did (a blocking finding reads
`fail`, a warning `warn`, and one below the threshold `pass`). A finding
a suppression or exception kept out of the verdict is recorded too; the
suppression or exception record says why it did not count.

`policy_source` distinguishes a bundle read live (`fetched`) from one
served fresh from cache (`cache`) from one used past its lifetime because
the platform was unreachable (`stale_cache`). That distinction belongs in
evidence: a verdict decided against a three-day-old bundle is a different
fact from one decided against the current bundle, and an auditor should
not have to infer which happened.

What it deliberately does **not** record: the project token, the
endpoint, and the organization and project identifiers. None of them
explain a verdict, and an evidence artifact is a file people attach to
tickets and audits.

The required field list is satisfied exactly:

- **ACBOM digest** -- `acbom_digest`, the current scan's own
  `ACBOMDocument.digest`.
- **Baseline digest and provenance** -- `baseline_digest`/
  `baseline_provenance`, from `BaselineDocument.digest`/`.provenance`
  of whichever baseline the comparison used.
- **Effective authority diff** -- `effective_authority_diff`, the raw
  `EffectiveAuthorityChange` tuple `diff_effective_authority`
  produces. This is deliberately *not*
  [`MaterialChangeSummary`](diff-output-format.md#material-capability-change-summary)
  (the higher-level material reclassification `ScanReport` carries):
  this artifact names the granular fact-level diff itself.
- **Findings** -- `findings` ([Finding model](finding-model.md)).
- **Suppressions** -- `suppressions`, the identical
  `SuppressionRecord` shape and "always present, never hidden"
  guarantee `ScanReport.suppressions` carries. See
  [Expiring repo-local suppressions](suppressions.md).
- **Completeness state** -- `completeness`, the raw completeness
  diagnostic tuple itself (`controlloop.acbom.completeness.completeness_summary`'s
  own return shape), not a derived boolean: the requirement names the
  state itself, distinct from `ScanReport`'s derived `incomplete`
  property. Unconditional -- populated identically regardless of
  `completeness_enforcement` below.
- **Completeness enforcement** -- `completeness_enforcement`/
  `completeness_enforcement_source`: the
  resolved `CompletenessEnforcement` setting ("warn" default / "enforce"
  opt-in) that decided whether `completeness` above could produce
  `verdict=review_required`, and which of `controlloop.config`'s four
  precedence tiers supplied it -- the same `PolicyConfig` field pair
  `severity_threshold`/`low_confidence_action` already carry. Both
  fields default to `CompletenessEnforcement.WARN`/`ConfigSource.DEFAULT`
  so a genuinely older 1.0.0 artifact (written before these fields
  existed) still validates against this 1.1.0 model -- see "Published,
  versioned schema" below.
- **Verdict** -- `verdict` (`Verdict`, unchanged from the terminal
  renderer).
- **All component versions** -- `versions` (`EvidenceVersions`), kept
  as its own model rather than a reuse of `ScanReport`'s
  `ReportVersions`, so a future breaking change to either schema
  remains an independent event.

## A diff requires a baseline

`baseline_digest` and `effective_authority_diff` are both `None` or
both present, enforced by a model validator: a diff cannot exist
without a baseline to compare against. This is deliberately *not*
enforced for `baseline_provenance` -- a real baseline legitimately has
no provenance (any baseline predating the provenance field, or one
where it was never supplied), the same reasoning
[`describe_provenance`](baseline-artifact-format.md#approval-provenance)
already documents. `findings=None` (no policy evaluated at all) is
independent of whether a baseline was used, and differs from a real,
empty `findings=()`. `gate` always evaluates policy against
every registered, non-disabled rule, so `findings` is a real tuple
(possibly empty) on every artifact `gate` actually produces --
`findings=None` remains a real, distinct state this model still
represents, for any future caller that composes an artifact without
running policy at all.

## Self-contained

Every field here is already a sanitized digest, ID, name, or
structured object -- never a raw path, source snippet, or credential
value -- so the artifact is sufficient to explain a verdict without
access to the source repository by construction, not by a separate
scrubbing pass.

## Published, versioned schema, determinism, and privacy

The packaged schema is generated directly from
`EvidenceArtifact.model_json_schema()`, the same disclosed design choice
[the report schema](report-format.md#published-versioned-schema)
already makes and for the same reason (every composed model already
declares `extra="forbid"`). The current version is `1.6.0`
(`src/controlloop/schemas/evidence/1.6.0/evidence.schema.json`) -- six
MINOR bumps so far: `1.0.0` -> `1.1.0` (two new, defaulted,
backward-compatible fields, `completeness_enforcement`/
`completeness_enforcement_source`), then `1.1.0` -> `1.2.0`
(`suppressions`'s element type changed from a placeholder
`tuple[str, ...]` to a real `tuple[SuppressionRecord, ...]` -- no real
artifact has ever populated that field with anything but an empty
tuple, so no real document is made unreadable; see [Schema versioning
and compatibility policy](schema-versioning.md)), then `1.2.0` ->
`1.3.0` (one new, defaulted field, `team`), then `1.3.0` -> `1.4.0`
(the optional `authority_delta`, the [authority
statement](authority-statement.md), left out when there is no delta),
then `1.4.0` -> `1.5.0` (the `team` block's approved entries carry their
matching constraints, and it gains `approved_components_digest`,
`sanction_judgments`, and `sanction_note`; see [the unsanctioned agent
component rule](policy-rules.md#unsanctioned-agent-component)), then
`1.5.0` -> `1.6.0` (each `team` rule's `action` and the per-finding
`finding_actions`, both left out when empty). Every
prior version's own file is kept unmodified at its own
`src/controlloop/schemas/evidence/<version>/` directory, the same
two-version precedent `schemas/baseline/` already established.
`tests/reporting/test_evidence_schema.py` ties the current file to a
committed digest (any edit fails CI until deliberately acknowledged)
and validates a real generated `EvidenceArtifact` against it with
`jsonschema.Draft202012Validator`.

`model_dump_json()`'s class-declaration-order field serialization
makes identical input byte-for-byte diffable with no dedicated
canonicalization step, matching every other computed-report model in
this codebase. `controlloop.reporting.evidence` reads no file,
subprocess, or network content of its own -- proven structurally by
`tests/test_redaction.py`'s `TestCanary` (the eleventh case).

## What this does not do

- Compute a `Verdict`, findings, or an effective-authority diff itself --
  see [Terminal report format](terminal-report-format.md#what-this-does-not-do).
  `gate` computes these and passes them in; this module still
  composes them, never derives them independently.
- Decide which suppressions apply -- that is
  `controlloop.policy.suppressions.apply_suppressions`'s job (see
  [Expiring repo-local suppressions](suppressions.md)); this model only
  carries the already-computed result.
- Name a retention policy for the written artifact beyond what the
  [GitHub Action](github-action.md) and [pre-commit
  hook](pre-commit-hook.md) already do with it (uploading it as a
  workflow artifact / leaving it on disk locally, respectively) --
  a dedicated, longer-term retention or storage service remains
  separate, not-yet-implemented Team-tier work.

## Next steps

- Review [Stable JSON report format](report-format.md) for the sibling
  envelope this artifact's field-composition discipline mirrors.
- Review [Baseline artifact format](baseline-artifact-format.md) for
  `ApprovalProvenance` and the baseline this artifact's
  `baseline_digest`/`baseline_provenance` describe.
- Review [Effective authority model](effective-authority-model.md) for
  `EffectiveAuthorityChange`'s own fields.
- Review [Finding model](finding-model.md) for the findings this
  artifact composes.
