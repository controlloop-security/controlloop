---
type: reference
title: SARIF export format
tags:
  - reference
  - reporting
created: 2026-08-20
---

# SARIF export format

**Status: Implemented, including live generation and upload.**
`controlloop.reporting.sarif`, described below, is implemented and
tested library code, validated against the real, vendored SARIF 2.1.0
JSON Schema. `controlloop scan --format sarif` and `controlloop gate
--format sarif`/`--sarif-path` both produce one from a real repository
scan today. The [ControlLoop GitHub Action](github-action.md) uploads
the generated document to GitHub code scanning and degrades to a
workflow warning on failure, never changing the gate's
own pass/fail result -- see that page, and "Uploading to GitHub code
scanning" below, for what remains a disclosed, repository-specific
limitation (this repository itself has no GitHub Advanced Security
enabled today).

## What this is

Findings appear natively in GitHub code scanning and any other SARIF
consumer. `render_sarif_log`
(`controlloop.reporting.sarif`) composes an already-computed `findings`
tuple and a tool identity into one complete SARIF 2.1.0 log document.
It reuses `controlloop.findings.rendering.finding_to_sarif_result`
unmodified for each finding's own `result` object -- that function's
own docstring explicitly leaves the surrounding log structure to this
module:

```python
def render_sarif_log(
    findings: tuple[Finding, ...],
    *,
    tool: Generator,
    information_uri: str | None = None,
    blast_radius_lines: tuple[str, ...] | None = None,
) -> dict[str, object]: ...
```

`tool` is a plain caller-supplied fact, matching
[`ReportVersions.scanner`](report-format.md)/
[`EvidenceVersions.scanner`](evidence-artifact-format.md)'s identical
`Generator` precedent -- this function computes nothing about the
findings or the tool itself.

## The blast-radius statement

Neither `EvidenceArtifact` nor this document originally carried the
[blast-radius statement](diff-output-format.md#blast-radius-statement)
.
`blast_radius_lines`, when supplied, is embedded verbatim (the exact
line tuple `describe_blast_radius` already produces for `--format
text`) as `runs[0].properties.controlloop.blastRadius` -- a JSON array
of strings, reusing this module's own existing `properties.controlloop`
extension namespace (see "Rule metadata," below) rather than a second
one. `None` (the default) omits the `properties` key entirely, so every
caller from before this parameter existed produces byte-identical
output. The [GitHub Action](github-action.md) reads this property
straight out of the SARIF file it already wrote to populate the check
summary, avoiding a second `gate` invocation.

## The authority statement

When a change hands an agent new power, `render_sarif_log` adds the
[authority statement](authority-statement.md):

- `runs[0].properties.controlloop.authorityDelta`: every entry, in
  order, with the same fields as the JSON report's `authority_delta`.
- On each result about one of those grants (its capability path ends at
  the granted component, or, for a repository-scoped finding, it is the
  only grant in the finding's file),
  `properties.controlloop.authorityStatement` and `approvalRecorded`.
- On each agent-authority rule in `tool.driver.rules`, `help.text`: the
  rule pack's own summary of what the rule looks for.

With no grant, none of these is present.

## Rule metadata in the driver section

Each finding maps to one SARIF `result` via `finding_to_sarif_result`:
a `ruleId`, a `level`, a `message`, and `locations`. Separately,
`render_sarif_log` builds one `ReportingDescriptor` per **unique** rule
referenced by `findings` in `runs[].tool.driver.rules[]`, each carrying
a `helpUri` from `Finding.documentation_url` -- both are
required, defaultless fields on `Finding`, so a descriptor's `helpUri`
and rule-version property are never missing or fabricated. Rules are
always sorted by ID, so two findings sharing a rule produce exactly one
descriptor, deterministically ordered regardless of input order.

## No fabricated location

`finding_to_sarif_result` already renders `locations` as an empty list
-- never a fabricated placeholder -- when a finding's evidence carries
only a `document_digest` and no `path`. `render_sarif_log` passes this
through unmodified; a populated and an empty-`findings` log both
validate against the real schema (see below).

## Validated against the real SARIF 2.1.0 schema, offline

`tests/fixtures/sarif/sarif-schema-2.1.0.json` is the official
SARIF 2.1.0 JSON Schema, vendored verbatim from `oasis-tcs/sarif-spec`
(see `tests/fixtures/sarif/README.md` for exact source, fetch
date, and license disclosure). `tests/reporting/test_sarif.py`
validates a real generated log document against it with
`jsonschema.Draft4Validator` (the schema's own `$schema` field
declares JSON Schema draft-04) -- satisfying "validates against the
SARIF 2.1.0 schema in CI" locally and offline, the same
way `tests/acbom/test_schema_and_models.py` already validates ACBOM
documents against the packaged ACBOM schema. A negative control test
confirms the validator genuinely rejects a malformed document, not
just anything.

## Uploading to GitHub code scanning

The [ControlLoop GitHub Action](github-action.md) uploads the generated
document via `github/codeql-action/upload-sarif`, with a stable
`category: controlloop` input (GitHub's own documented mechanism for
"repeated runs update rather than duplicate results"). Upload failure
degrades to a workflow warning and never changes the gate's own
pass/fail result.

**Where the upload lands:** code scanning must be enabled on the
repository for an uploaded log to appear in the Security tab. It is free for
public repositories; a private repository needs GitHub Advanced Security.
Where it is not enabled, the upload step's graceful degradation applies
(`.github/workflows/action-e2e.yml` exercises it), and the findings are still
in the gate log, the evidence artifact, and the check summary.

## What this does not do

- Compute a `Verdict` or the findings themselves -- see
  [Terminal report format](terminal-report-format.md#what-this-does-not-do).
- Decide whether code scanning is enabled for any given repository, or
  confirm a result actually renders in the Security tab -- see
  "Uploading to GitHub code scanning," above.

## Next steps

- Review [Finding model](finding-model.md) for `finding_to_sarif_result`,
  the per-finding rendering this module composes.
- Review [Stable JSON report format](report-format.md) and
  [Evidence artifact format](evidence-artifact-format.md) for the
  sibling envelopes this module's "compose, never compute" discipline
  mirrors.
