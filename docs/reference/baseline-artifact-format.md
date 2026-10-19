---
type: reference
title: Baseline artifact format
tags:
  - reference
  - baseline
  - acbom
created: 2026-08-19
---

# Baseline artifact format

**Status: Implemented foundation, with a real CLI consumer.** The model,
canonicalization, digesting, tamper/truncation detection, resolution, and
approval provenance described below are implemented and tested library code.
`controlloop diff` (see [CLI reference](cli.md#diff)) reads and compares a
baseline; no CLI command writes or commits one yet. This page is written
and reviewed in the same change as the behavior it documents, matching the
pattern already used for the [effective authority
model](effective-authority-model.md) and the [schema versioning and
compatibility policy](schema-versioning.md).

## What this is

A baseline is the versioned, canonical record of an **approved
capability set**: the ACBOM digest and schema version it was computed
from, the direct effective authority it asserts, the scanner that
produced it, the commit it describes, and (as of schema `1.1.0`) who
approved it, when, and at what commit. Every future comparison, policy,
and gate decision that needs "what did we last approve" is meant to read
one `BaselineDocument`, the same way every downstream diff, policy, and
report is meant to compute against `EffectiveAuthorityEntry` rather than
a different interpretation of the raw ACBOM graph.

This page covers the artifact **format**, plus two additions documented
in their own sections below: **resolution** (finding "the" baseline for
a repository and validating it) and **approval provenance** (who
approved a baseline, when, and at what commit). Writing a baseline,
committing it into a repository, and comparing two baselines are not yet
implemented.

## The model

```python
class BaselineDocument:
    schema_version: str  # this baseline format's own version, e.g. "1.1.0"
    generator: Generator  # scanner name + version
    repository: Repository  # commit + root_digest
    acbom_schema_version: (
        str  # the schema version of the ACBOM acbom_digest was computed from
    )
    acbom_digest: str  # sha256:... digest of the ACBOM this baseline was computed from
    effective_authority: tuple[
        EffectiveAuthorityEntry, ...
    ]  # the approved capability set (max 10,000 entries)
    provenance: (
        ApprovalProvenance | None
    )  # who approved this baseline, when, and at what commit -- optional
    digest: str  # sha256:... self-referential integrity digest, excluded from its own computation


class ApprovalProvenance:
    approver: str | None  # the approver's identity exactly as supplied
    approver_source: str | None  # "supplied" or "inferred" -- see below
    approved_at: str | None  # the approval timestamp exactly as supplied
    approved_commit: (
        str | None
    )  # the commit the approver attested to, exactly as supplied
```

Every field maps directly to one requirement: the baseline records the
ACBOM digest, effective authority, schema version, scanner version, and
the commit it describes.

- **ACBOM digest** — `acbom_digest`.
- **Effective authority** — `effective_authority`, the exact
  `EffectiveAuthorityEntry` model the [effective authority
  model](effective-authority-model.md) already defines and tests,
  reused here by import rather than
  redefined. A duplicate `(agent_id, action, resource_id,
  permitting_identity_id)` tuple is rejected: a baseline records an
  already-deduplicated fact set, the same guarantee
  `compute_effective_authority` gives on construction.
- **Schema version** — `acbom_schema_version`, the schema version of
  the ACBOM the recorded digest was computed from.
- **Scanner version** — `generator.version` (with `generator.name`
  alongside it), reusing the ACBOM's own `Generator` model.
- **The commit it describes** — `repository.commit`, reusing the
  ACBOM's own `Repository` model (which also carries `root_digest`).

### Why `schema_version` and `acbom_schema_version` are two separate fields

`schema_version` is the baseline format's *own* version — the field
every other versioned document in this codebase carries about itself
(`ACBOMDocument.schema_version`, `EffectiveAuthorityEntry.schema_version`,
`CapabilityPath.schema_version`). `acbom_schema_version` is the version
of a *different* document — the ACBOM `acbom_digest` was computed from.
A baseline format version bump and an ACBOM schema version bump are
independent events: the baseline format is now `1.1.0` (which added
`provenance`) while a digest computed under ACBOM schema `1.0.0` is still
perfectly valid to record.

## Versioning and compatibility

The baseline format follows the ACBOM compatibility policy literally,
not a re-derived equivalent of it:
`controlloop.baseline.integrity.load_baseline_document` calls
`controlloop.acbom.versioning.check_schema_version_compatible` — the
exact same function `load_acbom_document` uses — against the baseline's
own `schema_version` field. The policy is unchanged from [schema
versioning and compatibility](schema-versioning.md): a reader can read
any document at or below its own version within the same major line; a
different major, or a newer minor within the same major, is rejected
before any full parse is attempted.

The current baseline format version is `1.1.0`, which added the
optional `provenance` field, a backward-compatible MINOR addition per the
compatibility policy. `1.0.0` documents — including baselines committed
before provenance existed — remain fully readable by the current default
reader; `provenance` on such a document resolves to `None`, which is the
same "no provenance recorded" state described below, not an error.

The packaged JSON Schema lives at
`src/controlloop/schemas/baseline/1.1.0/baseline.schema.json` (the
unmodified `1.0.0/baseline.schema.json` remains published alongside it
for documents still declaring that version), Draft 2020-12, structured
the same way as the ACBOM schema
(`src/controlloop/schemas/acbom/1.0.0/acbom.schema.json`): shared
`$defs` for the same primitive shapes (`sha256Digest`, `safeIdentifier`,
`safeText`, `semanticVersion`, `generator`, `repository`, `confidence`,
`nodeId`), because they are the same underlying Pydantic types. Each
version's content is tied to its own committed golden digest in
`tests/baseline/test_baseline_integrity.py` (`1.0.0`) and
`tests/baseline/test_baseline_provenance.py` (`1.1.0`), so an edit to
either schema file without a deliberate version-bump decision fails the
build, the same discipline `test_packaged_schema_matches_its_golden_digest`
already enforces for the ACBOM schema.

## Tamper and truncation detection

A supplied baseline is either fully verified or rejected outright at
exit `2` (`ExitCode.INVALID_INPUT`) — `load_baseline_document` never
returns a partially parsed or partially validated document. Three
distinct failure categories are all normalized to the same
`BaselineIntegrityError`, itself carrying `exit_code =
ExitCode.INVALID_INPUT`:

1. **Truncated or unreadable bytes.** Invalid JSON, or a non-UTF-8
   decode.
2. **A malformed document.** An incompatible schema version (rejected
   before any full parse, per the compatibility policy above), or a
   document that fails `BaselineDocument`'s own structural validation
   (a missing required field, an invalid digest or ID pattern, and so
   on) — the underlying `pydantic.ValidationError` is never echoed
   verbatim, only a generic message, consistent with this codebase's
   "never echo hostile values in errors" rule and
   `hide_input_in_errors=True` on every canonical model.
3. **A tampered document.** The document parses and validates
   structurally, but its declared `digest` does not match a fresh
   recomputation over its own canonical bytes (`compute_baseline_digest`
   — the same canonicalize-then-SHA-256 pattern
   `controlloop.acbom.serialization.compute_digest` uses for the ACBOM,
   applied to a new input, not a new mechanism).

`load_baseline_document` verifies **already-supplied** bytes or text —
it does not open a file, resolve a path, or wire into any CLI command.
Reading a baseline from disk, and everything downstream of that
(comparison, gating), is separate, not-yet-implemented work.

## Privacy

A baseline can never carry source, secret, or environment values,
because every field that could carry file-shaped content is inherited,
not reimplemented: `effective_authority` entries are
`EffectiveAuthorityEntry` instances, whose own `evidence` field is the
ACBOM's `Evidence` model — `extra="forbid"`, so a field named `content`,
`raw_source`, `source_content`, `prompt`, `credential`, or
`environment_value` is rejected at the model level the instant it is
attached anywhere in a baseline, the identical guarantee already proven
for the ACBOM in
`tests/acbom/test_schema_and_models.py::test_prohibited_raw_content_field_names_are_rejected`.
`tests/baseline/test_baseline_models.py` asserts this directly for
the baseline (not only by reference to the ACBOM's own tests), plus a
canary test planting a secret-shaped value and asserting it never
appears in the resulting rejection error text.

## Determinism

Identical `effective_authority` content, constructed or supplied in any
order, canonicalizes to the same sorted order
(`canonicalize_baseline`, sorted by `(agent_id, action, resource_id,
permitting_identity_id)`) and therefore produces the same canonical
bytes and the same digest
(`compute_baseline_digest`/`with_baseline_digest`) — reusing
`controlloop.acbom.serialization.canonical_json_bytes`, the same
canonicalization primitive the ACBOM's own digest uses, rather than a
second, parallel implementation.

## Resolution

`controlloop.baseline.resolution.resolve_baseline(root, *,
explicit_path=None)` finds "the" baseline for a repository, given its
resolved root (`controlloop.repository.resolve_repository_root`) and an
optional explicit path, and validates whatever it finds by calling
`load_baseline_document` — the tamper/truncation detection above,
reused, not reimplemented.

- **Automatic discovery.** When
  `<repository root>/.controlloop/baseline.json` exists, it is
  discovered and used, with no flag required. The path is resolved
  against the repository root, never the current working directory. If
  nothing exists there and no explicit path was given,
  `resolve_baseline` returns `None` — a repository that has not
  committed a baseline yet is a legitimate, expected state, not an
  error.
- **Explicit override.** An explicit path, when supplied, wins
  unconditionally: automatic discovery is skipped entirely, not merely
  overridden after the fact, whether or not a conventional baseline also
  exists.
- **No silent fallback on failure.** Whichever source is
  selected, a baseline that fails validation raises
  `BaselineIntegrityError` straight through `resolve_baseline` — exit
  `2`, exactly as `load_baseline_document` already defines it. There is
  no `except` clause around that call in `resolve_baseline`, so an
  explicit baseline that fails is never silently replaced by the
  conventional one, and a conventional baseline that fails is never
  silently treated as absent. A selected path that cannot be read at all
  (missing, a directory, or otherwise unreadable) raises
  `BaselineResolutionError` instead, carrying the same `exit_code =
  ExitCode.INVALID_INPUT`.
- **Named source.** A successful resolution returns a
  `ResolvedBaseline` carrying the parsed `document`, a `BaselineSource`
  (`COMMITTED` or `EXPLICIT`) naming which path supplied it, and the
  exact `path` read. `controlloop diff` (below) names this source in
  every report it produces (`DiffReport.baseline_origin`).

`resolve_baseline` now has a real CLI consumer: `controlloop diff` (see
[CLI reference](cli.md#diff)) calls it first when resolving a
repository's baseline with no explicit `--baseline` value (a committed
baseline always takes precedence), and again for `--baseline PATH` when
`PATH` exists as a file (`resolve_baseline`'s own `explicit_path`,
unmodified). `scan`'s `_scan_resolve_baseline` and `gate`'s
`_gate_resolve_baseline` (in `cli.py`) both call `resolve_baseline` the
same way, on the same shared baseline-resolution path.

## Merge-base resolution

When no committed baseline exists, `controlloop.baseline.merge_base`
resolves the merge-base between the current revision and the repository's
default branch, and can scan that revision into a full ACBOM -- "with no
committed baseline, ControlLoop scans the merge-base of the default
branch and uses that."

- **Merge-base resolution, purely through local git.**
  `resolve_merge_base(root, *, default_branch=None)` runs
  `git rev-parse`, `git symbolic-ref`, and `git merge-base` only --
  never `git fetch`, never a remote URL, and the module imports no
  networking primitive. When `default_branch` is not supplied, the
  default branch is auto-detected by reading `refs/remotes/origin/HEAD`
  (a purely local ref, set by `git clone`, not re-fetched), falling back
  to the fixed local candidates `origin/main`, `origin/master`, `main`,
  `master`. An explicit `default_branch` always overrides this
  heuristic. A successful resolution returns a `MergeBaseResolution`
  naming the merge-base commit, the current `HEAD` commit, and the
  exact default-branch ref used.
- **Insufficient history is named, not silently compared against
  nothing.** If `git merge-base` cannot find a common ancestor,
  `resolve_merge_base` raises `MergeBaseResolutionError` (`exit_code =
  ExitCode.INVALID_INPUT`) with a message that checks
  `git rev-parse --is-shallow-repository` and definitively names a
  shallow clone as the cause when confirmed -- the common CI default
  (for example, GitHub Actions' `actions/checkout` with its default
  `fetch-depth: 1`) -- or describes the more general "shallow, partial,
  or genuinely unrelated history" case otherwise, always naming the
  concrete remediation (`git fetch --unshallow`, or `fetch-depth: 0` in
  CI). The same error is raised if the default branch itself cannot be
  determined locally at all, since that is frequently a symptom of the
  same root cause.
- **No git history at all is a distinct condition.** If `HEAD` cannot
  be resolved to a commit -- zero commits, or not a git repository at
  all -- `resolve_merge_base` raises `NoGitHistoryError` (`exit_code =
  ExitCode.INCOMPLETE_ANALYSIS`), deliberately distinct from
  `MergeBaseResolutionError`: "no history at all" and "some history, but
  not enough to find a merge-base" are different, differently remediated
  conditions. The complete observable outcome -- "a repository with no
  git history *and* no committed baseline reports that no comparison is
  possible, rather than reporting zero changes" -- is delivered by
  `controlloop diff`, which combines `NoGitHistoryError` with a `None`
  result from `resolve_baseline` -- see [CLI reference](cli.md#diff).
  This module itself does not build that combinator and does no
  diff/comparison rendering; it only raises the structural signal a
  comparison command needs.
- **Scanning that revision.** `build_merge_base_acbom(root,
  resolution, *, bounds=None)` materializes the resolved commit's
  complete tracked tree via `git archive` into an isolated, throwaway
  temporary directory -- deliberately not `git worktree add`, which
  would write into the repository's *shared* `.git/worktrees/`
  administrative area and risk racing other concurrent sessions of the
  same repository -- and scans that copy with
  `controlloop.bom.build_acbom_document`, the exact same function
  `controlloop bom` itself calls for the live tree. "Same scanner and
  adapter versions" holds by construction: there is only one
  `build_acbom_document` in this codebase, not a second, parallel
  baseline-only copy that could drift from it. `build_acbom_document`
  gained one new optional `commit_override` parameter (default `None`,
  every existing caller unaffected) so the resulting document's
  `repository.commit` names the actual revision scanned instead of
  `"unknown"`.

`resolve_merge_base` and `build_merge_base_acbom` now have a real CLI
consumer: `controlloop diff` (see [CLI reference](cli.md#diff)) calls
both when resolving a repository's baseline automatically (no
`--baseline` given, and no committed baseline exists).
`NoGitHistoryError` and `MergeBaseResolutionError` are each surfaced
with their own actionable message at exit `2`; "a repository with no git
history and no committed baseline reports that no comparison is
possible, rather than reporting zero changes" is delivered by that
combinator -- see [`diff`'s baseline resolution](cli.md#baseline-resolution)
for the full behavior. No CLI command wires a `--default-branch` option to
`resolve_merge_base` yet; `diff` always resolves the default branch
automatically for this path. A related, independent extension,
`build_acbom_at_revision`/`resolve_revision_commit` (also in
`controlloop.baseline.merge_base`), materializes and scans an arbitrary
already-resolved revision rather than specifically a merge-base, added for
`diff --baseline VALUE`'s explicit-git-revision path.

## Approval provenance

`BaselineDocument.provenance` is an optional `ApprovalProvenance`
recording who approved the baseline's capability set, when, and at what
commit. It is `None` for every baseline written before this
schema version — a repository's first committed baseline, or any
baseline written by a tool that has not yet adopted provenance, is a
legitimate, expected state, not an error.

- **Every field is optional bounded free text.**
  `approver`, `approver_source`, `approved_at`, and `approved_commit` are
  all `SafeText | None` — bounded (1–1024 characters), free of control
  characters, but otherwise unconstrained. This is deliberate: a stricter
  type (a closed enum for `approver_source`, a pattern-constrained commit
  identifier for `approved_commit`) would make a malformed value reject
  the *entire* baseline document at parse time. The requirement is the
  opposite — "a baseline with missing or malformed provenance is usable
  but reported as unattributed" — so whether provenance is complete and
  trustworthy is a semantic judgment, not a structural one.
- **`describe_provenance` classifies attribution.**
  `controlloop.baseline.provenance.describe_provenance(document)` returns
  a `ProvenanceSummary` with `status` (`ATTRIBUTED` or `UNATTRIBUTED`)
  and an `issues` tuple naming every specific gap (no approver, no stated
  source, an unparseable timestamp, no approved commit, or an
  `approver_source` value that is neither `"supplied"` nor `"inferred"`).
  It never raises — a missing or malformed `provenance` is an ordinary
  input, not an error condition. A partially present fact (for example an
  approver name with no confirmed source) is preserved in the summary
  even when the overall status is `UNATTRIBUTED`, never discarded.
- **`format_provenance_lines` renders the summary.**
  `controlloop.baseline.provenance.format_provenance_lines(document)`
  renders `describe_provenance`'s result as CLI-voice text lines
  following the CLI's stable-symbol convention. An attributed line
  always qualifies the approver as `(supplied)` or `(inferred)` — never
  an unqualified identity — and an unattributed line starts with `!` and
  states `UNATTRIBUTED` prominently, so the report says so prominently.
  No code in this repository infers an approver identity from git
  history or anywhere else; `ApproverSource` exists so that if later
  work adds inference, it has an honest way to say so, and so this rendering never claims an identity was directly
  supplied when it was not.
- **Digest coverage.** `provenance`, when present, is an ordinary
  `BaselineDocument` field like any other — it is included in
  `compute_baseline_digest`'s canonical bytes with no special-casing, so
  altering a recorded approver, timestamp, or commit after the fact is
  detected exactly like tampering with any other field. One narrow exception exists purely for backward
  compatibility: when `provenance` is absent (`None`), it is dropped from
  the canonical bytes entirely rather than serialized as an explicit
  `null`, so that a baseline digested and committed before this field
  existed — such as this package's own `minimal-baseline.json` fixture
  — still recomputes to its already-committed digest today.
  See `controlloop.baseline.serialization._document_data`'s docstring for
  the full reasoning.

`describe_provenance` and `format_provenance_lines` are tested library
functions with no CLI surface yet. Provenance is meant to display
"whenever a baseline is used" -- `controlloop diff` now uses a baseline
but does not call either function. `gate` carries a resolved baseline's
raw `ApprovalProvenance` in its `EvidenceArtifact`'s own
`baseline_provenance` field, but nothing in
`gate` renders it through `describe_provenance`/`format_provenance_lines`
either. Wiring either function into `diff`'s or `gate`'s own rendered
output is deferred, not-yet-implemented work.

## Staleness detection

`controlloop.baseline.staleness.detect_baseline_staleness(*,
baseline_commit, default_branch_commit, commits_behind, baseline_path,
max_staleness_commits=100)` answers whether a resolved baseline's
recorded commit still describes the repository, given the default
branch's current commit and how many commits apart the two are. It is
deliberately pure: the caller resolves `default_branch_commit` and
`commits_behind` first (`resolve_default_branch_commit` and
`count_commits_between`, the module's own local-only `git`
subprocess helpers — `symbolic-ref`, `rev-parse`, `rev-list --count`,
never reaching the network) and passes the results in, the same
compute/impure-boundary split every capability and repository-scanning
function in this codebase already follows.

- **Divergence is reported.** Two identical commits are always
  current. Otherwise, `commits_behind` — the number of commits between
  the baseline's commit and the default branch's current commit — is
  compared against `max_staleness_commits`.
- **Configurable threshold, a real finding.**
  `max_staleness_commits` (default `100`, a disclosed implementer
  default, not an approved policy value) is a parameter of
  `detect_baseline_staleness` itself. Crossing it returns a
  `BASELINE-STALE` `Diagnostic` — a `controlloop.acbom.models.Diagnostic`
  like any other in this codebase, not a bare log line.
- **Human, JSON, and SARIF output.** A returned `Diagnostic`
  serializes to JSON identically everywhere else in this codebase
  (`model_dump_json()`); `describe_staleness(diagnostic)` renders the
  one-line CLI-voice human form, following the same stable-glyph
  convention as `controlloop.diagnostics.render_text` and
  `format_provenance_lines` above. No SARIF exporter exists anywhere in
  this codebase yet — there is nothing to route SARIF output
  through until one exists; see "Known limitations" below.
- **Unverifiable commits.** When `commits_behind` is `None` —
  the baseline's commit could not be found anywhere in the repository's
  history — `detect_baseline_staleness` returns a distinct
  `BASELINE-UNVERIFIABLE` `Diagnostic` (`confidence=UNKNOWN`) rather than
  a confident "not stale" verdict or a crash.
- **No silent merge-base fallback.** This module never
  substitutes a different baseline; it has no source-selection logic
  of its own. `controlloop.baseline.merge_base`
  now exists and can resolve and scan a merge-base
  revision, but choosing *between* a committed baseline and a
  merge-base fallback, and naming which one was used, is that module's
  and `resolve_baseline`'s job (`ResolvedBaseline.source`,
  `MergeBaseResolution`), not this one's. A future caller wiring
  `detect_baseline_staleness` into a real command must thread whichever
  source it resolved through unchanged into its own output.

`detect_baseline_staleness`, `resolve_default_branch_commit`, and
`count_commits_between` are tested library functions with no CLI surface
yet, the same position `resolve_baseline` was in before `controlloop diff`
(see [CLI reference](cli.md#diff)) wired it in: no command -- `diff`,
`scan`, or `gate` -- calls `detect_baseline_staleness` today, so no
command can meaningfully consume a staleness verdict without also
performing comparison logic that belongs to separate, not-yet-implemented
work.

## Known limitations

- `controlloop diff` reads a committed or explicit
  baseline and compares it against a repository (`resolve_baseline`) or
  resolves and scans a merge-base or an explicit revision when no committed
  baseline exists (`resolve_merge_base`/`build_merge_base_acbom`,
  `build_acbom_at_revision`) -- see [CLI reference](cli.md#diff). No CLI
  command *writes* or *commits* a baseline yet; `load_baseline_document` still
  only verifies already-supplied bytes/text, and
  `describe_provenance`/`format_provenance_lines` and
  `detect_baseline_staleness`/`resolve_default_branch_commit`/
  `count_commits_between` are not yet wired into any command's output.
- No-history handling is delivered: `controlloop diff` combines
  `NoGitHistoryError` with `resolve_baseline`'s `None` result to produce
  the full, user-facing "no comparison is possible" report, distinct
  from reporting zero changes -- see [`diff`'s baseline
  resolution](cli.md#baseline-resolution).
- No SARIF exporter exists anywhere in this codebase yet; a
  staleness finding's JSON form is its only structured output today.
- Any gate decision built on a baseline comparison is separate,
  not-yet-implemented work.
- No code infers an approver identity from git history or any other
  source; `provenance` is only ever what a caller explicitly constructs
  `ApprovalProvenance` with. Nothing writes a baseline yet at all, so in
  practice no baseline in this repository carries real provenance outside
  of test fixtures.
- The schema is not yet published at a public URL, the same position
  the ACBOM's, the manifest's, and the effective authority model's own
  schemas are in.

## Next steps

- Review [Effective authority model](effective-authority-model.md) for
  the `EffectiveAuthorityEntry` model a baseline records.
- Review [Schema versioning and compatibility
  policy](schema-versioning.md) for the compatibility rule this format
  reuses.
- Review the [CLI reference](cli.md) for what is available today.
