---
type: reference
title: Diff output format
tags:
  - reference
  - diff
created: 2026-08-19
---

# Diff output format

**Status: Implemented, with a real CLI consumer.** The model and
computation described below are implemented and tested library code.
`controlloop diff` (see [CLI reference](cli.md#diff)) computes and
renders a diff from a live scan. This page is written and reviewed in
the same change as the behavior it documents, so that a versioned
contract is defined before implementation, not after.

## What this is

Change classification answers one question for every node, edge, and
effective-capability fact a scan can produce: *compared to a baseline
graph, is this added, removed, changed, or unknown?* `compute_diff`
takes two full graphs -- a baseline's `nodes`/`edges` and a current
scan's -- and returns a `DiffResult` naming exactly what differs.
Nothing that is unchanged is represented at all: an empty `DiffResult`
*is* "no difference," not a separate case a caller has to detect for
itself.

## The model

```python
class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNKNOWN = "unknown"


class NodeChange:
    kind: ChangeKind
    node_id: str
    before: Node | None  # None when kind is ADDED
    after: Node | None  # None when kind is REMOVED


class EdgeChange:
    kind: ChangeKind
    edge_id: str
    before: Edge | None
    after: Edge | None


class EffectiveAuthorityChange:
    kind: ChangeKind
    agent_id: str
    action: EdgeType
    resource_id: str
    before: EffectiveAuthorityEntry | None
    after: EffectiveAuthorityEntry | None


class DiffResult:
    schema_version: str  # semantic version, e.g. "1.0.0"
    node_changes: tuple[NodeChange, ...]
    edge_changes: tuple[EdgeChange, ...]
    effective_authority_changes: tuple[EffectiveAuthorityChange, ...]
    is_empty: bool  # property: true iff all three are empty
```

No packaged JSON schema file exists for this contract, matching
`controlloop.capability`'s own precedent: this is a computed report
over already-canonical data, not a persisted artifact like the ACBOM or
a baseline, so it does not need one of its own.

## All four states

- **`ADDED`** — present in the current graph, absent from the baseline.
- **`REMOVED`** — present in the baseline, absent from the current
  graph.
- **`CHANGED`** — present in both, with a real difference between them.
- **`UNKNOWN`** — present in both, where the baseline side was
  confidently known (`confidence` was not `Confidence.UNKNOWN`) and the
  current side's `confidence` is now `Confidence.UNKNOWN`. Distinct from
  both `REMOVED` and an ordinary `CHANGED` (see below).

Any identity present on both sides with no real difference is simply
absent from the result -- there is no fifth "unchanged" state to
represent, which is what makes "an identical repository against its own
baseline produces an empty diff" a structural property of this model.

## Stable identity, not position

Nodes and edges are matched between baseline and current by their
stable canonical ID (`controlloop.acbom.identity`), never by file
position, order, or any other positional signal. A node or edge ID
already excludes evidence, line numbers, security attributes, and
confidence from its own computation, so a definition that only moved
within a file, or was reformatted, keeps the same ID and is matched to
itself rather than appearing as a spurious removed-then-added pair.

Comparison for `CHANGED` also excludes each object's own `evidence`
field, for the same reason: evidence records *where* something was
discovered, not *what* it is. Two definitions that are identical except
for their recorded line numbers are reported as no change at all, not
as `CHANGED` -- "not reported as a change," taken literally.

## Effective-authority keying, and why it differs from `EffectiveAuthorityEntry`'s own key

`EffectiveAuthorityChange` is keyed by `(agent_id, action, resource_id)`
-- deliberately narrower than `EffectiveAuthorityEntry`'s own dedup key
(`agent_id, action, resource_id, permitting_identity_id`, from
`BaselineDocument.validate_effective_authority_is_deduplicated`).

Which identity permits a capability, and how confidently, are treated
as *properties of* that capability's current state here, not part of
its identity. This is what makes the following possible: an agent
whose access to a resource keeps existing, but whose permitting identity
edge disappears (so the recomputed entry now carries
`permitting_identity_id=None` and `confidence=Confidence.UNKNOWN`), is
reported as one `UNKNOWN` `EffectiveAuthorityChange` -- never as an
unrelated `REMOVED` entry for the old identity paired with an `ADDED`
entry for the same fact now missing one. A capability that genuinely
stops existing at all (its key disappears from the current graph
entirely) is `REMOVED`, without exception; this module does not
speculate about *why* a key vanished (a real removal versus an
unrelated analysis gap it cannot see), since nothing in this module
connects a vanished key back to a specific incompleteness diagnostic.

## Determinism

Every collection on `DiffResult` is sorted before being returned:
`node_changes` by `(node_id, kind)`, `edge_changes` by
`(edge_id, kind)`, `effective_authority_changes` by
`(agent_id, action, resource_id, kind)`. Feeding the same nodes, edges,
or effective-authority entries in a different order produces the exact
same sequence of changes.

## Comparison targets, and staying out of choosing one

`compute_diff(*, baseline_nodes, baseline_edges, current_nodes,
current_edges)` is the general case: two full ACBOM graphs. It computes
effective authority for both sides itself, via
`compute_effective_authority` -- never accepting a precomputed
`effective_authority` collection as an input, so a baseline's own
recorded facts are never silently substituted for a fresh
recomputation. This module has no opinion about where either side's
`nodes`/`edges` came from; three sources exist in this codebase that
could supply them, and this module treats all three
identically:

1. Two full `ACBOMDocument`s' own `nodes`/`edges` -- a previous scan
   versus a current one.
2. `controlloop.baseline.merge_base.build_merge_base_acbom` -- a full
   `ACBOMDocument` scanned from the default branch's merge-base, when no
   committed baseline exists.
3. A committed `BaselineDocument` (see [Baseline artifact
   format](baseline-artifact-format.md)) -- but it carries no `nodes`
   or `edges` at all, only `effective_authority`, so it cannot support
   a node or edge diff by itself. A caller comparing a live scan
   against a resolved `BaselineDocument` can call
   `diff_effective_authority` directly, passing
   `BaselineDocument.effective_authority` as the baseline side and a
   freshly computed `compute_effective_authority(current_nodes,
   current_edges)` as the current side.

"Diff output never silently switches to the merge-base baseline; the
user is told which was used" is not this module's job to satisfy by
itself, and it does not try to: choosing *which* of the sources above
supplied a comparison's baseline side, and naming that choice, is
`controlloop.baseline.resolution`'s and
`controlloop.baseline.merge_base`'s responsibility
(`ResolvedBaseline.source`, `MergeBaseResolution`) -- this module has no
source-selection or fallback logic of its own. `controlloop diff` (see
below) is the caller that wires `compute_diff` to a real command and
threads whichever source it resolved through into its own output,
unchanged.

## CLI report envelope

`controlloop diff` (see [CLI reference](cli.md#diff)) is the real command
that computes and renders a diff. It never returns a bare `DiffResult` on
its own: `DiffResult` says nothing about *where* its baseline side came
from or *whether* a node/edge comparison was even attempted, both of which
are structural facts about `diff`'s own three usage forms, not properties
of classification itself. `DiffResult` itself, and every field on
`NodeChange`/`EdgeChange`/`EffectiveAuthorityChange`, is unmodified by this
addition.

`controlloop.diff.report.DiffReport` (schema `1.1.0`; `1.1.0` added the
optional `authority_delta`, the [authority
statement](authority-statement.md)) wraps an unmodified `DiffResult` with
that missing context:

```python
class BaselineOrigin(StrEnum):
    TWO_ACBOMS = "two_acboms"
    EXPLICIT_BASELINE_FILE = "explicit_baseline_file"
    COMMITTED_BASELINE = "committed_baseline"
    MERGE_BASE = "merge_base"
    EXPLICIT_REVISION = "explicit_revision"


class ComparisonScope(StrEnum):
    FULL = "full"
    EFFECTIVE_AUTHORITY_ONLY = "effective_authority_only"


class DiffReport:
    schema_version: str  # semantic version, e.g. "1.0.0"
    baseline_origin: BaselineOrigin
    baseline_description: (
        str  # a path, a resolved commit and ref, or the two compared files
    )
    comparison_scope: ComparisonScope
    result: DiffResult
```

`comparison_scope` is `EFFECTIVE_AUTHORITY_ONLY` whenever the resolved
baseline is a `BaselineDocument` (a committed or an explicit `--baseline`
file) -- see [Baseline artifact format](baseline-artifact-format.md):
that artifact carries `effective_authority` but no `nodes`/`edges` at
all, so a node/edge comparison is structurally impossible, not merely
skipped. `diff` calls `diff_effective_authority` directly in this case
rather than calling `compute_diff` with a fabricated empty node/edge
graph on the baseline side, which would incorrectly report every current
node/edge as `ADDED`. `node_changes`/`edge_changes` on the wrapped
`DiffResult` are therefore empty tuples in this scope -- because they
were never evaluated, not because nothing changed.

This distinction lives in the same payload as the changes themselves, in
both `--format json` and `--format text` output, not only a stderr
diagnostic: a caller parsing only stdout must not be able to mistake
"not evaluated" for "confirmed zero," directly applying this product's
"unknown, never omitted" invariant to this command's own biggest honesty
risk.

No packaged JSON schema file exists for `DiffReport`, matching
`DiffResult`'s own precedent: this is a computed CLI report, not a
persisted artifact like the ACBOM or a baseline.

## Transitive capability path changes

`diff_transitive_capability_paths(baseline_paths, current_paths) ->
tuple[CapabilityPathChange, ...]` extends the same
four-state classification to bounded multi-hop capability paths
(`controlloop.capability.compute.compute_transitive_capability_paths`),
reusing `_classify` unchanged -- `CapabilityPath` carries its own
`confidence` field, so the confidence-drop-to-`UNKNOWN` rule above
applies identically here.

Unlike `diff_effective_authority`, this function does **not** narrow
its key to `(agent_id, target_id)`. `compute_transitive_capability_paths`
can legitimately return more than one distinct route to the same
target (different chains through the graph), each a genuinely separate
fact -- so `diff_transitive_capability_paths` keys on each path's own
full edge-ID chain (`tuple(hop.edge_id for hop in path.hops)`) instead,
reporting every route independently rather than collapsing them.

## Material capability change summary

`compute_material_change_summary(*, baseline_nodes, baseline_edges,
current_nodes, current_edges, max_depth=5) -> MaterialChangeSummary`
 answers the question a raw `DiffResult` does not:
not *which* nodes, edges, or facts differ, but *what real-world power
an agent gained or lost*, in terms of
[Material capability taxonomy](material-capability-taxonomy.md)'s
already-defined classes.

- **Classified by material class.** Every direct
  effective-authority change and every transitive capability-path
  change is looked up against its resource's or target's own
  `SecurityAttributes` via `classify_material_capability`. A change
  matching more than one class (for example a destructive *and*
  sensitive-data-access write) produces one `MaterialChange` per
  matched class, never just the worst or the first.
- **No material change is empty, not a sentinel.** A cosmetic
  change (identical content once evidence is set aside) never reaches
  this function at all, since `diff_effective_authority`/
  `diff_transitive_capability_paths` already omit it. This extends one
  step further: a real change whose resource carries no material
  `SecurityAttributes` at all (`classify_material_capability` returns
  an empty set) also contributes nothing -- the summary's purpose
  ("what real-world power the agent gained -- not which files
  changed") is exactly the judgment an empty classification already
  makes. `MaterialChangeSummary.is_empty` is `True` in both cases; the
  structural absence *is* "no material change."
- **Transitive gains carry their path.** A target reachable
  only through a bounded multi-hop chain (never a single direct edge)
  is reported with `MaterialChange.transitive = True` and
  `MaterialChange.path` populated with the full hop chain that
  delivers it -- distinct from a direct one-hop gain, which is
  `transitive = False` with an empty path.
- **Generated from structured data.**
  `describe_material_change_summary(summary) -> tuple[str, ...]`
  renders `MaterialChangeSummary`'s own already-computed fields
  through a fixed template following the CLI's stable-symbol
  convention (`• GAINED`/`• LOST`/`• CHANGED`/`! UNKNOWN`) -- there is
  no model call
  anywhere in this function's or its callees' import graph, verified
  structurally by `TestCanary::test_material_summary_module_never_reads_raw_content`.
  An empty summary renders one explicit `"• no material capability
  change"` line rather than an empty tuple.
- **Deterministic.** `MaterialChange`s are sorted by
  `(agent_id, target_id, action, material_class, kind, transitive)`
  before being returned, independent of the input nodes'/edges' order.

`agent_name`/`target_name` on `MaterialChange` are the resolved
`Node.name` display strings at compute time, denormalized onto the
model so a rendered line can name something a person recognizes
rather than only a content-addressed ID -- the same reasoning that led
every other rendering helper in this codebase (`describe_provenance`,
`describe_staleness`) to work from already-resolved structured fields,
never re-deriving display text from raw IDs at render time.

## Capability reduction reporting

`compute_capability_reduction_report(summary: MaterialChangeSummary) ->
CapabilityReductionReport` answers the question a raw
`MaterialChangeSummary` leaves implicit: is this diff *only* a
reduction of authority, or does it also gain, change, or leave
something unknown? A change that revokes authority is reported as a
named result, so tightening is rewarded rather than met with silence.

- **Same vocabulary as additions.** `CapabilityReductionReport`
  performs no new classification -- it partitions an already-computed
  `MaterialChangeSummary.changes` into `reductions`
  (`MaterialChangeKind.LOST`) and `other_changes` (everything else).
  The material capability change summary already guarantees a
  reduction and a gain of the same underlying fact classify to the same
  `MaterialCapabilityClass`, since both directions run through the
  identical `classify_material_capability` call.
- **A reduction-only change passes and states what was reduced.**
  `CapabilityReductionReport.is_reduction_only` is `True` only when
  there is at least one real reduction and `other_changes` is empty --
  an entirely empty summary is not "reduction only," it is simply
  empty; "passes" requires something to have actually been reduced.
  `describe_capability_reduction` renders one `• REDUCED` line per
  reduction, and appends an explicit `✓ PASSED
  capability reduced only -- no new authority gained` line when
  `is_reduction_only` is `True` -- a real, visible signal using the
  CLI's own recommended `✓ PASSED` form, not merely the absence of a
  warning.
- **Human and JSON output.** `describe_capability_reduction`
  is the human form; `CapabilityReductionReport` is an ordinary
  pydantic model, serializing to JSON identically to every other model
  in this codebase (`model_dump_json()`). No SARIF exporter exists
  anywhere in this codebase yet; see "Known limitations" below.
- **Never miscounted as a finding or a failure.** This is satisfied
  structurally rather than by wiring into a finding model or gate:
  `reductions` and `other_changes` are two separately named, disjoint
  collections (`reductions | other_changes == summary.changes`,
  asserted directly in tests). A gate or finding-counter reads
  `other_changes` for anything that should count as a finding and never
  `reductions` --
  there is no shared collection for a `LOST` entry to be accidentally
  counted from.

## Blast-radius statement

`controlloop.capability.blast_radius.compute_blast_radius(nodes, edges,
*, max_depth=5) -> BlastRadiusStatement | None`
answers a different question from everything above: not what changed
against a baseline, but *right now, in this one graph, what is the
single worst thing reachable at all* -- the line a reviewer forwards
to their manager, meant to lead every result before any list of
findings. It lives in `controlloop.capability`, not `controlloop.diff`
-- it has no dependency on `controlloop.diff` or on any baseline; it
is the same "what can this agent really do" question every other `controlloop.capability` module
already answers, computed over one graph's full capability surface
(every direct effective-authority fact and every bounded transitive
capability path).

- **Worst-ranked action, resource, and permitting identity.**
  Every direct and transitive fact is classified via
  `classify_material_capability`; `worst_class` (the [material
  capability taxonomy](material-capability-taxonomy.md)'s own defined
  ordering, reused unmodified) picks the single worst class found
  anywhere in the graph. Ties among facts sharing that worst class are
  broken by a fixed deterministic sort key. For a direct fact,
  the permitting identity is `EffectiveAuthorityEntry.permitting_identity_id`;
  `CapabilityPath` carries no equivalent field, so for a transitive
  fact the permitting identity (when present) is derived by scanning
  the path's own hops for an `AUTHENTICATES_AS` edge and naming its
  target.
- **No model produces it.** `describe_blast_radius` renders
  `BlastRadiusStatement`'s own already-computed fields through a fixed
  template -- there is no model call anywhere in this module's or its
  callees' import graph, verified structurally by
  `TestCanary::test_blast_radius_module_never_reads_raw_content`.
- **Transitive-only worst action names its path.** When the
  winning fact is `transitive=True`, `describe_blast_radius` renders
  one line per hop directly beneath the headline.
- **Incomplete analysis is qualified, not asserted complete.**
  `incomplete` is `True` whenever `compute_transitive_capability_paths`
  returned *any* diagnostic anywhere in the graph, regardless of
  whether the winning fact itself was direct or transitive -- an
  unexplored deeper path could always turn out worse. The rendered
  headline is suffixed with an explicit qualifier rather than silently
  presented as a confident final answer.
- **Appears first, and as a discrete field.** `BlastRadiusStatement`
  is designed to be a top-level field in a JSON/SARIF report, never
  folded into a findings array, and `describe_blast_radius`'s lines are
  designed to be emitted before any findings list -- a contract every
  report assembler must honor.
- **Reference refund scenario.** A fixture
  (`refund-agent`, permitted by `service-account`, writing a
  `destructive`-and-`sensitivity=restricted`-classified `billing-db`
  resource) asserts the exact expected headline sentence byte for
  byte, reusing the project's established worked-example naming for
  continuity.

## Known limitations

- `controlloop diff` (see [CLI reference](cli.md#diff)) computes and
  renders a `DiffResult`-based comparison (`compute_diff`,
  `diff_effective_authority`). It does not call
  `compute_material_change_summary`, `diff_transitive_capability_paths`,
  `compute_capability_reduction_report`, or `compute_blast_radius`: wiring
  the material capability change summary, the capability
  reduction report built on top of it, or the blast-radius
  statement into `diff`'s own output is separate,
  not-yet-implemented work, even though `describe_material_change_summary`,
  `describe_capability_reduction`, and `describe_blast_radius` already
  render CLI-voice text (`• GAINED`/`• LOST`/`• CHANGED`/`! UNKNOWN`,
  `• REDUCED`/`✓ PASSED`, and `! WORST REACHABLE`, above) as tested
  library code.
- `controlloop diff` has no SARIF renderer of its own (the [SARIF
  exporter](sarif-export-format.md)'s `render_sarif_log` is wired into
  `scan --format sarif` and `gate --format sarif`/`--sarif-path`
  instead, not `diff`).
  `controlloop diff --format json` serializes `DiffReport` (including the
  wrapped `DiffResult`) identically to any other canonical model in this
  codebase (`model_dump_json()`); `--format text` renders a CLI-voice
  summary. Neither is SARIF, and neither is `MaterialChangeSummary`'s,
  `CapabilityReductionReport`'s, nor `BlastRadiusStatement`'s own text
  rendering.
- `controlloop.policy.engine` is a foundational rule evaluator; ten
  concrete rules now exist in `controlloop.policy.rules.ALL_RULES`,
  producing real `Finding`s via the real finding contract (see [Finding
  model](finding-model.md)). This module does not compare any of
  `DiffResult`, `MaterialChangeSummary`, `CapabilityReductionReport`, or
  `BlastRadiusStatement` against a policy or gate; evaluating any of them
  against a real rule, or counting a
  `CapabilityReductionReport.other_changes` entry as a real finding,
  remains separate, not-yet-implemented work. `controlloop diff`
  evaluates no policy and returns exit `0` or `2` only.
- `controlloop diff` does not write or commit a baseline. Producing a
  `.controlloop/baseline.json` from a diff's current side is separate,
  not-yet-implemented work.
- `compute_material_change_summary`/`compute_blast_radius` do not surface
  `compute_transitive_capability_paths`'s own incompleteness diagnostics
  (`INCOMPLETE-BOUND-EXCEEDED`/`INCOMPLETE-CYCLE-DETECTED`) in the
  summary/reduction report itself -- only `BlastRadiusStatement.incomplete`
  carries this signal. If either side's transitive walk hits one of its
  own bounds, the comparison may under-report a transitively gained or
  lost capability beyond that bound -- this also means a capability
  reduction report built on top of it may under-report a reduction. This
  does not affect `controlloop diff`'s own output today, since it does
  not call `compute_material_change_summary`,
  `compute_capability_reduction_report`, or `compute_blast_radius`.

## Next steps

- Review [Effective authority model](effective-authority-model.md) for
  `EffectiveAuthorityEntry`, the model this page's effective-authority
  diff is computed from.
- Review [Baseline artifact format](baseline-artifact-format.md) for
  the compact baseline `diff_effective_authority` can be compared
  against directly.
- Review the [CLI reference](cli.md) for what is available today.
