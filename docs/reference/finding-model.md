---
type: reference
title: Finding model
tags:
  - reference
  - policy
created: 2026-08-20
---

# Finding model

**Status: Implemented foundation.** The model, its stable identity
computation, and its human/JSON/SARIF-result rendering described below
are implemented and tested library code. **Every registered rule
produces real `Finding`s** (see [Policy rules](policy-rules.md)). `controlloop scan` and `controlloop gate` both
consume every registered rule's `findings()` (see the [CLI
reference](cli.md#scan)). Schema `1.1.0` made
`affected_agent`/`capability_path` optional together, for a repository-
scoped finding with no single affected agent -- see "`affected_agent`/
`capability_path` are optional" below.

## What this is

`controlloop.policy.engine.evaluate` (the [deterministic rule
engine](rule-engine.md)) reports a `RuleObservation` per rule: a
rule ID, a message, and evidence -- the minimum shape needed to prove
that engine's own ordering and determinism guarantees. A `Finding`,
defined in `controlloop.findings`, is what a `RuleObservation` becomes
once the additional context a rule invocation carries is attached:
rule identifier and version, severity, confidence, the affected agent,
evidence, a capability path, change state against a baseline,
remediation text, and a documentation URL -- everything a reviewer
needs to judge it without opening the codebase.

## The model

```python
class Finding:  # controlloop.findings.models
    schema_version: str  # SemanticVersion, "1.1.0" today
    id: str  # FindingId: "clp:finding:sha256:<hex>"
    rule_id: str  # SafeIdentifier
    rule_version: str  # SemanticVersion; shape only, see below
    message: str  # SafeText, carried from RuleObservation
    severity: FindingSeverity  # info | low | medium | high | critical
    confidence: Confidence  # reused from controlloop.acbom.models
    affected_agent: str | None  # AgentNodeId, or None (repository-scoped)
    evidence: tuple[Evidence, ...]  # reused EvidenceCollection, min 1
    capability_path: CapabilityPath | None  # reused, or None (repository-scoped)
    change_state: (
        FindingChangeState  # added | removed | changed | unknown | not-compared
    )
    remediation: str  # SafeText
    documentation_url: str  # https://..., shape-validated, never fetched
```

Every field is required with no default except `affected_agent` and
`capability_path`, both defaulting to `None` together (schema `1.1.0`
-- see "`affected_agent`/`capability_path` are optional" below). Omitting a required field, supplying one with an
invalid shape, or supplying exactly one of `affected_agent`/
`capability_path` alone, all raise `pydantic.ValidationError` rather
than producing a partially-populated result. A `model_validator`
enforces this: both `None` (repository-scoped, valid), both present
with `affected_agent == capability_path.agent_id` (agent-scoped, valid
-- the original behavior), or exactly one present (always
rejected).

`controlloop.findings.models.finding_from_observation` builds a
`Finding` from one `RuleObservation` plus the context only a caller
has:

```python
finding_from_observation(
    observation,               # controlloop.policy.models.RuleObservation
    *,
    rule_version, severity, confidence, affected_agent,
    capability_path, change_state, remediation, documentation_url,
) -> Finding
```

`rule_id`, `message`, and `evidence` are copied from `observation`
unchanged; `id` is always computed via `finding_id` (below) before
construction. This is a convenience constructor, not the only valid
one -- a `Finding` may also be built directly, supplying an
already-computed `id`, the same relationship
`controlloop.acbom.identity.node_id` has to direct `Node(...)`
construction.

## Why `Finding`, not a change to `RuleObservation` (deliberate, disclosed)

`controlloop.policy.models.RuleObservation` is unchanged. Its own
docstring already names `Finding` as its successor: `Finding` is what
an observation becomes once a rule invocation's own judgment
(severity, confidence, which agent, which capability path, remediation
guidance) is attached -- none of which is inferable from a bare rule
ID, message, and evidence. `message` is carried onto `Finding` because
without it, a `Finding` would name a rule and a severity but never
describe, in words, what was actually found, undermining this
document's own opening claim.

## Severity: a minimal, disclosed placeholder scale (deliberate, disclosed)

`FindingSeverity` is a five-member scale (`info`, `low`, `medium`,
`high`, `critical`) in ascending declared order. **No ranking function,
comparison operator, or configurable gate threshold is defined here.**
Which severities fail a build, which rules are mandatory, and how a
repository configures that are all left to [Severity, confidence, and
thresholds](policy-thresholds.md), which depends on this model rather
than duplicating it. `confidence` reuses
`controlloop.acbom.models.Confidence` verbatim -- the same enum every
node, edge, diagnostic, and capability path in this codebase already
uses -- rather than a second confidence vocabulary.

## `rule_version`: a validated shape, not a rule-pack registry (deliberate, disclosed)

`rule_version` reuses `controlloop.acbom.models.SemanticVersion`, the
same annotated type `ACBOMDocument.schema_version` already uses:
semantic-version shape validation only, unchanged by [Rule pack
versioning](rule-pack-versioning.md), which defines the independent
rule-pack registry (`RulePack`, its own name and version, a content
fingerprint, and `--version` reporting) without connecting it to this
field or to finding identity -- `rule_version` here
remains exactly analogous to `RuleContext.policy_version` in the rule
engine: threaded through and shape-validated, opaque otherwise.

## `capability_path`: reused directly, now optional in lockstep with `affected_agent` (deliberate, disclosed)

`Finding.capability_path` reuses `controlloop.capability.models.
CapabilityPath` unmodified. Originally required and unconditional: "this
works specifically because `affected_agent` is also required: every
finding is inherently agent-scoped, so a capability path... can always
be constructed." A real counter-example was found -- a hardcoded
secret in a shared file has no natural single-agent attribution -- and
it was resolved by making `affected_agent` optional. `capability_path`
becomes optional in lockstep as a necessary consequence, not as an
independent design choice: `CapabilityPath.agent_id` is itself a
required real agent node ID, so a repository-scoped finding structurally
cannot carry one. When `affected_agent` is present, `capability_path`
still works exactly as before -- a path from that agent to the resource,
tool, identity, permission, or data-class the finding concerns, even a
single-hop path (`CapabilityPath.hops` already requires at least one
hop; no multi-hop traversal is mandatory).

## `affected_agent`/`capability_path` are optional (schema `1.1.0`)

A repository-scoped `Finding` (both fields `None`) is now valid --
appropriate for a hardcoded secret in a shared file with zero, one, or
many potential agent readers, where "which agent" is not the right
question the way it is for every other rule in this package (undeclared
tools, delegation, broad permissions -- all inherently agent-scoped).
This is an additive, backward-compatible change: `schema_version` moves
from `"1.0.0"` to `"1.1.0"` (MINOR, per [Schema
versioning](schema-versioning.md)'s general vocabulary -- a new optional
field, nothing removed, renamed, retyped, or newly rejected). Every one
of the other nine original rules still always supplies both fields,
unaffected by this change; `controlloop.policy.rules.hardcoded_secrets`
was, when the change was made, the one rule that constructs a
repository-scoped `Finding`.

Stable identity (below) needed a real answer for this new case too:
`finding_id` gains one additive parameter, `evidence_paths`, consulted
only when `affected_agent is None`, populated automatically by
`finding_from_observation` from the observation's own evidence. The
agent-scoped identity payload is completely unchanged by this addition.

## `change_state`: `ChangeKind`'s four states, plus one honest fifth (deliberate, disclosed)

`FindingChangeState` mirrors `controlloop.diff.models.ChangeKind`'s
four members one-for-one (`added`, `removed`, `changed`, `unknown`)
without importing or modifying that type, and adds a fifth,
`not-compared`. `RuleContext.diff` is `DiffResult | None` -- a
rule may run with no baseline at all, and every finding still needs a
`change_state`. Collapsing "no baseline was compared" into
`ChangeKind.UNKNOWN` would contradict that member's own documented
meaning (a specific claim about a completed comparison whose
confidence dropped, not an absent one) and would violate this
repository's "unknown, never omitted" invariant -- the same reasoning
`controlloop.diff.report.ComparisonScope` already applied, in the same
non-invasive way, to keep "not evaluated" distinct from "confirmed
unchanged."

## `documentation_url`: validated shape, never fetched (deliberate, disclosed)

A new `DocumentationUrl` type requires an `https://` prefix, no control
characters, and a bounded length. ControlLoop never fetches the URL:
verifying that a finding's documentation URL actually resolves is a
separate concern.

## Finding identity

`controlloop.findings.identity.finding_id` reuses
`controlloop.acbom.identity`'s exact canonicalization scheme: a fixed
identity version, a fixed namespace (`"controlloop.finding"`), a
canonical JSON payload sorted and hashed with SHA-256, rendered as
`clp:finding:sha256:<hex>`.

Identity material is deliberately narrow:

- `rule_id`, `affected_agent`
- `capability_path.agent_id`, `.target_id`, `.target_type`, and the
  ordered tuple of every hop's `edge_id`

**Deliberately excluded**, each for a disclosed reason: `evidence`
(mutable provenance, the same exclusion node/edge identity already
applies); `severity`/`confidence` (a policy or analysis change must not
mint a "new" finding for the same issue); `change_state` (differs by
definition across different baseline comparisons -- including it would
make "the same issue is recognizable between scans" impossible for the
most common case); `message`/`remediation`/`documentation_url`/
`rule_version` (presentation and version text, not semantic identity).

`rule_version`'s exclusion is a deliberate judgment call: a rule's
version increment describing a still-detected issue does not, in this
design, create a new issue. [Rule pack
versioning](rule-pack-versioning.md) has not yet defined how a rule's
version relates to identity and may revisit this.

**Repository-scoped identity.** When `affected_agent
is None`, none of the agent-scoped identity material above is
available -- there is no agent and no capability path. `finding_id`
falls back to `evidence_paths`, the finding's own sanitized
repository-relative evidence paths (sorted, deduplicated), the closest
allowlisted, non-mutable anchor left -- the same *category* of identity
material (`source_path`) `controlloop.acbom.identity.SemanticIdentity`
already treats as approved for a node, reused here for the one case
that has nothing else. **Disclosed limitation:** line numbers still
never participate, so two distinct secrets of the *same* detected
pattern in the *same* file collapse to one finding identity -- a real,
disclosed accuracy limitation, not a fabricated per-occurrence
precision this codebase's own identity constraints (no line numbers, no
source content) cannot honestly provide. The agent-scoped payload shape
is completely unchanged by this addition.

## Serialization across human, JSON, and SARIF

- **JSON** -- ordinary `Finding.model_dump_json()`. No dedicated
  function; this is the same deterministic Pydantic serialization every
  other computed-report model in this codebase already uses.
- **Human** -- `controlloop.findings.rendering.render_finding_text`
  follows `controlloop.diagnostics.render_text`'s glyph-and-label
  convention: one summary line, then one location line per evidence
  entry carrying a `path`, rendered through
  `controlloop.redaction.source_reference` (never raw content).
- **SARIF** -- `controlloop.findings.rendering.finding_to_sarif_result`
  returns **one SARIF `result` object shape only** -- not a complete
  SARIF log document. `runs[].tool.driver.rules[]`,
  `originalUriBaseIds`, and the rest of that document-level structure
  are built separately -- see [SARIF export
  format](sarif-export-format.md).
  `severity` maps to SARIF's `level`: `info`/`low` -> `note`,
  `medium` -> `warning`, `high`/`critical` -> `error`. Every model field
  without a native SARIF `result` slot (finding ID, rule version,
  confidence, affected agent, capability path, change state,
  remediation, documentation URL) is carried in a
  `properties.controlloop` bag, SARIF's own documented open extension
  point.

"Serialize identically" is read as: the same underlying data is present
and mutually consistent across all three renderings -- not
byte-identical text across three structurally different formats. Every
evidence entry with a `path` renders as one location in all three
formats; an entry with only a `document_digest` has no location to
render in any of them and is simply omitted, not raised as an error.

## Privacy

No new raw-content path exists: `message`/`remediation` are `SafeText`
(the same control-character-excluding, length-bounded type used
throughout this codebase), and `evidence` reuses
`controlloop.acbom.models.EvidenceCollection`/`Evidence` verbatim --
structurally incapable of carrying file content. `controlloop.findings`
is proven, by the same `ast`-based structural check
`test_diff_module_never_reads_raw_content` established, to import none
of `pathlib`, `subprocess`, `socket`, `os`, `shutil`, `urllib`, `http`
and to contain no bare `open(...)` call. A canary test plants a
secret-shaped value inside a `Finding`'s `message` and `remediation`,
renders it as human text, JSON, and a SARIF result inside
`controlloop.redaction.redirected_streams`, and asserts the planted
value never survives any of the three -- proving the CLI's single
enforced redaction boundary still catches a hypothetical careless rule
author.

## Known limitations

- Every registered rule produces real `Finding`s (see [Concrete policy
  rules](policy-rules.md)). Expiring suppressions are a suppression
  mechanism, not a rule.
- `FindingSeverity` itself is still a field shape only, defined entirely in
  this module. The ranking/threshold/confidence-downgrade decision core now
  exists as a separate, later layer -- see [Severity, confidence, and
  thresholds](policy-thresholds.md) -- and `scan`/`gate`
  both consume it via `evaluate_gate`; the rules above still each
  choose their own fixed severity value per finding, which the threshold
  then classifies as blocking or warning.
- A rule-pack versioning scheme now exists as a separate registry -- see
  [Rule pack versioning](rule-pack-versioning.md) -- but
  `rule_version` itself is still shape-validated and otherwise opaque, and
  is deliberately excluded from finding identity; the two are not
  connected. `CURRENT_RULE_PACK` carries every registered rule with a
  decided `RuleMetadata.mandatory` flag per rule.
- `controlloop scan` and `controlloop gate` both consume this via
  `ALL_RULES` (see [CLI reference](cli.md#scan)).
- Repository-scoped finding identity collapses two
  distinct secrets of the same detected pattern in the same file into
  one finding identity -- see "Finding identity" above.
- `finding_to_sarif_result` returns one SARIF `result` object, not a
  complete SARIF log document.
- A finding's documentation URL is validated for shape only and is
  never fetched or verified to resolve.

## Next steps

- Review [Deterministic rule engine](rule-engine.md) for
  `RuleObservation`, the type `finding_from_observation` consumes.
- Review [Material capability taxonomy](material-capability-taxonomy.md)
  and [Effective authority model](effective-authority-model.md) for
  `CapabilityPath`, reused unmodified as `Finding.capability_path`.
- Review [Diff output format](diff-output-format.md) for `ChangeKind`,
  the type `FindingChangeState` mirrors.
- Review [Severity, confidence, and thresholds](policy-thresholds.md) for
  the ranking/threshold decision core built on `FindingSeverity`.
- Review the [CLI reference](cli.md) for what is available today.
