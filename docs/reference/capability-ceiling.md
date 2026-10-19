---
type: reference
title: Capability ceiling declaration
tags:
  - reference
  - manifest
  - capability
created: 2026-08-20
---

# Capability ceiling declaration

**Status: Implemented, including live evaluation.** The schema,
evaluation semantics, and ACBOM projection described below are
implemented and tested library code. Whether a specific discovered
capability actually breaches an effective ceiling is decided by the
`policy.capability-ceiling` rule -- see [Policy
rules](policy-rules.md#capability-ceiling-evaluation).
`controlloop scan` and `controlloop gate` both evaluate a declared ceiling against a live scan today
and block on a violation -- see [Writing a capability
ceiling](../guides/capability-ceiling-guide.md) for worked examples of
real `scan` output. This rule is wired into the shipped rule pack
(`CURRENT_RULE_PACK`) as `RuleMetadata.mandatory=True` -- a repository cannot disable it via
`disabled_rules`, so a ceiling breach cannot be silenced by disabling
pattern rules.

## What this is

A `controlloop.yaml` manifest can declare the maximum authority an
agent may ever hold: resources it may never write, actions it may
never take, external destinations it may never reach, data
classifications it may never touch, and agents it may never delegate
to. Rules (a denylist) always lag novel risk; a ceiling (an allowlist
boundary) does not -- see
[the manifest schema](manifest-schema.md#schema-fields).

## Evaluation semantics

These were documented *before* the implementation they govern.

1. **At most one ceiling per scope.** A `CapabilityCeiling` entry either
   names an `agent` (agent-scoped) or leaves it unset (repository-wide).
   At most one entry may exist per agent name, and at most one may be
   repository-wide. This is enforced structurally by a model validator
   on `ManifestDocument` -- true for every caller, not only a
   YAML-parsing path -- so an ambiguous manifest is rejected with
   `ExitCode.INVALID_INPUT` before any ceiling is evaluated, never
   partially applied.
2. **The stricter of the two is the union, never an override.**
   `effective_ceiling(agent_name, manifest)` combines the
   repository-wide ceiling's prohibitions (if any) with that agent's
   own ceiling's prohibitions (if any) into one effective ceiling: the
   union, category by category. A prohibition is a floor no narrower
   scope can loosen -- an agent-specific ceiling can only ever add
   restrictions relative to the repository default, never remove one.
3. **The ceiling is projected into the ACBOM, not evaluated by the
   projection.** `ceiling_policy_boundary_nodes_and_edges` computes the
   effective ceiling for every agent an owner named (directly, or
   implicitly through a repository-wide ceiling covering every
   discovered agent) and emits one `policy-boundary` node per non-empty
   prohibition category, linked to that agent's node by a
   `constrained-by` edge. This makes the declared boundary visible as
   real graph content -- something a future rule or gate can read --
   without the projection deciding whether any specific discovered
   capability actually crosses it.
4. **An agent named by a ceiling but never discovered is unverified,
   never fabricated.** No agent node is invented to satisfy a ceiling
   declaration; the reconciliation machinery's existing
   `INCOMPLETE-UNVERIFIED-DECLARATION` diagnostic covers this case
   instead, consistent with "unknown, never omitted, and never a
   confident claim about something unverified."

## Example

```yaml
schema_version: "1.0.0"
owner: security-team
ceilings:
  - prohibited_data_classes: [restricted]
    prohibited_external_destinations: [pastebin.com]
  - agent: refund-agent
    prohibited_resources: [customer-payment-methods]
    prohibited_actions: [writes]
    prohibited_delegation_targets: [unapproved-agent]
```

`refund-agent`'s effective ceiling here is the union of both entries:
it may never touch restricted data or reach `pastebin.com` (the
repository-wide floor every agent shares), and additionally may never
write `customer-payment-methods` or delegate to `unapproved-agent`.

## Starter proposal

`controlloop init` (the only CLI command that touches `ceilings` today)
proposes a starter ceiling rather than leaving the section an always-empty
TODO: `controlloop.manifest.ceiling.propose_starter_ceiling` derives real
`CapabilityCeiling` entries from the same discovery `init` already gathers,
using current *direct* effective authority
(`controlloop.capability.compute_effective_authority`, whose documented
scope is direct-only -- see [Effective authority
model](effective-authority-model.md)):

- `prohibited_actions` proposes every one of `reads`/`writes`/`invokes` this
  scan found *no* evidence the agent takes, at any confidence.
- `prohibited_delegation_targets` proposes every other discovered,
  safely-identified agent this agent was not observed delegating to, at any
  confidence.
- `prohibited_resources`, `prohibited_external_destinations`, and
  `prohibited_data_classes` are never proposed: unlike the two categories
  above, they describe an open-world "everything that is not this" that
  static repository discovery cannot enumerate. `init` discloses this
  explicitly in the generated comment rather than rendering a silent, empty,
  seemingly-considered answer.

An action or delegation edge discovered only at `Confidence.LOW` or
`Confidence.UNKNOWN` is excluded from the proposed prohibition (prohibiting
something this scan actually observed, even weakly, could make adopting the
proposal unchanged immediately conflict with this same scan) and is never
silently treated as a confidently reviewed grant either -- it is surfaced
separately, in its own disclosed comment, for a human to review. The whole
section is marked a starting point requiring review, never an approved
envelope; see [`init`](cli.md#init) for the full generated-file behavior.

## Known limitations

- `init` only *proposes* a starting ceiling, per the section above --
  it never evaluates one. `controlloop scan` and
  `controlloop gate` are what evaluate a declared
  ceiling against a live scan and block on a violation, via the
  `policy.capability-ceiling` rule -- see [Policy
  rules](policy-rules.md#capability-ceiling-evaluation)
  for its own disclosed scope boundaries, including a bare disallowed
  delegation with no further discovered capability, and how
  `prohibited_resources`/`prohibited_external_destinations` are
  matched.
- "External destinations" are free-form identifier strings; there is no
  canonical, structured domain/URL type in this codebase yet to reuse.
- The starter proposal only covers direct effective authority, not the
  bounded transitive capability paths added later; a
  multi-hop capability (for example, delegation-then-invoke) is not
  reflected in the proposed ceiling.

## Next steps

- Review [controlloop.yaml manifest schema](manifest-schema.md) for the
  full schema this ceiling extends.
- Review [`init`](cli.md#init) for how the starter proposal is generated
  and rendered.
- Review [Adapter status](../adapters/readme.md) for what discovery
  currently produces `policy-boundary` projection runs against.
