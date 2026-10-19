---
type: reference
title: Deterministic rule engine
tags:
  - reference
  - policy
created: 2026-08-20
---

# Deterministic rule engine

**Status: Implemented foundation.** The model and evaluation logic
described below are implemented and tested library code. **Ten rules
are registered** (see [Policy rules](policy-rules.md)). Expiring
suppressions are a suppression mechanism, not a rule, and are not
included in that count. `controlloop scan` and `controlloop gate` both
consume `ALL_RULES` for every non-disabled rule -- see the [CLI
reference](cli.md#scan). This page is not always updated in the same
change as every later individual rule; the current rules are listed on
[Concrete policy rules](policy-rules.md).

## What this is

`controlloop.policy.engine.evaluate` runs a set of rules against
explicit evidence and explicit policy, with no side effects and no
model in the verdict: a rule reads an ACBOM, optionally a `DiffResult`,
and optionally a parsed `controlloop.yaml` manifest, and reports zero
or more observations. It is the policy engine component of the local
CLI.

## The model

```python
class RuleObservation:  # controlloop.policy.models
    rule_id: str  # SafeIdentifier, e.g. "policy.undeclared-tools"
    message: str  # SafeText
    evidence: tuple[Evidence, ...]  # min 1, reuses the ACBOM's own Evidence type


class RuleContext:  # a frozen dataclass, never serialized
    acbom: ACBOMDocument
    policy_version: str  # SafeText; opaque, caller-supplied
    diff: DiffResult | None = None
    manifest: ManifestDocument | None = None


class Rule:  # a frozen dataclass: id + pure function
    id: str  # SafeIdentifier
    evaluate: Callable[[RuleContext], tuple[RuleObservation, ...]]


class EvaluationBounds:  # a frozen dataclass, mirrors TraversalBounds
    max_rules: int = 1_000  # deterministic proxy for "bounded in time"
    max_observations: int = 10_000  # deterministic proxy for "bounded in memory"


class EvaluationResult:  # controlloop.policy.models
    observations: tuple[RuleObservation, ...]
    diagnostics: tuple[Diagnostic, ...]  # reuses controlloop.acbom.models.Diagnostic
    is_incomplete: bool  # property: any(d.incomplete for d in diagnostics)
```

`evaluate(rules, context, *, bounds=None) -> EvaluationResult` is the
one entry point.

## Why `RuleObservation`, not `Finding` (deliberate, disclosed)

A rule's output is naturally called a "finding," but the real finding
model -- rule identifier, rule version, severity, confidence, affected
agent, capability path, change state, remediation text, a documentation
URL -- is separate, and depends on this engine rather than the reverse. `RuleObservation` is deliberately the minimum
shape this engine needs to prove its own determinism and ordering
guarantees: a rule ID, a message, and evidence. The [finding
model](finding-model.md) is built alongside this type rather than
replacing it; naming this type `Finding` would have prejudged that
design.

## A rule is a pure function, not a class

A `Rule` pairs a stable, namespaced `id` with an ordinary function,
`def evaluate(context: RuleContext) -> tuple[RuleObservation, ...]`.
There is no base class to subclass and no required inheritance --
matching every other "evaluate explicit data against explicit data"
primitive already in this codebase (`compute_diff`,
`compute_effective_authority`, `classify_material_capability`).

## No side effects, structurally enforced

Two structural checks exist, both using the AST-based technique
`tests/test_diagnostics.py` and `tests/test_redaction.py`
already established for other modules in this codebase (parse a
module's own source, walk its `import` statements, assert a forbidden
set is absent):

1. `controlloop.policy.engine` and `controlloop.policy.models`
   themselves are checked, test-only, to prove the engine's own
   machinery never imports `subprocess`, `socket`, `os`, `shutil`,
   `urllib`, `http`, or any of today's known LLM SDK names
   (`openai`, `anthropic`, `google.generativeai`, `cohere`,
   `langchain`, `langchain_openai`, `transformers`), and contains no
   bare `open(...)` call.
2. `evaluate()` itself runs the identical check, **at runtime**,
   against the defining module of every `Rule.evaluate` callable it is
   given, once per unique module, before invoking any rule --
   `RuleSafetyError` is raised, naming the rule ID and the forbidden
   import, rather than ever calling that rule. A rule whose `evaluate`
   callable has no real resolvable module (for example, dynamically
   built code) is rejected the same way: an unverifiable rule is
   refused, never silently trusted.

This is disclosed as a best-effort, defense-in-depth guard, not a
sandbox: the forbidden-import list is closed and necessarily
incomplete (a brand-new LLM SDK name it does not yet know about would
not be caught on day one), and source inspection alone cannot preempt
a single rule's own unbounded in-process loop -- it can only make an
*external* file, process, or network operation structurally
unreachable through an import. See `controlloop.policy.engine`'s own
module docstring for the full reasoning.

## Order cannot affect the result

`evaluate()` always canonicalizes execution order to `sorted(rule.id)`
internally, regardless of the order the caller's `rules` tuple arrives
in. This makes the guarantee hold even when a bound (below) is smaller
than the number of supplied rules: *which* rules actually run is a
deterministic function of their own IDs, never of caller-supplied
ordering, so a shuffled and an unshuffled call to `evaluate()` produce
byte-identical results in every case -- including a truncated,
honestly-incomplete one.

Every `RuleObservation` collected from every executed rule is also
sorted deterministically before being returned, by
`(rule_id, message, evidence)`, independent of the order any single
rule returned its own observations in.

## Bounded evaluation

`EvaluationBounds` uses two count-based proxies rather than
wall-clock, since a wall-clock bound is flaky under CI load and is not
itself deterministic:

- `max_rules` -- the maximum number of rules actually invoked in one
  `evaluate()` call.
- `max_observations` -- the maximum number of `RuleObservation`s
  retained in the final result, a global, cumulative cap mirroring
  `TraversalBounds.max_total_bytes`'s own role for repository
  traversal.

Exceeding either bound adds one `INCOMPLETE-BOUND-EXCEEDED` diagnostic
(reusing `controlloop.acbom.completeness`'s existing registry code
unchanged) and marks `EvaluationResult.is_incomplete` `True`, rather
than silently returning a partial answer. Defaults (`max_rules=1_000`,
`max_observations=10_000`) are generous, disclosed starting points, not
approved business thresholds.

**Known limitation:** a step-count bound caps *how many* rules run and
*how many* observations are kept; it cannot stop a single rule's own
unbounded internal loop mid-execution. Doing so would require real
preemption (a thread, process, or signal-based timeout), which this
engine deliberately does not add -- it would either reintroduce the
same CI flakiness the count-based bound exists to avoid, or require
exactly the subprocess capability the engine forbids. The structural safety
check above is this engine's actual defense here: it makes an
unbounded *external* operation (a hung network call, a blocking
subprocess) structurally unreachable for a conforming rule, leaving
only a rule's own in-process CPU loop as a residual, disclosed risk.

## A rule's own exception propagates (deliberate, disclosed)

Unlike an adapter -- which parses untrusted, malformed real-world
repository content and is therefore isolated so one failed artifact
does not discard unrelated valid discoveries -- a rule here only ever
receives already-validated canonical models. A rule raising is a
defect in that rule, not a data-quality problem; `evaluate()` lets it
propagate uncaught rather than converting it into a silent diagnostic
that could mask a real bug in this product's own deterministic core.

## Determinism

Given an identical `rules` set (in any order) and an identical
`RuleContext`, `evaluate()` always returns a byte-identical
`EvaluationResult`. `policy_version` is threaded through unchanged and
opaque -- this engine does not define what produces it or what format it
takes; [Rule pack versioning](rule-pack-versioning.md)
later defined an independent `RulePack`/version/fingerprint registry
without changing `policy_version` itself, which remains opaque here.

## Coding-agent hosts are hidden from the original rules

An ACBOM can contain coding-agent hosts such as Claude Code, with their
hooks, helper commands, plugins, skills, subagents, permission rules,
and agent-running workflows: the nodes whose subtype is one of `host`,
`subagent`, `hook`, `helper-command`, `plugin`, `marketplace`, `skill`,
`workflow-runtime`, or `permission-rule`.

The ten rules that predate the coding-agent host rules cover the agents
a repository ships, and they do not see these components. Each such rule
gets a view
of the evidence with them, the edges touching them, and the diff entries
about them removed. A formatter hook is therefore never reported as "a
privileged tool with no logging path", and a repository's first scan is
never blocked on authority it has always had. A rule reads them only if
it declares `reads_agent_authority=True`; the coding-agent authority
rules do.

A document with no such components, which includes every document
produced before coding-agent hosts were recorded, passes through
unchanged, so existing results did not change. MCP servers are not hidden: a server reachable only from a
coding-agent host is, to the original rules, reachable from nothing,
exactly as it was before the host was recorded.

## Known limitations

- Ten rules are registered (`controlloop.policy.rules.ALL_RULES` --
  undeclared tools, newly introduced destructive or financial action,
  broad or wildcard permission, sensitive write without declared
  approval, missing action logging on a privileged tool, unauthorized
  delegation, unresolved dynamic tool registration, capability ceiling
  evaluation, exfiltration triangle detection, hardcoded secret
  material). See [Concrete policy rules](policy-rules.md). Expiring
  suppressions are a suppression mechanism, not a rule, and are not
  included in that count.
- The real finding model exists (see [Finding model](finding-model.md)),
  and every registered rule produces `Finding`s alongside its
  `RuleObservation`s -- hardcoded secret material produces a
  repository-scoped `Finding` with no affected agent, using the optional
  `affected_agent`/`capability_path` fields. `RuleObservation` itself is
  unchanged and remains the type `Rule.evaluate` returns.
- [Rule pack versioning](rule-pack-versioning.md) defines an independent
  rule-pack registry; `policy_version` here is still an opaque string
  with no defined format or compatibility policy tying it to that
  registry. `CURRENT_RULE_PACK` carries every registered rule, each with
  a decided `RuleMetadata.mandatory` flag (see
  `controlloop.policy.rules`'s own module docstring).
- `controlloop scan` and `controlloop gate` both consume this engine via
  `ALL_RULES` (see [CLI reference](cli.md#scan)).
- The forbidden-import list behind the no-side-effects and no-model
  guarantees is a maintained, disclosed, necessarily incomplete list,
  not a sandbox.
- A single rule's own unbounded internal loop is not preempted (see
  "Bounded evaluation," above).

## Next steps

- Review [Diff output format](diff-output-format.md) for `DiffResult`,
  one of the two explicit-evidence inputs a `RuleContext` may carry.
- Review [Capability ceiling declaration](capability-ceiling.md) for
  `ManifestDocument`, the explicit-policy input a `RuleContext` may
  carry.
- Review the [CLI reference](cli.md) for what is available today.
