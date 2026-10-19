---
type: reference
title: Reference agent repository
tags:
  - reference
  - fixtures
created: 2026-08-23
---

# Reference agent repository

**Status: base scenario written, with runnable agent code behind its artifacts.** This page records
what exists in the separate, public
[`controlloop-security/controlloop-reference-agent`](https://github.com/controlloop-security/controlloop-reference-agent)
repository and the real evidence behind it. It does not itself contain
scanner code or scenario content — see that repository directly for the
files this page describes.

## What that repository is

A companion repository, not a subdirectory of this one, containing a
realistic, deliberately vulnerable agent that anyone can fork and scan
with the `controlloop` CLI.

## `scenarios/order-support-agent/`

A fictional internal customer-support agent for "Widgetworks" (a made-up
online store): it looks up orders, issues refunds, and replies to
support tickets, delegating disputed charges to a separate billing
agent. This is the base scenario every other scenario in that repository
 is expected to build on -- the "currently approved"
starting point they diff against.

### A plausible agent with MCP tools, an OpenAPI-backed service, IAM policy, and a delegated sub-agent

| Requirement | File | Real, verified `controlloop bom` result |
| --- | --- | --- |
| MCP tools | `.mcp.json` | 1 MCP server node (`order-support-tools`) |
| OpenAPI-backed service | `openapi/orders-api.yaml` | 3 `openapi-path` resource nodes, 3 `openapi-operation` tool nodes |
| IAM policy | `iam/policy.json` (AWS-shaped) | 3 `iam-statement` permission nodes |
| Delegated sub-agent | `agent-card.json` (`x-controlloop-delegates-to`) + `sub-agents/billing-escalation/agent-card.json` | 2 `a2a-agent-card` agent nodes, one real `delegates-to` edge between them |

Command and real output, run from the root of this repository against a
checkout of the reference-agent repository at the commit above:

```
$ uv run controlloop bom <path-to-scenarios/order-support-agent>
```

produced an ACBOM with **15 nodes, 7 edges**, including the
`delegates-to` edge above and 3 `invokes` edges from the primary agent
to its tools. Full output is not reproduced here (see that repository's
`scenarios/order-support-agent/README.md`, which documents the exact
regeneration commands); this table is derived from that real run, not
invented.

### Realistic, not a contrived test file

The scenario reads as a small real project would: a plausible fictional
company and domain, an OpenAPI spec with named operations, an IAM policy
with resource-scoped statements (including one realistically over-broad
statement -- `ses:SendEmail`/`ses:SendRawEmail` on `Resource: "*"`,
rather than a scoped ARN -- the kind of thing a real review would flag,
not an obviously synthetic marker), and a `controlloop.yaml` manifest
that is *not* fully in sync with the live agent: `controlloop scan`
against it reports 3 real `policy.undeclared-tools` MEDIUM findings
(the agent's three skills are reachable but not individually declared)
and otherwise passes. That gap is deliberate -- see that scenario's own
README for why a spotless manifest would have been less realistic, not
more.

#### The code behind the artifacts

At first the scenario was only half realistic. It had every artifact
type in the table above and **no agent**: `.mcp.json` pointed at
`./mcp-server/index.js`, which did not exist, and nothing implemented
the three skills the card advertises. Ten configuration files with
nothing consuming them is the definition of a contrived fixture, and it
put the reference implementation of *evidence over declarations* in the
position of shipping declarations with no evidence.

`scenarios/order-support-agent/` now contains a runnable Python agent:
`src/order_support/` (the loop, three tools, the delegation, and an MCP
server), `stubs/` (in-process stand-ins for the orders API, mail, and
the billing sub-agent), `tests/`, and `SCAN.md`. It runs with no API
key, no credential, and no socket.

Each declaration is backed by behavior rather than asserted: the lookup
tool mutates nothing (`read_only: true`), the refund tool moves money in
the ledger (`financial_action: true`), the reply tool leaves through the
SES stand-in (`external_communication: true`), each tool writes the
exact `audit_path` `controlloop.yaml` declares for it, and
`x-controlloop-delegates-to` is resolved at runtime so deleting the
declaration really removes the capability.
`tests/test_artifact_parity.py` reads the committed artifacts rather
than restating them; mutating any of the four artifacts fails a
different, specific test.

**The ACBOM is unchanged where it matters.** Real recorded comparison of
`origin/main` against the branch tip:

```
main    nodes 15  edges 7  diagnostics 0
branch  nodes 15  edges 7  diagnostics 0
node id difference: 0
controlloop gate output: byte-identical, exit 0, PASSED
```

`.controlloop/baseline.json` and every `expected/*.json` are untouched.
`repository.root_digest` does move -- it is a SHA-256 over the sorted
relative paths a scan walked (`controlloop.bom._compute_root_digest`),
so adding twelve files necessarily changes it. That is the field doing
its job, not drift: it names *what was scanned*, and what was scanned
genuinely changed.

**Known limitation, stated in `SCAN.md` rather than papered over.** The
three `a2a-skill` tool nodes and the three `openapi-operation` tool
nodes have no edge between them: ControlLoop does not know that `Issue a
refund` calls `issueRefund`, because no committed artifact says so. Only
the code says it. Static discovery reports what the artifacts declare
and does not infer a call it cannot see.

The agent is also deliberately deterministic rather than model-driven --
it routes on an explicit `kind` field. The capability structure
ControlLoop analyzes is identical either way, and a real model would add
an API key, a network dependency, and a non-reproducible run to a
repository whose value is being forkable and offline.

### The README states plainly that it is deliberately vulnerable

The repository's top-level `README.md` has carried a prominent warning
banner since its first commit. Its "Scenarios" and "Status" sections
list each scenario without replacing the warning.

### No real credentials, no copied proprietary code

"Widgetworks" is fictional; the IAM policy's account ID
(`111111111111`) and every URL are placeholders. No content in the
scenario was copied from any other project.

### A committed baseline with recorded approval provenance

`scenarios/order-support-agent/.controlloop/baseline.json`
(schema `1.1.0`) was generated for real from that exact directory, using
the `controlloop` CLI's own internal
`controlloop.capability.compute.compute_effective_authority` and
`controlloop.baseline.serialization.with_baseline_digest` functions --
**not hand-written**, and not produced by any CLI subcommand, because
none exists yet (see [Baseline artifact
format](baseline-artifact-format.md): *"Nothing writes a baseline yet at
all... no CLI command writes or commits a baseline yet"*). Its
`provenance` block records who approved it (`approver_source:
"supplied"`), when, and at which commit --
`54e7063`, the scenario-content commit immediately before the baseline
was added, matching `repository.commit`.

Real, verified evidence, run from this repository's root against that
scenario directory
with the baseline in place:

```
$ uv run controlloop diff <path>
✓ COMPARED   no differences from baseline

$ uv run controlloop gate <path> --evidence-path evidence.json
✓ PASSED   (3 MEDIUM findings, same as scan; exit 0)

$ uv run controlloop bom <acbom-file> --validate
✓ VALID
```

**Fixed.** Validating the generated `baseline.json`
directly against the packaged
`src/controlloop/schemas/baseline/1.1.0/baseline.schema.json` file
used to raise `EffectiveAuthorityEntry.permitting_identity_id: None is
not of type 'string'` -- the packaged schema required a pattern-matched
string, while the Pydantic model
(`controlloop.capability.models.EffectiveAuthorityEntry`) and
`compute_effective_authority` both allow and produce `None` for an
action edge with no matching identity, by design. This scenario's own
baseline hits exactly that case: its `invokes` edges have no
`authenticates-as` identity. The packaged schema now declares
`anyOf: [nodeId, null]` for that field, matching the already-correct
definition of the identically-named field in the sibling report `1.1.0`
schema, and `TestNullablePermittingIdentityParity` guards it. `1.0.0`
carries the same defect and was deliberately left alone as a frozen
historical version; nothing writes a `1.0.0` baseline today.

## Scenario: ceiling breach with no matching rule

Branch
[`scenario/ceiling-breach`](https://github.com/controlloop-security/controlloop-reference-agent/tree/scenario/ceiling-breach).
The branch is the artifact and is never merged, so the
[end-to-end proof in CI](#end-to-end-proof-in-ci) always has a diff
against `main` to re-run.

The branch adds one skill to the base agent, `update-payment-method`,
named `customer-payment-methods` -- a plausible support request, and
authority the agent's ceiling has prohibited since the base scenario was
written. Every pattern-rule finding it produces is explicitly suppressed
in `controlloop.yaml`, so the ceiling is the only thing left that can
block. Real recorded output:

```
$ controlloop gate scenarios/order-support-agent
✕ DEPLOYMENT BLOCKED

✕ CRITICAL policy.capability-ceiling: agent 'widgetworks-order-support-agent'
  reaches 'customer-payment-methods', which is a prohibited resource or external
  destination under its capability ceiling
    at agent-card.json
```

Exit code `1`. Against `controlloop.amended.yaml` -- the identical
manifest with `customer-payment-methods` removed from
`prohibited_resources`, and the identical `agent-card.json` -- the same
change passes with `✓ PASSED` and exit `0`. The capability did not
change between those two runs; only the declared ceiling did.

`scenarios/order-support-agent/expected/ceiling-breach.json` holds the
committed expectations, produced by a real
`controlloop scan --format json` run.

## The base scenario now declares what its tools do

`scenarios/order-support-agent/controlloop.yaml` declares
`tool_capabilities` at manifest schema `1.1.0`: `Issue a refund` is a
`financial_action`, `Look up an order` reads `confidential` data, and
`Reply to customer` communicates externally. Without that block nothing
in the repository states any of it, and every scan reported `no material
capability is reachable`.

With it, a real scan produces a blast-radius statement for the first
time:

```
$ controlloop scan scenarios/order-support-agent
! WORST REACHABLE  financial-action: widgetworks-order-support-agent can invoke
  Issue a refund

✓ PASSED
```

The same change also added audit paths for the two tools this makes
newly privileged, and corrected the existing `logged_tools` entry from
the skill id (`issue-refund`) to the skill name (`Issue a refund`) --
`logged_tools` matches a discovered node's name, so the old value had
always matched nothing.

The committed baseline was regenerated against that state. It is the
first baseline here that validates cleanly against the packaged baseline
`1.1.0` JSON Schema and loads through the CLI with a verified digest.
(Serializing it with explicit nulls still fails that schema, on
`Evidence`'s optional fields -- a separate known defect of the same kind
as the nullable-identity one above.)

## Scenario: capability expansion

Branch
[`scenario/capability-expansion`](https://github.com/controlloop-security/controlloop-reference-agent/tree/scenario/capability-expansion).
**It is never merged** -- the branch is the artifact, and merging it
would move the expansion into the base scenario.

This is the headline scenario ControlLoop exists to catch. The pull
request adds a tool (the `bulk-refund-orders` skill), a
resource (`POST /orders/bulk-refund`), and an identity change (an IAM
statement granting `payments:CreateDisbursement` and
`payments:ApproveDisbursement` on `Resource: "*"`).

The new tool is declared in `tool_capabilities` and given an audit path
in `logged_tools`, deliberately -- so the block is not a paperwork
failure. The gate objects to the capability itself:

```
$ controlloop gate scenarios/order-support-agent
! WORST REACHABLE  destructive-action: widgetworks-order-support-agent can
  invoke Bulk refund orders

✕ DEPLOYMENT BLOCKED

✕ HIGH     policy.destructive-or-financial-action: Agent gained new direct
  invokes access to 'Bulk refund orders', classified as destructive-action and
  financial-action.
    at agent-card.json
```

Exit code `1`. Two things make this readable: the blast radius worsens
from `financial-action` on `Issue a refund` to `destructive-action` on
`Bulk refund orders`, stated before any finding; and the finding carries
`change_state: added`, so it objects to authority the pull request
*introduces* rather than to refunds existing.

## Scenarios still blocked

The exfiltration-triangle scenario is **still blocked**. Its
sensitive-data-access leg is now expressible via `tool_capabilities`,
but its untrusted-input leg needs a `receives-from` edge, and no adapter
emits one. That needs a separate decision.

The [capability-reduction scenario](#scenario-capability-reduction) was
blocked until [subdirectory
scans](#subdirectory-scans-and-the-merge-base-baseline) landed. It has
to name reduced capabilities by material class. The only wired renderer
for that ran solely on the merge-base path, which a committed baseline
disables, and that path needed the scan target to be the git root while
`tool_capabilities` needs `controlloop.yaml` at the scan root --
mutually exclusive for a scenario subdirectory.

## End-to-end proof in CI

`.github/workflows/reference-scenarios.yml` runs each scenario against
this repository through the **published** Action
(`uses: controlloop-security/controlloop@<ref>`, never a local checkout), on
a daily schedule, on every published release, and on demand. It asserts
verdict, findings, and the blast-radius statement against the scenario's
own committed `expected/` file; a mismatch fails the job, which blocks
the release. It uses `contents: read` and no secret beyond
`GITHUB_TOKEN`, proving the free public path.

Each scenario is one entry in the workflow's `scenario` matrix, so
adding a scenario is a one-entry data change, which is what that
structure exists for. The Action is pinned to `main` because no tagged
release exists yet; pin it to the tag once the first release is cut.

## Keeping a scenario branch current with `main`

Each scenario lives on its own branch, with `main` as the approved base.
Merging `main` into a scenario branch is ordinary maintenance, and
before the repair below it silently destroyed one of them.

### What went wrong

`main`'s history is:

```
6202429 Revert "Merge pull request #1 from .../scenario/ceiling-breach"
09d0675 Merge pull request #1 from .../scenario/ceiling-breach
3c934b7 Merge main: keep the ceiling breach against the declared base
```

The merge base with `scenario/ceiling-breach` is `3c934b7`, where the
scenario content already existed. `main` then acquired that content in
`09d0675` and deleted it in `6202429`. A three-way merge therefore read
main's side as a deliberate deletion and dropped all 261 lines of the
scenario, including its `expected/ceiling-breach.json`. Git behaved
correctly; the history was the trap.

**Only `scenario/ceiling-breach` was affected.** `6202429` reverted that
scenario's content specifically, and `scenario/capability-expansion`'s
content was never on `main` at all -- merging `main` into it deletes
nothing, verified.

**The release gate was never at risk of a silent pass.**
`assert_scenario_expectations.py` already raised on a missing
expectations file (`::error::... does not exist`, exit 1), and
`test_a_missing_expected_file_fails_loudly` already locked that
behavior. A damaged scenario branch turned the job red, not green.

### The repair

One commit on `scenario/ceiling-breach` (`076a9f8`) that merges `main`
and undoes the deletion in the same commit:

```
git checkout scenario/ceiling-breach
git merge main
git revert --no-commit 6202429
git commit
```

This advances the merge base past the revert. `main` is untouched and no
history was rewritten. Verified against a simulated later `main` commit:
afterwards the new content arrives and nothing is deleted.

Do **not** apply the same recipe to `scenario/capability-expansion`.
Reverting `6202429` there would import the *ceiling-breach* content onto
a branch that should not have it. That branch merges `main` cleanly on
its own.

### The guard

`.github/workflows/reference-scenarios.yml` now asserts, before running
the gate, that each scenario still contains its distinguishing content:

| Scenario | Must contain |
| --- | --- |
| `ceiling-breach` | `customer-payment-methods` in `agent-card.json` |
| `capability-expansion` | `bulk-refund-orders` in `agent-card.json` |
| `crewai-incomplete` | `tools_for_environment` in `crew.py` |

A scenario that stops demonstrating what it exists to demonstrate now
fails by name, rather than as a verdict that drifted for reasons a
reader has to reconstruct.

## Scenario: capability reduction

Branch
[`scenario/capability-reduction`](https://github.com/controlloop-security/controlloop-reference-agent/tree/scenario/capability-reduction),
against the `support-triage-agent` base on `main`.

It removes the `purge-ticket-history` skill and drops
`dynamodb:DeleteItem` and `s3:DeleteObject` from the IAM policy. Nothing
is gained. Real recorded output:

```
! WORST REACHABLE  sensitive-data-access: support-triage-agent can invoke Read a
  customer record

✓ PASSED

• REDUCED  destructive-action: support-triage-agent no longer invokes Purge
  ticket history
• REDUCED  sensitive-data-access: support-triage-agent no longer invokes Purge
  ticket history
• REDUCED  write-access: support-triage-agent no longer invokes Purge ticket
  history
✓ PASSED   capability reduced only -- no new authority gained

• no findings
exit 0
```

### Why this scenario has no committed baseline

Deliberate and load-bearing. `.controlloop/baseline.json` carries only
`effective_authority`, not the node and edge graphs that material change
classification needs, so a scenario with one reports `material change:
not evaluated`. Leaving it out lets the merge-base path engage, which
builds a real ACBOM of the directory as it was.

That path was itself unreachable from a scenario subdirectory until
subdirectory scans were supported -- see below.

## Subdirectory scans and the merge-base baseline

A scan root that is a **tracked subdirectory** of a git repository now
resolves a merge base in the repository containing it, and the
materialized baseline tree is scoped to that subpath. A scan of
`repo/scenarios/x` compares `x`-then against `x`-now, never the whole
repository.

Previously any root without its own `.git` was refused outright. The
reasoning was sound -- a plain directory nested in an unrelated
repository must not silently borrow that repository's history -- but the
remedy was too broad, and this repository is a repository of scenario
subdirectories, so every scenario sat on the wrong side of the line.

The distinction moved from *"does this directory have its own `.git`"*
to *"is this directory tracked in the repository that contains it"*,
which is the question that actually separates a scoped comparison from a
borrowed one. Still refused, and still tested:

- a directory that belongs to no repository;
- an **untracked** directory nested inside one;
- a directory that did not exist at the merge-base commit, which has no
  prior state rather than an empty one.

## Scenarios: agent configuration

`scenarios/storefront-agent-config/` (reference-agent pull request #8,
merge commit `208745a`) is a fictional storefront whose coding agents are
configured the way a careful team would configure them: a Prettier hook
after edits, `Bash(npm test)` allowed and `Read(./.env)` denied, a
marketplace pinned to a commit, one MCP server pinned to `1.4.2`, and a
review workflow with a read-only token. Five branches each change one
thing from it. The first four reproduce the incident patterns behind
[the agent authority diff](authority-statement.md). The fifth is a benign
change that must not fail.

| Branch | The change | Recorded verdict | Rule that fired |
| --- | --- | --- | --- |
| `scenario/session-start-harvester-hook` | A `SessionStart` hook that runs `node .github/setup.js` | Deployment blocked | `policy.agent-hook-command-change` (high) |
| `scenario/mcp-package-drift` | `catalog-docs` moves from `1.4.2` to `1.5.0` under the same name | Deployment blocked | `policy.mcp-server-identity-change` (high) |
| `scenario/allow-list-widened` | `Bash(npm test)` becomes `Bash(*)` | Deployment blocked | `policy.widened-permission-rule` (high) |
| `scenario/agent-workflow-id-token` | The review workflow gets `id-token: write` and `--dangerously-skip-permissions` | Deployment blocked | `policy.overprivileged-agent-workflow` (high) |
| `scenario/pinned-plugin-added` | A plugin pinned to a commit is listed in the team marketplace | Passed | `policy.unpinned-agent-component` (low, pinned) |

The hook branch's recorded authority statement is the target sentence:

```text
This change gives Claude Code the power to run `node .github/setup.js` on
every session start (`.claude/settings.json`, hook `SessionStart`). No
approval is recorded.
```

Everything in the scenario is inert. The hook script only exits, the MCP
package and the plugin repository are fictional, and the workflow lives
under `scenarios/`, so GitHub never runs it. No file holds a credential
shape; ControlLoop's redaction primitive was run over every file on
every branch.

Each branch commits `expected/<scenario>.json`, recorded from a real
`controlloop gate` run. Besides the verdict, exit code, and blast radius,
these assert `rules_fired` and the exact `authority_statements`, which
[the assertion script](../../action-scripts/assert_scenario_expectations.py)
reads from the SARIF document's `authorityDelta`. The five rows are in
the [reference-scenario workflow](#end-to-end-proof-in-ci). That
workflow runs the published Action from `main`, so these rows pass only
once the rules they assert are merged there.
