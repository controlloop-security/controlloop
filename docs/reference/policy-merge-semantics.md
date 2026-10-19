---
type: guide
title: How organization and repository policy combine
tags:
  - reference
  - platform
  - policy
created: 2026-09-01
---

# Tighten your repository's policy without weakening your organization's

A ControlLoop organization publishes a policy bundle. A repository can
have its own policy too. This page explains exactly how the two combine —
which changes a repository may make, which it may not, and what happens
when it tries.

The rule in one line: **a repository may tighten, never loosen.**

> **Availability:** Implemented on both sides. The merge runs server-side
> when a scan envelope is ingested, and the resulting effective policy is
> recorded on that scan. The CLI implements the same merge locally, so a
> Team gate enforces the merged policy in your CI and sends
> its repository delta for the server to re-merge and record. Local
> Community scanning is unaffected and needs no network.

## Why the asymmetry exists

An organization's mandatory rule is worthless if a repository can switch
it off in its own configuration. The opposite failure is just as bad: a
rule that silently stayed on while the repository believed it was off
produces a verdict nobody can explain.

So neither happens. A weakening attempt is **refused with an
explanation**, and the refusal names the rule and the organization policy
version that forbade it.

## What counts as tightening

Applied without comment:

| Change | Why it tightens |
| --- | --- |
| Raise a rule's severity floor | More findings reach the threshold |
| Disable a rule the organization did **not** mark mandatory | Removes an allowance the repository had been granted |
| Add a rule the organization never configured | Adds a check that did not exist |
| Remove an approved-component entry | Fewer components are sanctioned |

## What counts as weakening

Refused, every time:

| Change | Why it weakens |
| --- | --- |
| Lower a rule's severity floor | Findings that would have blocked now pass |
| Disable a rule the organization marked **mandatory** | Removes a check the organization requires |
| Add an approved-component entry | This is precisely how an unsanctioned dependency becomes invisible |

An unrecognized severity value is also refused. It cannot be shown to be
tightening, and "unknown, therefore allowed" is the wrong default for a
security control.

## Approved-component constraints

> **Availability:** Implemented in the platform's merge and, with merge
> semantics `1.1.0`, in the CLI's gate, which runs the same golden
> vectors (the CLI's copy of the platform's contract is
> `tests/fixtures/contract/policy_merge_vectors.json`).

An approved-component entry can carry constraints: `package`,
`version_range`, `digest`, `command_pattern` (hook entries only), and
`pin_required`. See [Unsanctioned agent
component](policy-rules.md#unsanctioned-agent-component) for how
ControlLoop decides a component is unsanctioned. A repository entry is paired with the organization entry that has the
same `type` and `name_pattern`.

**A repository entry inherits every constraint it does not restate.** The
effective entry starts from the organization's and can only become
narrower. Leaving a field out of the repository entry keeps the
organization's value, so a constraint can never be dropped by omission.

| Field | A repository may | A repository may not |
| --- | --- | --- |
| `package` | Set one where the organization set none | Change it to a different package |
| `version_range` | Set a range inside the organization's range, or any range where the organization set none | Set a range that reaches outside the organization's range |
| `digest` | Set one where the organization set none, or extend the organization's digest prefix | Set a digest that does not start with the organization's |
| `command_pattern` | Set a pattern the organization's pattern covers | Set a pattern the organization's pattern does not cover |
| `pin_required` | Set it to `true` | Set it to `false` where the organization says `true` |

Two definitions make the table exact:

- **One range is inside another** when its lower bound is at or above the
  other's lower bound and its upper bound is at or below the other's upper
  bound, and where a bound is equal it is not more inclusive. `1.0.x` is
  inside `>=1.0.0 <2.0.0`; `>=1.0.0 <=2.0.0` is not inside
  `>=1.0.0 <2.0.0`, because it adds `2.0.0`.
- **One command pattern covers another** when it is exact and the other
  is identical, or it ends in `*` and the other begins with the text
  before the `*`. `node .github/*` covers `node .github/setup.js` and
  `node .github/hooks/*`; it does not cover `node scripts/setup.js`.

Removing a whole entry and adding an entry the organization does not list
are unchanged: removing narrows and is applied, adding widens and is
refused.

A refusal names the entry and the organization version:

```json
{
  "code": "policy_weakening_rejected",
  "rule_id": "approved-component:mcp_server:github",
  "organization_bundle_version": "7",
  "message": "Repository policy widens the version range of the mcp_server `github` beyond what organization policy version 7 approves. A repository may narrow an approved component, never widen it."
}
```

The platform's contract includes vectors that list organization and
repository entries with the effective list and the refusals they must
produce (the CLI's copy is
`tests/fixtures/contract/policy_merge_vectors.json`). The platform runs
every vector, and the CLI gate runs the same file, so the two cannot disagree about an effective approved-components
list.

### What publishing records

Publishing a bundle records `policy.published` in the audit log. Next to
the version, it counts how the approved components changed from the
previously published version:

- `approved_added`: entries the previous version did not list;
- `approved_removed`: entries this version no longer lists;
- `approved_narrowed`: entries with the same type and name pattern whose
  constraints only tightened;
- `approved_widened`: entries with the same type and name pattern where
  any constraint loosened or was dropped.

## What a refusal looks like

```json
{
  "error": {
    "code": "policy_weakening_rejected",
    "message": "Repository policy disables `capability.new-tool`, which organization policy version 7 marks mandatory. Repository policy may tighten a mandatory rule but never disable it.",
    "details": {
      "rejections": [
        {
          "code": "policy_weakening_rejected",
          "rule_id": "capability.new-tool",
          "organization_bundle_version": "7",
          "message": "Repository policy disables `capability.new-tool`, ..."
        }
      ]
    }
  }
}
```

The message names the rule and the version, so it says what to change and
what governs it. Every weakening in the configuration is reported, not
just the first.

## Reproducibility

The merge is a pure function of `(organization bundle, repository
delta)`. It reads no clock, no database, and no environment, and its
output does not depend on the order rules are listed in. Two runs with
the same inputs produce identical results.

That is what makes a recorded verdict re-derivable: a scan stores the
organization bundle version, the merge-semantics version, and the
resulting effective policy, so months later you can reconstruct exactly
what was enforced and why.

## Precedence, stated once

1. The organization bundle is the floor.
2. The repository delta may raise the floor, never lower it.
3. A published organization bundle version is immutable — a change is a
   new version, so the version recorded on a scan always means the same
   thing.

## What a rule configuration carries

A rule inside a bundle carries four things a client can act on, plus the
metadata the API attaches on read:

| Field | Meaning |
| --- | --- |
| `rule_id` | The scanner's own identifier, e.g. `policy.undeclared-tools`. |
| `enabled` | Whether the rule runs at all. |
| `severity_floor` | How bad a finding must be before the rule reports it. |
| `action` | What a reported finding does to the verdict. |
| `mandatory` | Whether a repository may weaken this rule in its own policy. |
| `name`, `description` | Attached on read from the rule catalogue; never stored in the bundle. |

`severity_floor` and `action` answer different questions and both
matter. The first is a threshold for reporting; the second is a
consequence.

### The four actions

`action` uses the gate's own verdict vocabulary, so there is no second
set of words to learn:

| Action | Effect |
| --- | --- |
| `fail` | A finding blocks. This is the default, and what every bundle written before the field existed does. |
| `require_review` | A finding marks the scan as needing a human. |
| `warn` | A finding is reported without blocking. |
| `pass` | The rule runs and reports, but never affects the verdict. |

`pass` is **monitor mode**, and it is not the same as `enabled: false`.
A disabled rule does not run and produces nothing; a rule set to `pass`
runs, and its findings appear in scans, reports, and the fleet view
while never failing a build. That is the state to use when adopting a
new rule across a fleet before enforcing it.

> **Availability:** `action` is carried by the contract and stored with
> the bundle today. **The CLI gate does not honor it yet.** Until then a gate applies its existing behavior
> regardless of what `action` says, so setting a rule to `warn` or
> `pass` does not yet change a build outcome.

## What a project's gate behaviour means

A project reports `gate_behavior`, and it is **derived, never
configured here**:

| Value | Meaning |
| --- | --- |
| `fail_closed` | At least one enabled rule blocks — its action is `fail` or `require_review`. |
| `fail_open` | A policy governs the project and none of its enabled rules blocks. Findings are reported; builds go green. |
| `ungoverned` | No published bundle governs this project. Nothing here can block. |

`ungoverned` is deliberately its own state rather than folded into
`fail_open`: "nothing is configured" and "configured not to block" are
different facts, and an admin needs to tell them apart.

The value is computed from the effective policy and cannot be set
through the API. `controlloop.yaml` and the organization's bundle stay
the only places gate behaviour is decided, so what the dashboard reports
cannot drift from what the gate does.

## Rule names

A client never needs a hardcoded rule catalogue.
`GET /api/v1/organizations/{organization_id}/policy-rules` lists every
rule the scanner can evaluate, with its name, description, and whether a
repository may disable it. The same name and description are attached to
each configured rule when a bundle is read.

That metadata is **generated from the scanner's own rule pack** and
guarded by a test that regenerates and compares, so a rule renamed in
the scanner cannot keep its old name in the API. Names are derived from
the rule id rather than authored separately, for the same reason.

## Bundle bindings

A bundle reports which projects it governs:

```json
"bindings": { "tracking_latest": 6, "pinned": 2, "total": 8 }
```

`GET .../policy-bundles/{bundle_id}/bindings` lists them per project,
paginated.

Only the **newest published** bundle reports projects under
`tracking_latest`, because that is the version a project on `latest`
actually follows. A superseded version reports zero there — counting the
organization's whole `latest` population against every version would
look plausible and be wrong.

## Limitations

- **The merge is implemented twice**, once in the platform and once in
  the CLI, because neither side can delegate to the other: the CLI has to
  decide a verdict locally, and the server has to record an effective
  policy it computed itself rather than one a client asserted.
  Shared vectors in the platform's contract, generated from the platform
  implementation, are what the CLI is asserted against (the CLI's copy
  is `tests/fixtures/contract/policy-merge-vectors.json`). Binding
  the *platform* to the same file is not done yet, so the vectors
  currently guard one side of the pair.
- The repository delta the CLI sends is its disabled rules only.
  `severity_threshold`, `low_confidence_action`, and
  `completeness_enforcement` are gate-wide thresholds rather than per-rule
  configuration and have no field in the contract, so the effective policy
  recorded on a scan does not name them. Your local verdict still applies
  them.
- There is no preview endpoint that answers "what would this config
  produce?" before a scan runs. Running `controlloop gate` with Team
  enabled is the way to find out, and a refused change is reported on
  standard error.
- Exceptions are a separate mechanism with their own lifecycle, not part
  of this merge.

## Next step

See [Team behavior](cli.md#team-behavior) in the CLI reference for how
`gate` applies the merged policy, and [Your first Team
gate](../guides/first-team-gate.md) for a walkthrough.
