---
type: guide
title: Writing a capability ceiling
tags:
  - guide
  - manifest
  - capability
created: 2026-08-20
---

# Writing a capability ceiling

This guide walks through writing a capability ceiling for your own
agents: what it is, how to start from `controlloop init`'s own
proposal and tighten it, three worked examples, and the one failure
mode that makes a ceiling worthless without you ever noticing. For the
schema itself -- every field, how an agent-specific and a
repository-wide ceiling combine -- see [Capability ceiling
declaration](../reference/capability-ceiling.md); this page is about
using it well, not the reference for what exists.

Every example below shows real, captured `controlloop scan` and
`controlloop init --dry-run` output, run against a small synthetic
agent -- not invented prose describing what the tool is expected to
do.

## An allowlist, not a denylist

Every other policy rule in this product -- undeclared tools, broad
permissions, unauthorized delegation, and the rest -- is a **denylist**:
it recognizes a specific, named shape of risk and blocks it. A denylist
is only ever as good as the list of shapes someone already thought to
write down. The capability a rule has never seen, because nobody wrote
a rule for it yet, passes silently.

A capability ceiling is the opposite: an **allowlist boundary**. You
declare the maximum authority an agent may ever hold -- not a list of
specific bad things, but a hard limit on the category of thing at all.
An agent that gains a brand-new capability nobody anticipated is still
caught, as long as that capability falls inside a category the ceiling
already prohibits, because the ceiling was never enumerating threats
in the first place -- it was drawing a boundary.

This is the whole reason a ceiling is worth the extra few minutes to
write, and also why it is easy to write one that looks complete but
does nothing -- covered at the end of this guide.

## Start from `init`, then tighten it

`controlloop init --dry-run` discovers your repository's agents and
proposes a starter ceiling for each one, in the same draft
`controlloop.yaml` it generates for everything else. Run against a
small agent that only invokes one tool, `issue-refund`:

```text
# TODO: ceilings
# This section is a STARTING POINT, not an approved security
# boundary -- review every entry below before relying on it.
# ControlLoop proposed each prohibited_actions and
# prohibited_delegation_targets value from what this scan
# actually observed: an action or delegation target is only
# proposed as prohibited when this scan found zero evidence of
# it, so adopting this section unchanged does not conflict with
# anything found in this scan.
#
# ControlLoop cannot determine prohibited_resources,
# prohibited_external_destinations, or prohibited_data_classes
# from repository discovery alone: these describe things never
# observed (a resource never touched, a domain never contacted,
# a data class never seen), which static analysis has no way to
# enumerate. They are left as empty TODO lists below -- that is
# an incomplete analysis, not a considered "nothing to prohibit"
# answer.
ceilings:
  - agent: "refund-agent"
    prohibited_actions: ["reads", "writes"]
    prohibited_delegation_targets: []
    prohibited_resources: []
    prohibited_external_destinations: []
    prohibited_data_classes: []
```

Read this proposal for what it actually is: `refund-agent` was only
ever observed *invoking* something, never reading or writing a
resource directly, so `init` proposes prohibiting `reads` and `writes`
outright -- if this agent ever gains a direct read or write capability
later, the ceiling now blocks it, whether or not any rule was ever
written for that specific case.

Three things `init` never proposes, and why each one is now your own
job to add:

- **`prohibited_resources` / `prohibited_external_destinations`** --
  `init` has no way to enumerate "a resource this agent should never
  touch" from what it has *not yet* observed. Only you know which
  resources are dangerous enough to name outright, even before this
  agent ever reaches for them. The payments example below adds one.
- **`prohibited_data_classes`** -- the same problem, for sensitivity
  classes rather than named resources. No adapter in this product
  today discovers a resource's own data sensitivity from repository
  content alone (that is a manifest-level judgment call, via
  `data_classification`, not something static analysis infers) --
  which means `prohibited_data_classes` currently protects only
  against a capability this product's own future discovery adds
  later, never one it can show you blocking today. Declare it anyway
  if your agent should never touch `restricted` or `confidential`
  data: the ceiling is still real, even though no worked example below
  can show it firing live yet.
- **Delegation targets `init` did observe, at low or unknown
  confidence** -- these are neither prohibited (that could immediately
  conflict with what this scan found) nor silently trusted; `init`
  lists them in their own comment for you to review and decide,
  individually.

Tightening the proposal is adding what `init` structurally cannot
know: the specific resources and destinations this agent must never
reach, decided by you, not discovered by a scan.

## Three worked examples

### 1. A read-only reporting agent

An agent that only ever reads a dashboard metric and reports on it
has no legitimate reason to ever write anything or delegate to
another agent. Its ceiling can be almost entirely categorical:

```yaml
schema_version: "1.0.0"
owner: security-team
ceilings:
  - agent: report-agent
    prohibited_actions: [writes]
```

```text
$ controlloop scan
• no material capability is reachable

✓ PASSED

• material change: not evaluated

! MEDIUM   policy.undeclared-tools: Tool 'read-quarterly-metrics' is reachable
  but not declared in controlloop.yaml.
    at agent-card.json
```

Exit `0`: the agent's real behavior (reading one tool) never crosses
its own ceiling, so the scan passes. The separate `undeclared-tools`
finding is a different, lower-severity rule (a denylist one) noticing
the tool has no `controlloop.yaml` approval entry yet -- unrelated to
the ceiling, and not enough to block on its own at the default
severity threshold. The ceiling itself contributed nothing to this
particular result *today* -- its value is what it would catch the
day this agent's own code gains a write path nobody reviewed.

### 2. A payments agent that delegates

`refund-agent` invokes a tool named `delete-database` -- exactly the
kind of specific, named resource `init`'s own proposal could never
have enumerated. Naming it explicitly is the whole point of tightening
the proposal by hand:

```yaml
schema_version: "1.0.0"
owner: security-team
ceilings:
  - agent: refund-agent
    prohibited_resources: [delete-database]
```

```text
$ controlloop scan
• no material capability is reachable

✕ DEPLOYMENT BLOCKED

• material change: not evaluated

✕ CRITICAL policy.capability-ceiling: agent 'refund-agent' reaches
  'delete-database', which is a prohibited resource or external
  destination under its capability ceiling
    at agent-card.json

! MEDIUM   policy.undeclared-tools: Tool 'delete-database' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json
```

Exit `1`. The ceiling caught this the moment `delete-database` was
discoverable at all -- whether it was reached directly or, per
[capability ceiling evaluation](../reference/policy-rules.md#capability-ceiling-evaluation),
only transitively through a chain of delegation, the full path is
still reported.

### 3. An agent reaching a risky external destination

`prohibited_resources` and `prohibited_external_destinations` are
matched the identical way -- by the reached target's own name -- since
nothing in this product's discovery today distinguishes "an internal
resource" from "an external destination" at the graph level. An agent
whose one tool happens to be named after a real exfiltration risk:

```yaml
schema_version: "1.0.0"
owner: security-team
ceilings:
  - agent: notes-agent
    prohibited_external_destinations: [pastebin.com]
```

```text
$ controlloop scan
• no material capability is reachable

✕ DEPLOYMENT BLOCKED

• material change: not evaluated

! MEDIUM   policy.undeclared-tools: Tool 'pastebin.com' is reachable but not
  declared in controlloop.yaml.
    at agent-card.json

✕ CRITICAL policy.capability-ceiling: agent 'notes-agent' reaches
  'pastebin.com', which is a prohibited resource or external destination
  under its capability ceiling
    at agent-card.json
```

Exit `1`, the same way. The lesson from examples 2 and 3 together:
name the specific things you already know are dangerous, using
whichever of the two fields best communicates *why* to the next person
reading the manifest -- the evaluation itself does not care which one
you pick.

## The failure mode: a ceiling that permits everything

A capability ceiling can be present in `controlloop.yaml`, name a real
agent, and still do absolutely nothing. Two ways this happens:

**An empty ceiling entry.** Declaring an agent with no prohibition
fields at all:

```yaml
schema_version: "1.0.0"
owner: security-team
ceilings:
  - agent: report-agent
```

```text
$ controlloop scan
• no material capability is reachable

✓ PASSED

• material change: not evaluated

! MEDIUM   policy.undeclared-tools: Tool 'read-quarterly-metrics' is reachable
  but not declared in controlloop.yaml.
    at agent-card.json
```

No `policy.capability-ceiling` observation appears at all -- not even
an advisory one. An agent whose effective ceiling has every
prohibition field empty is not evaluated against the ceiling rule as
"having no ceiling" (that produces its own explicit, honest
disclosure -- see the next paragraph); it is silently excluded from
consideration entirely, because there is structurally nothing to
check it against. `report-agent` above looks declared. It is not
protected.

**No ceiling declared at all** looks different, and is easier to
notice precisely because ControlLoop says so outright rather than
staying silent:

```text
$ controlloop scan
# (no controlloop.yaml present)
```

A repository with genuinely no `controlloop.yaml`, or a
`controlloop.yaml` with an empty `ceilings` list, produces an explicit
`policy.capability-ceiling` observation stating that no capability
ceiling is declared for the repository -- never a silent pass. That
disclosure is exactly what an *empty entry* does not give you: an
agent with a present-but-toothless ceiling entry looks, from the
outside, identical to one with a real ceiling that simply never fired.

### How to actually detect it

There is no automated rule today that flags "this ceiling declares an
agent but prohibits nothing" as its own finding -- detecting it is a
review step, not a tooling feature this product ships yet. Concretely:

1. Read every `ceilings` entry in `controlloop.yaml` and confirm each
   one actually names at least one prohibition field with real
   content -- an entry with only an `agent:` key and nothing else is
   the exact failure mode above.
2. Cross-check the ceiling against what `controlloop bom` or
   `controlloop scan` actually discovers that agent reaching. A
   ceiling that prohibits resources the agent was never going to touch
   anyway gives you the feeling of protection without the substance --
   the same problem as an empty entry, just less obviously.
3. When you tighten a ceiling for a new capability, re-run
   `controlloop scan` and confirm the result changes the way you
   expect -- a ceiling you have never seen actually block something is
   a ceiling you have not verified works at all.

Treat this the same way you would treat an untested alarm system: it
existing in the file is not evidence it does anything.

## Next steps

- Review [Capability ceiling declaration](../reference/capability-ceiling.md)
  for the full schema and evaluation semantics this guide builds on.
- Review [Concrete policy rules](../reference/policy-rules.md#capability-ceiling-evaluation)
  for exactly how a breach is detected, including transitive reach and
  the unverifiable-confidence case.
- Review the [CLI reference](../reference/cli.md#init) for `init`'s
  full generated-file behavior.
