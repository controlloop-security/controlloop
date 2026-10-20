---
type: reference
title: Expiring repo-local suppressions
tags:
  - reference
  - manifest
  - policy
created: 2026-08-21
---

# Expiring repo-local suppressions

**Status: Implemented, including live evaluation.** The schema and
matching semantics described below are implemented and tested library
code. `controlloop scan` and `controlloop gate` both apply declared suppressions against a live scan today,
before classifying findings as blocking or warning -- see [Concrete
policy rules](policy-rules.md) for the rules whose findings a
suppression can name.

## What this is

A gate with no escape hatch gets disabled repo-wide the first time it is
wrong, and the false-positive signal never comes back. A repository can
instead declare, in `controlloop.yaml`, that one specific finding is
suppressed -- with a reason and an expiry date, visible in every scan and
gate result, never hidden. Team-tier attributable exceptions are a separate, later,
paid-tier concept;
this is the free-tier equivalent.

## Declaring a suppression

```yaml
schema_version: "1.0.0"
owner: security-team
suppressions:
  - rule_id: policy.undeclared-tools
    target: clp:finding:sha256:a86cb3610b02da19fc10d433fe4416d4161e0c529da47d146a8081f6f7de9e71
    reason: "reviewed by security team, tool usage is expected here"
    expires_at: "2026-12-31"
```

All four fields are required. Omitting any one of them -- `rule_id`, a
scoped `target`, a written `reason`, or an `expires_at` date -- makes
`controlloop.yaml` fail to parse: `scan`/`gate` exit `2`
(`ExitCode.INVALID_INPUT`) before any rule runs, the same way any other
malformed manifest field does.

| Field | Purpose |
| --- | --- |
| `rule_id` | The rule this suppression concerns (for example `policy.undeclared-tools`), matching a real `Finding.rule_id` -- see [Concrete policy rules](policy-rules.md). |
| `target` | The exact, stable identity of the one finding this suppression names, in the same `clp:finding:sha256:<hex>` shape as a real `Finding.id` -- see [Finding model](finding-model.md#finding-identity). |
| `reason` | A written, human-authored justification (1-1024 characters). Published as-is in every scan and gate result -- never a secret value. |
| `expires_at` | A calendar date, `YYYY-MM-DD`. Valid through the end of that date; the day after, the suppression expires. |

## Finding the `target` to suppress

A suppression's `target` is a finding's own stable ID -- the exact value
already printed as `Finding.id` in `--format json` output, or embedded in
each finding's SARIF `ruleId`/`fingerprints`. The fastest way to obtain
it: run `controlloop scan --format json` once, locate the finding to
suppress, and copy its `id` verbatim. `Finding.id` is stable across
reruns as long as the underlying capability chain does not change (it
excludes evidence, severity, confidence, and change state -- see
[Finding model](finding-model.md#finding-identity)) -- a later code change that
alters the actual capability path produces a new ID, and the old
suppression becomes stale (see below), a deliberate signal that the
suppression needs re-review, not silent carry-over onto a materially
different finding.

## How matching works: never broader than its declared scope

A suppression applies to a finding only when **both** `rule_id` and
`target` match that finding exactly -- plain string equality, checked
against every currently-evaluated finding's own `rule_id` and `id`.
There is no wildcard, glob, prefix, or pattern syntax anywhere in this
mechanism: `target` is shape-constrained to a real finding-ID pattern at
parse time, so a suppression can never even be written in a way that
could match more than the one finding it names. A suppression whose
`rule_id` disagrees with what `target` actually belongs to matches
nothing at all, rather than matching some other, unintended finding --
it fails safe, reported as stale (below).

## Every declared suppression's status: never hidden

Every declared suppression -- not only ones currently in effect -- is
listed in full in every scan and gate result: the JSON `suppressions`
field on `--format json` output, the `Suppressions:` section appended to
`--format text` output, and the `suppressions` field on `gate`'s written
evidence artifact.

| Status | Meaning |
| --- | --- |
| `active` | Matched exactly one currently-evaluated finding, is not expired, and does not target the capability-ceiling rule (see below). That finding is removed from the gate's blocking/warning decision -- but never removed from the full `findings` list, so it stays visible for audit. |
| `expired` | `expires_at` is before today. Has no effect, regardless of whether it would otherwise have matched. |
| `stale` | Not expired, but matches no currently-evaluated finding -- the finding may have been fixed, or the suppression may never have matched anything real. Reported so suppressions do not silently accumulate forever. |
| `ceiling-protected` | Targets `policy.capability-ceiling` -- see below. Never suppresses anything, regardless of expiry or match. |

## Cannot suppress a capability ceiling breach

A suppression naming `policy.capability-ceiling` never takes effect,
under any circumstances -- reported `ceiling-protected`, not merely
`expired` or `stale`, so it is clear the suppression can never work, not
only that it does not work today. The only way to change a capability
ceiling breach's outcome is to amend the ceiling itself in
`controlloop.yaml` -- see [Capability ceiling
declaration](capability-ceiling.md). This is deliberate: a capability
ceiling is this product's own core differentiator (an allowlist boundary
an agent may never exceed), and allowing a repo-local suppression to
silently defeat it would undermine the one guarantee this product exists
to make.

## What a suppression does not do

- **Never hides a finding from evidence.** `findings` in every scan and
  gate result stays the full, unfiltered set, including
  `active`-suppressed ones -- only the *gate decision* changes. In text
  output an `active`-suppressed finding keeps its severity but takes the
  neutral `•` glyph and a closing line, `suppressed until YYYY-MM-DD;
  does not affect the verdict`, so it never reads as one that blocks.
- **Never widens.** No suppression can ever affect more than the one
  finding it names by exact ID (see "How matching works" above).
- **Never persists across a materially different finding.** A code
  change that alters the underlying capability chain produces a new
  `Finding.id`; the old suppression targets an ID that no longer
  matches anything and is reported `stale`.
- **Is not the paid-tier attributable-exception mechanism.** Team-tier
  exceptions (owner and reason attributed to a specific approver,
  centrally managed across repositories) are separate, not-yet-implemented,
  later scope.

## Privacy and determinism

`reason` is exactly the text a repository owner chose to publish in
their own `controlloop.yaml` -- never scanner-discovered evidence, never
a secret or credential value. Suppression matching is a pure function of
already-computed findings, the declared suppression set, and an explicit
reference date supplied by the caller (never an internal, hidden clock
read) -- identical input produces an identical, deterministically sorted
result.

## Next steps

- Review [the manifest schema](manifest-schema.md) for every other
  `controlloop.yaml` field.
- Review [Capability ceiling declaration](capability-ceiling.md) for
  why a ceiling breach is the one thing a suppression can never silence.
- Review [Concrete policy rules](policy-rules.md) for the rules
  whose findings a suppression can name.
