---
type: reference
title: controlloop.yaml manifest schema
tags:
  - reference
  - manifest
created: 2026-08-19
---

# `controlloop.yaml` manifest schema

**Status: Implemented foundation.** The schema, parser, and
reconciliation logic described below are implemented and tested
library code. `scan` and `gate` both load `controlloop.yaml` from the
repository (via `_scan_load_manifest` in `cli.py`) and pass the parsed
manifest into every rule's `RuleContext` -- see the [CLI
reference](cli.md).

## What this is

`controlloop.yaml` is an optional, human-authored security manifest a
repository can commit alongside its agent code. It supplements
evidence ControlLoop discovers on its own -- it never replaces or
deletes a discovered capability, and a manifest declaration that
conflicts with what was actually found is reported, not silently
trusted.

## Schema fields

| Field | Purpose |
| --- | --- |
| `schema_version` | Semantic version of this manifest document; follows the [same compatibility policy as the ACBOM](schema-versioning.md). |
| `owner` | The manifest's owning identity. |
| `trust_boundaries` | Named boundaries, each with the agents that belong to it. |
| `approvals` | Human-owned approval records for named capabilities, each with an optional `expires_at` (see below). |
| `prohibited_capabilities` | Capabilities (an agent, an edge type, and a target) that must never exist. |
| `allowed_delegation` | Per-agent allow-lists of delegation targets. |
| `data_classification` | Declared sensitivity for named resources. |
| `ceilings` | The maximum authority an agent (or, repository-wide, every agent) may ever hold -- see [Capability ceiling declaration](capability-ceiling.md). |
| `logged_tools` | Per-tool declarations of where a privileged tool's invocations are logged or audited -- see [Concrete policy rules](policy-rules.md#missing-action-logging-on-a-privileged-tool). |
| `suppressions` | Repo-local, expiring suppressions of specific findings, each with a rule identifier, a scoped target, a written reason, and an expiry date -- see [Expiring repo-local suppressions](suppressions.md). |
| `tool_capabilities` | What a named tool actually does -- the declaration that makes an agent's capability surface classifiable at all (see below). |

The packaged JSON Schema for the current version lives at
`src/controlloop/schemas/manifest/1.2.0/manifest.schema.json`.
`1.0.0` and `1.1.0` remain packaged, frozen, and never edited; an
existing manifest at either version still reads fine under the
one-directional compatibility rule in
[Schema versioning](schema-versioning.md).

## Naming a discovered agent, tool, or resource

**Every field that names something discovery found takes the name
discovery actually produced — spaces included.**

That name is a human display name. An A2A skill declared as
`{"id": "issue-refund", "name": "Issue a refund"}` is discovered as a
node named `Issue a refund`, so `Issue a refund` is what a manifest
must write. Run `controlloop bom` and read the node names if you are
unsure.

This applies to `trust_boundaries[].agents`, `approvals[].capability`,
`prohibited_capabilities[].agent` and `.target`,
`allowed_delegation[].agent` and `.targets`,
`data_classification[].resource`, `logged_tools[].tool`,
`tool_capabilities[].tool`, and every `ceilings[]` field that names a
node (`agent`, `prohibited_resources`,
`prohibited_external_destinations`, `prohibited_delegation_targets`).

Before schema `1.2.0` most of those rejected any name
containing a space outright — the manifest failed to parse with exit
`2`, so a ceiling could not name over half of a realistic agent's
tools.

Fields that name a person, a team, a log destination, or the manifest's
own label are **not** node names and remain strict identifiers:
`owner`, `trust_boundaries[].name`, `approvals[].approver`, and
`logged_tools[].audit_path`.

## Declaring what a tool does (`tool_capabilities`)

Without this block, **ControlLoop cannot classify any of your agent's
capabilities**, and every scan reports `no material capability is
reachable`.

Discovery can read an agent card, an OpenAPI spec, and an IAM policy.
None of those state that issuing a refund moves money, or that a lookup
tool touches confidential data. Those are semantics only the repository
knows, and ControlLoop deliberately does not guess them from method or
action names. So the material-capability taxonomy, the blast-radius
statement, the material change summary, and the capability reduction
report all stay empty until you declare them here.

```yaml
schema_version: "1.1.0"
owner: support-eng

tool_capabilities:
  - tool: Issue a refund       # matches the DISCOVERED tool's name
    financial_action: true
    read_only: false
    sensitivity: confidential
  - tool: Look up an order
    read_only: true
    sensitivity: confidential
```

| Attribute | Meaning |
| --- | --- |
| `destructive` | The tool destroys or irreversibly alters data. |
| `financial_action` | The tool moves money or incurs cost. |
| `code_execution` | The tool executes code. |
| `external_communication` | The tool sends data outside the trust boundary. |
| `read_only` | The tool only reads. `false` makes an `invokes` edge count as write access. |
| `privileged` | The tool holds elevated authority. |
| `requires_approval` | The tool is meant to require human approval. |
| `sensitivity` | The data class the tool touches, reusing `Sensitivity`. |
| `data_classes` | Additional named data classes, merged with anything discovery already found. |

Every boolean also accepts `"unknown"`, so you can record "this might be
destructive and we have not established it" rather than being forced
into a confident answer. The taxonomy maps `"unknown"` to
`UNCLASSIFIED`, which it ranks **worst of all** -- an unknown risk is
never treated as safer than a known one.

### Matching, and why it is by display name

`tool` is matched against a **discovered tool node's `name`**, the same
human-writable identifier `logged_tools` and the capability ceiling
already match on. Content-addressed node IDs are hashes nobody can write
into YAML.

That name is the tool's display name, not its id. An A2A skill declared
as `{"id": "issue-refund", "name": "Issue a refund"}` is discovered as a
node named `Issue a refund`, so **`- tool: Issue a refund` is correct
and `- tool: issue-refund` matches nothing.** Run `controlloop bom` and
read the node names if you are unsure. A declaration naming a tool
discovery did not find produces an explicit `unverified` diagnostic
rather than silently doing nothing.

The same change widened `logged_tools`'s own `tool` field, for
the same reason -- it previously could not name any tool whose display
name contained a space.

### What it never does

- It only ever **supplements**. An attribute you omit leaves whatever
  discovery found untouched; omitting an attribute is never the same as
  declaring it `false`.
- `data_classes` and permission scopes are **merged** with discovered
  values, never replaced.
- It **cannot change a node's identity**. Security attributes are
  excluded from ID material, so annotating a tool never moves an ID or
  invalidates a committed baseline.
- A repository that declares no `tool_capabilities` produces a
  byte-identical ACBOM to one built before this feature existed.

## How declarations are checked against discovery

`reconcile_manifest` compares a parsed manifest against already-discovered
ACBOM nodes and edges (from the adapters described in [Adapter
status](../adapters/readme.md)) and returns diagnostics -- it never
constructs a modified copy of what was discovered, so a manifest can
only add information, never remove it.

- A `prohibited_capabilities` entry whose exact capability *is* found in
  discovery, or an `allowed_delegation` entry whose agent delegates
  outside the declared set, produces a `MANIFEST-CONTRADICTS-DISCOVERY`
  diagnostic.
- A `data_classification` entry naming a resource discovery did not find
  produces an `INCOMPLETE-UNVERIFIED-DECLARATION` diagnostic -- not
  proof the declaration is wrong, just that it could not be confirmed.

Matching is by declared name (`Node.name`), since node and edge IDs are
content-addressed hashes a human cannot write into a YAML file.

## Approval expiration

`Approval.expires_at` is an optional RFC 3339 timestamp string, exactly as
supplied and not strictly enforced at the model layer (a malformed value
does not reject an otherwise-valid manifest, the same posture
`BaselineDocument.provenance.approved_at` already established). `None`
means the approval never expires.

`controlloop.manifest.approvals.is_approval_active`/`active_approvals`
decide whether an approval is still active as of an explicit,
caller-supplied `as_of` — deliberately outside the deterministic rule
engine, which must never read a real clock internally (see [Concrete
policy rules](policy-rules.md#sensitive-write-without-declared-approval)
for the full rationale). No CLI command calls either function yet; a
later manifest-loading change is expected to filter expired approvals out
before policy evaluation.

## Known limitations

- `scan` and `gate` both load `controlloop.yaml` from a repository.
- `MANIFEST-CONTRADICTS-DISCOVERY` is represented with the existing
  `Diagnostic` model, not the separate `Finding` model (see
  [Finding model](finding-model.md)); this may migrate in the future.
- The schema is not yet published at a public URL (its `$id` names one
  it does not yet resolve to); the ACBOM's own schema is in the same
  position pending a hosting decision.
- A declared ceiling is projected into the ACBOM as graph content, and
  the `capability_ceiling` rule evaluates it against a
  live scan and blocks on a violation -- see [Capability ceiling
  declaration](capability-ceiling.md).
- `logged_tools`, `allowed_delegation`, and `trust_boundaries` are read
  by the [policy rules](policy-rules.md) for missing action logging and
  unauthorized delegation, and by `scan`/`gate` end to end: both commands load
  `controlloop.yaml` and pass the parsed `ManifestDocument` into every
  rule's `RuleContext`.
- `tool_capabilities` is applied during ACBOM
  construction, so `bom`, `init`, `diff`, `scan`, and `gate` all agree
  on the same annotated graph and the same digest. Declaring a tool
  privileged may newly trigger
  [`policy.missing-action-logging`](policy-rules.md#missing-action-logging-on-a-privileged-tool),
  which then requires a matching `logged_tools` entry.
- `suppressions` is applied by both `scan` and
  `gate`, before policy classification -- see [Expiring repo-local
  suppressions](suppressions.md) for the full mechanism, including its
  two structural, security-relevant guarantees (cannot broaden beyond
  the one finding it names; cannot suppress a capability-ceiling
  breach).

## Next steps

- Review [Expiring repo-local suppressions](suppressions.md) for how a
  team suppresses a specific finding with a reason and an expiry.
- Review [Capability ceiling declaration](capability-ceiling.md) for
  the product's core differentiator: declaring an agent's maximum
  authority.
- Review [Adapter status](../adapters/readme.md) for what discovery
  currently produces to reconcile against.
- Review [Schema versioning and compatibility policy](schema-versioning.md).
