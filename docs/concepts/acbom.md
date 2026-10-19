---
type: guide
title: The ACBOM and capability evidence
tags:
  - concepts
  - acbom
created: 2026-08-14
---

# The ACBOM and capability evidence

An agent can gain real-world authority through tools, APIs, data, identities,
permissions, and other agents. Those relationships are often scattered across
code and configuration, which makes a small change difficult to review.

ControlLoop's central artifact is the **Agent Capability Bill of Materials
(ACBOM)**: a versioned graph intended to turn that scattered authority into a
reviewable, comparable record.

> **Current availability:** the repository implements the canonical ACBOM
> 1.0.0 model, schema, stable identifiers, deterministic serialization, and
> tests. `controlloop bom` discovers a repository and exports an ACBOM;
> `controlloop init`, `diff`, `scan`, and `gate` build one internally too.

## How to read the model

Every example below is drawn from one connected reference scenario --
`refund-agent`, an agent that processes customer refunds -- the same
worked example the diff and blast-radius documentation uses. The examples are generated directly from real
`Node`/`Edge` objects and from `controlloop.capability`'s own traversal
functions (`tests/concepts/reference_fixture.py`), not hand-typed, so
they cannot silently drift from what the model and the algorithms actually
allow.

### Nodes are the things that matter

The canonical model can represent these node types:

<!-- BEGIN GENERATED: node-examples -->
- **agent**: `refund-agent` -- the agent that receives and processes refund requests.
- **tool**: `refund-tool` -- the tool `refund-agent` invokes to carry out a refund.
- **resource**: `billing-db` -- the destructive, `restricted`-sensitivity resource `refund-agent` writes to.
- **identity**: `service-account` -- the identity `refund-agent` authenticates as.
- **permission**: `refund:write` -- the permission scope `service-account` is permitted by.
- **data-class**: `customer-pii` -- the data classification `refund-tool` reads while looking up the account.
- **trigger**: `support-ticket-created` -- the inbound event `refund-agent` receives from.
- **policy-boundary**: `finance-boundary` -- the policy boundary `refund-agent` is constrained by.
<!-- END GENERATED: node-examples -->

Security classifications describe properties without storing secret or
customer values: `billing-db` above is marked `destructive` and
`sensitivity: restricted`, never the account data itself.

### Edges show how authority flows

Relationships connect the nodes above:

<!-- BEGIN GENERATED: edge-examples -->
- `refund-agent` -invokes-> `refund-tool`
- `refund-tool` -reads-> `customer-pii`
- `refund-agent` -writes-> `billing-db`
- `refund-agent` -authenticates-as-> `service-account`
- `service-account` -permitted-by-> `refund:write`
- `refund-agent` -delegates-to-> `escalation-agent`
- `refund-agent` -receives-from-> `support-ticket-created`
- `refund-agent` -constrained-by-> `finance-boundary`
<!-- END GENERATED: edge-examples -->

A direct path is one edge from an agent to a tool, resource, identity,
permission, or data class -- computed by `compute_direct_capability_paths`:

```text
<!-- BEGIN GENERATED: direct-path-example -->
refund-agent
  -> invokes -> refund-tool
<!-- END GENERATED: direct-path-example -->
```

A transitive path chains two or more hops to reach the same five target
categories. `refund-agent` has no direct edge to `refund:write`; only
`compute_transitive_capability_paths` reveals that it can reach it in two
hops:

```text
<!-- BEGIN GENERATED: transitive-path-example -->
refund-agent
  -> authenticates-as -> service-account
  -> permitted-by -> refund:write
<!-- END GENERATED: transitive-path-example -->
```

Direct and transitive path analysis is implemented and tested
(`controlloop.capability`). No command lists every capability path directly,
but `controlloop scan` and `controlloop gate` expose this data through each
finding's own `capability_path` field and through the blast-radius statement
that leads every report.

## Evidence makes a claim reviewable

An inventory without provenance is difficult to trust. Each implemented
canonical node and edge requires bounded evidence such as an adapter identity,
sanitized repository-relative path, safe line range, parser or schema identity,
or document digest. Confidence records how strongly the evidence supports the
claim.

Evidence must not contain source snippets, prompt bodies, credentials, secret
values, environment-variable values, or customer data. Absolute paths are not
valid canonical evidence paths.

## Stable identity makes diffs meaningful

ControlLoop uses versioned, SHA-256-based canonical identifiers derived from
allowlisted semantic identity material. Display text, line numbers, evidence,
timestamps, mutable security attributes, and secret-bearing fields are not
identity inputs.

This allows the same logical component to keep the same ID when only its
presentation or evidence location changes. The implemented algorithm and its
compatibility constraints are implemented in `src/controlloop/acbom/` and
enforced by tests.

## Baselines, diffs, policies, and findings

- A **baseline** is an approved ACBOM used as the comparison point.
- A **diff** classifies components and effective capabilities as added,
  removed, changed, or unknown. `controlloop diff` (see the [CLI
  reference](../reference/cli.md#diff)) implements this today.
- A **policy** evaluates canonical data and a diff using versioned,
  deterministic rules. `controlloop scan` and `controlloop gate` implement
  this today.
- A **finding** explains the affected agent, evidence, capability path, reason,
  and remediation. `scan` and `gate` render findings in every report format.
- An **exception** is a future Team workflow for a narrow, attributable,
  expiring decision. It is not available today.

Policy evaluation is designed to be pure, bounded, and independent of model
judgment. A model-generated opinion cannot be the sole reason a build fails.

## Unknown is not safe

Dynamic registration, unresolved references, unparsed regions, and resource
bounds can prevent a scanner from proving what exists. Rather than silently
omitting that gap, the canonical model records it as an explicit,
`incomplete=True` diagnostic drawn from a closed registry of reasons
(`INCOMPLETE-UNRESOLVED-REFERENCE`, `INCOMPLETE-DYNAMIC-REGISTRATION`,
`INCOMPLETE-UNPARSED-REGION`, `INCOMPLETE-BOUND-EXCEEDED`), with
`confidence` set to `unknown` -- never a confident claim about the very
thing that could not be resolved. For example:

```text
<!-- BEGIN GENERATED: unknown-example -->
INCOMPLETE-DYNAMIC-REGISTRATION (confidence: unknown)
  a dynamically registered tool could not be resolved to a concrete identity
<!-- END GENERATED: unknown-example -->
```

A document's completeness summary is a deterministic view over these
diagnostics, and this state is part of the canonical digest like everything
else in the document. This mechanism is implemented and tested; no adapter
exists yet to produce one of these from a real repository scan.

Likewise, a passing `scan` or `gate` means that the evaluated policy did not
block the analyzed evidence. It does not guarantee that an agent is safe.

## Next steps

- Check the [CLI reference](../reference/cli.md) for what can be run today.
- Check [Adapter status](../adapters/readme.md) before assuming a source format
  is supported.
- Read [Privacy, security, and limitations](../reference/privacy-security.md)
  for the boundary between implemented safeguards and approved design.
