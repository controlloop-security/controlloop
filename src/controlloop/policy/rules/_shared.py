"""Shared helpers for concrete policy rules. `documentation_url` is used
by every rule in this package.

Every rule in this package is a pure function operating only on
`controlloop.policy.models.RuleContext`: no file, process, network, or
model access. This module factors out the small amount of logic more
than one rule needs, rather than duplicating it three times:

- `documentation_url`: builds each rule's stable documentation link,
  all pointing at `docs/reference/policy-rules.md`. Derives the anchor
  from `RULE_ID` directly rather than accepting a hand-typed anchor
  string -- hand-typed anchors once drifted from their section's real
  `<a id>` in `policy-rules.md`, found and fixed while building the
  build-time check that would have caught it. Deriving the anchor from
  `RULE_ID` (already the single source of truth every `Finding.rule_id`
  also uses) makes that whole class of drift structurally impossible,
  not just tested for.
- `node_change_state`: derives a `Finding`'s required `change_state`
  from `RuleContext.diff` when a baseline comparison was supplied. Only
  a node-keyed variant exists today because every rule here attributes
  its `Finding`s to a node (a tool or, transitively, a capability
  target), never to a bare edge; an `edge_change_state` counterpart is
  straightforward to add, by the same pattern, if a future rule needs
  one -- not added speculatively here.

**Disclosed limitation (recorded once here, referenced by every rule's
own module docstring rather than repeated):** `controlloop.diff.models.
DiffResult` structurally never represents an *unchanged* identity --
`docs/reference/diff-output-format.md` documents this as a deliberate
property of that model ("an identity unchanged on both sides is never
represented at all"). `controlloop.findings.models.FindingChangeState`
correspondingly has no "unchanged" member -- only `added`, `removed`,
`changed`, `unknown`, and `not-compared`. When `RuleContext.diff` is
supplied but the specific node or edge a finding concerns is absent from
`diff.node_changes`/`diff.edge_changes` (genuinely unchanged since the
baseline), the helpers below fall back to `FindingChangeState.
NOT_COMPARED` rather than inventing an unapproved sixth member or
misusing `UNKNOWN`'s own documented meaning (a confidence drop on a
still-present identity, not "nothing to report"). This is a real,
disclosed gap between two independently designed contracts (`DiffResult`
and `FindingChangeState`) -- fixing it would mean adding a new enum
member to an already-shipped, versioned model.
"""

from __future__ import annotations

from controlloop.diff.models import DiffResult
from controlloop.findings.models import FindingChangeState

_DOCS_PAGE = "https://docs.controlloop.ai/reference/policy-rules"


def documentation_url(rule_id: str) -> str:
    """The stable documentation URL for the rule identified by `rule_id`
    (for example `"policy.undeclared-tools"`, the exact value every rule
    module's own `RULE_ID` constant and every `Finding.rule_id` already
    carries). The anchor is `rule_id` with its `"policy."` prefix
    stripped -- `policy-rules.md`'s own real `<a id="...">` anchors, one
    per rule section, use this identical convention (checked by a real,
    build-time, offline structural test against the real page, not
    merely documented here). Shape-validated only by
    `controlloop.findings.models.DocumentationUrl`; never fetched, per
    that type's own contract."""

    anchor = rule_id.removeprefix("policy.")
    return f"{_DOCS_PAGE}#{anchor}"


def node_change_state(diff: DiffResult | None, node_id: str) -> FindingChangeState:
    """`FindingChangeState` for the node identified by `node_id`, given
    an optional baseline `diff` (see this module's own docstring for
    the disclosed "unchanged" gap)."""

    if diff is None:
        return FindingChangeState.NOT_COMPARED
    for change in diff.node_changes:
        if change.node_id == node_id:
            return FindingChangeState(change.kind.value)
    return FindingChangeState.NOT_COMPARED
