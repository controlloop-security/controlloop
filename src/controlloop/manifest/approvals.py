"""Approval expiry -- a pure, deterministic-given-an-explicit-reference-time
utility, kept entirely outside the deterministic rule engine and
`RuleContext`.

`controlloop.policy.engine.evaluate`'s own docstring promises that an
identical `(rules, context)` pair always produces a byte-identical
`EvaluationResult`. A rule that read real wall-clock time internally
would make that promise false for its own output: deterministic core
logic must not depend on the clock.

This module therefore lives in `controlloop.manifest`, not
`controlloop.policy`, and both functions take an explicit `as_of`
parameter rather than reading the clock themselves. The sensitive-write
rule (`controlloop.policy.rules.sensitive_write_without_approval`) never
calls either function and never reads a clock -- it only ever inspects
whatever `RuleContext.manifest.approvals` it is given. The CLI calls
`active_approvals` when assembling that `RuleContext`, so an expired
approval is simply absent from what the rule ever sees.

An unparseable `expires_at` is treated as **already expired** (fail
closed): silently treating a malformed expiry as "never expires" could
wrongly suppress a real finding, exactly the "confident pass" failure
mode this product treats as its worst one.
"""

from __future__ import annotations

from datetime import datetime

from controlloop.manifest.models import Approval, ManifestDocument


def _parse_timestamp(value: str) -> datetime | None:
    """Tolerates the common RFC 3339 trailing `Z` that
    `datetime.fromisoformat` does not accept on its own -- the same
    parsing `controlloop.baseline.provenance._parseable_timestamp`
    already established for the same reason. Returns `None`, never
    raises, when `value` does not parse."""

    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None  # an unqualified timestamp is not safely comparable
    return parsed


def is_approval_active(approval: Approval, *, as_of: datetime) -> bool:
    """Whether `approval` is still active at `as_of`.

    `approval.expires_at is None` means the approval never expires and is
    always active. A present `expires_at` that fails to parse as a
    timezone-aware timestamp is treated as already expired (fail closed --
    see this module's own docstring). `as_of` must itself be
    timezone-aware; a naive `as_of` raises `ValueError` immediately rather
    than silently comparing against an ambiguous local time.
    """

    if as_of.tzinfo is None:
        raise ValueError("as_of must be a timezone-aware datetime")

    if approval.expires_at is None:
        return True

    expires_at = _parse_timestamp(approval.expires_at)
    if expires_at is None:
        return False

    return as_of < expires_at


def active_approvals(
    manifest: ManifestDocument, *, as_of: datetime
) -> tuple[Approval, ...]:
    """Every approval in `manifest.approvals` that is still active at
    `as_of`, in the same relative order, deterministic for a given
    `as_of`."""

    return tuple(
        approval
        for approval in manifest.approvals
        if is_approval_active(approval, as_of=as_of)
    )
