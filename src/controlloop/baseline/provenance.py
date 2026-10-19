"""Approval provenance reporting.

`describe_provenance` classifies a `BaselineDocument`'s `provenance`
field (`controlloop.baseline.models.ApprovalProvenance`, or its absence)
as attributed or unattributed, never raising on a missing or malformed
value: a baseline with missing or malformed provenance is usable but
reported as unattributed, and the report says so prominently.
`format_provenance_lines` renders that classification as CLI-voice text
lines following the CLI's output convention (the `✓`/`!`/`✕`/`•`
stable-symbol convention; output stays useful without color), and never
renders an approver identity without explicitly qualifying it as
supplied or inferred.

Neither function is called by any CLI command today. `diff` and `gate`
(the only commands whose purpose could plausibly display provenance, in
their output whenever a baseline is used) remain argument-free stubs
(`controlloop.cli`) that perform no comparison and produce no report --
mirroring `controlloop.baseline.resolution`, which is likewise disclosed
as not wired. This module is a tested library primitive, ready for the
command that will eventually call it.

Every test in `tests/baseline/test_baseline_provenance.py` that
exercises this module uses only in-process fixtures; nothing here reads
a file, opens a socket, or otherwise depends on the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from controlloop.baseline.models import (
    ApprovalProvenance,
    ApproverSource,
    BaselineDocument,
)


class ProvenanceStatus(StrEnum):
    """Whether a baseline's approval provenance can be trusted and
    displayed as a complete attribution."""

    ATTRIBUTED = "attributed"
    UNATTRIBUTED = "unattributed"


@dataclass(frozen=True, slots=True)
class ProvenanceSummary:
    """The result of classifying a `BaselineDocument`'s `provenance`.

    Carries every field `describe_provenance` was able to read, even
    when `status` is `UNATTRIBUTED` -- a partially present fact (for
    example an approver name with no confirmed source) is never
    discarded just because the whole is incomplete, only reported
    honestly alongside `issues` naming what is missing or unusable.
    """

    status: ProvenanceStatus
    approver: str | None
    approver_source: str | None
    approved_at: str | None
    approved_commit: str | None
    issues: tuple[str, ...]


def _parseable_timestamp(value: str) -> bool:
    """Whether `value` parses as a real date/time, tolerating the common
    RFC 3339 trailing `Z` that `datetime.fromisoformat` does not accept
    on its own before Python rewrites it to an explicit UTC offset."""

    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return True


def describe_provenance(document: BaselineDocument) -> ProvenanceSummary:
    """Classify `document.provenance` as attributed or unattributed.

    Never raises: a `None` provenance (older baselines carry none) and a
    present-but-incomplete or unparseable one are both ordinary,
    expected inputs, not errors.

    Attribution requires every one of the four fields to be present,
    `approver_source` to be exactly `ApproverSource.SUPPLIED.value` or
    `ApproverSource.INFERRED.value`, and `approved_at` to parse as a
    real timestamp. Anything short of that is `UNATTRIBUTED`, with
    `issues` naming each specific gap.
    """

    provenance: ApprovalProvenance | None = document.provenance
    approver = provenance.approver if provenance else None
    approver_source = provenance.approver_source if provenance else None
    approved_at = provenance.approved_at if provenance else None
    approved_commit = provenance.approved_commit if provenance else None

    issues: list[str] = []

    if not approver:
        issues.append("no approver recorded")

    known_sources = {ApproverSource.SUPPLIED.value, ApproverSource.INFERRED.value}
    if not approver_source:
        issues.append("approver source not stated as supplied or inferred")
    elif approver_source not in known_sources:
        issues.append(
            f"approver source {approver_source!r} is not a recognized value "
            "(expected supplied or inferred)"
        )

    if not approved_at:
        issues.append("no approval timestamp recorded")
    elif not _parseable_timestamp(approved_at):
        issues.append("approval timestamp is not a recognizable date/time")

    if not approved_commit:
        issues.append("no approved commit recorded")

    status = ProvenanceStatus.UNATTRIBUTED if issues else ProvenanceStatus.ATTRIBUTED

    return ProvenanceSummary(
        status=status,
        approver=approver,
        approver_source=approver_source,
        approved_at=approved_at,
        approved_commit=approved_commit,
        issues=tuple(issues),
    )


def format_provenance_lines(document: BaselineDocument) -> tuple[str, ...]:
    """Render `describe_provenance`'s result as CLI-voice text lines.

    Follows the CLI's output convention: a significant line starts with
    a stable symbol and word, and meaning never depends on color alone.
    An attributed summary never states an approver identity without
    qualifying it as `(supplied)` or `(inferred)`, so an approver
    identity is never presented as if directly supplied when it was only
    inferred.
    """

    summary = describe_provenance(document)

    if summary.status is ProvenanceStatus.UNATTRIBUTED:
        reasons = "; ".join(summary.issues)
        return (f"! UNATTRIBUTED  baseline has no verified approver: {reasons}",)

    qualifier = (
        "(supplied)"
        if summary.approver_source == ApproverSource.SUPPLIED.value
        else "(inferred)"
    )
    return (
        f"• PROVENANCE  approved by {summary.approver} {qualifier} "
        f"at {summary.approved_at}, commit {summary.approved_commit}",
    )
