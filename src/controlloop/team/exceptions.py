"""Organization exceptions as a gate input.

An exception is an organization saying "we have seen this exact finding
and accepted it, until this date." The CLI's job is narrow and entirely
mechanical: honor it if it matches exactly and has not expired, and
otherwise do not.

This module deliberately mirrors `controlloop.policy.suppressions`, the
repo-local mechanism that already exists, rather than inventing a second
vocabulary for the same idea. Both produce a record for every declared
item -- honored or not -- and a narrowed `effective_findings` tuple; both
are what the caller passes to `evaluate_gate` in place of the unfiltered
findings; both put their records in the evidence artifact so nothing is
silently dropped.

## Matching is exact, and only by fingerprint

`ActiveException.finding_fingerprint` is compared to `Finding.id` for
equality. No prefix matching, no rule-level wildcards, no "same rule in
the same file" heuristic. `Finding.id` is derived from allowlisted
semantic identity material, so it survives reformatting and line moves but
changes when the finding genuinely becomes a different finding -- which is
exactly the behavior an approval should have. A broader match would let an
approval for one accepted risk silently cover a second, different one that
appeared later in the same rule.

## Expiry is evaluated at gate time, against an injected instant

`apply_exceptions` takes `evaluated_at` as a parameter. It reads no clock,
which is what lets the determinism harness pin a gate to a fixed instant
and get the same verdict every run.

An expired exception is not ignored quietly: it produces an
`ExceptionState.EXPIRED` record carrying its expiry date, the finding
re-enters the evaluated set, and `controlloop.cli` renders the date in
the gate output, so the gate visibly re-blocks with the expiry date. The
failure this prevents is a team discovering that a build broke because an
approval lapsed, with nothing on screen saying so.

## Nothing about who approved what is here

The contract's `ActiveException` carries a fingerprint and an expiry and
nothing else -- no owner, no reason, no approver -- because, as it puts
it, a CI log is not the place for who accepted which risk. This module
therefore has nothing of that kind to leak.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from controlloop.findings.models import Finding


class ExceptionState(StrEnum):
    """One exception's disposition for this gate run."""

    #: Matched a finding and had not expired: the finding was removed from
    #: the evaluated set.
    APPLIED = "applied"
    #: Expired at `evaluated_at`: the finding re-blocks, and the expiry
    #: date is rendered.
    EXPIRED = "expired"
    #: Unexpired, but no finding in this scan carries its fingerprint.
    #: Recorded rather than dropped so evidence shows the full set the
    #: organization published, not only the part that bit.
    UNMATCHED = "unmatched"


class ExceptionRecord(BaseModel):
    """One exception's auditable disposition, embedded in the evidence
    artifact.

    A Pydantic model with the same discipline as `SuppressionRecord`, for
    the same reason: it is embedded in `EvidenceArtifact`, and every type
    embedded there shares one serialization and validation contract.
    """

    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, strict=True
    )

    finding_fingerprint: str
    expires_at: datetime
    state: ExceptionState


@dataclass(frozen=True, slots=True)
class ActiveException:
    """One unexpired exception as published by the platform."""

    finding_fingerprint: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ExceptionOutcome:
    """The complete result of one `apply_exceptions` call.

    `records` always covers every supplied exception, sorted
    deterministically. `effective_findings` is the narrowed tuple the
    caller passes to `evaluate_gate`.
    """

    records: tuple[ExceptionRecord, ...]
    effective_findings: tuple[Finding, ...]

    def expired(self) -> tuple[ExceptionRecord, ...]:
        """Records a caller should render: an approval that lapsed is the
        one state a developer needs told about."""

        return tuple(
            record for record in self.records if record.state is ExceptionState.EXPIRED
        )


def apply_exceptions(
    findings: tuple[Finding, ...],
    exceptions: tuple[ActiveException, ...],
    *,
    evaluated_at: datetime,
) -> ExceptionOutcome:
    """Honor every unexpired, exactly-matching exception.

    Returns every exception's record and the narrowed findings tuple. A
    finding whose exception has expired stays in the tuple, so it blocks
    exactly as it would have without any approval at all.
    """

    if not exceptions:
        return ExceptionOutcome(records=(), effective_findings=findings)

    present = {finding.id for finding in findings}
    applied: set[str] = set()
    records: list[ExceptionRecord] = []

    for exception in exceptions:
        if exception.expires_at <= evaluated_at:
            state = ExceptionState.EXPIRED
        elif exception.finding_fingerprint in present:
            state = ExceptionState.APPLIED
            applied.add(exception.finding_fingerprint)
        else:
            state = ExceptionState.UNMATCHED
        records.append(
            ExceptionRecord(
                finding_fingerprint=exception.finding_fingerprint,
                expires_at=exception.expires_at,
                state=state,
            )
        )

    return ExceptionOutcome(
        records=tuple(
            sorted(
                records,
                key=lambda record: (record.finding_fingerprint, record.state.value),
            )
        ),
        effective_findings=tuple(
            finding for finding in findings if finding.id not in applied
        ),
    )
