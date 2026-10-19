"""Expiring repo-local suppressions.

**Not a detection rule.** `controlloop.policy.rules`'s own module
docstring already names this explicitly: expiring repo-local
suppressions are "not a detection rule at all." This module never
produces a `RuleObservation` or a `Finding`;
it consumes already-computed `Finding`s (produced by every other
registered rule, unchanged) and a repository's own declared
`controlloop.manifest.models.Suppression` entries (read from
`controlloop.yaml`, unchanged by this module), and decides which
findings a suppression actually removes from `evaluate_gate`'s blocking/
warning classification.

## Why this lives beside `thresholds.py`, not inside it

`controlloop.policy.thresholds.evaluate_gate` already owns "which
findings block, which warn, which are dropped by configuration" --
`disabled_rule_ids` already drops a finding by rule ID before
classification. Suppression is a materially different kind of
exception: narrower (one specific finding, not a whole rule), reasoned
(a required `reason`), time-bounded (a required `expires_at`), and
always visible even when it has no effect (the `EXPIRED`/`STALE`
statuses). Folding it into
`evaluate_gate` itself would conflate "a repository turned a whole rule
off" with "a repository suppressed one specific, already-triaged
finding, with a reason and an expiry, visibly" -- two different
governance actions with two different audit trails. This module's own
`apply_suppressions` therefore runs *before* `evaluate_gate`, in the
caller (`controlloop.cli`'s `scan`/`gate`), narrowing the `findings`
tuple passed to `evaluate_gate` -- `evaluate_gate` itself is unchanged
by suppressions.

## The two structural guarantees

**"Cannot broaden beyond its declared scope":** a
`Suppression.target` is already shape-constrained to a real
`Finding.id` pattern (`controlloop.manifest.models.SuppressionTarget`),
and matching here is exact string equality on `(rule_id, target)` --
never a prefix, glob, substring, or wildcard. There is no mechanism
anywhere in this module a suppression author could use to match more
than the one finding whose exact stable identity they named, even
deliberately -- this is a structural guarantee, not a documented
convention a future change could silently weaken. See
`tests/policy/test_suppressions.py`'s
`TestCannotBroadenBeyondDeclaredScope` for a fixture that attempts
exactly this (a suppression naming one finding's `target`, asserted to
never affect a second, different finding that merely shares the same
`rule_id`).

**"Cannot suppress ceiling breaches unless the ceiling itself is
amended":** any suppression whose `rule_id` equals
`controlloop.policy.rules.capability_ceiling.RULE_ID` is always
classified `SuppressionStatus.CEILING_PROTECTED` and never added to
`SuppressionOutcome.suppressed_finding_ids` -- checked before expiry and
before matching, so a ceiling-targeting suppression is reported as
permanently ineffective, never as merely "currently" inactive the way an
`EXPIRED` one is. The only way to change a ceiling breach's outcome is
to amend `ManifestDocument.ceilings` itself, which this module never
reads or modifies. See
`tests/policy/test_suppressions.py`'s
`TestCannotSuppressCeilingBreaches`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from controlloop.acbom.models import SafeIdentifier, SafeText
from controlloop.manifest.models import (
    Suppression,
    SuppressionExpiry,
    SuppressionTarget,
)

if TYPE_CHECKING:
    # Deferred to a `TYPE_CHECKING`-only import, exactly like
    # `controlloop.policy.thresholds`'s own identical deferral (see that
    # module's docstring): `controlloop.findings.models` imports
    # `controlloop.policy.models.RuleObservation`, and importing any
    # submodule of the `controlloop.policy` package first runs
    # `controlloop/policy/__init__.py`, which (once this module is
    # exported from it) imports this module -- a module-level import of
    # `controlloop.findings.models` here would be circular.
    from controlloop.findings.models import Finding


class SuppressionStatus(StrEnum):
    """One declared suppression's real, observable effect ("active
    suppressions are listed in every scan and gate result, never hidden"
    -- extended here to every status, not only `ACTIVE`, since a
    repository author needs to see an `EXPIRED`/`STALE`/
    `CEILING_PROTECTED` suppression exactly as much as an effective one:
    an expired suppression is reported as expired, a stale one as
    stale)."""

    #: Matched exactly one real, currently-evaluated finding, is not
    #: expired, and does not target the capability-ceiling rule --
    #: removed that finding from `evaluate_gate`'s classification.
    ACTIVE = "active"
    #: `expires_at` is before the reference date this suppression was
    #: evaluated against. Has no effect, regardless of whether
    #: it would otherwise have matched.
    EXPIRED = "expired"
    #: Not expired, not ceiling-protected, but matches no
    #: currently-evaluated finding ("so suppressions do not accumulate
    #: invisibly"). The finding it once suppressed may have
    #: been fixed, or the suppression's own `rule_id`/`target` may never
    #: have matched anything real.
    STALE = "stale"
    #: Targets `controlloop.policy.rules.capability_ceiling.RULE_ID`.
    #: Always reported this way regardless of expiry or match --
    #: a ceiling breach can only ever be resolved by amending the
    #: ceiling itself, never by any suppression.
    CEILING_PROTECTED = "ceiling-protected"


class _SuppressionRecordModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class SuppressionRecord(_SuppressionRecordModel):
    """One declared suppression's full, human-auditable disposition --
    the "visible" record, carried unchanged from the
    `Suppression` this repository declared plus the `SuppressionStatus`
    this module computed for it. Every field here is already
    redaction-safe: `rule_id`/`target`/`expires_at` are shape-constrained
    identifiers or dates, never raw repository content, and `reason` is
    exactly the human-authored text a repository owner chose to publish
    in their own `controlloop.yaml` -- not scanner-discovered evidence.

    A real Pydantic model (`extra="forbid", frozen=True, strict=True`),
    matching every other canonical/computed-report model in this
    codebase (`Finding`, `Diagnostic`, ...), rather than a plain
    dataclass -- this type is embedded directly in
    `controlloop.reporting.report.ScanReport.suppressions` and
    `controlloop.reporting.evidence.EvidenceArtifact.suppressions`, both
    of which require every embedded type to share this
    same serialization and validation discipline.
    """

    rule_id: SafeIdentifier
    target: SuppressionTarget
    reason: SafeText
    expires_at: SuppressionExpiry
    status: SuppressionStatus


@dataclass(frozen=True, slots=True)
class SuppressionOutcome:
    """The complete result of one `apply_suppressions` call: every
    declared suppression's own `SuppressionRecord` (always present,
    sorted deterministically), and the narrowed `findings` tuple
    with every `ACTIVE`-suppressed finding removed -- the tuple a caller
    passes to `controlloop.policy.thresholds.evaluate_gate` in place of
    the original, unfiltered `findings`."""

    records: tuple[SuppressionRecord, ...]
    effective_findings: tuple[Finding, ...]


def _capability_ceiling_rule_id() -> str:
    """Imported lazily, inside this function, not at module level --
    `controlloop.policy.rules` (and every concrete rule module under it)
    is a materially heavier import than this module otherwise needs, and
    keeping this the one deferred call site makes the dependency
    direction explicit: this module depends on knowing the ceiling
    rule's own ID, never the reverse."""

    from controlloop.policy.rules.capability_ceiling import RULE_ID

    return RULE_ID


def apply_suppressions(
    findings: tuple[Finding, ...],
    suppressions: tuple[Suppression, ...],
    *,
    reference_date: date,
) -> SuppressionOutcome:
    """Classify every declared `Suppression` against `findings` and
    return the resulting `SuppressionOutcome`.

    Pure and deterministic: `reference_date` is supplied by the caller
    (`controlloop.cli`'s `scan`/`gate`, from the real process clock) --
    this function never calls `date.today()` itself, matching this
    codebase's rule that a clock is injected behind an explicit
    interface and deterministic core logic must not depend on it.

    Classification order, per suppression, checked in this priority
    (ceiling protection is checked first, ahead of expiry --
    see this module's own docstring for why a ceiling-targeting
    suppression is reported as *permanently* ineffective rather than
    merely "currently" inactive the way `EXPIRED` implies):

    1. `rule_id` names the capability-ceiling rule -> `CEILING_PROTECTED`,
       never suppresses anything.
    2. `expires_at` is before `reference_date` -> `EXPIRED`, never
       suppresses anything.
    3. `(rule_id, target)` matches no finding in `findings` -> `STALE`.
    4. Otherwise -> `ACTIVE`; the matched finding is removed from
       `effective_findings`.

    Matching itself is exact equality on the pair `(finding.rule_id,
    finding.id) == (suppression.rule_id, suppression.target)` -- see
    this module's own docstring, "Cannot broaden beyond its declared
    scope," for why this makes broadening
    beyond the declared scope structurally impossible, not merely
    disallowed by convention.
    """

    ceiling_rule_id = _capability_ceiling_rule_id()
    finding_keys = {(finding.rule_id, finding.id) for finding in findings}

    records: list[SuppressionRecord] = []
    suppressed_keys: set[tuple[str, str]] = set()

    for suppression in suppressions:
        key = (suppression.rule_id, suppression.target)

        if suppression.rule_id == ceiling_rule_id:
            status = SuppressionStatus.CEILING_PROTECTED
        elif date.fromisoformat(suppression.expires_at) < reference_date:
            status = SuppressionStatus.EXPIRED
        elif key in finding_keys:
            status = SuppressionStatus.ACTIVE
            suppressed_keys.add(key)
        else:
            status = SuppressionStatus.STALE

        records.append(
            SuppressionRecord(
                rule_id=suppression.rule_id,
                target=suppression.target,
                reason=suppression.reason,
                expires_at=suppression.expires_at,
                status=status,
            )
        )

    ordered_records = tuple(
        sorted(records, key=lambda record: (record.rule_id, record.target))
    )
    effective_findings = tuple(
        finding
        for finding in findings
        if (finding.rule_id, finding.id) not in suppressed_keys
    )
    return SuppressionOutcome(
        records=ordered_records, effective_findings=effective_findings
    )
