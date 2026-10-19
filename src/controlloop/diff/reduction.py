"""Capability reduction reporting.

A change that revokes authority is reported as a named result, so
tightening is rewarded rather than met with silence.
`compute_capability_reduction_report` takes an already-computed
`controlloop.diff.material_summary.MaterialChangeSummary` and
partitions it into `reductions` (capabilities the agent lost) and
`other_changes` (everything else -- gained, changed, or unknown). It
performs no new classification of its own: `MaterialChangeKind.LOST`
entries already carry the exact same `MaterialCapabilityClass`
vocabulary a gain of the same fact would -- the material summary
already guarantees this, since both directions of the same underlying
diff run through the identical `classify_material_capability` call.

A reduction is never miscounted as a finding or a failure. That is
satisfied structurally, not by consulting a finding or gate model.
`reductions` and `other_changes` are two separately named, disjoint
collections -- `reductions | other_changes == summary.changes` and
`reductions & other_changes == {}`, asserted directly in this module's
own tests. A future gate or finding-counter reads `other_changes` for
anything that should count as a finding and never `reductions`; there
is no shared collection for a `LOST` entry to be accidentally counted
from.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from controlloop.diff.material_summary import (
    MaterialChange,
    MaterialChangeKind,
    MaterialChangeSummary,
)

CURRENT_CAPABILITY_REDUCTION_REPORT_SCHEMA_VERSION = "1.0.0"


class _ReductionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


class CapabilityReductionReport(_ReductionModel):
    """A material change summary partitioned into reductions and
    everything else. `is_reduction_only` is `True` only when there is
    at least one real reduction and nothing else -- an entirely empty
    summary is not "reduction only," it is simply empty (a pass
    requires something to have actually been reduced)."""

    schema_version: str
    reductions: tuple[MaterialChange, ...]
    other_changes: tuple[MaterialChange, ...]

    @property
    def is_reduction_only(self) -> bool:
        return bool(self.reductions) and not self.other_changes


def compute_capability_reduction_report(
    summary: MaterialChangeSummary,
) -> CapabilityReductionReport:
    """Partition `summary.changes` into `reductions`
    (`MaterialChangeKind.LOST`) and `other_changes` (everything else),
    preserving `MaterialChangeSummary`'s own already-deterministic
    order within each bucket."""

    reductions = tuple(
        change for change in summary.changes if change.kind is MaterialChangeKind.LOST
    )
    other_changes = tuple(
        change
        for change in summary.changes
        if change.kind is not MaterialChangeKind.LOST
    )
    return CapabilityReductionReport(
        schema_version=CURRENT_CAPABILITY_REDUCTION_REPORT_SCHEMA_VERSION,
        reductions=reductions,
        other_changes=other_changes,
    )


def _describe_reduction(change: MaterialChange) -> str:
    if change.transitive:
        return (
            f"• REDUCED  {change.material_class.value}: {change.agent_name} no "
            f"longer reaches {change.target_name} via {change.action.value} "
            f"({len(change.path)}-hop chain)"
        )
    return (
        f"• REDUCED  {change.material_class.value}: {change.agent_name} no "
        f"longer {change.action.value} {change.target_name}"
    )


def describe_capability_reduction(report: CapabilityReductionReport) -> tuple[str, ...]:
    """Render `report` as CLI-voice text lines, one `• REDUCED` line
    per reduction, following the CLI's stable symbol convention. When
    the report is reduction-only, an explicit `✓ PASSED` line is
    appended -- the pass made a real, visible signal rather than mere
    absence of a warning. Returns an empty tuple when there are no
    reductions at all: nothing to state."""

    if not report.reductions:
        return ()

    lines = [_describe_reduction(change) for change in report.reductions]
    if report.is_reduction_only:
        lines.append("✓ PASSED   capability reduced only -- no new authority gained")
    return tuple(lines)
