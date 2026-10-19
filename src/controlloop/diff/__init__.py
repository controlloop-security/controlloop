"""Change classification: every node, edge, effective capability, and
bounded transitive capability path of a live ACBOM graph classified as
added, removed, changed, or unknown against a baseline graph, keyed by
stable identity so a moved or reformatted definition is never reported
as a change; built on top of that, a material capability change
summary naming what real-world power an agent gained or lost, using
`controlloop.capability.taxonomy`'s classes rather than raw graph
deltas; and, built on top of that summary, a capability reduction
report naming a diff that only revoked authority as a distinct,
positive result, never miscounted as a finding. See
docs/reference/diff-output-format.md.

`controlloop diff` is the real CLI command that
computes and renders a `DiffReport` -- see `controlloop.diff.report` and
`controlloop.cli`. It calls `compute_diff` and `diff_effective_authority`;
it does not yet call `compute_material_change_summary`,
`diff_transitive_capability_paths`, or `compute_capability_reduction_report`
-- wiring the material capability change summary or the capability
reduction report built on top of it into `diff`'s own output is
separate, not-yet-implemented work.
"""

from controlloop.diff.compute import (
    compute_diff,
    diff_edges,
    diff_effective_authority,
    diff_nodes,
    diff_transitive_capability_paths,
)
from controlloop.diff.material_summary import (
    CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION,
    MaterialChange,
    MaterialChangeKind,
    MaterialChangeSummary,
    compute_material_change_summary,
    describe_material_change_summary,
)
from controlloop.diff.models import (
    CURRENT_DIFF_SCHEMA_VERSION,
    CapabilityPathChange,
    ChangeKind,
    DiffResult,
    EdgeChange,
    EffectiveAuthorityChange,
    NodeChange,
)
from controlloop.diff.reduction import (
    CURRENT_CAPABILITY_REDUCTION_REPORT_SCHEMA_VERSION,
    CapabilityReductionReport,
    compute_capability_reduction_report,
    describe_capability_reduction,
)
from controlloop.diff.report import (
    CURRENT_DIFF_REPORT_SCHEMA_VERSION,
    BaselineOrigin,
    ComparisonScope,
    DiffReport,
)

__all__ = [
    "CURRENT_CAPABILITY_REDUCTION_REPORT_SCHEMA_VERSION",
    "CURRENT_DIFF_REPORT_SCHEMA_VERSION",
    "CURRENT_DIFF_SCHEMA_VERSION",
    "CURRENT_MATERIAL_CHANGE_SUMMARY_SCHEMA_VERSION",
    "BaselineOrigin",
    "CapabilityPathChange",
    "CapabilityReductionReport",
    "ChangeKind",
    "ComparisonScope",
    "DiffReport",
    "DiffResult",
    "EdgeChange",
    "EffectiveAuthorityChange",
    "MaterialChange",
    "MaterialChangeKind",
    "MaterialChangeSummary",
    "NodeChange",
    "compute_capability_reduction_report",
    "compute_diff",
    "compute_material_change_summary",
    "describe_capability_reduction",
    "describe_material_change_summary",
    "diff_edges",
    "diff_effective_authority",
    "diff_nodes",
    "diff_transitive_capability_paths",
]
