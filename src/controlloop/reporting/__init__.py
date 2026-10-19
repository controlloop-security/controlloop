"""Report assembly and rendering.

`controlloop.reporting.terminal` is a deterministic terminal renderer
that composes already-computed pieces (a blast-radius statement, a
verdict, an optional material change summary, and optional findings)
into one ordered, colour-safe, width-adaptive human-readable report.

`controlloop.reporting.report` composes the same kind of
already-computed pieces -- plus diagnostics, a completeness state, every
declared repo-local suppression's own disposition, and versions -- into
`ScanReport`, a stable, versioned, machine-readable JSON envelope.

`controlloop.reporting.evidence` composes ACBOM and baseline digests,
baseline provenance, the raw effective-authority diff, findings,
completeness, every declared suppression's own disposition, a verdict,
and component versions into `EvidenceArtifact`, a single retainable
artifact meant to fully explain a gate verdict after the fact, without
access to the source repository.

`controlloop.reporting.sarif` composes an already-computed `findings`
tuple and a tool identity into one complete SARIF 2.1.0 log document,
reusing `controlloop.findings.rendering.finding_to_sarif_result`'s
per-finding `result` rendering and adding the surrounding
`runs[].tool.driver` structure, including per-rule help URIs.

`controlloop.cli`'s `scan` and `gate` commands wire these in: `scan`
renders `ScanReport` and SARIF; `gate` additionally composes and writes
`EvidenceArtifact` (see `docs/reference/cli.md#gate`).

`controlloop.reporting.cyclonedx` projects an already-built
`ACBOMDocument` into a CycloneDX 1.6 BOM, the reduced projection
documented in `docs/reference/cyclonedx-export-format.md`.
`controlloop.cli`'s `bom --format cyclonedx` wires this in.
"""

from controlloop.reporting.authority import (
    AuthorityDelta,
    AuthorityEntry,
    compute_authority_delta,
    describe_authority_delta,
)
from controlloop.reporting.cyclonedx import (
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    render_cyclonedx,
)
from controlloop.reporting.evidence import (
    CURRENT_EVIDENCE_SCHEMA_VERSION,
    EvidenceArtifact,
    EvidenceVersions,
)
from controlloop.reporting.report import (
    CURRENT_REPORT_SCHEMA_VERSION,
    ReportVersions,
    ScanReport,
)
from controlloop.reporting.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    render_sarif_log,
)
from controlloop.reporting.terminal import (
    Verdict,
    render_suppressions,
    render_terminal_report,
    render_verdict,
)

__all__ = [
    "CURRENT_EVIDENCE_SCHEMA_VERSION",
    "CURRENT_REPORT_SCHEMA_VERSION",
    "CYCLONEDX_BOM_FORMAT",
    "CYCLONEDX_SPEC_VERSION",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "AuthorityDelta",
    "AuthorityEntry",
    "EvidenceArtifact",
    "EvidenceVersions",
    "ReportVersions",
    "ScanReport",
    "Verdict",
    "compute_authority_delta",
    "describe_authority_delta",
    "render_cyclonedx",
    "render_sarif_log",
    "render_suppressions",
    "render_terminal_report",
    "render_verdict",
]
