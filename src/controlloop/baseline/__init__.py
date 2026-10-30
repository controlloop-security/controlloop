"""The versioned, canonical baseline artifact: a recorded approved
capability set (ACBOM digest, schema version, effective authority,
scanner version, commit, and approval provenance), with deterministic
serialization/digesting, tamper/truncation detection, resolution of "the"
baseline for a repository (conventional-path discovery, an explicit-path
override, and validation reusing the same integrity check), a
merge-base fallback resolution when no committed baseline exists
(local-git-only resolution of the default branch's merge-base, plus
scanning that revision with the exact same pipeline the live scan uses),
a provenance reporting helper, and staleness detection (is a resolved
baseline's recorded commit too far behind the repository's default
branch to still describe it). See
docs/reference/baseline-artifact-format.md.

`controlloop diff` is the real CLI command that consumes
`resolve_baseline` and `resolve_merge_base`/`build_merge_base_acbom` to
compare a repository against a resolved baseline -- see `controlloop.cli`
and docs/reference/cli.md#diff. Writing or committing a baseline, and
wiring `describe_provenance`/`format_provenance_lines` or
`detect_baseline_staleness` into any command's output, remain separate,
not-yet-implemented work.
"""

from controlloop.baseline.integrity import (
    BaselineIntegrityError,
    load_baseline_document,
)
from controlloop.baseline.merge_base import (
    MergeBaseResolution,
    MergeBaseResolutionError,
    NoGitHistoryError,
    build_acbom_at_revision,
    build_merge_base_acbom,
    checked_out_branch,
    resolve_merge_base,
    resolve_revision_commit,
)
from controlloop.baseline.models import (
    CURRENT_BASELINE_SCHEMA_VERSION,
    ApprovalProvenance,
    ApproverSource,
    BaselineDocument,
)
from controlloop.baseline.provenance import (
    ProvenanceStatus,
    ProvenanceSummary,
    describe_provenance,
    format_provenance_lines,
)
from controlloop.baseline.resolution import (
    CONVENTIONAL_BASELINE_RELATIVE_PATH,
    BaselineResolutionError,
    BaselineSource,
    ResolvedBaseline,
    resolve_baseline,
)
from controlloop.baseline.serialization import (
    canonicalize_baseline,
    compute_baseline_digest,
    serialize_baseline,
    with_baseline_digest,
)
from controlloop.baseline.staleness import (
    BASELINE_DIAGNOSTIC_REGISTRY,
    count_commits_between,
    describe_staleness,
    detect_baseline_staleness,
    resolve_default_branch_commit,
)

__all__ = [
    "BASELINE_DIAGNOSTIC_REGISTRY",
    "CONVENTIONAL_BASELINE_RELATIVE_PATH",
    "CURRENT_BASELINE_SCHEMA_VERSION",
    "ApprovalProvenance",
    "ApproverSource",
    "BaselineDocument",
    "BaselineIntegrityError",
    "BaselineResolutionError",
    "BaselineSource",
    "MergeBaseResolution",
    "MergeBaseResolutionError",
    "NoGitHistoryError",
    "ProvenanceStatus",
    "ProvenanceSummary",
    "ResolvedBaseline",
    "build_acbom_at_revision",
    "build_merge_base_acbom",
    "canonicalize_baseline",
    "checked_out_branch",
    "compute_baseline_digest",
    "count_commits_between",
    "describe_provenance",
    "describe_staleness",
    "detect_baseline_staleness",
    "format_provenance_lines",
    "load_baseline_document",
    "resolve_baseline",
    "resolve_default_branch_commit",
    "resolve_merge_base",
    "resolve_revision_commit",
    "serialize_baseline",
    "with_baseline_digest",
]
